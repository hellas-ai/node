use super::mailbox::AppMailboxReadWriteMessage;
use super::metrics::CoreMetrics;
use super::payload::{
    decode_anchor, decode_execution_payload, encode_payload, genesis_digest, genesis_payload,
    missing_dependency_or_execution, payload_digest, validate_payload,
};
use crate::execution::{
    ExecutionError, FinalizationDiffs, FinalizationTracker, ObjectState, SpeculativeExecutionStore,
    execute_block, execute_transaction, genesis_state,
};
use crate::object::{Coin, ObjectId};
use crate::object::{MAX_TXS_PER_BLOCK, Transaction};
use crate::shard::core::{ShardEffect, ShardRecoverer};
use crate::shard::protocol::{BlockKey, CodingImpl, ShardMessage, ZodaCommitment, ZodaShard};
use bytes::Bytes;
use commonware_coding::Scheme as CodingScheme;
use commonware_consensus::types::Epoch;
use commonware_cryptography::sha256::Digest;
use commonware_parallel::Rayon;
use commonware_utils::channel::oneshot;
use hellas_types::{Context, PublicKey};
use indexmap::{IndexMap, IndexSet};
use std::collections::{HashMap, VecDeque};

struct DeferredVerify {
    context: Context,
    payload: Digest,
    response: oneshot::Sender<bool>,
}

pub(super) enum CoreEffect {
    Digest {
        response: oneshot::Sender<Digest>,
        digest: Digest,
    },
    Verify {
        response: oneshot::Sender<bool>,
        valid: bool,
    },
    Coin {
        response: oneshot::Sender<Option<Coin>>,
        coin: Option<Coin>,
    },
}

pub(super) enum NetworkEffect {
    BroadcastShard(Box<ShardMessage>),
    DistributeShards {
        key: BlockKey,
        commitment: ZodaCommitment,
        shards: Vec<ZodaShard>,
    },
}

pub(super) struct CoreEffects {
    pub(super) replies: VecDeque<CoreEffect>,
    pub(super) network: VecDeque<NetworkEffect>,
}

impl CoreEffects {
    pub(super) fn new() -> Self {
        Self {
            replies: VecDeque::new(),
            network: VecDeque::new(),
        }
    }
}

pub(super) struct AppCore {
    seen: HashMap<Digest, Bytes>,
    pending: IndexSet<Digest>,
    pending_shards: HashMap<Digest, (BlockKey, ZodaCommitment, Vec<ZodaShard>)>,
    waiters: IndexMap<Digest, Vec<DeferredVerify>>,
    mempool: VecDeque<Transaction>,
    speculative_store: SpeculativeExecutionStore,
    finalized: FinalizationTracker,
    persisted_roots: IndexMap<Digest, Digest>,
    latest_anchor: Option<(Digest, Digest)>,
    validators: Vec<PublicKey>,
    strategy: Rayon,
    shard_recoverer: ShardRecoverer,
    metrics: CoreMetrics,
}

impl AppCore {
    const MAX_PENDING_DIGESTS: usize = 256;
    const MAX_WAITER_KEYS: usize = 512;
    const MAX_MEMPOOL_SIZE: usize = 1024;
    const MAX_FINALIZED_EXECUTIONS: usize = 512;
    const MAX_PERSISTED_ROOTS: usize = 2048;

    // Construction + identity -------------------------------------------------
    pub(super) fn new(
        me: &PublicKey,
        mut validators: Vec<PublicKey>,
        my_index: u16,
        coding_config: commonware_coding::Config,
        strategy: Rayon,
        metrics: CoreMetrics,
    ) -> Self {
        validators.sort();
        validators.dedup();
        if validators.is_empty() {
            warn!("validator set was empty; defaulting to self-only validator set");
            validators.push(me.clone());
        }

        let core = Self {
            seen: HashMap::new(),
            pending: IndexSet::new(),
            pending_shards: HashMap::new(),
            waiters: IndexMap::new(),
            mempool: VecDeque::new(),
            speculative_store: SpeculativeExecutionStore::new(),
            finalized: FinalizationTracker::new(Self::MAX_FINALIZED_EXECUTIONS),
            persisted_roots: IndexMap::new(),
            latest_anchor: None,
            validators,
            strategy: strategy.clone(),
            shard_recoverer: ShardRecoverer::new(me, my_index, coding_config, strategy),
            metrics,
        };
        core.metrics.waiter_keys.set(0);
        core.metrics.waiter_total.set(0);
        core.metrics.mempool_size.set(0);
        core.metrics.pending_payloads.set(0);
        core.metrics.persisted_roots.set(0);
        core.metrics.unpersisted_finalizations.set(0);
        core
    }

    pub(super) const fn me(&self) -> &PublicKey {
        self.shard_recoverer.me()
    }

    pub(super) fn validators(&self) -> &[PublicKey] {
        &self.validators
    }

    // Driver entry points -----------------------------------------------------
    pub(super) fn on_message<F>(
        &mut self,
        message: AppMailboxReadWriteMessage,
        now: u64,
        validator_index: &F,
    ) -> CoreEffects
    where
        F: Fn(&PublicKey) -> Option<u16>,
    {
        let mut effects = CoreEffects::new();
        match message {
            AppMailboxReadWriteMessage::Propose { context, response } => {
                let digest = self.propose(&context, now);
                effects
                    .replies
                    .push_back(CoreEffect::Digest { response, digest });
            }
            AppMailboxReadWriteMessage::Verify {
                context,
                payload,
                response,
            } => {
                let key = BlockKey::new(context.round, payload);
                self.process_verify_request(&context, payload, response, now, &mut effects);
                for msg in self.shard_recoverer.note_known_key(key, &context.leader) {
                    self.handle_shard_message(msg, now, validator_index, &mut effects);
                }
            }
            AppMailboxReadWriteMessage::Broadcast { payload } => {
                self.enqueue_broadcast(payload, &mut effects);
            }
            AppMailboxReadWriteMessage::SubmitTx { tx } => {
                if self.mempool.len() < Self::MAX_MEMPOOL_SIZE {
                    self.mempool.push_back(tx);
                    self.metrics
                        .mempool_size
                        .set(i64::try_from(self.mempool.len()).unwrap_or(i64::MAX));
                }
            }
            AppMailboxReadWriteMessage::GetCoin {
                payload,
                object,
                response,
            } => {
                let coin = self.get_coin(payload, object);
                effects
                    .replies
                    .push_back(CoreEffect::Coin { response, coin });
            }
            AppMailboxReadWriteMessage::Genesis { .. }
            | AppMailboxReadWriteMessage::GetStateRoot { .. }
            | AppMailboxReadWriteMessage::GetProof { .. }
            | AppMailboxReadWriteMessage::GetFinalization { .. }
            | AppMailboxReadWriteMessage::DrainExternalEvents => {
                unreachable!(
                    "application should intercept non-core ingress before AppCore::on_message"
                );
            }
        }
        effects
    }

    pub(super) fn on_shard_message<F>(
        &mut self,
        message: ShardMessage,
        now: u64,
        validator_index: &F,
    ) -> CoreEffects
    where
        F: Fn(&PublicKey) -> Option<u16>,
    {
        let mut effects = CoreEffects::new();
        self.handle_shard_message(message, now, validator_index, &mut effects);
        effects
    }

    pub(super) fn on_finalized(&mut self, payload: Digest, parent_payload: Digest) -> CoreEffects {
        let mut effects = CoreEffects::new();
        self.handle_finalized(payload, parent_payload, &mut effects);
        effects
    }

    pub(super) fn next_unpersisted_finalization(&self) -> Option<(Digest, &FinalizationDiffs)> {
        self.finalized.next_unpersisted_finalization()
    }

    pub(super) fn mark_finalization_persisted(&mut self, payload: Digest) -> bool {
        let marked = self.finalized.mark_persisted(payload);
        self.metrics.unpersisted_finalizations.set(
            i64::try_from(self.finalized.unpersisted_finalization_count()).unwrap_or(i64::MAX),
        );
        marked
    }

    pub(super) fn unpersisted_finalization_count(&self) -> usize {
        self.finalized.unpersisted_finalization_count()
    }

    pub(super) fn note_persisted_root(&mut self, payload: Digest, root: Digest) {
        self.persisted_roots.insert(payload, root);
        while self.persisted_roots.len() > Self::MAX_PERSISTED_ROOTS {
            let Some((_oldest, _)) = self.persisted_roots.shift_remove_index(0) else {
                break;
            };
        }
        self.latest_anchor = Some((payload, root));
        self.metrics
            .persisted_roots
            .set(i64::try_from(self.persisted_roots.len()).unwrap_or(i64::MAX));
    }

    pub(super) fn has_persisted_roots(&self) -> bool {
        !self.persisted_roots.is_empty()
    }

    pub(super) fn on_persisted_root(
        &mut self,
        payload: Digest,
        root: Digest,
        now: u64,
    ) -> CoreEffects {
        self.note_persisted_root(payload, root);
        let mut effects = CoreEffects::new();
        self.retry_waiters(payload, now, &mut effects);
        effects
    }

    // Consensus callbacks -----------------------------------------------------
    pub(super) fn genesis(&mut self, epoch: Epoch) -> Digest {
        let payload = genesis_payload(epoch);
        let digest = genesis_digest(epoch);
        self.seen.insert(digest, payload);
        let genesis_execution = genesis_state(&self.validators);
        let diffs = FinalizationDiffs {
            created: genesis_execution.created,
            deleted: genesis_execution.deleted,
        };
        self.speculative_store.insert_state_with_diffs(
            digest,
            Digest::from([0u8; 32]),
            genesis_execution.state,
            diffs,
        );
        digest
    }

    pub(super) fn propose(&mut self, context: &Context, now: u64) -> Digest {
        let parent = context.parent.1;
        let _span = info_span!(
            "app.core.propose",
            round = ?context.round,
            parent = ?parent,
            now_ms = now,
            payload = tracing::field::Empty
        )
        .entered();
        self.metrics.propose_total.inc();
        let mut txs = Vec::new();
        let mut resulting_state = None;
        let mut resulting_diffs = None;

        if self.ensure_execution_materialized(parent) {
            let Some(parent_state) = self.speculative_store.execution(parent).cloned() else {
                warn!(
                    parent = ?parent,
                    "execution materialization reported success but parent state was missing"
                );
                return self.propose_empty(context, now);
            };
            let mut running_state = parent_state.clone();
            let mut retained = VecDeque::new();
            while let Some(tx) = self.mempool.pop_front() {
                if txs.len() >= MAX_TXS_PER_BLOCK {
                    retained.push_back(tx);
                    continue;
                }
                match execute_transaction(&mut running_state, &tx) {
                    Ok(()) => {
                        txs.push(tx);
                    }
                    Err(ExecutionError::ObjectNotFound { .. }) => {
                        retained.push_back(tx);
                    }
                    Err(err) => {
                        warn!(?err, "dropping permanently invalid tx from mempool");
                    }
                }
            }
            self.mempool = retained;
            self.metrics
                .mempool_size
                .set(i64::try_from(self.mempool.len()).unwrap_or(i64::MAX));

            // Re-execute via execute_block to obtain diffs.
            if txs.is_empty() {
                resulting_diffs = Some(FinalizationDiffs {
                    created: Vec::new(),
                    deleted: Vec::new(),
                });
                resulting_state = Some(running_state);
            } else {
                match execute_block(&parent_state, &txs) {
                    Ok(exec) => {
                        resulting_diffs = Some(FinalizationDiffs {
                            created: exec.created,
                            deleted: exec.deleted,
                        });
                        resulting_state = Some(exec.state);
                    }
                    Err(err) => {
                        error!(
                            ?err,
                            parent = ?parent,
                            tx_count = txs.len(),
                            "failed to re-execute selected txs for proposal; proposing empty block"
                        );
                        // If we cannot derive diffs, do not cache or propose a stateful block.
                        for tx in txs.into_iter().rev() {
                            self.mempool.push_front(tx);
                        }
                        self.metrics
                            .mempool_size
                            .set(i64::try_from(self.mempool.len()).unwrap_or(i64::MAX));
                        return self.propose_empty(context, now);
                    }
                }
            }
        } else {
            warn!(parent = ?parent, "missing parent execution; proposing empty block");
        }

        let digest =
            self.propose_with_txs(context, now, parent, &txs, resulting_state, resulting_diffs);
        tracing::Span::current().record("payload", tracing::field::debug(&digest));
        digest
    }

    // Proposal assembly -------------------------------------------------------
    fn propose_empty(&mut self, context: &Context, now: u64) -> Digest {
        self.propose_with_txs(context, now, context.parent.1, &[], None, None)
    }

    fn propose_with_txs(
        &mut self,
        context: &Context,
        timestamp: u64,
        parent: Digest,
        txs: &[Transaction],
        resulting_state: Option<ObjectState>,
        resulting_diffs: Option<FinalizationDiffs>,
    ) -> Digest {
        let tx_count = txs.len();
        let _span = debug_span!(
            "app.core.proposal_assembly",
            round = ?context.round,
            parent = ?parent,
            timestamp,
            tx_count
        )
        .entered();
        let Some((anchor_payload, anchor_root)) = self
            .latest_anchor
            .or_else(|| self.persisted_root(parent).map(|root| (parent, root)))
        else {
            self.metrics.propose_missing_anchor_total.inc();
            error!(
                parent = ?parent,
                "no persisted state root anchor available for proposal; aborting to avoid unverifiable payload"
            );
            std::process::abort();
        };
        let payload = encode_payload(
            context.round,
            parent,
            timestamp,
            anchor_payload,
            anchor_root,
            &txs,
        );
        let digest = payload_digest(&payload);
        trace!(
            payload = ?digest,
            ?anchor_payload,
            ?anchor_root,
            tx_count,
            "assembled proposal payload"
        );
        let key = BlockKey::new(context.round, digest);
        let encoded = CodingImpl::encode(
            self.shard_recoverer.coding_config(),
            payload.as_ref(),
            &self.strategy,
        );

        self.pending.insert(digest);
        match encoded {
            Ok((commitment, shards)) => {
                self.pending_shards
                    .insert(digest, (key, commitment, shards));
            }
            Err(err) => {
                warn!(?err, digest = ?digest, "zoda encode failed; payload will not be broadcast");
            }
        }
        self.enforce_pending_capacity();
        self.metrics
            .pending_payloads
            .set(i64::try_from(self.pending.len()).unwrap_or(i64::MAX));
        self.seen.insert(digest, payload);
        match (resulting_state, resulting_diffs) {
            (Some(state), Some(diffs)) => {
                self.speculative_store
                    .insert_state_with_diffs(digest, parent, state, diffs);
            }
            (Some(_), None) => {
                error!(
                    "internal invariant violated: proposal state was computed without finalization diffs; aborting"
                );
                std::process::abort();
            }
            _ => {
                self.speculative_store.note_parent(digest, parent);
            }
        }
        digest
    }

    // Verification + execution ------------------------------------------------
    fn verify_payload(
        &mut self,
        context: &Context,
        payload: Digest,
        contents: &Bytes,
        anchor_payload: Digest,
        anchor_root: Digest,
        local_anchor_root: Digest,
        now: u64,
    ) -> bool {
        let parent = context.parent.1;
        let _span = debug_span!(
            "app.core.verify_payload",
            round = ?context.round,
            parent = ?parent,
            payload = ?payload,
            anchor_payload = ?anchor_payload,
            now_ms = now
        )
        .entered();
        if !self.ensure_execution_materialized(parent) {
            warn!(
                parent = ?parent,
                "missing parent execution during verify"
            );
            return false;
        }
        let Some(parent_bytes) = self.seen.get(&parent) else {
            warn!(
                parent = ?parent,
                "parent bytes missing during verify despite dependency check"
            );
            return false;
        };
        let Some(parent_state) = self.speculative_store.execution(parent).cloned() else {
            warn!(
                parent = ?parent,
                "parent execution missing during verify despite dependency check"
            );
            return false;
        };
        if local_anchor_root != anchor_root {
            self.metrics.anchor_mismatch_total.inc();
            error!(
                payload = ?payload,
                anchor_payload = ?anchor_payload,
                claimed_anchor_root = ?anchor_root,
                local_anchor_root = ?local_anchor_root,
                "anchor root mismatch for known anchor payload; possible Byzantine proposal or local state divergence"
            );
            return false;
        }
        match validate_payload(context.round, parent, payload, contents, now, parent_bytes) {
            Ok(txs) => match execute_block(&parent_state, &txs) {
                Ok(exec) => {
                    let diffs = FinalizationDiffs {
                        created: exec.created,
                        deleted: exec.deleted,
                    };
                    self.speculative_store
                        .insert_state_with_diffs(payload, parent, exec.state, diffs);
                    true
                }
                Err(err) => {
                    warn!(?err, payload = ?payload, "payload execution failed");
                    false
                }
            },
            Err(err) => {
                warn!(%err, payload = ?payload, "payload validation failed");
                false
            }
        }
    }

    // Deferred verify queue ---------------------------------------------------
    fn process_verify_request(
        &mut self,
        context: &Context,
        payload: Digest,
        response: oneshot::Sender<bool>,
        now: u64,
        effects: &mut CoreEffects,
    ) {
        let parent = context.parent.1;
        let _span = info_span!(
            "app.core.verify_request",
            round = ?context.round,
            parent = ?parent,
            payload = ?payload,
            now_ms = now
        )
        .entered();
        self.metrics.verify_requests_total.inc();
        if !self.speculative_store.contains_execution(parent) {
            let _ = self.ensure_execution_materialized(parent);
        }
        if let Some(missing_digest) =
            missing_dependency_or_execution(&self.seen, &self.speculative_store, context, payload)
        {
            self.metrics.verify_deferred_dependency_total.inc();
            debug!(
                ?payload,
                ?missing_digest,
                "deferring verify while waiting for dependency"
            );
            self.queue_waiter(
                missing_digest,
                DeferredVerify {
                    context: context.clone(),
                    payload,
                    response,
                },
                effects,
            );
            return;
        }
        let Some(contents) = self.seen.get(&payload).cloned() else {
            warn!(
                payload = ?payload,
                "payload bytes missing during verify despite dependency check"
            );
            self.metrics.verify_invalid_total.inc();
            effects.replies.push_back(CoreEffect::Verify {
                response,
                valid: false,
            });
            return;
        };
        let Some((anchor_payload, anchor_root)) = decode_anchor(&contents) else {
            warn!(payload = ?payload, "payload missing anchor fields");
            self.metrics.verify_invalid_total.inc();
            effects.replies.push_back(CoreEffect::Verify {
                response,
                valid: false,
            });
            return;
        };
        let Some(local_anchor_root) = self.persisted_root(anchor_payload) else {
            self.metrics.verify_deferred_anchor_total.inc();
            debug!(
                ?payload,
                ?anchor_payload,
                "deferring verify while waiting for anchor root"
            );
            self.queue_waiter(
                anchor_payload,
                DeferredVerify {
                    context: context.clone(),
                    payload,
                    response,
                },
                effects,
            );
            return;
        };
        let valid = self.verify_payload(
            context,
            payload,
            &contents,
            anchor_payload,
            anchor_root,
            local_anchor_root,
            now,
        );
        effects
            .replies
            .push_back(CoreEffect::Verify { response, valid });
        if valid {
            self.metrics.verify_valid_total.inc();
            self.retry_waiters(payload, now, effects);
        } else {
            self.metrics.verify_invalid_total.inc();
            self.reject_waiters(payload, effects);
        }
    }

    fn queue_waiter(
        &mut self,
        digest: Digest,
        deferred: DeferredVerify,
        effects: &mut CoreEffects,
    ) {
        self.waiters.entry(digest).or_default().push(deferred);
        for stale in self.trim_waiter_keys() {
            effects.replies.push_back(CoreEffect::Verify {
                response: stale.response,
                valid: false,
            });
        }
        self.update_waiter_metrics();
    }

    fn retry_waiters(&mut self, digest: Digest, now: u64, effects: &mut CoreEffects) {
        for deferred in self.waiters.shift_remove(&digest).unwrap_or_default() {
            self.process_verify_request(
                &deferred.context,
                deferred.payload,
                deferred.response,
                now,
                effects,
            );
        }
        self.update_waiter_metrics();
    }

    fn reject_waiters(&mut self, digest: Digest, effects: &mut CoreEffects) {
        for deferred in self.waiters.shift_remove(&digest).unwrap_or_default() {
            effects.replies.push_back(CoreEffect::Verify {
                response: deferred.response,
                valid: false,
            });
        }
        self.update_waiter_metrics();
    }

    fn trim_waiter_keys(&mut self) -> Vec<DeferredVerify> {
        let mut evicted = Vec::new();
        while self.waiters.len() > Self::MAX_WAITER_KEYS {
            let Some((_oldest, stale)) = self.waiters.shift_remove_index(0) else {
                break;
            };
            evicted.extend(stale);
        }
        evicted
    }

    fn update_waiter_metrics(&self) {
        self.metrics
            .waiter_keys
            .set(i64::try_from(self.waiters.len()).unwrap_or(i64::MAX));
        let waiter_total = self.waiters.values().map(Vec::len).sum::<usize>();
        self.metrics
            .waiter_total
            .set(i64::try_from(waiter_total).unwrap_or(i64::MAX));
    }

    // Pending payload retention -----------------------------------------------
    fn enforce_pending_capacity(&mut self) {
        while self.pending.len() > Self::MAX_PENDING_DIGESTS {
            let Some(oldest) = self.pending.shift_remove_index(0) else {
                break;
            };
            self.pending_shards.remove(&oldest);
        }
        self.metrics
            .pending_payloads
            .set(i64::try_from(self.pending.len()).unwrap_or(i64::MAX));
    }

    // Finalization pruning ----------------------------------------------------
    fn handle_finalized(
        &mut self,
        payload: Digest,
        parent_payload: Digest,
        effects: &mut CoreEffects,
    ) {
        let _span = info_span!(
            "app.core.finalize",
            payload = ?payload,
            parent_payload = ?parent_payload
        )
        .entered();
        self.speculative_store
            .note_parent_if_absent(payload, parent_payload);
        if !self.ensure_execution_materialized(payload) {
            warn!(
                ?payload,
                "finalization arrived before local execution state was available"
            );
            return;
        }
        let was_finalized = self.finalized.is_finalized(payload);
        let diffs = self.speculative_store.take_diffs(payload);
        if diffs.is_none() && !was_finalized {
            warn!(
                ?payload,
                "finalized payload had no execution diffs; persistence queue will skip it"
            );
        }
        self.finalized.observe_finalized(payload, diffs);
        self.metrics.unpersisted_finalizations.set(
            i64::try_from(self.finalized.unpersisted_finalization_count()).unwrap_or(i64::MAX),
        );

        let finalized = &self.finalized;
        let pruned = self
            .speculative_store
            .prune_non_descendants(payload, |digest| finalized.is_finalized(digest));
        for digest in pruned {
            for deferred in self.remove_digest(digest) {
                effects.replies.push_back(CoreEffect::Verify {
                    response: deferred.response,
                    valid: false,
                });
            }
        }
    }

    fn remove_digest(&mut self, digest: Digest) -> Vec<DeferredVerify> {
        self.seen.remove(&digest);
        self.pending.shift_remove(&digest);
        self.pending_shards.remove(&digest);
        let removed = self.waiters.shift_remove(&digest).unwrap_or_default();
        self.metrics
            .pending_payloads
            .set(i64::try_from(self.pending.len()).unwrap_or(i64::MAX));
        self.update_waiter_metrics();
        removed
    }

    // Shard recovery + broadcast ----------------------------------------------
    fn apply_shard_effect(&mut self, effect: ShardEffect, now: u64, effects: &mut CoreEffects) {
        match effect {
            ShardEffect::Broadcast(message) => {
                let key = message.key();
                trace!(
                    payload = ?key.digest,
                    round = ?key.round,
                    "queueing shard rebroadcast"
                );
                effects
                    .network
                    .push_back(NetworkEffect::BroadcastShard(message));
            }
            ShardEffect::Recovered { key, contents } => {
                info!(
                    payload = ?key.digest,
                    round = ?key.round,
                    "recovered payload from shards"
                );
                self.seen.insert(key.digest, contents);
                self.pending.shift_remove(&key.digest);
                self.pending_shards.remove(&key.digest);
                self.metrics
                    .pending_payloads
                    .set(i64::try_from(self.pending.len()).unwrap_or(i64::MAX));
                self.retry_waiters(key.digest, now, effects);
            }
            ShardEffect::Failed { key } => {
                warn!(
                    payload = ?key.digest,
                    round = ?key.round,
                    "shard recovery failed for payload"
                );
                self.reject_waiters(key.digest, effects);
            }
        }
    }

    fn handle_shard_message<F>(
        &mut self,
        message: ShardMessage,
        now: u64,
        validator_index: &F,
        effects: &mut CoreEffects,
    ) where
        F: Fn(&PublicKey) -> Option<u16>,
    {
        let key = message.key();
        let _span = debug_span!(
            "app.core.shard_message",
            payload = ?key.digest,
            round = ?key.round,
            sender = ?message.sender()
        )
        .entered();
        let shard_effects =
            self.shard_recoverer
                .handle_message(message, &self.seen, validator_index);
        for effect in shard_effects {
            self.apply_shard_effect(effect, now, effects);
        }
    }

    fn enqueue_broadcast(&mut self, digest: Digest, effects: &mut CoreEffects) {
        let _span = info_span!("app.core.enqueue_broadcast", payload = ?digest).entered();
        self.pending.shift_remove(&digest);
        self.metrics
            .pending_payloads
            .set(i64::try_from(self.pending.len()).unwrap_or(i64::MAX));
        let Some((key, commitment, shards)) = self.pending_shards.remove(&digest) else {
            warn!(?digest, "broadcast requested for unknown pending shards");
            return;
        };
        effects.network.push_back(NetworkEffect::DistributeShards {
            key,
            commitment,
            shards,
        });
    }

    // Read API ----------------------------------------------------------------
    fn get_coin(&self, payload: Digest, object: ObjectId) -> Option<Coin> {
        self.speculative_store
            .execution(payload)
            .and_then(|state| state.get(&object).cloned())
    }

    fn persisted_root(&self, payload: Digest) -> Option<Digest> {
        self.persisted_roots.get(&payload).copied()
    }

    // Shared helper -----------------------------------------------------------
    fn ensure_execution_materialized(&mut self, digest: Digest) -> bool {
        self.speculative_store
            .ensure_execution_for_payload(digest, &|candidate| {
                decode_execution_payload(&self.seen, candidate)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::payload::decode_anchor;
    use crate::shard::protocol::coding_config;
    use commonware_consensus::minimmit::scheme::ed25519 as minimmit_ed25519;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::certificate::mocks::Fixture;
    use commonware_runtime::{Metrics, Runner, deterministic};
    use commonware_utils::channel::oneshot;
    use hellas_types::Context;
    use std::time::Duration;

    fn test_metrics(context: &deterministic::Context, label: &str) -> CoreMetrics {
        CoreMetrics::register(&context.with_label(label))
    }

    #[test_log::test]
    fn finalization_prunes_non_descendant_execution_state() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-prune-test", 6);

            let me = participants[0].clone();
            let strategy = crate::coding_strategy();
            let mut core = AppCore::new(
                &me,
                participants.clone(),
                0,
                coding_config(6),
                strategy,
                test_metrics(&context, "core_prune"),
            );

            let epoch = Epoch::new(1);
            let genesis = core.genesis(epoch);
            core.note_persisted_root(genesis, Digest::from([1u8; 32]));

            let canonical_context = Context {
                round: Round::new(epoch, View::new(1)),
                leader: participants[0].clone(),
                parent: (View::zero(), genesis),
            };
            let canonical = core.propose(&canonical_context, 100);

            let fork_context = Context {
                round: Round::new(epoch, View::new(2)),
                leader: participants[1].clone(),
                parent: (View::zero(), genesis),
            };
            let fork = core.propose(&fork_context, 101);

            assert!(core.speculative_store.contains_execution(canonical));
            assert!(core.speculative_store.contains_execution(fork));

            let effects = core.on_finalized(canonical, genesis);
            assert!(effects.replies.is_empty());
            assert!(effects.network.is_empty());

            assert_eq!(core.finalized.latest_finalized(), Some(canonical));
            assert!(core.speculative_store.contains_execution(canonical));
            assert!(!core.speculative_store.contains_execution(fork));
            assert!(!core.seen.contains_key(&fork));
        });
    }

    #[test_log::test]
    fn proposal_carries_latest_persisted_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-anchor-proposal-test", 6);

            let me = participants[0].clone();
            let strategy = crate::coding_strategy();
            let mut core = AppCore::new(
                &me,
                participants.clone(),
                0,
                coding_config(6),
                strategy,
                test_metrics(&context, "core_proposal_anchor"),
            );

            let epoch = Epoch::new(1);
            let genesis = core.genesis(epoch);
            let genesis_root = Digest::from([7u8; 32]);
            core.note_persisted_root(genesis, genesis_root);

            let context = Context {
                round: Round::new(epoch, View::new(1)),
                leader: participants[0].clone(),
                parent: (View::zero(), genesis),
            };
            let payload = core.propose(&context, 100);
            let contents = core
                .seen
                .get(&payload)
                .expect("payload bytes should be cached");
            assert_eq!(decode_anchor(contents), Some((genesis, genesis_root)));
        });
    }

    #[test_log::test]
    fn verify_deferred_until_anchor_root_is_persisted() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-anchor-defer-test", 6);

            let strategy = crate::coding_strategy();
            let mut proposer = AppCore::new(
                &participants[0],
                participants.clone(),
                0,
                coding_config(6),
                strategy.clone(),
                test_metrics(&context, "core_defer_proposer"),
            );
            let mut verifier = AppCore::new(
                &participants[1],
                participants.clone(),
                1,
                coding_config(6),
                strategy,
                test_metrics(&context, "core_defer_verifier"),
            );

            let epoch = Epoch::new(1);
            let genesis = proposer.genesis(epoch);
            let _ = verifier.genesis(epoch);
            let anchor_root = Digest::from([9u8; 32]);
            proposer.note_persisted_root(genesis, anchor_root);

            let proposal_context = Context {
                round: Round::new(epoch, View::new(1)),
                leader: participants[0].clone(),
                parent: (View::zero(), genesis),
            };
            let payload = proposer.propose(&proposal_context, 123);
            let payload_contents = proposer
                .seen
                .get(&payload)
                .expect("proposed payload must exist")
                .clone();
            verifier.seen.insert(payload, payload_contents);

            let (response, _receiver) = oneshot::channel();
            let deferred = verifier.on_message(
                AppMailboxReadWriteMessage::Verify {
                    context: proposal_context.clone(),
                    payload,
                    response,
                },
                123,
                &|_| Some(0),
            );
            assert!(deferred.replies.is_empty());

            let resumed = verifier.on_persisted_root(genesis, anchor_root, 124);
            assert_eq!(resumed.replies.len(), 1);
            let Some(CoreEffect::Verify { valid, .. }) = resumed.replies.front() else {
                panic!("expected deferred verify reply");
            };
            assert!(*valid);
        });
    }

    #[test_log::test]
    fn verify_rejects_payload_with_wrong_anchor_root() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-anchor-mismatch-test", 6);

            let strategy = crate::coding_strategy();
            let mut proposer = AppCore::new(
                &participants[0],
                participants.clone(),
                0,
                coding_config(6),
                strategy.clone(),
                test_metrics(&context, "core_mismatch_proposer"),
            );
            let mut verifier = AppCore::new(
                &participants[1],
                participants.clone(),
                1,
                coding_config(6),
                strategy,
                test_metrics(&context, "core_mismatch_verifier"),
            );

            let epoch = Epoch::new(1);
            let genesis = proposer.genesis(epoch);
            let _ = verifier.genesis(epoch);

            proposer.note_persisted_root(genesis, Digest::from([11u8; 32]));
            verifier.note_persisted_root(genesis, Digest::from([12u8; 32]));

            let proposal_context = Context {
                round: Round::new(epoch, View::new(1)),
                leader: participants[0].clone(),
                parent: (View::zero(), genesis),
            };
            let payload = proposer.propose(&proposal_context, 200);
            let payload_contents = proposer
                .seen
                .get(&payload)
                .expect("proposed payload must exist")
                .clone();
            let (anchor_payload, anchor_root) =
                decode_anchor(&payload_contents).expect("payload should include anchors");
            let local_anchor_root = verifier
                .persisted_root(anchor_payload)
                .expect("verifier should have anchor root");
            assert!(!verifier.verify_payload(
                &proposal_context,
                payload,
                &payload_contents,
                anchor_payload,
                anchor_root,
                local_anchor_root,
                200
            ));
        });
    }
}
