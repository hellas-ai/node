use super::mailbox::AppMailboxReadWriteMessage;
use super::metrics::{CoreMetrics, gauge_set_len};
use super::payload::{
    SeenBlock, encode_payload, first_missing_execution_dependency, genesis_digest, genesis_payload,
    missing_dependency_or_execution, payload_digest,
};
use crate::execution::{
    ExecutionError, FinalizationDiffs, FinalizationTracker, ObjectState, SpeculativeExecutionStore,
    execute_block, execute_transaction, genesis_state,
};
use crate::gauged::{GaugedIndexMap, GaugedIndexSet, GaugedVecDeque};
use hellas_types::{Coin, MAX_TXS_PER_BLOCK, ObjectId, Transaction};
use crate::shard::WireShardMessage;
use crate::shard::core::{ShardEffect, ShardRecoverer};
use crate::shard::protocol::{BlockKey, CodingImpl, ShardMessage, ZodaCommitment, ZodaShard};
use bytes::Bytes;
use commonware_coding::Scheme as CodingScheme;
use commonware_consensus::types::Epoch;
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_parallel::Rayon;
use commonware_runtime::{Metrics, Spawner};
use commonware_utils::channel::oneshot;
use hellas_types::{Context, PublicKey};
use indexmap::IndexMap;
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeferredReason {
    Dependency,
    Anchor,
}

struct DeferredVerify {
    context: Context,
    payload: Digest,
    reason: DeferredReason,
    queued_at_ms: u64,
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
    SendShard {
        recipient: PublicKey,
        message: Box<ShardMessage>,
    },
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
    seen: HashMap<Digest, SeenBlock>,
    persistable_payloads: IndexMap<Digest, Bytes>,
    pending_finalizations: IndexMap<Digest, Digest>,
    pending: GaugedIndexSet<Digest>,
    pending_shards: HashMap<Digest, (BlockKey, ZodaCommitment, Vec<ZodaShard>)>,
    waiters: IndexMap<Digest, Vec<DeferredVerify>>,
    pending_fetches: HashMap<Digest, u64>,
    mempool: GaugedVecDeque<Transaction>,
    speculative_store: SpeculativeExecutionStore,
    finalized: FinalizationTracker,
    persisted_roots: GaugedIndexMap<Digest, Digest>,
    latest_anchor: Option<(Digest, Digest)>,
    verify_wait_timeout_ms: u64,
    validators: Vec<PublicKey>,
    strategy: Rayon,
    shard_recoverer: ShardRecoverer<Rayon>,
    metrics: CoreMetrics,
}

impl AppCore {
    const MAX_PENDING_DIGESTS: usize = 256;
    const MAX_PERSISTABLE_PAYLOADS: usize = 2048;
    const MAX_PENDING_FINALIZATIONS: usize = 2048;
    const MAX_WAITER_KEYS: usize = 512;
    const MAX_MEMPOOL_SIZE: usize = 1024;
    const MAX_FINALIZED_EXECUTIONS: usize = 512;
    const MAX_PERSISTED_ROOTS: usize = 2048;
    const FETCH_RETRY_MS: u64 = 200;

    // Construction + identity -------------------------------------------------
    pub(super) fn new(
        me: &PublicKey,
        mut validators: Vec<PublicKey>,
        my_index: u16,
        coding_config: commonware_coding::Config,
        verify_wait_timeout_ms: u64,
        strategy: Rayon,
        metrics: CoreMetrics,
        context: &(impl Spawner + Metrics + Clone),
    ) -> Self {
        validators.sort();
        validators.dedup();
        if validators.is_empty() {
            warn!("validator set was empty; defaulting to self-only validator set");
            validators.push(me.clone());
        }

        let pending = GaugedIndexSet::new(metrics.pending_payloads.clone());
        let mempool = GaugedVecDeque::new(metrics.mempool_size.clone());
        let persisted_roots = GaugedIndexMap::new(metrics.persisted_roots.clone());
        let core = Self {
            seen: HashMap::new(),
            persistable_payloads: IndexMap::new(),
            pending_finalizations: IndexMap::new(),
            pending,
            pending_shards: HashMap::new(),
            waiters: IndexMap::new(),
            pending_fetches: HashMap::new(),
            mempool,
            speculative_store: SpeculativeExecutionStore::new(),
            finalized: FinalizationTracker::new(Self::MAX_FINALIZED_EXECUTIONS),
            persisted_roots,
            latest_anchor: None,
            verify_wait_timeout_ms: verify_wait_timeout_ms.max(1),
            validators,
            strategy: strategy.clone(),
            shard_recoverer: ShardRecoverer::new(me, my_index, coding_config, strategy, context),
            metrics,
        };
        core.metrics.waiter_keys.set(0);
        core.metrics.waiter_total.set(0);
        core.metrics.unpersisted_finalizations.set(0);
        core
    }

    pub(super) const fn me(&self) -> &PublicKey {
        self.shard_recoverer.me()
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
                let digest = self.propose_with_effects(&context, now, &mut effects);
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
                let (drained_msgs, shard_effects) =
                    self.shard_recoverer.announce_leader(key, &context.leader);
                for effect in shard_effects {
                    self.apply_shard_effect(effect, now, &mut effects);
                }
                for msg in drained_msgs {
                    self.handle_shard_message(msg, now, validator_index, &mut effects);
                }
            }
            AppMailboxReadWriteMessage::Broadcast { payload } => {
                self.enqueue_broadcast(payload, &mut effects);
            }
            AppMailboxReadWriteMessage::SubmitTx { tx } => {
                if self.mempool.len() < Self::MAX_MEMPOOL_SIZE {
                    self.mempool.push_back(tx);
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
            | AppMailboxReadWriteMessage::ShardEvent { .. }
            | AppMailboxReadWriteMessage::FinalizationEvent { .. }
            | AppMailboxReadWriteMessage::Persisted { .. } => {
                unreachable!(
                    "application should intercept non-core ingress before AppCore::on_message"
                );
            }
        }
        effects
    }

    /// Run periodic maintenance (waiter expiry, dependency fetches, finalization
    /// retries).  Called by the Application actor after every mailbox message
    /// instead of on a timer, keeping the application purely event-driven while
    /// maintaining a separate stack frame from the primary message handler.
    pub(super) fn run_maintenance(&mut self, now: u64, effects: &mut CoreEffects) {
        self.drain_coding_events(now, effects);
        self.expire_waiters(now, effects);
        self.retry_dependency_fetches(now, effects);
        self.retry_pending_finalizations(now, effects);
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

    pub(super) fn on_finalized(&mut self, payload: Digest, parent_payload: Digest, now: u64) -> CoreEffects {
        let mut effects = CoreEffects::new();
        self.handle_finalized(payload, parent_payload, now, &mut effects);
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
        self.persisted_roots.enforce_capacity(Self::MAX_PERSISTED_ROOTS);
        self.latest_anchor = Some((payload, root));
    }

    pub(super) fn has_persisted_roots(&self) -> bool {
        !self.persisted_roots.is_empty()
    }

    pub(super) fn drain_persistable_payloads(&mut self) -> Vec<(Digest, Bytes)> {
        std::mem::take(&mut self.persistable_payloads)
            .into_iter()
            .collect()
    }

    pub(super) fn payload_bytes(&self, digest: &Digest) -> Option<Bytes> {
        self.seen.get(digest).map(|b| b.bytes().clone())
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
        self.note_payload_seen(digest, payload);
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

    fn propose_with_effects(
        &mut self,
        context: &Context,
        now: u64,
        effects: &mut CoreEffects,
    ) -> Digest {
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
            self.mempool.replace(retained);

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
                        return self.propose_empty(context, now);
                    }
                }
            }
        } else {
            let missing =
                first_missing_execution_dependency(&self.seen, &self.speculative_store, parent)
                    .unwrap_or(parent);
            self.schedule_dependency_fetch(missing, now, effects);
            warn!(
                parent = ?parent,
                missing_dependency = ?missing,
                "missing parent execution; proposing empty block and requesting dependency fetch"
            );
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
        let genesis_anchor = {
            let genesis = genesis_digest(context.round.epoch());
            self.persisted_root(genesis).map(|root| (genesis, root))
        };
        let Some((anchor_payload, anchor_root)) = genesis_anchor
            .or(self.latest_anchor)
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
        self.note_payload_seen(digest, payload);
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
        local_anchor_root: Digest,
        now: u64,
    ) -> bool {
        let parent = context.parent.1;
        let _span = debug_span!(
            "app.core.verify_payload",
            round = ?context.round,
            parent = ?parent,
            payload = ?payload,
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
        let parent_timestamp = match self.seen.get(&parent) {
            Some(parent_block) => parent_block.data().timestamp,
            None => {
                warn!(
                    parent = ?parent,
                    "parent block missing during verify despite dependency check"
                );
                return false;
            }
        };
        let Some(parent_state) = self.speculative_store.execution(parent).cloned() else {
            warn!(
                parent = ?parent,
                "parent execution missing during verify despite dependency check"
            );
            return false;
        };

        // Remove from seen so we can consume via into_validated.
        let Some(block) = self.seen.remove(&payload) else {
            warn!(payload = ?payload, "payload missing from seen during verify");
            return false;
        };
        match block.into_validated(
            context.round,
            parent,
            payload,
            now,
            parent_timestamp,
            local_anchor_root,
        ) {
            Ok(validated) => {
                let data = validated.data();
                self.metrics
                    .validation_timestamp_drift
                    .set((now as i64).wrapping_sub(data.timestamp as i64));
                match execute_block(&parent_state, &data.txs) {
                    Ok(exec) => {
                        let diffs = FinalizationDiffs {
                            created: exec.created,
                            deleted: exec.deleted,
                        };
                        self.speculative_store
                            .insert_state_with_diffs(payload, parent, exec.state, diffs);
                        self.seen.insert(payload, validated);
                        true
                    }
                    Err(err) => {
                        warn!(?err, payload = ?payload, "payload execution failed");
                        // Re-insert as validated since the block itself was valid,
                        // only execution failed.
                        self.seen.insert(payload, validated);
                        false
                    }
                }
            }
            Err(err) => {
                if matches!(err, super::payload::PayloadValidationError::AnchorRootMismatch { .. }) {
                    self.metrics.anchor_mismatch_total.inc();
                }
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
        self.expire_waiters(now, effects);
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
            self.schedule_dependency_fetch(missing_digest, now, effects);
            self.queue_waiter(
                missing_digest,
                DeferredVerify {
                    context: context.clone(),
                    payload,
                    reason: DeferredReason::Dependency,
                    queued_at_ms: now,
                    response,
                },
                effects,
            );
            return;
        }
        let Some(block) = self.seen.get(&payload) else {
            warn!(
                payload = ?payload,
                "payload missing during verify despite dependency check"
            );
            self.metrics.verify_invalid_total.inc();
            effects.replies.push_back(CoreEffect::Verify {
                response,
                valid: false,
            });
            return;
        };
        let anchor_payload = block.data().anchor_payload;
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
                    reason: DeferredReason::Anchor,
                    queued_at_ms: now,
                    response,
                },
                effects,
            );
            return;
        };
        let valid = self.verify_payload(
            context,
            payload,
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
        gauge_set_len(&self.metrics.waiter_keys, self.waiters.len());
        let waiter_total = self.waiters.values().map(Vec::len).sum::<usize>();
        gauge_set_len(&self.metrics.waiter_total, waiter_total);
    }

    pub(super) fn shutdown_shard_recoverer(&mut self) {
        self.shard_recoverer.shutdown();
    }

    fn drain_coding_events(&mut self, now: u64, effects: &mut CoreEffects) {
        for effect in self.shard_recoverer.drain_coding_events() {
            self.apply_shard_effect(effect, now, effects);
        }
    }

    fn expire_waiters(&mut self, now: u64, effects: &mut CoreEffects) {
        if self.waiters.is_empty() {
            return;
        }
        let digests: Vec<Digest> = self.waiters.keys().copied().collect();
        for digest in digests {
            let mut remove_key = false;
            if let Some(waiters) = self.waiters.get_mut(&digest) {
                let mut idx = 0usize;
                while idx < waiters.len() {
                    let age_ms = now.saturating_sub(waiters[idx].queued_at_ms);
                    if age_ms >= self.verify_wait_timeout_ms {
                        let stale = waiters.swap_remove(idx);
                        effects.replies.push_back(CoreEffect::Verify {
                            response: stale.response,
                            valid: false,
                        });
                    } else {
                        idx += 1;
                    }
                }
                remove_key = waiters.is_empty();
            }
            if remove_key {
                self.waiters.shift_remove(&digest);
            }
        }
        self.update_waiter_metrics();
    }

    fn retry_dependency_fetches(&mut self, now: u64, effects: &mut CoreEffects) {
        if self.waiters.is_empty() {
            return;
        }
        let mut missing = Vec::new();
        for (digest, waiters) in self.waiters.iter() {
            if self.seen.contains_key(digest) {
                continue;
            }
            if waiters
                .iter()
                .any(|waiter| waiter.reason == DeferredReason::Dependency)
            {
                missing.push(*digest);
            }
        }
        for digest in missing {
            self.schedule_dependency_fetch(digest, now, effects);
        }
    }

    fn retry_pending_finalizations(&mut self, now: u64, effects: &mut CoreEffects) {
        if self.pending_finalizations.is_empty() {
            return;
        }
        let pending: Vec<(Digest, Digest)> = self
            .pending_finalizations
            .iter()
            .map(|(payload, parent)| (*payload, *parent))
            .collect();
        for (payload, parent_payload) in pending {
            if self.ensure_execution_materialized(payload) {
                self.pending_finalizations.shift_remove(&payload);
                self.handle_finalized(payload, parent_payload, now, effects);
                continue;
            }

            if !self.seen.contains_key(&payload) {
                self.schedule_dependency_fetch(payload, now, effects);
                continue;
            }

            if let Some(block) = self.seen.get(&payload) {
                let parent = block.data().parent;
                if let Some(missing) =
                    first_missing_execution_dependency(&self.seen, &self.speculative_store, parent)
                {
                    self.schedule_dependency_fetch(missing, now, effects);
                }
            }
        }
    }

    fn schedule_dependency_fetch(&mut self, digest: Digest, now: u64, effects: &mut CoreEffects) {
        if self.seen.contains_key(&digest) {
            self.pending_fetches.remove(&digest);
            return;
        }
        if let Some(&requested_at) = self.pending_fetches.get(&digest) {
            if now.saturating_sub(requested_at) < Self::FETCH_RETRY_MS {
                return; // too soon to retry
            }
        }
        self.pending_fetches.insert(digest, now);
        effects
            .network
            .push_back(NetworkEffect::BroadcastShard(Box::new(
                ShardMessage::fetch_payload(self.me(), digest),
            )));
    }

    // Pending payload retention -----------------------------------------------
    fn enforce_pending_capacity(&mut self) {
        for oldest in self.pending.enforce_capacity(Self::MAX_PENDING_DIGESTS) {
            self.pending_shards.remove(&oldest);
            warn!(
                ?oldest,
                max_pending = Self::MAX_PENDING_DIGESTS,
                "evicting oldest pending payload before broadcast"
            );
        }
    }

    // Finalization pruning ----------------------------------------------------
    fn handle_finalized(
        &mut self,
        payload: Digest,
        parent_payload: Digest,
        now: u64,
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
            if let Some(existing_parent) = self.pending_finalizations.get(&payload)
                && *existing_parent != parent_payload
            {
                error!(
                    ?payload,
                    existing_parent = ?existing_parent,
                    incoming_parent = ?parent_payload,
                    "conflicting parent observed for deferred finalization; entering fail-stop"
                );
                std::process::abort();
            }
            self.pending_finalizations.insert(payload, parent_payload);
            if self.pending_finalizations.len() > Self::MAX_PENDING_FINALIZATIONS {
                error!(
                    pending = self.pending_finalizations.len(),
                    max = Self::MAX_PENDING_FINALIZATIONS,
                    "pending finalization queue overflowed; refusing to drop deferred finalizations"
                );
                std::process::abort();
            }
            warn!(
                ?payload,
                "finalization arrived before local execution state was available"
            );
            return;
        }
        self.pending_finalizations.shift_remove(&payload);
        let was_finalized = self.finalized.is_finalized(payload);
        let diffs = self.speculative_store.take_diffs(payload);
        if diffs.is_none() && !was_finalized {
            warn!(
                ?payload,
                "finalized payload had no execution diffs; persistence queue will skip it"
            );
        }
        self.finalized.observe_finalized(payload, diffs);
        if let Some(block) = self.seen.get(&payload) {
            let block_ts = block.data().timestamp;
            self.metrics
                .finalization_timestamp_drift
                .set((now as i64).wrapping_sub(block_ts as i64));
        }
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
        self.persistable_payloads.shift_remove(&digest);
        self.pending_finalizations.shift_remove(&digest);
        self.pending.shift_remove(&digest);
        self.pending_shards.remove(&digest);
        let removed = self.waiters.shift_remove(&digest).unwrap_or_default();
        self.update_waiter_metrics();
        removed
    }

    // Shard recovery + broadcast ----------------------------------------------
    fn apply_shard_effect(&mut self, effect: ShardEffect, now: u64, effects: &mut CoreEffects) {
        match effect {
            ShardEffect::Broadcast(message) => {
                if let Some(key) = message.key() {
                    trace!(
                        payload = ?key.digest,
                        round = ?key.round,
                        "queueing shard rebroadcast"
                    );
                }
                effects
                    .network
                    .push_back(NetworkEffect::BroadcastShard(message));
            }
            ShardEffect::Recovered { key, contents } => {
                debug!(
                    payload = ?key.digest,
                    round = ?key.round,
                    "recovered payload from shards"
                );
                self.note_payload_seen(key.digest, contents);
                self.pending.shift_remove(&key.digest);
                self.pending_shards.remove(&key.digest);
                self.retry_waiters(key.digest, now, effects);
                self.retry_pending_finalizations(now, effects);
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
            payload = ?key.map(|k| k.digest),
            round = ?key.map(|k| k.round),
            sender = ?message.sender()
        )
        .entered();
        let sender = message.sender().clone();

        match &message.body {
            WireShardMessage::FetchPayload { digest } => {
                if let Some(block) = self.seen.get(digest) {
                    effects.network.push_back(NetworkEffect::SendShard {
                        recipient: sender,
                        message: Box::new(ShardMessage::payload_response(
                            self.me(),
                            *digest,
                            block.bytes().clone(),
                        )),
                    });
                }
                return;
            }
            WireShardMessage::PayloadResponse { digest, payload } => {
                if Sha256::hash(payload.as_ref()) != *digest {
                    warn!(
                        ?digest,
                        sender = ?message.sender(),
                        "ignoring payload response with digest mismatch"
                    );
                    return;
                }
                self.note_payload_seen(*digest, payload.clone());
                self.pending.shift_remove(digest);
                self.pending_shards.remove(digest);
                self.retry_waiters(*digest, now, effects);
                self.retry_pending_finalizations(now, effects);
                return;
            }
            WireShardMessage::Initial { .. } | WireShardMessage::ReShare { .. } => {}
        }

        let shard_effects =
            self.shard_recoverer
                .handle_message(message, |d| self.seen.contains_key(d), validator_index);
        for effect in shard_effects {
            self.apply_shard_effect(effect, now, effects);
        }
        self.drain_coding_events(now, effects);
    }

    fn enqueue_broadcast(&mut self, digest: Digest, effects: &mut CoreEffects) {
        let _span = info_span!("app.core.enqueue_broadcast", payload = ?digest).entered();
        self.pending.shift_remove(&digest);
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
                let block = self.seen.get(&candidate)?;
                let data = block.data();
                Some((data.parent, data.txs.clone()))
            })
    }

    /// Like `note_payload_seen` but also retries deferred verify waiters
    /// for the resolved digest.  Used by the local persistence resolution
    /// path in `apply_core_effects` to unblock deferred verifications after
    /// recovering payload bytes from the Freezer.
    pub(super) fn resolve_payload_locally(
        &mut self,
        digest: Digest,
        payload: Bytes,
        now: u64,
        effects: &mut CoreEffects,
    ) {
        self.note_payload_seen(digest, payload);
        self.retry_waiters(digest, now, effects);
    }

    pub(super) fn note_payload_seen(&mut self, digest: Digest, payload: Bytes) {
        if let Some(existing) = self.seen.get(&digest) {
            if existing.bytes() != &payload {
                error!(
                    ?digest,
                    "digest collision detected for payload bytes; entering fail-stop"
                );
                std::process::abort();
            }
            return;
        }

        let Some(block) = SeenBlock::decode(payload.clone()) else {
            warn!(?digest, "ignoring malformed payload bytes");
            return;
        };
        self.seen.insert(digest, block);
        self.pending_fetches.remove(&digest);
        self.persistable_payloads.insert(digest, payload);
        while self.persistable_payloads.len() > Self::MAX_PERSISTABLE_PAYLOADS {
            let Some((oldest, _)) = self.persistable_payloads.shift_remove_index(0) else {
                break;
            };
            warn!(
                ?oldest,
                max_persistable = Self::MAX_PERSISTABLE_PAYLOADS,
                "evicting oldest payload before persistence handoff"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::protocol::coding_config;
    use commonware_consensus::minimmit::scheme::ed25519 as minimmit_ed25519;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::certificate::mocks::Fixture;
    use commonware_runtime::{Metrics, Runner, deterministic};
    use commonware_utils::channel::oneshot;
    use hellas_types::Context;
    use proptest::prelude::*;
    use std::time::Duration;

    fn test_metrics(context: &deterministic::Context, label: &str) -> CoreMetrics {
        CoreMetrics::register(&context.with_label(label))
    }

    const TEST_WAIT_TIMEOUT_MS: u64 = 500;

    fn has_valid_verify_reply(effects: &CoreEffects) -> bool {
        effects
            .replies
            .iter()
            .any(|effect| matches!(effect, CoreEffect::Verify { valid: true, .. }))
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
                TEST_WAIT_TIMEOUT_MS,
                strategy,
                test_metrics(&context, "core_prune"),
                &context,
            );

            let epoch = Epoch::new(1);
            let genesis = core.genesis(epoch);
            core.note_persisted_root(genesis, Digest::from([1u8; 32]));

            let canonical_context = Context {
                round: Round::new(epoch, View::new(1)),
                leader: participants[0].clone(),
                parent: (View::zero(), genesis),
            };
            let mut canonical_effects = CoreEffects::new();
            let canonical =
                core.propose_with_effects(&canonical_context, 100, &mut canonical_effects);

            let fork_context = Context {
                round: Round::new(epoch, View::new(2)),
                leader: participants[1].clone(),
                parent: (View::zero(), genesis),
            };
            let mut fork_effects = CoreEffects::new();
            let fork = core.propose_with_effects(&fork_context, 101, &mut fork_effects);

            assert!(core.speculative_store.contains_execution(canonical));
            assert!(core.speculative_store.contains_execution(fork));

            let effects = core.on_finalized(canonical, genesis, 0);
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
                TEST_WAIT_TIMEOUT_MS,
                strategy,
                test_metrics(&context, "core_proposal_anchor"),
                &context,
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
            let mut propose_effects = CoreEffects::new();
            let payload = core.propose_with_effects(&context, 100, &mut propose_effects);
            let block = core
                .seen
                .get(&payload)
                .expect("payload should be cached");
            let data = block.data();
            assert_eq!(data.anchor_payload, genesis);
            assert_eq!(data.anchor_root, genesis_root);
        });
    }

    #[test_log::test]
    fn verify_deferred_until_anchor_root_is_persisted() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-anchor-defer-test", 6);

            let strategy = crate::coding_strategy();
            let proposer_ctx = context.with_label("core_defer_proposer");
            let verifier_ctx = context.with_label("core_defer_verifier");
            let mut proposer = AppCore::new(
                &participants[0],
                participants.clone(),
                0,
                coding_config(6),
                TEST_WAIT_TIMEOUT_MS,
                strategy.clone(),
                test_metrics(&context, "core_defer_proposer"),
                &proposer_ctx,
            );
            let mut verifier = AppCore::new(
                &participants[1],
                participants.clone(),
                1,
                coding_config(6),
                TEST_WAIT_TIMEOUT_MS,
                strategy,
                test_metrics(&context, "core_defer_verifier"),
                &verifier_ctx,
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
            let mut propose_effects = CoreEffects::new();
            let payload =
                proposer.propose_with_effects(&proposal_context, 123, &mut propose_effects);
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
            let proposer_ctx = context.with_label("core_mismatch_proposer");
            let verifier_ctx = context.with_label("core_mismatch_verifier");
            let mut proposer = AppCore::new(
                &participants[0],
                participants.clone(),
                0,
                coding_config(6),
                TEST_WAIT_TIMEOUT_MS,
                strategy.clone(),
                test_metrics(&context, "core_mismatch_proposer"),
                &proposer_ctx,
            );
            let mut verifier = AppCore::new(
                &participants[1],
                participants.clone(),
                1,
                coding_config(6),
                TEST_WAIT_TIMEOUT_MS,
                strategy,
                test_metrics(&context, "core_mismatch_verifier"),
                &verifier_ctx,
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
            let mut propose_effects = CoreEffects::new();
            let payload =
                proposer.propose_with_effects(&proposal_context, 200, &mut propose_effects);
            let proposed_block = proposer
                .seen
                .get(&payload)
                .expect("proposed payload must exist")
                .clone();
            let anchor_payload = proposed_block.data().anchor_payload;
            verifier.seen.insert(payload, proposed_block);
            let local_anchor_root = verifier
                .persisted_root(anchor_payload)
                .expect("verifier should have anchor root");
            assert!(!verifier.verify_payload(
                &proposal_context,
                payload,
                local_anchor_root,
                200
            ));
        });
    }

    #[test_log::test]
    fn verify_dependency_defer_requests_fetch_and_times_out() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-fetch-timeout-test", 6);
            let strategy = crate::coding_strategy();
            let mut core = AppCore::new(
                &participants[1],
                participants.clone(),
                1,
                coding_config(6),
                TEST_WAIT_TIMEOUT_MS,
                strategy,
                test_metrics(&context, "core_fetch_timeout"),
                &context,
            );

            let epoch = Epoch::new(1);
            let genesis = core.genesis(epoch);
            core.note_persisted_root(genesis, Digest::from([3u8; 32]));

            let context = Context {
                round: Round::new(epoch, View::new(1)),
                leader: participants[0].clone(),
                parent: (View::zero(), genesis),
            };
            let missing_payload = Digest::from([9u8; 32]);
            let (response, _receiver) = oneshot::channel();
            let deferred = core.on_message(
                AppMailboxReadWriteMessage::Verify {
                    context,
                    payload: missing_payload,
                    response,
                },
                100,
                &|_| Some(0),
            );
            assert!(deferred.replies.is_empty());
            assert!(
                deferred.network.iter().any(|effect| {
                    matches!(
                        effect,
                        NetworkEffect::BroadcastShard(message)
                            if matches!(
                                message.body,
                                WireShardMessage::FetchPayload { digest }
                                    if digest == missing_payload
                            )
                    )
                }),
                "expected at least one fetch request for the missing payload"
            );

            let mut timeout = CoreEffects::new();
            core.expire_waiters(100 + TEST_WAIT_TIMEOUT_MS + 1, &mut timeout);
            assert_eq!(timeout.replies.len(), 1);
            let Some(CoreEffect::Verify { valid, .. }) = timeout.replies.front() else {
                panic!("expected timed-out verify reply");
            };
            assert!(!*valid);
        });
    }

    #[test_log::test]
    fn payload_response_satisfies_deferred_verify() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-fetch-repair-test", 6);
            let strategy = crate::coding_strategy();
            let mut core = AppCore::new(
                &participants[1],
                participants.clone(),
                1,
                coding_config(6),
                TEST_WAIT_TIMEOUT_MS,
                strategy,
                test_metrics(&context, "core_fetch_repair"),
                &context,
            );

            let epoch = Epoch::new(1);
            let genesis = core.genesis(epoch);
            let anchor_root = Digest::from([5u8; 32]);
            core.note_persisted_root(genesis, anchor_root);

            let verify_context = Context {
                round: Round::new(epoch, View::new(1)),
                leader: participants[0].clone(),
                parent: (View::zero(), genesis),
            };
            let payload_contents = encode_payload(
                verify_context.round,
                genesis,
                101,
                genesis,
                anchor_root,
                &[],
            );
            let payload = payload_digest(&payload_contents);

            let (response, _receiver) = oneshot::channel();
            let deferred = core.on_message(
                AppMailboxReadWriteMessage::Verify {
                    context: verify_context.clone(),
                    payload,
                    response,
                },
                101,
                &|_| Some(0),
            );
            assert!(deferred.replies.is_empty());

            let repaired = core.on_shard_message(
                ShardMessage::payload_response(&participants[0], payload, payload_contents),
                102,
                &|_| None,
            );
            assert_eq!(repaired.replies.len(), 1);
            let Some(CoreEffect::Verify { valid, .. }) = repaired.replies.front() else {
                panic!("expected repaired verify reply");
            };
            assert!(*valid);
        });
    }

    #[test_log::test]
    fn verify_fetches_first_missing_ancestor_dependency() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-missing-ancestor-fetch-test", 6);
            let strategy = crate::coding_strategy();
            let mut core = AppCore::new(
                &participants[1],
                participants.clone(),
                1,
                coding_config(6),
                TEST_WAIT_TIMEOUT_MS,
                strategy,
                test_metrics(&context, "core_missing_ancestor_fetch"),
                &context,
            );

            let epoch = Epoch::new(1);
            let genesis = core.genesis(epoch);
            let anchor_root = Digest::from([4u8; 32]);
            core.note_persisted_root(genesis, anchor_root);

            let missing_ancestor = Digest::from([9u8; 32]);
            let parent_contents = encode_payload(
                Round::new(epoch, View::new(1)),
                missing_ancestor,
                100,
                genesis,
                anchor_root,
                &[],
            );
            let parent_payload = payload_digest(&parent_contents);
            core.note_payload_seen(parent_payload, parent_contents);

            let verify_context = Context {
                round: Round::new(epoch, View::new(2)),
                leader: participants[0].clone(),
                parent: (View::new(1), parent_payload),
            };
            let payload_contents = encode_payload(
                verify_context.round,
                parent_payload,
                101,
                genesis,
                anchor_root,
                &[],
            );
            let payload = payload_digest(&payload_contents);
            core.note_payload_seen(payload, payload_contents);

            let (response, _receiver) = oneshot::channel();
            let deferred = core.on_message(
                AppMailboxReadWriteMessage::Verify {
                    context: verify_context,
                    payload,
                    response,
                },
                101,
                &|_| Some(0),
            );
            assert!(deferred.replies.is_empty());
            assert!(
                deferred.network.iter().any(|effect| {
                    matches!(
                        effect,
                        NetworkEffect::BroadcastShard(message)
                            if matches!(
                                message.body,
                                WireShardMessage::FetchPayload { digest }
                                    if digest == missing_ancestor
                            )
                    )
                }),
                "expected at least one fetch request for the missing ancestor"
            );
        });
    }

    #[test_log::test]
    fn pending_finalization_fetches_first_missing_ancestor_dependency() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(
                    &mut context,
                    b"core-finalization-ancestor-fetch-test",
                    6,
                );
            let strategy = crate::coding_strategy();
            let mut core = AppCore::new(
                &participants[1],
                participants.clone(),
                1,
                coding_config(6),
                TEST_WAIT_TIMEOUT_MS,
                strategy,
                test_metrics(&context, "core_finalization_ancestor_fetch"),
                &context,
            );

            let epoch = Epoch::new(1);
            let genesis = core.genesis(epoch);
            let anchor_root = Digest::from([6u8; 32]);
            core.note_persisted_root(genesis, anchor_root);

            let missing_ancestor = Digest::from([8u8; 32]);
            let parent_contents = encode_payload(
                Round::new(epoch, View::new(1)),
                missing_ancestor,
                100,
                genesis,
                anchor_root,
                &[],
            );
            let parent_payload = payload_digest(&parent_contents);
            core.note_payload_seen(parent_payload, parent_contents);

            let payload_contents = encode_payload(
                Round::new(epoch, View::new(2)),
                parent_payload,
                101,
                genesis,
                anchor_root,
                &[],
            );
            let payload = payload_digest(&payload_contents);
            core.note_payload_seen(payload, payload_contents);

            let deferred = core.on_finalized(payload, parent_payload, 0);
            assert!(deferred.replies.is_empty());
            assert!(deferred.network.is_empty());

            let mut retry = CoreEffects::new();
            core.retry_pending_finalizations(200, &mut retry);
            assert_eq!(retry.network.len(), 1);
            let Some(NetworkEffect::BroadcastShard(message)) = retry.network.front() else {
                panic!("expected fetch request network effect");
            };
            match &message.body {
                WireShardMessage::FetchPayload { digest } => {
                    assert_eq!(*digest, missing_ancestor)
                }
                _ => panic!("expected fetch payload request"),
            }
        });
    }

    #[test_log::test]
    fn propose_missing_parent_requests_fetch_and_stops_after_repair() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-propose-missing-parent-fetch", 6);
            let strategy = crate::coding_strategy();
            let mut core = AppCore::new(
                &participants[1],
                participants.clone(),
                1,
                coding_config(6),
                TEST_WAIT_TIMEOUT_MS,
                strategy,
                test_metrics(&context, "core_propose_missing_parent_fetch"),
                &context,
            );

            let epoch = Epoch::new(1);
            let genesis = core.genesis(epoch);
            let anchor_root = Digest::from([10u8; 32]);
            core.note_persisted_root(genesis, anchor_root);

            let missing_contents = encode_payload(
                Round::new(epoch, View::new(1)),
                genesis,
                100,
                genesis,
                anchor_root,
                &[],
            );
            let missing_digest = payload_digest(&missing_contents);
            let parent_contents = encode_payload(
                Round::new(epoch, View::new(2)),
                missing_digest,
                101,
                genesis,
                anchor_root,
                &[],
            );
            let parent_payload = payload_digest(&parent_contents);
            core.note_payload_seen(parent_payload, parent_contents);

            let propose_context = Context {
                round: Round::new(epoch, View::new(3)),
                leader: participants[1].clone(),
                parent: (View::new(2), parent_payload),
            };

            let (first_response, _first_receiver) = oneshot::channel();
            let first = core.on_message(
                AppMailboxReadWriteMessage::Propose {
                    context: propose_context.clone(),
                    response: first_response,
                },
                200,
                &|_| Some(0),
            );
            assert_eq!(first.replies.len(), 1);
            assert!(
                first.network.iter().any(|effect| {
                    matches!(
                        effect,
                        NetworkEffect::BroadcastShard(message)
                            if matches!(
                                message.body,
                                WireShardMessage::FetchPayload { digest }
                                    if digest == missing_digest
                            )
                    )
                }),
                "propose should request fetch for missing parent dependency"
            );

            let repaired = core.on_shard_message(
                ShardMessage::payload_response(&participants[0], missing_digest, missing_contents),
                201,
                &|_| None,
            );
            assert!(repaired.replies.is_empty());
            assert!(repaired.network.is_empty());

            assert!(
                core.ensure_execution_materialized(parent_payload),
                "parent execution should become materializable after repair"
            );

            let second_context = Context {
                round: Round::new(epoch, View::new(4)),
                leader: participants[1].clone(),
                parent: (View::new(2), parent_payload),
            };
            let (second_response, _second_receiver) = oneshot::channel();
            let second = core.on_message(
                AppMailboxReadWriteMessage::Propose {
                    context: second_context,
                    response: second_response,
                },
                202,
                &|_| Some(0),
            );
            assert_eq!(second.replies.len(), 1);
            assert!(
                second.network.is_empty(),
                "propose should stop requesting fetch once dependencies are repaired"
            );
        });
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn eventual_repair_unblocks_deferred_verify_and_finalization(
            chain_len in 3usize..8usize,
            missing_prefix in 1usize..6usize,
            shuffle_seed in any::<u64>(),
            maintenance_offsets in prop::collection::vec(1u64..20u64, 0..12),
        ) {
            let available_from = 1 + missing_prefix;
            prop_assume!(available_from < chain_len);

            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                    minimmit_ed25519::fixture(
                        &mut context,
                        b"core-eventual-repair-proptest",
                        6,
                    );
                let strategy = crate::coding_strategy();
                let mut core = AppCore::new(
                    &participants[1],
                    participants.clone(),
                    1,
                    coding_config(6),
                    10_000,
                    strategy,
                    test_metrics(&context, "core_eventual_repair_proptest"),
                    &context,
                );

                let epoch = Epoch::new(1);
                let genesis = core.genesis(epoch);
                let anchor_root = Digest::from([21u8; 32]);
                core.note_persisted_root(genesis, anchor_root);

                let mut digests = vec![genesis];
                let mut payloads = HashMap::new();
                for idx in 1..=chain_len {
                    let round = Round::new(epoch, View::new(u64::try_from(idx).unwrap_or(u64::MAX)));
                    let parent = digests[idx - 1];
                    let contents = encode_payload(
                        round,
                        parent,
                        100 + u64::try_from(idx).unwrap_or(0),
                        genesis,
                        anchor_root,
                        &[],
                    );
                    let digest = payload_digest(&contents);
                    digests.push(digest);
                    payloads.insert(digest, contents);
                }

                for idx in available_from..=chain_len {
                    let digest = digests[idx];
                    let bytes = payloads
                        .get(&digest)
                        .expect("payload bytes for known digest should exist")
                        .clone();
                    core.note_payload_seen(digest, bytes);
                }

                let tip = digests[chain_len];
                let tip_parent = digests[chain_len - 1];
                let verify_context = Context {
                    round: Round::new(epoch, View::new(u64::try_from(chain_len).unwrap_or(u64::MAX))),
                    leader: participants[0].clone(),
                    parent: (
                        View::new(u64::try_from(chain_len - 1).unwrap_or(u64::MAX)),
                        tip_parent,
                    ),
                };
                let expected_first_missing = digests[available_from - 1];

                let (response, _receiver) = oneshot::channel();
                let initial_verify = core.on_message(
                    AppMailboxReadWriteMessage::Verify {
                        context: verify_context,
                        payload: tip,
                        response,
                    },
                    200,
                    &|_| Some(0),
                );
                assert!(initial_verify.replies.is_empty());
                assert!(
                    initial_verify.network.iter().any(|effect| {
                        matches!(
                            effect,
                            NetworkEffect::BroadcastShard(message)
                                if matches!(
                                    message.body,
                                    WireShardMessage::FetchPayload { digest }
                                        if digest == expected_first_missing
                                )
                        )
                    }),
                    "initial verify should fetch first missing ancestor"
                );

                let initial_finalized = core.on_finalized(tip, tip_parent, 0);
                assert!(initial_finalized.replies.is_empty());
                assert!(initial_finalized.network.is_empty());
                assert!(!core.finalized.is_finalized(tip));
                assert!(core.pending_finalizations.contains_key(&tip));

                let mut missing_indices: Vec<usize> = (1..available_from).collect();
                missing_indices.sort_by_key(|idx| {
                    (u64::try_from(*idx).unwrap_or(0))
                        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                        ^ shuffle_seed
                });

                let mut now = 250u64;
                let mut saw_valid_verify = false;

                for (step, idx) in missing_indices.into_iter().enumerate() {
                    if !maintenance_offsets.is_empty() {
                        let delta = maintenance_offsets[step % maintenance_offsets.len()];
                        now = now.saturating_add(delta);
                        let mut tick = CoreEffects::new();
                        core.drain_coding_events(now, &mut tick);
                        core.expire_waiters(now, &mut tick);
                        core.retry_dependency_fetches(now, &mut tick);
                        core.retry_pending_finalizations(now, &mut tick);
                        saw_valid_verify |= has_valid_verify_reply(&tick);
                    }

                    let digest = digests[idx];
                    let bytes = payloads
                        .get(&digest)
                        .expect("payload bytes for missing digest should exist")
                        .clone();
                    now = now.saturating_add(1);
                    let repaired = core.on_shard_message(
                        ShardMessage::payload_response(&participants[0], digest, bytes),
                        now,
                        &|_| None,
                    );
                    saw_valid_verify |= has_valid_verify_reply(&repaired);
                }

                for _ in 0..3 {
                    now = now.saturating_add(1);
                    let mut tick = CoreEffects::new();
                    core.drain_coding_events(now, &mut tick);
                    core.expire_waiters(now, &mut tick);
                    core.retry_dependency_fetches(now, &mut tick);
                    core.retry_pending_finalizations(now, &mut tick);
                    saw_valid_verify |= has_valid_verify_reply(&tick);
                }

                assert!(
                    saw_valid_verify,
                    "verify should become valid once missing ancestors are repaired"
                );
                assert!(core.finalized.is_finalized(tip));
                assert!(!core.pending_finalizations.contains_key(&tip));
            });
        }
    }

    #[test_log::test]
    fn finalization_retries_after_payload_recovery() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-finalization-retry-test", 6);
            let strategy = crate::coding_strategy();
            let mut core = AppCore::new(
                &participants[1],
                participants.clone(),
                1,
                coding_config(6),
                TEST_WAIT_TIMEOUT_MS,
                strategy,
                test_metrics(&context, "core_finalization_retry"),
                &context,
            );

            let epoch = Epoch::new(1);
            let genesis = core.genesis(epoch);
            let anchor_root = Digest::from([7u8; 32]);
            core.note_persisted_root(genesis, anchor_root);

            let context = Context {
                round: Round::new(epoch, View::new(1)),
                leader: participants[0].clone(),
                parent: (View::zero(), genesis),
            };
            let payload_contents =
                encode_payload(context.round, genesis, 101, genesis, anchor_root, &[]);
            let payload = payload_digest(&payload_contents);

            let deferred = core.on_finalized(payload, genesis, 0);
            assert!(deferred.replies.is_empty());
            assert!(deferred.network.is_empty());
            assert!(!core.finalized.is_finalized(payload));

            let recovered = core.on_shard_message(
                ShardMessage::payload_response(&participants[0], payload, payload_contents),
                102,
                &|_| None,
            );
            assert!(recovered.replies.is_empty());
            assert!(core.finalized.is_finalized(payload));
            assert_eq!(
                core.next_unpersisted_finalization()
                    .map(|(digest, _)| digest),
                Some(payload)
            );
        });
    }

    fn count_fetch_broadcasts(effects: &CoreEffects) -> usize {
        effects
            .network
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    NetworkEffect::BroadcastShard(msg)
                        if matches!(msg.body, WireShardMessage::FetchPayload { .. })
                )
            })
            .count()
    }

    #[test_log::test]
    fn dependency_fetch_dedup_and_retry_lifecycle() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-fetch-dedup-lifecycle", 6);
            let strategy = crate::coding_strategy();
            let mut core = AppCore::new(
                &participants[1],
                participants.clone(),
                1,
                coding_config(6),
                TEST_WAIT_TIMEOUT_MS,
                strategy,
                test_metrics(&context, "core_fetch_dedup"),
                &context,
            );

            let epoch = Epoch::new(1);
            let genesis = core.genesis(epoch);
            let anchor_root = Digest::from([3u8; 32]);
            core.note_persisted_root(genesis, anchor_root);

            // Build a valid payload (parent=genesis, no txs) but withhold it from `seen`.
            let payload_contents = encode_payload(
                Round::new(epoch, View::new(1)),
                genesis,
                100,
                genesis,
                anchor_root,
                &[],
            );
            let payload = payload_digest(&payload_contents);

            let make_verify = |view: u64| -> (AppMailboxReadWriteMessage, oneshot::Receiver<bool>) {
                let (response, receiver) = oneshot::channel();
                (
                    AppMailboxReadWriteMessage::Verify {
                        context: Context {
                            round: Round::new(epoch, View::new(view)),
                            leader: participants[0].clone(),
                            parent: (View::zero(), genesis),
                        },
                        payload,
                        response,
                    },
                    receiver,
                )
            };

            // ── Phase 1: First verify defers, emits exactly 1 fetch ──────────
            let (msg1, _rx1) = make_verify(1);
            let e1 = core.on_message(msg1, 100, &|_| Some(0));
            assert!(e1.replies.is_empty(), "verify should defer (payload missing)");
            assert_eq!(count_fetch_broadcasts(&e1), 1, "first verify: 1 fetch");

            // ── Phase 2: Second verify for same payload — deduped ─────────────
            // Same view=1 because the payload encodes view 1; a separate
            // response channel still creates a distinct waiter.
            let (msg2, _rx2) = make_verify(1);
            let e2 = core.on_message(msg2, 101, &|_| Some(0));
            assert!(e2.replies.is_empty(), "second verify should also defer");
            assert_eq!(count_fetch_broadcasts(&e2), 0, "dedup: no fetch within retry window");

            // ── Phase 3: Maintenance within retry window — no re-request ──────
            let mut me1 = CoreEffects::new();
            core.run_maintenance(102, &mut me1);
            assert_eq!(count_fetch_broadcasts(&me1), 0, "maintenance within retry window: no fetch");

            // ── Phase 4: Maintenance after retry window — re-requests ─────────
            let mut me2 = CoreEffects::new();
            core.run_maintenance(100 + AppCore::FETCH_RETRY_MS + 1, &mut me2);
            assert_eq!(count_fetch_broadcasts(&me2), 1, "maintenance after retry window: 1 retry fetch");

            // ── Phase 5: Another verify still deduped (maintenance just sent) ─
            let (msg3, _rx3) = make_verify(1);
            let e3 = core.on_message(msg3, 100 + AppCore::FETCH_RETRY_MS + 2, &|_| Some(0));
            assert_eq!(count_fetch_broadcasts(&e3), 0, "dedup: maintenance already sent fetch");

            // ── Phase 6: Payload arrives via shard → resolves all 3 waiters ───
            let repaired = core.on_shard_message(
                ShardMessage::payload_response(&participants[0], payload, payload_contents),
                100 + AppCore::FETCH_RETRY_MS + 10,
                &|_| None,
            );
            let valid_count = repaired
                .replies
                .iter()
                .filter(|e| matches!(e, CoreEffect::Verify { valid: true, .. }))
                .count();
            assert_eq!(valid_count, 3, "all 3 deferred verifies resolved as valid");

            // ── Phase 7: Maintenance after resolution — no fetches ────────────
            let mut me3 = CoreEffects::new();
            core.run_maintenance(100 + AppCore::FETCH_RETRY_MS + 20, &mut me3);
            assert_eq!(count_fetch_broadcasts(&me3), 0, "no fetches after payload delivered");

            // Verify the pending_fetches map is clean.
            assert!(
                core.pending_fetches.is_empty(),
                "pending_fetches should be empty after delivery"
            );
        });
    }

    /// Simulates an unclean restart: a fresh AppCore (empty `seen` and
    /// `speculative_store`) receives a finalization for a chain tip whose
    /// ancestor bytes are missing.  Payload bytes are then drip-fed one at a
    /// time — mimicking the local persistence resolution loop in
    /// `apply_core_effects` — and the test verifies that the deferred
    /// finalization eventually materializes.
    #[test_log::test]
    fn restart_with_empty_seen_resolves_via_drip_feed() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-restart-drip-feed-test", 6);
            let strategy = crate::coding_strategy();

            let mut core = AppCore::new(
                &participants[1],
                participants.clone(),
                1,
                coding_config(6),
                TEST_WAIT_TIMEOUT_MS,
                strategy,
                test_metrics(&context, "core_restart_drip"),
                &context,
            );

            let epoch = Epoch::new(1);
            let genesis = core.genesis(epoch);
            let anchor_root = Digest::from([11u8; 32]);
            core.note_persisted_root(genesis, anchor_root);

            // ── Phase 1: Manually construct a 3-block chain ───────────────────
            // genesis → A → B → C  (payload bytes constructed by hand)
            let bytes_a = encode_payload(
                Round::new(epoch, View::new(1)),
                genesis,
                100,
                genesis,
                anchor_root,
                &[],
            );
            let block_a = payload_digest(&bytes_a);

            let bytes_b = encode_payload(
                Round::new(epoch, View::new(2)),
                block_a,
                101,
                genesis,
                anchor_root,
                &[],
            );
            let block_b = payload_digest(&bytes_b);

            let bytes_c = encode_payload(
                Round::new(epoch, View::new(3)),
                block_b,
                102,
                genesis,
                anchor_root,
                &[],
            );
            let block_c = payload_digest(&bytes_c);

            // `seen` is empty for blocks A, B, C — simulates post-restart state.
            assert!(!core.seen.contains_key(&block_a));
            assert!(!core.seen.contains_key(&block_b));
            assert!(!core.seen.contains_key(&block_c));

            // ── Phase 2: Finalize C — should defer ────────────────────────────
            let deferred = core.on_finalized(block_c, block_b, 200);
            assert!(deferred.replies.is_empty());
            assert!(deferred.network.is_empty());
            assert!(
                !core.finalized.is_finalized(block_c),
                "finalization must defer with empty seen"
            );

            // ── Phase 3: Drip-feed payload bytes one at a time ────────────────
            // Retry emits FetchPayload for block_c (not in seen yet).
            let mut retry1 = CoreEffects::new();
            core.retry_pending_finalizations(300, &mut retry1);
            assert_eq!(
                count_fetch_broadcasts(&retry1),
                1,
                "should request block_c"
            );

            // Simulate local persistence resolution: feed block_c bytes.
            core.note_payload_seen(block_c, bytes_c);

            // Now retry discovers block_b is missing (parent of C).
            let mut retry2 = CoreEffects::new();
            core.retry_pending_finalizations(400, &mut retry2);
            assert_eq!(
                count_fetch_broadcasts(&retry2),
                1,
                "should request block_b"
            );

            core.note_payload_seen(block_b, bytes_b);

            // Now retry discovers block_a is missing (parent of B).
            let mut retry3 = CoreEffects::new();
            core.retry_pending_finalizations(500, &mut retry3);
            assert_eq!(
                count_fetch_broadcasts(&retry3),
                1,
                "should request block_a"
            );

            core.note_payload_seen(block_a, bytes_a);

            // ── Phase 4: Final retry — execution materializes, finalization
            // completes ──
            let mut retry4 = CoreEffects::new();
            core.retry_pending_finalizations(600, &mut retry4);
            assert_eq!(count_fetch_broadcasts(&retry4), 0, "no more fetches needed");

            assert!(
                core.finalized.is_finalized(block_c),
                "block_c must be finalized after all ancestors hydrated"
            );
            assert!(
                core.pending_finalizations.is_empty(),
                "no pending finalizations should remain"
            );
            assert!(
                core.next_unpersisted_finalization().is_some(),
                "finalization diffs should be queued for persistence"
            );
        });
    }
}
