use super::mailbox::AppMailboxReadWriteMessage;
use super::payload::{
    decode_execution_payload, encode_payload_with_txs, genesis_digest, genesis_payload,
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

struct PayloadBook {
    seen: HashMap<Digest, Bytes>,
    pending: IndexSet<Digest>,
    pending_shards: HashMap<Digest, (BlockKey, ZodaCommitment, Vec<ZodaShard>)>,
    waiters: IndexMap<Digest, Vec<DeferredVerify>>,
}

impl PayloadBook {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
            pending: IndexSet::new(),
            pending_shards: HashMap::new(),
            waiters: IndexMap::new(),
        }
    }

    #[cfg(test)]
    fn contains_seen(&self, digest: Digest) -> bool {
        self.seen.contains_key(&digest)
    }

    fn seen(&self, digest: Digest) -> Option<&Bytes> {
        self.seen.get(&digest)
    }

    fn seen_cloned(&self, digest: Digest) -> Option<Bytes> {
        self.seen.get(&digest).cloned()
    }

    fn note_seen(&mut self, digest: Digest, payload: Bytes) {
        self.seen.insert(digest, payload);
    }

    fn mark_pending(&mut self, digest: Digest) {
        self.pending.insert(digest);
    }

    fn note_pending_shards(
        &mut self,
        digest: Digest,
        key: BlockKey,
        commitment: ZodaCommitment,
        shards: Vec<ZodaShard>,
    ) {
        self.pending_shards
            .insert(digest, (key, commitment, shards));
    }

    fn take_pending_shards(
        &mut self,
        digest: Digest,
    ) -> Option<(BlockKey, ZodaCommitment, Vec<ZodaShard>)> {
        self.pending.shift_remove(&digest);
        self.pending_shards.remove(&digest)
    }

    fn clear_pending(&mut self, digest: Digest) {
        self.pending.shift_remove(&digest);
        self.pending_shards.remove(&digest);
    }

    fn enforce_pending_capacity(&mut self, max_pending: usize) {
        while self.pending.len() > max_pending {
            let Some(oldest) = self.pending.shift_remove_index(0) else {
                break;
            };
            self.pending_shards.remove(&oldest);
        }
    }

    fn queue_waiter(&mut self, digest: Digest, deferred: DeferredVerify) {
        self.waiters.entry(digest).or_default().push(deferred);
    }

    fn trim_waiter_keys(&mut self, max_waiter_keys: usize) -> Vec<DeferredVerify> {
        let mut evicted = Vec::new();
        while self.waiters.len() > max_waiter_keys {
            let Some((_oldest, stale)) = self.waiters.shift_remove_index(0) else {
                break;
            };
            evicted.extend(stale);
        }
        evicted
    }

    fn take_waiters(&mut self, digest: Digest) -> Vec<DeferredVerify> {
        self.waiters.shift_remove(&digest).unwrap_or_default()
    }

    fn remove_digest(&mut self, digest: Digest) -> Vec<DeferredVerify> {
        self.seen.remove(&digest);
        self.pending.shift_remove(&digest);
        self.pending_shards.remove(&digest);
        self.take_waiters(digest)
    }
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
    fn new() -> Self {
        Self {
            replies: VecDeque::new(),
            network: VecDeque::new(),
        }
    }
}

pub(super) struct AppCore {
    payloads: PayloadBook,
    mempool: VecDeque<Transaction>,
    speculative_store: SpeculativeExecutionStore,
    finalized: FinalizationTracker,
    validators: Vec<PublicKey>,
    strategy: Rayon,
    shard_recoverer: ShardRecoverer,
}

impl AppCore {
    const MAX_PENDING_DIGESTS: usize = 256;
    const MAX_WAITER_KEYS: usize = 512;
    const MAX_MEMPOOL_SIZE: usize = 1024;
    const MAX_FINALIZED_EXECUTIONS: usize = 512;

    // Construction + identity -------------------------------------------------
    pub(super) fn new(
        me: &PublicKey,
        mut validators: Vec<PublicKey>,
        my_index: u16,
        coding_config: commonware_coding::Config,
        strategy: Rayon,
    ) -> Self {
        validators.sort();
        validators.dedup();
        if validators.is_empty() {
            warn!("validator set was empty; defaulting to self-only validator set");
            validators.push(me.clone());
        }

        Self {
            payloads: PayloadBook::new(),
            mempool: VecDeque::new(),
            speculative_store: SpeculativeExecutionStore::new(),
            finalized: FinalizationTracker::new(Self::MAX_FINALIZED_EXECUTIONS),
            validators,
            strategy: strategy.clone(),
            shard_recoverer: ShardRecoverer::new(me, my_index, coding_config, strategy),
        }
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
            AppMailboxReadWriteMessage::Genesis { epoch, response } => {
                let digest = self.genesis(epoch);
                effects
                    .replies
                    .push_back(CoreEffect::Digest { response, digest });
            }
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
            AppMailboxReadWriteMessage::GetStateRoot { .. }
            | AppMailboxReadWriteMessage::GetProof { .. }
            | AppMailboxReadWriteMessage::RetryPersistence => {
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
        self.finalized.mark_persisted(payload)
    }

    pub(super) fn unpersisted_finalization_count(&self) -> usize {
        self.finalized.unpersisted_finalization_count()
    }

    // Consensus callbacks -----------------------------------------------------
    pub(super) fn genesis(&mut self, epoch: Epoch) -> Digest {
        let payload = genesis_payload(epoch);
        let digest = genesis_digest(epoch);
        self.payloads.note_seen(digest, payload);
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

            // Re-execute via execute_block to obtain diffs.
            if !txs.is_empty() {
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
            } else {
                resulting_diffs = Some(FinalizationDiffs {
                    created: Vec::new(),
                    deleted: Vec::new(),
                });
                resulting_state = Some(running_state);
            }
        } else {
            warn!(parent = ?parent, "missing parent execution; proposing empty block");
        }

        self.propose_with_txs(context, now, parent, txs, resulting_state, resulting_diffs)
    }

    // Proposal assembly -------------------------------------------------------
    fn propose_empty(&mut self, context: &Context, now: u64) -> Digest {
        self.propose_with_txs(context, now, context.parent.1, Vec::new(), None, None)
    }

    fn propose_with_txs(
        &mut self,
        context: &Context,
        timestamp: u64,
        parent: Digest,
        txs: Vec<Transaction>,
        resulting_state: Option<ObjectState>,
        resulting_diffs: Option<FinalizationDiffs>,
    ) -> Digest {
        let payload = encode_payload_with_txs(context.round, parent, timestamp, &txs);
        let digest = payload_digest(&payload);
        let key = BlockKey::new(context.round, digest);
        let encoded = CodingImpl::encode(
            self.shard_recoverer.coding_config(),
            payload.as_ref(),
            &self.strategy,
        );

        self.payloads.mark_pending(digest);
        match encoded {
            Ok((commitment, shards)) => {
                self.payloads
                    .note_pending_shards(digest, key, commitment, shards);
            }
            Err(err) => {
                warn!(?err, digest = ?digest, "zoda encode failed; payload will not be broadcast");
            }
        }
        self.enforce_pending_capacity();
        self.payloads.note_seen(digest, payload);
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
        now: u64,
    ) -> bool {
        let parent = context.parent.1;
        if !self.ensure_execution_materialized(parent) {
            warn!(
                parent = ?parent,
                "missing parent execution during verify"
            );
            return false;
        }
        let Some(parent_bytes) = self.payloads.seen(parent) else {
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
        if !self.speculative_store.contains_execution(parent) {
            let _ = self.ensure_execution_materialized(parent);
        }
        if let Some(missing_digest) = missing_dependency_or_execution(
            &self.payloads.seen,
            &self.speculative_store,
            context,
            payload,
        ) {
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
        let Some(contents) = self.payloads.seen_cloned(payload) else {
            warn!(
                payload = ?payload,
                "payload bytes missing during verify despite dependency check"
            );
            effects.replies.push_back(CoreEffect::Verify {
                response,
                valid: false,
            });
            return;
        };
        let valid = self.verify_payload(context, payload, &contents, now);
        effects
            .replies
            .push_back(CoreEffect::Verify { response, valid });
        if valid {
            self.retry_waiters(payload, now, effects);
        } else {
            self.reject_waiters(payload, effects);
        }
    }

    fn queue_waiter(
        &mut self,
        digest: Digest,
        deferred: DeferredVerify,
        effects: &mut CoreEffects,
    ) {
        self.payloads.queue_waiter(digest, deferred);
        for stale in self.payloads.trim_waiter_keys(Self::MAX_WAITER_KEYS) {
            effects.replies.push_back(CoreEffect::Verify {
                response: stale.response,
                valid: false,
            });
        }
    }

    fn retry_waiters(&mut self, digest: Digest, now: u64, effects: &mut CoreEffects) {
        for deferred in self.take_waiters_for(digest) {
            self.process_verify_request(
                &deferred.context,
                deferred.payload,
                deferred.response,
                now,
                effects,
            );
        }
    }

    fn reject_waiters(&mut self, digest: Digest, effects: &mut CoreEffects) {
        for deferred in self.take_waiters_for(digest) {
            effects.replies.push_back(CoreEffect::Verify {
                response: deferred.response,
                valid: false,
            });
        }
    }

    fn take_waiters_for(&mut self, digest: Digest) -> Vec<DeferredVerify> {
        self.payloads.take_waiters(digest)
    }

    // Pending payload retention -----------------------------------------------
    fn enforce_pending_capacity(&mut self) {
        self.payloads
            .enforce_pending_capacity(Self::MAX_PENDING_DIGESTS);
    }

    // Finalization pruning ----------------------------------------------------
    fn handle_finalized(
        &mut self,
        payload: Digest,
        parent_payload: Digest,
        effects: &mut CoreEffects,
    ) {
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

        let finalized = &self.finalized;
        let pruned = self
            .speculative_store
            .prune_non_descendants(payload, |digest| finalized.is_finalized(digest));
        for digest in pruned {
            for deferred in self.payloads.remove_digest(digest) {
                effects.replies.push_back(CoreEffect::Verify {
                    response: deferred.response,
                    valid: false,
                });
            }
        }
    }

    // Shard recovery + broadcast ----------------------------------------------
    fn apply_shard_effect(&mut self, effect: ShardEffect, now: u64, effects: &mut CoreEffects) {
        match effect {
            ShardEffect::Broadcast(message) => {
                effects
                    .network
                    .push_back(NetworkEffect::BroadcastShard(message));
            }
            ShardEffect::Recovered { key, contents } => {
                self.payloads.note_seen(key.digest, contents);
                self.payloads.clear_pending(key.digest);
                self.retry_waiters(key.digest, now, effects);
            }
            ShardEffect::Failed { key } => {
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
        let shard_effects =
            self.shard_recoverer
                .handle_message(message, &self.payloads.seen, validator_index);
        for effect in shard_effects {
            self.apply_shard_effect(effect, now, effects);
        }
    }

    fn enqueue_broadcast(&mut self, digest: Digest, effects: &mut CoreEffects) {
        let Some((key, commitment, shards)) = self.payloads.take_pending_shards(digest) else {
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

    // Shared helper -----------------------------------------------------------
    fn ensure_execution_materialized(&mut self, digest: Digest) -> bool {
        self.speculative_store
            .ensure_execution_for_payload(digest, &|candidate| {
                decode_execution_payload(&self.payloads.seen, candidate)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::protocol::coding_config;
    use commonware_consensus::minimmit::scheme::ed25519 as minimmit_ed25519;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::certificate::mocks::Fixture;
    use commonware_runtime::{Runner, deterministic};
    use hellas_types::Context;
    use std::time::Duration;

    #[test]
    fn finalization_prunes_non_descendant_execution_state() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"core-prune-test", 6);

            let me = participants[0].clone();
            let strategy = crate::coding_strategy();
            let mut core = AppCore::new(&me, participants.clone(), 0, coding_config(6), strategy);

            let epoch = Epoch::new(1);
            let genesis = core.genesis(epoch);

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
            assert!(!core.payloads.contains_seen(fork));
        });
    }
}
