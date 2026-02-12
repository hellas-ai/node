mod core;
mod mailbox;
mod payload;

pub use mailbox::Mailbox;

use crate::execution::store::{UtxoDb, utxo_db_config};
use crate::execution::{FinalizationDiffs, genesis_state};
use crate::shard::{ShardMessage, ShardTransport, coding_config};
use commonware_consensus::Reporter;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_macros::select_loop;
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell};
use commonware_storage::kv::Batchable;
use commonware_utils::{SystemTimeExt, channels::fallible::OneshotExt};
use core::{AppCore, CoreEffect, CoreEffects, NetworkEffect};
use futures::{StreamExt, channel::mpsc};
use hellas_types::{Activity, PublicKey};
use mailbox::{Ingress, ReadOnlyMessage};
use std::time::Duration;

#[derive(Clone, Copy)]
pub(crate) struct FinalizationNotice {
    pub payload: Digest,
    pub parent_payload: Digest,
}

enum PersistDrainStatus {
    Idle,
    Drained,
    Blocked,
}

// ---------------------------------------------------------------------------
// TraceReporter — logs consensus activity
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TraceReporter;

impl Reporter for TraceReporter {
    type Activity = Activity;

    async fn report(&mut self, activity: Self::Activity) {
        info!(activity = ?activity);
    }
}

// ---------------------------------------------------------------------------
// Application actor — async driver over AppCore
// ---------------------------------------------------------------------------

pub(crate) struct Application<E: Clock + Spawner + Storage + Metrics> {
    context: ContextCell<E>,

    relay: std::sync::Arc<dyn ShardTransport>,
    shard_rx: mpsc::UnboundedReceiver<ShardMessage>,
    finalization_rx: mpsc::UnboundedReceiver<FinalizationNotice>,

    mailbox_rx: tokio::sync::mpsc::Receiver<Ingress>,

    core: AppCore,

    /// Partition prefix for QMDB storage (unique per validator instance).
    partition_prefix: String,

    /// QMDB for finalized UTXO state. `Option` for type-state take/put pattern
    /// during mutable transitions.
    db: Option<UtxoDb<ContextCell<E>>>,

    /// Latest Merkle root from the QMDB after the most recent finalization commit.
    state_root: Option<Digest>,

    /// Exponential backoff delay currently used for persistence retries.
    persistence_retry_delay: Duration,

    /// Next retry deadline in epoch millis for persistence, if a retry is pending.
    next_persistence_retry_at_ms: Option<u64>,

    #[cfg(test)]
    persistence_failures_remaining: usize,
}

impl<E: Clock + Spawner + Storage + Metrics> Application<E> {
    const MAILBOX_CAPACITY: usize = 1024;
    const MAX_PENDING_PERSISTENCE_QUEUE: usize = 1024;
    const PERSISTENCE_RETRY_BASE: Duration = Duration::from_millis(50);
    const PERSISTENCE_RETRY_MAX: Duration = Duration::from_secs(5);
    const PERSISTENCE_IDLE_SLEEP: Duration = Duration::from_secs(3600);

    pub(crate) fn new(
        context: E,
        relay: std::sync::Arc<dyn ShardTransport>,
        me: &PublicKey,
        validators: Vec<PublicKey>,
        partition_prefix: String,
    ) -> (Self, Mailbox, mpsc::UnboundedSender<FinalizationNotice>) {
        let (finalization_tx, finalization_rx) = mpsc::unbounded();
        let (app, mailbox) = Self::new_with_finalization_receiver(
            context,
            relay,
            me,
            validators,
            finalization_rx,
            partition_prefix,
        );
        (app, mailbox, finalization_tx)
    }

    #[cfg(test)]
    pub(crate) fn new_with_persistence_failures(
        context: E,
        relay: std::sync::Arc<dyn ShardTransport>,
        me: &PublicKey,
        validators: Vec<PublicKey>,
        partition_prefix: String,
        persistence_failures_remaining: usize,
    ) -> (Self, Mailbox, mpsc::UnboundedSender<FinalizationNotice>) {
        let (mut app, mailbox, finalization_tx) =
            Self::new(context, relay, me, validators, partition_prefix);
        app.persistence_failures_remaining = persistence_failures_remaining;
        (app, mailbox, finalization_tx)
    }

    fn new_with_finalization_receiver(
        context: E,
        relay: std::sync::Arc<dyn ShardTransport>,
        me: &PublicKey,
        validators: Vec<PublicKey>,
        finalization_rx: mpsc::UnboundedReceiver<FinalizationNotice>,
        partition_prefix: String,
    ) -> (Self, Mailbox) {
        let shard_rx = relay.register(me);
        let (sender, receiver) = tokio::sync::mpsc::channel(Self::MAILBOX_CAPACITY);
        let my_index = relay.validator_index(me).unwrap_or_else(|| {
            warn!("validator index unavailable for local key; defaulting to index 0");
            0
        });
        let coding_config = coding_config(relay.validator_count());
        let core = AppCore::new(me, validators, my_index, coding_config);

        (
            Self {
                context: ContextCell::new(context),
                relay,
                shard_rx,
                finalization_rx,
                mailbox_rx: receiver,
                core,
                partition_prefix,
                db: None,
                state_root: None,
                persistence_retry_delay: Self::PERSISTENCE_RETRY_BASE,
                next_persistence_retry_at_ms: None,
                #[cfg(test)]
                persistence_failures_remaining: 0,
            },
            Mailbox::new(sender),
        )
    }

    fn apply_reply_effect(&mut self, effect: CoreEffect) {
        match effect {
            CoreEffect::Digest { response, digest } => {
                response.send_lossy(digest);
            }
            CoreEffect::Verify { response, valid } => {
                response.send_lossy(valid);
            }
            #[cfg(debug_assertions)]
            CoreEffect::Coin { response, coin } => {
                response.send_lossy(coin);
            }
        }
    }

    async fn apply_network_effect(&mut self, effect: NetworkEffect) {
        match effect {
            NetworkEffect::BroadcastShard(message) => {
                self.relay.broadcast_except(self.core.me(), *message).await;
            }
            NetworkEffect::DistributeShards {
                key,
                commitment,
                shards,
            } => {
                self.relay
                    .distribute_shards(self.core.me(), key, commitment, shards)
                    .await;
            }
        }
    }

    async fn apply_core_effects(&mut self, effects: CoreEffects) {
        for effect in effects.replies {
            self.apply_reply_effect(effect);
        }
        for effect in effects.network {
            self.apply_network_effect(effect).await;
        }
    }

    async fn apply_diffs_to_db(&mut self, diffs: &FinalizationDiffs) -> bool {
        #[cfg(test)]
        if self.persistence_failures_remaining > 0
            && self.core.next_unpersisted_finalization().is_some()
        {
            self.persistence_failures_remaining -= 1;
            warn!(
                remaining = self.persistence_failures_remaining,
                "injecting persistence failure for retry-path test"
            );
            return false;
        }

        let Some(db) = self.db.take() else {
            warn!("QMDB unavailable; skipping persistence update");
            return false;
        };
        let mut db = db.into_mutable();

        let batch: Vec<_> = diffs
            .deleted
            .iter()
            .map(|id| (*id, None))
            .chain(
                diffs
                    .created
                    .iter()
                    .map(|(id, coin)| (*id, Some(coin.clone()))),
            )
            .collect();

        if let Err(err) = db.write_batch(batch.into_iter()).await {
            error!(?err, "QMDB write_batch failed");
            self.reopen_db_after_failure("write_batch").await;
            return false;
        }

        let (db, _range) = match db.commit(None).await {
            Ok(result) => result,
            Err(err) => {
                error!(?err, "QMDB commit failed");
                self.reopen_db_after_failure("commit").await;
                return false;
            }
        };
        let db = match db.into_merkleized().await {
            Ok(db) => db,
            Err(err) => {
                error!(?err, "QMDB merkleize failed");
                self.reopen_db_after_failure("merkleize").await;
                return false;
            }
        };
        self.state_root = Some(db.root());
        self.db = Some(db);
        true
    }

    async fn reopen_db_after_failure(&mut self, stage: &'static str) {
        let config = utxo_db_config(&self.partition_prefix);
        match UtxoDb::init(self.context.with_label("utxo_db_recover"), config).await {
            Ok(db) => {
                self.state_root = if db.is_empty() { None } else { Some(db.root()) };
                self.db = Some(db);
                warn!(
                    stage,
                    "re-opened QMDB after persistence failure; pending finalizations can be retried"
                );
            }
            Err(err) => {
                error!(
                    ?err,
                    stage, "failed to re-open QMDB after persistence failure"
                );
            }
        }
    }

    async fn persist_pending_finalizations(&mut self) -> PersistDrainStatus {
        let mut attempted = false;
        while let Some((payload, diffs)) = self.core.next_unpersisted_finalization() {
            attempted = true;
            if !self.apply_diffs_to_db(&diffs).await {
                warn!(?payload, "failed to persist finalized state");
                return PersistDrainStatus::Blocked;
            }
            if !self.core.mark_finalization_persisted(payload) {
                warn!(
                    ?payload,
                    "persisted finalization was not present in execution cache"
                );
                return PersistDrainStatus::Blocked;
            }
        }
        if attempted {
            PersistDrainStatus::Drained
        } else {
            PersistDrainStatus::Idle
        }
    }

    fn persistence_sleep_duration(&self, now_ms: u64) -> Duration {
        let Some(deadline_ms) = self.next_persistence_retry_at_ms else {
            return Self::PERSISTENCE_IDLE_SLEEP;
        };
        Duration::from_millis(deadline_ms.saturating_sub(now_ms))
    }

    fn schedule_persistence_retry(&mut self, now_ms: u64) {
        let delay_ms = u64::try_from(self.persistence_retry_delay.as_millis()).unwrap_or(u64::MAX);
        self.next_persistence_retry_at_ms = Some(now_ms.saturating_add(delay_ms));
        self.persistence_retry_delay =
            (self.persistence_retry_delay * 2).min(Self::PERSISTENCE_RETRY_MAX);
    }

    fn clear_persistence_retry(&mut self) {
        self.next_persistence_retry_at_ms = None;
        self.persistence_retry_delay = Self::PERSISTENCE_RETRY_BASE;
    }

    async fn drive_persistence(&mut self, now_ms: u64) {
        match self.persist_pending_finalizations().await {
            PersistDrainStatus::Idle | PersistDrainStatus::Drained => {
                self.clear_persistence_retry();
            }
            PersistDrainStatus::Blocked => {
                self.schedule_persistence_retry(now_ms);
            }
        }
    }

    async fn on_persistence_retry_tick(&mut self, now_ms: u64) {
        let Some(deadline_ms) = self.next_persistence_retry_at_ms else {
            return;
        };
        if now_ms < deadline_ms {
            return;
        }
        self.drive_persistence(now_ms).await;
    }

    async fn bootstrap_genesis_state_if_empty(&mut self) {
        let Some(db) = self.db.as_ref() else {
            return;
        };
        if !db.is_empty() {
            self.state_root = Some(db.root());
            return;
        }

        let genesis_execution = genesis_state(self.core.validators());
        let diffs = FinalizationDiffs {
            created: genesis_execution.created,
            deleted: genesis_execution.deleted,
        };
        let _ = self.apply_diffs_to_db(&diffs).await;
    }

    async fn handle_read_only(&self, msg: ReadOnlyMessage) {
        match msg {
            ReadOnlyMessage::GetStateRoot { response } => {
                let _ = response.send(self.state_root);
            }
            ReadOnlyMessage::GetProof { object, response } => {
                let proof = if let Some(db) = &self.db {
                    let mut hasher = Sha256::default();
                    db.key_value_proof(&mut hasher, object).await.ok()
                } else {
                    None
                };
                let _ = response.send(proof);
            }
        }
    }

    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        // Initialize QMDB.
        let config = utxo_db_config(&self.partition_prefix);
        match UtxoDb::init(self.context.with_label("utxo_db"), config).await {
            Ok(db) => {
                self.db = Some(db);
                self.bootstrap_genesis_state_if_empty().await;
            }
            Err(err) => {
                error!(
                    ?err,
                    "QMDB initialization failed; running without persistence"
                );
            }
        }

        select_loop! {
            self.context,
            on_start => {
                let now_ms = self.context.current().epoch_millis();
                let persistence_sleep = self.persistence_sleep_duration(now_ms);
            },
            on_stopped => {
                if let Some(mut db) = self.db.take() {
                    if let Err(err) = db.sync().await {
                        warn!(?err, "QMDB sync on shutdown failed");
                    }
                }
                debug!("application shutting down");
            },
            message = self.mailbox_rx.recv() => {
                let ingress = match message {
                    Some(ingress) => ingress,
                    None => break,
                };
                match ingress {
                    Ingress::ReadWrite(message) => {
                        let now = self.context.current().epoch_millis();
                        let relay = &self.relay;
                        let effects = self
                            .core
                            .on_message(message, now, &|sender| relay.validator_index(sender));
                        self.apply_core_effects(effects).await;
                    }
                    Ingress::ReadOnly(message) => {
                        self.handle_read_only(message).await;
                    }
                }
            },
            shard = self.shard_rx.next() => {
                match shard {
                    Some(shard) => {
                        let now = self.context.current().epoch_millis();
                        let relay = &self.relay;
                        let effects = self
                            .core
                            .on_shard_message(shard, now, &|sender| relay.validator_index(sender));
                        self.apply_core_effects(effects).await;
                    }
                    None => {
                        warn!("shard relay closed");
                        break;
                    }
                }
            },
            finalized = self.finalization_rx.next() => {
                match finalized {
                    Some(finalized) => {
                        let effects = self.core.on_finalized(
                            finalized.payload, finalized.parent_payload,
                        );
                        let pending = self.core.unpersisted_finalization_count();
                        if pending > Self::MAX_PENDING_PERSISTENCE_QUEUE {
                            error!(
                                pending,
                                max = Self::MAX_PENDING_PERSISTENCE_QUEUE,
                                "pending persistence queue exceeded bound; entering fail-stop"
                            );
                            std::process::abort();
                        }
                        let now = self.context.current().epoch_millis();
                        self.drive_persistence(now).await;
                        self.apply_core_effects(effects).await;
                    }
                    None => {
                        warn!("finalization channel closed");
                        break;
                    }
                }
            },
            _ = self.context.sleep(persistence_sleep) => {
                let now = self.context.current().epoch_millis();
                self.on_persistence_retry_tick(now).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::payload::{
        PayloadValidationError, SYNCHRONY_BOUND, decode_timestamp, encode_payload, genesis_payload,
        payload_digest, validate_payload,
    };
    use super::*;
    use crate::execution::store::UtxoDb;
    use crate::object::{Coin, GENESIS_BALANCE, Transaction, genesis_object_id, output_object_id};
    use crate::shard::mock::MockShardTransport;
    use bytes::Bytes;
    use commonware_codec::Encode;
    use commonware_consensus::minimmit::scheme::ed25519 as minimmit_ed25519;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_consensus::{Automaton, Relay};
    use commonware_cryptography::certificate::mocks::Fixture;
    use commonware_cryptography::{Hasher, Sha256, Signer};
    use commonware_runtime::{Clock, ContextCell, Metrics, Runner, deterministic};
    use futures::channel::oneshot::Canceled;
    use hellas_types::{Context, PrivateKey};
    use proptest::prelude::*;
    use std::{sync::Arc, time::Duration};

    /// Cap timestamp ranges to avoid saturating_add degeneracy near u64::MAX.
    const MAX_TIMESTAMP: u64 = u64::MAX - SYNCHRONY_BOUND - 10_001;

    fn make_round(epoch: u16, view: u16) -> Round {
        Round::new(Epoch::new(epoch as u64), View::new(view as u64))
    }

    fn mutate_byte(mut bytes: Vec<u8>, index: usize) -> Vec<u8> {
        let idx = index % bytes.len();
        bytes[idx] ^= 0x01;
        bytes
    }

    fn default_parent_contents() -> Bytes {
        genesis_payload(Epoch::new(0))
    }

    proptest! {
        #[test]
        fn valid_payload_is_accepted(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
            slack in 0u64..=SYNCHRONY_BOUND,
        ) {
            let round = make_round(epoch, view);
            let parent = Digest::from(parent);
            let contents = encode_payload(round, parent, timestamp);
            let payload = payload_digest(&contents);
            let now = timestamp + slack;
            let parent_contents = default_parent_contents();

            prop_assert!(matches!(
                validate_payload(round, parent, payload, &contents, now, &parent_contents),
                Ok(txs) if txs.is_empty()
            ));
        }

        #[test]
        fn mutated_payload_is_rejected(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
            index in any::<usize>(),
        ) {
            let round = make_round(epoch, view);
            let parent = Digest::from(parent);
            let contents = encode_payload(round, parent, timestamp);
            let payload = payload_digest(&contents);
            let mutated = Bytes::from(mutate_byte(contents.to_vec(), index));
            let parent_contents = default_parent_contents();

            assert!(matches!(
                validate_payload(
                    round,
                    parent,
                    payload,
                    &mutated,
                    timestamp + SYNCHRONY_BOUND,
                    &parent_contents,
                ),
                Err(PayloadValidationError::DigestMismatch { .. })
            ));
        }

        #[test]
        fn round_mismatch_is_rejected(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
        ) {
            let round = make_round(epoch, view);
            let parent = Digest::from(parent);
            let contents = encode_payload(round, parent, timestamp);
            let payload = payload_digest(&contents);
            let now = timestamp + SYNCHRONY_BOUND;
            let parent_contents = default_parent_contents();

            let wrong_round = make_round(epoch.wrapping_add(1), view);
            assert!(matches!(
                validate_payload(
                    wrong_round,
                    parent,
                    payload,
                    &contents,
                    now,
                    &parent_contents,
                ),
                Err(PayloadValidationError::RoundMismatch { .. })
            ));
        }

        #[test]
        fn parent_mismatch_is_rejected(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
        ) {
            let round = make_round(epoch, view);
            let parent = Digest::from(parent);
            let contents = encode_payload(round, parent, timestamp);
            let payload = payload_digest(&contents);
            let now = timestamp + SYNCHRONY_BOUND;
            let parent_contents = default_parent_contents();

            let mut wrong_parent = parent.0;
            wrong_parent[0] ^= 0x01;
            assert!(matches!(
                validate_payload(
                    round,
                    Digest::from(wrong_parent),
                    payload,
                    &contents,
                    now,
                    &parent_contents,
                ),
                Err(PayloadValidationError::ParentMismatch { .. })
            ));
        }

        #[test]
        fn future_timestamp_is_rejected(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            now in 0u64..=MAX_TIMESTAMP,
            delta in (SYNCHRONY_BOUND + 1)..=(SYNCHRONY_BOUND + 10_000),
        ) {
            let round = make_round(epoch, view);
            let parent = Digest::from(parent);
            let timestamp = now + delta;
            let contents = encode_payload(round, parent, timestamp);
            let payload = payload_digest(&contents);
            let parent_contents = default_parent_contents();

            assert!(matches!(
                validate_payload(round, parent, payload, &contents, now, &parent_contents),
                Err(PayloadValidationError::FutureTimestamp { .. })
            ));
        }

        #[test]
        fn past_timestamp_is_accepted(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
            age in 0u64..=1_000_000u64,
        ) {
            let round = make_round(epoch, view);
            let parent = Digest::from(parent);
            let contents = encode_payload(round, parent, timestamp);
            let payload = payload_digest(&contents);
            let now = timestamp + age;
            let parent_contents = default_parent_contents();

            prop_assert!(matches!(
                validate_payload(round, parent, payload, &contents, now, &parent_contents),
                Ok(txs) if txs.is_empty()
            ));
        }

        #[test]
        fn timestamp_regression_is_rejected(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent_digest in any::<[u8; 32]>(),
            parent_ts in 1u64..=MAX_TIMESTAMP,
            regression in 1u64..=1_000u64,
        ) {
            let round = make_round(epoch, view);
            let parent_digest = Digest::from(parent_digest);
            let child_ts = parent_ts - regression;
            let contents = encode_payload(round, parent_digest, child_ts);
            let payload = payload_digest(&contents);
            let now = parent_ts + SYNCHRONY_BOUND;

            // Build parent payload bytes
            let parent_round = make_round(epoch, view.wrapping_sub(1));
            let parent_contents = encode_payload(parent_round, Digest::from([0u8; 32]), parent_ts);

            assert!(matches!(
                validate_payload(round, parent_digest, payload, &contents, now, &parent_contents),
                Err(PayloadValidationError::TimestampRegression { .. })
            ));
        }

        #[test]
        fn monotonic_timestamp_is_accepted(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent_digest in any::<[u8; 32]>(),
            parent_ts in 0u64..=(MAX_TIMESTAMP / 2),
            advance in 0u64..=1_000u64,
        ) {
            let round = make_round(epoch, view);
            let parent_digest = Digest::from(parent_digest);
            let child_ts = parent_ts + advance;
            let contents = encode_payload(round, parent_digest, child_ts);
            let payload = payload_digest(&contents);
            let now = child_ts + SYNCHRONY_BOUND;

            let parent_round = make_round(epoch, view.wrapping_sub(1));
            let parent_contents = encode_payload(parent_round, Digest::from([0u8; 32]), parent_ts);

            prop_assert!(matches!(
                validate_payload(round, parent_digest, payload, &contents, now, &parent_contents),
                Ok(txs) if txs.is_empty()
            ));
        }
    }

    #[test]
    fn invalid_encoding_is_rejected() {
        let round = Round::new(Epoch::new(1), View::new(1));
        let parent = Digest::from([7; 32]);
        let contents = Bytes::from_static(b"not-a-valid-payload");
        let payload = payload_digest(&contents);
        let parent_contents = default_parent_contents();

        assert!(matches!(
            validate_payload(round, parent, payload, &contents, 0, &parent_contents),
            Err(PayloadValidationError::InvalidEncoding)
        ));
    }

    #[test]
    fn invalid_parent_encoding_is_rejected() {
        let round = Round::new(Epoch::new(1), View::new(1));
        let parent = Digest::from([7; 32]);
        let contents = encode_payload(round, parent, 10);
        let payload = payload_digest(&contents);
        let bad_parent_contents = Bytes::from_static(b"bad-parent");

        assert!(matches!(
            validate_payload(round, parent, payload, &contents, 10, &bad_parent_contents),
            Err(PayloadValidationError::InvalidParentEncoding)
        ));
    }

    #[test]
    fn genesis_has_zero_timestamp() {
        let epoch = Epoch::new(1);
        let payload = genesis_payload(epoch);
        assert_eq!(decode_timestamp(&payload), Some(0));
    }

    #[test]
    fn preleader_shards_drain_after_verify() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"app-shard-test", 6);

            let relay = Arc::new(MockShardTransport::new());
            for participant in participants.iter() {
                relay.declare(participant);
            }
            relay.finalize_validators();

            let mut mailboxes = Vec::new();
            let mut handles = Vec::new();
            let mut finalization_txs = Vec::new();
            for (idx, participant) in participants.iter().enumerate() {
                let (app, mailbox, finalization_tx) = Application::new(
                    context.with_label(&format!("app_{idx}")),
                    relay.clone(),
                    participant,
                    participants.clone(),
                    format!("test_app_{idx}"),
                );
                handles.push(app.start());
                mailboxes.push(mailbox);
                finalization_txs.push(finalization_tx);
            }

            let epoch = Epoch::new(1);
            let mut genesis = None;
            for mailbox in mailboxes.iter_mut() {
                let digest = mailbox.genesis(epoch).await;
                if let Some(existing) = genesis {
                    assert_eq!(existing, digest);
                } else {
                    genesis = Some(digest);
                }
            }
            let genesis = genesis.expect("genesis should be set");

            let round = Round::new(epoch, View::new(1));
            let proposal_context = Context {
                round,
                leader: participants[0].clone(),
                parent: (View::zero(), genesis),
            };

            let digest = mailboxes[0]
                .propose(proposal_context.clone())
                .await
                .await
                .expect("proposal should resolve");

            // Broadcast before any verify to force pre-leader buffering.
            mailboxes[0].broadcast(digest).await;
            context.sleep(Duration::from_millis(10)).await;

            let mut verify_rx_1 = mailboxes[1].verify(proposal_context.clone(), digest).await;
            context.sleep(Duration::from_millis(10)).await;
            match verify_rx_1.try_recv() {
                Ok(Some(v)) => panic!("verify should not resolve yet, got {:?}", v),
                Ok(None) => {}
                Err(Canceled) => panic!("verify receiver canceled unexpectedly"),
            }

            let verify_rx_2 = mailboxes[2].verify(proposal_context, digest).await;
            assert!(verify_rx_2.await.expect("verify 2 should resolve"));
            assert!(verify_rx_1.await.expect("verify 1 should resolve"));

            drop(handles);
            drop(finalization_txs);
        });
    }

    #[test]
    fn empty_qmdb_bootstraps_genesis_state() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let relay = Arc::new(MockShardTransport::new());
            let key = PrivateKey::from_seed(42).public_key();
            relay.declare(&key);
            relay.finalize_validators();

            let (app, mut mailbox, _finalization_tx) = Application::new(
                context.with_label("bootstrap_app"),
                relay,
                &key,
                vec![key.clone()],
                "bootstrap_test_partition".to_string(),
            );
            let _handle = app.start();

            let _ = mailbox.genesis(Epoch::new(1)).await;

            let root = mailbox
                .get_state_root()
                .await
                .expect("state root request should not fail");
            assert!(
                root.is_some(),
                "state root should be available after startup"
            );

            let proof = mailbox
                .get_proof(genesis_object_id(0))
                .await
                .expect("proof request should not fail");
            assert!(
                proof.is_some(),
                "genesis object should be provable from the state root"
            );

            let root = root.expect("state root should be set");
            let proof = proof.expect("proof should exist for genesis object");
            let expected_coin = Coin {
                owner: key.clone(),
                value: GENESIS_BALANCE,
            };
            let mut hasher = Sha256::default();
            assert!(
                UtxoDb::<ContextCell<deterministic::Context>>::verify_key_value_proof(
                    &mut hasher,
                    genesis_object_id(0),
                    expected_coin,
                    &proof,
                    &root,
                )
            );
        });
    }

    #[test]
    fn qmdb_root_and_proof_survive_app_restart() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let key = PrivateKey::from_seed(77).public_key();
            let validators = vec![key.clone()];
            let partition = "restart_test_partition".to_string();

            let relay_a = Arc::new(MockShardTransport::new());
            relay_a.declare(&key);
            relay_a.finalize_validators();
            let (app_a, mut mailbox_a, _finalization_tx_a) = Application::new(
                context.with_label("restart_app_a"),
                relay_a,
                &key,
                validators.clone(),
                partition.clone(),
            );
            let app_a_handle = app_a.start();
            let _ = mailbox_a.genesis(Epoch::new(1)).await;

            let root_a = mailbox_a
                .get_state_root()
                .await
                .expect("state root request should not fail")
                .expect("state root should be set before restart");
            let proof_a = mailbox_a
                .get_proof(genesis_object_id(0))
                .await
                .expect("proof request should not fail")
                .expect("proof should exist before restart");

            let expected_coin = Coin {
                owner: key.clone(),
                value: GENESIS_BALANCE,
            };
            let mut hasher = Sha256::default();
            assert!(
                UtxoDb::<ContextCell<deterministic::Context>>::verify_key_value_proof(
                    &mut hasher,
                    genesis_object_id(0),
                    expected_coin.clone(),
                    &proof_a,
                    &root_a,
                )
            );

            app_a_handle.abort();
            let _ = app_a_handle.await;

            let relay_b = Arc::new(MockShardTransport::new());
            relay_b.declare(&key);
            relay_b.finalize_validators();
            let (app_b, mailbox_b, _finalization_tx_b) = Application::new(
                context.with_label("restart_app_b"),
                relay_b,
                &key,
                validators,
                partition,
            );
            let _app_b_handle = app_b.start();

            let root_b = mailbox_b
                .get_state_root()
                .await
                .expect("state root request should not fail")
                .expect("state root should be loaded after restart");
            assert_eq!(root_a, root_b);

            let proof_b = mailbox_b
                .get_proof(genesis_object_id(0))
                .await
                .expect("proof request should not fail")
                .expect("proof should exist after restart");
            let mut hasher = Sha256::default();
            assert!(
                UtxoDb::<ContextCell<deterministic::Context>>::verify_key_value_proof(
                    &mut hasher,
                    genesis_object_id(0),
                    expected_coin,
                    &proof_b,
                    &root_b,
                )
            );
        });
    }

    #[test]
    fn persistence_retry_worker_applies_finalized_diffs_without_new_finalizations() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let relay = Arc::new(MockShardTransport::new());
            let sender = PrivateKey::from_seed(88);
            let sender_pk = sender.public_key();
            let recipient_pk = PrivateKey::from_seed(89).public_key();
            relay.declare(&sender_pk);
            relay.finalize_validators();

            let (app, mut mailbox, finalization_tx) = Application::new_with_persistence_failures(
                context.with_label("retry_worker_app"),
                relay,
                &sender_pk,
                vec![sender_pk.clone()],
                "retry_worker_partition".to_string(),
                2,
            );
            let _app_handle = app.start();

            let epoch = Epoch::new(1);
            let genesis = mailbox.genesis(epoch).await;
            let root_before = mailbox
                .get_state_root()
                .await
                .expect("state root request should not fail")
                .expect("genesis root should exist");

            let input = genesis_object_id(0);
            let tx = Transaction::transfer(&sender, input, recipient_pk.clone(), 1);
            let tx_digest = Sha256::hash(&tx.encode());
            let recipient_output = output_object_id(&tx_digest, 0);
            mailbox.submit_tx(tx).await;

            let proposal_context = Context {
                round: Round::new(epoch, View::new(1)),
                leader: sender_pk.clone(),
                parent: (View::zero(), genesis),
            };
            let payload = mailbox
                .propose(proposal_context)
                .await
                .await
                .expect("proposal should resolve");
            finalization_tx
                .unbounded_send(FinalizationNotice {
                    payload,
                    parent_payload: genesis,
                })
                .expect("finalization should enqueue");

            // Retries are timer-driven (50ms base with exponential backoff). No additional
            // finalization events are sent here.
            context.sleep(Duration::from_secs(1)).await;

            let root_after = mailbox
                .get_state_root()
                .await
                .expect("state root request should not fail")
                .expect("state root should be updated after retries");
            assert_ne!(root_before, root_after);

            let proof = mailbox
                .get_proof(recipient_output)
                .await
                .expect("proof request should not fail")
                .expect("recipient output proof should exist");
            let expected_coin = Coin {
                owner: recipient_pk,
                value: 1,
            };
            let mut hasher = Sha256::default();
            assert!(
                UtxoDb::<ContextCell<deterministic::Context>>::verify_key_value_proof(
                    &mut hasher,
                    recipient_output,
                    expected_coin,
                    &proof,
                    &root_after,
                )
            );
        });
    }
}
