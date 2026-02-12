mod core;
mod mailbox;
mod payload;
mod persistence;

pub use mailbox::AppMailbox;

use crate::object::ObjectId;
use crate::shard::protocol::{ShardMessage, coding_config};
use crate::shard::transport::ShardTransport;
use commonware_actor::{Actor, service::ServiceBuilder};
use commonware_consensus::Reporter;
use commonware_cryptography::sha256::Digest;
use commonware_macros::select;
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_utils::{
    SystemTimeExt,
    channel::{fallible::OneshotExt, oneshot},
};
use core::{AppCore, CoreEffect, CoreEffects, NetworkEffect};
use futures::{StreamExt, channel::mpsc};
use hellas_types::{Activity, PublicKey};
use mailbox::{AppMailboxMessage, AppMailboxReadWriteMessage};
use persistence::{PageCacheConfig, PersistenceCommand, PersistenceEvent, PersistenceWorker};
use std::{collections::VecDeque, convert::Infallible, num::NonZeroUsize};

#[derive(Clone, Copy)]
pub(crate) struct FinalizationNotice {
    pub payload: Digest,
    pub parent_payload: Digest,
}

enum ExternalEvent {
    Shard(Box<ShardMessage>),
    Finalization(FinalizationNotice),
    Persistence(PersistenceEvent),
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

pub(crate) struct Application<E, T>
where
    E: Clock + Spawner + Storage + Metrics,
    T: ShardTransport,
{
    context: ContextCell<E>,

    relay: std::sync::Arc<T>,
    shard_rx: mpsc::UnboundedReceiver<ShardMessage>,
    finalization_rx: mpsc::UnboundedReceiver<FinalizationNotice>,

    core: AppCore,

    /// Partition prefix for QMDB storage (unique per validator instance).
    partition_prefix: String,

    /// QMDB page cache tuning.
    page_cache: PageCacheConfig,

    /// Commands sent to the background persistence worker.
    persistence_tx: mpsc::UnboundedSender<PersistenceCommand>,

    /// Events emitted by the background persistence worker.
    persistence_rx: mpsc::UnboundedReceiver<PersistenceEvent>,

    /// Handle to the background persistence worker task.
    persistence_handle: Option<Handle<()>>,

    /// Receiver consumed when spawning the background persistence worker.
    persistence_cmd_rx: Option<mpsc::UnboundedReceiver<PersistenceCommand>>,

    /// Sender consumed when spawning the background persistence worker.
    persistence_event_tx: Option<mpsc::UnboundedSender<PersistenceEvent>>,

    /// External events captured in `on_external` and replayed through
    /// `on_read_write` via `DrainExternalEvents`.
    pending_external: VecDeque<ExternalEvent>,

    /// Payload currently enqueued for persistence and awaiting acknowledgment.
    inflight_persistence: Option<Digest>,

    #[cfg(test)]
    persistence_failures_remaining: usize,
}

impl<E, T> Application<E, T>
where
    E: Clock + Spawner + Storage + Metrics,
    T: ShardTransport,
{
    const MAILBOX_CAPACITY: usize = 1024;
    const MAX_PENDING_PERSISTENCE_QUEUE: usize = 1024;

    pub(crate) fn new(
        context: E,
        relay: std::sync::Arc<T>,
        me: &PublicKey,
        validators: Vec<PublicKey>,
        partition_prefix: String,
    ) -> (Self, mpsc::UnboundedSender<FinalizationNotice>) {
        let page_cache = PageCacheConfig {
            size: crate::execution::store::DEFAULT_PAGE_CACHE_SIZE.get(),
            count: crate::execution::store::DEFAULT_PAGE_CACHE_COUNT.get(),
        };
        let (finalization_tx, finalization_rx) = mpsc::unbounded();
        let app = Self::new_with_finalization_receiver(
            context,
            relay,
            me,
            validators,
            partition_prefix,
            finalization_rx,
            page_cache,
        );
        (app, finalization_tx)
    }

    pub(crate) fn new_with_page_cache(
        context: E,
        relay: std::sync::Arc<T>,
        me: &PublicKey,
        validators: Vec<PublicKey>,
        partition_prefix: String,
        page_cache_size: u16,
        page_cache_count: usize,
    ) -> (Self, mpsc::UnboundedSender<FinalizationNotice>) {
        let (mut app, finalization_tx) =
            Self::new(context, relay, me, validators, partition_prefix);
        app.page_cache = PageCacheConfig {
            size: page_cache_size,
            count: page_cache_count,
        };
        (app, finalization_tx)
    }

    #[cfg(test)]
    pub(crate) fn new_with_persistence_failures(
        context: E,
        relay: std::sync::Arc<T>,
        me: &PublicKey,
        validators: Vec<PublicKey>,
        partition_prefix: String,
        persistence_failures_remaining: usize,
    ) -> (Self, mpsc::UnboundedSender<FinalizationNotice>) {
        let (mut app, finalization_tx) =
            Self::new(context, relay, me, validators, partition_prefix);
        app.persistence_failures_remaining = persistence_failures_remaining;
        (app, finalization_tx)
    }

    fn new_with_finalization_receiver(
        context: E,
        relay: std::sync::Arc<T>,
        me: &PublicKey,
        validators: Vec<PublicKey>,
        partition_prefix: String,
        finalization_rx: mpsc::UnboundedReceiver<FinalizationNotice>,
        page_cache: PageCacheConfig,
    ) -> Self {
        let shard_rx = relay.register(me);
        let my_index = relay.validator_index(me).unwrap_or_else(|| {
            warn!("validator index unavailable for local key; defaulting to index 0");
            0
        });
        let coding_config = coding_config(relay.validator_count());
        let strategy = crate::coding_strategy();
        let core = AppCore::new(me, validators, my_index, coding_config, strategy);
        let (persistence_tx, persistence_cmd_rx) = mpsc::unbounded();
        let (persistence_event_tx, persistence_rx) = mpsc::unbounded();

        Self {
            context: ContextCell::new(context),
            relay,
            shard_rx,
            finalization_rx,
            core,
            partition_prefix,
            page_cache,
            persistence_tx,
            persistence_rx,
            persistence_handle: None,
            pending_external: VecDeque::new(),
            inflight_persistence: None,
            persistence_cmd_rx: Some(persistence_cmd_rx),
            persistence_event_tx: Some(persistence_event_tx),
            #[cfg(test)]
            persistence_failures_remaining: 0,
        }
    }

    fn apply_reply_effect(&mut self, effect: CoreEffect) {
        match effect {
            CoreEffect::Digest { response, digest } => {
                response.send_lossy(digest);
            }
            CoreEffect::Verify { response, valid } => {
                response.send_lossy(valid);
            }
            CoreEffect::Coin { response, coin } => {
                let _ = response.send(coin);
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

    fn start_persistence_worker(&mut self, context: &mut E) {
        if self.persistence_handle.is_some() {
            return;
        }
        let Some(command_rx) = self.persistence_cmd_rx.take() else {
            warn!("persistence command receiver unavailable on startup");
            return;
        };
        let Some(event_tx) = self.persistence_event_tx.take() else {
            warn!("persistence event sender unavailable on startup");
            return;
        };

        let worker = PersistenceWorker::new(
            self.partition_prefix.clone(),
            self.page_cache,
            self.core.validators().to_vec(),
            command_rx,
            event_tx,
            #[cfg(test)]
            self.persistence_failures_remaining,
        );
        let handle = context.clone().spawn(move |mut worker_context| async move {
            worker.run(&mut worker_context).await;
        });
        self.persistence_handle = Some(handle);
    }

    fn dispatch_next_persistence_if_idle(&mut self) {
        if self.inflight_persistence.is_some() {
            return;
        }
        let Some((payload, diffs)) = self.core.next_unpersisted_finalization() else {
            return;
        };
        let command = PersistenceCommand::Enqueue {
            payload,
            diffs: diffs.clone(),
        };
        match self.persistence_tx.unbounded_send(command) {
            Ok(()) => {
                self.inflight_persistence = Some(payload);
            }
            Err(err) => {
                warn!(
                    ?err,
                    ?payload,
                    "failed to enqueue finalized diffs for persistence"
                );
            }
        }
    }

    fn on_persisted(&mut self, payload: Digest) {
        if self.inflight_persistence != Some(payload) {
            warn!(
                ?payload,
                inflight = ?self.inflight_persistence,
                "received persistence ack for unexpected payload"
            );
        }
        if !self.core.mark_finalization_persisted(payload) {
            warn!(
                ?payload,
                "persisted finalization was not present in execution cache"
            );
        }
        if self.inflight_persistence == Some(payload) {
            self.inflight_persistence = None;
        }
        self.dispatch_next_persistence_if_idle();
    }

    async fn state_root_via_worker(&mut self) -> Option<Digest> {
        let (response, receiver) = oneshot::channel();
        if let Err(err) = self
            .persistence_tx
            .unbounded_send(PersistenceCommand::GetStateRoot { response })
        {
            warn!(?err, "failed to request state root from persistence worker");
            return None;
        }
        match receiver.await {
            Ok(root) => root,
            Err(err) => {
                warn!(?err, "persistence worker dropped state root response");
                None
            }
        }
    }

    async fn proof_for_object_via_worker(
        &mut self,
        object: ObjectId,
    ) -> Option<mailbox::ProofResponse> {
        let (response, receiver) = oneshot::channel();
        if let Err(err) = self
            .persistence_tx
            .unbounded_send(PersistenceCommand::GetProof { object, response })
        {
            warn!(?err, "failed to request proof from persistence worker");
            return None;
        }
        match receiver.await {
            Ok(proof) => proof,
            Err(err) => {
                warn!(?err, "persistence worker dropped proof response");
                None
            }
        }
    }

    async fn shutdown_persistence_worker(&mut self) {
        let Some(handle) = self.persistence_handle.take() else {
            return;
        };

        let (response, receiver) = oneshot::channel();
        if let Err(err) = self
            .persistence_tx
            .unbounded_send(PersistenceCommand::Shutdown { response })
        {
            warn!(?err, "failed to signal persistence worker shutdown");
        } else if let Err(err) = receiver.await {
            warn!(?err, "persistence worker dropped shutdown response");
        }

        let _ = handle.await;
    }

    async fn on_mailbox_message(&mut self, context: &mut E, message: AppMailboxReadWriteMessage) {
        match message {
            AppMailboxReadWriteMessage::DrainExternalEvents => {
                while let Some(event) = self.pending_external.pop_front() {
                    match event {
                        ExternalEvent::Shard(message) => {
                            let now = context.current().epoch_millis();
                            let relay = &self.relay;
                            let effects = self.core.on_shard_message(*message, now, &|sender| {
                                relay.validator_index(sender)
                            });
                            self.apply_core_effects(effects).await;
                        }
                        ExternalEvent::Finalization(FinalizationNotice {
                            payload,
                            parent_payload,
                        }) => {
                            let effects = self.core.on_finalized(payload, parent_payload);
                            let pending = self.core.unpersisted_finalization_count();
                            if pending > Self::MAX_PENDING_PERSISTENCE_QUEUE {
                                error!(
                                    pending,
                                    max = Self::MAX_PENDING_PERSISTENCE_QUEUE,
                                    "pending persistence queue exceeded bound; entering fail-stop"
                                );
                                std::process::abort();
                            }
                            self.dispatch_next_persistence_if_idle();
                            self.apply_core_effects(effects).await;
                        }
                        ExternalEvent::Persistence(PersistenceEvent::Persisted { payload }) => {
                            self.on_persisted(payload);
                        }
                    }
                }
            }
            AppMailboxReadWriteMessage::GetStateRoot { response } => {
                let _ = response.send(self.state_root_via_worker().await);
            }
            AppMailboxReadWriteMessage::GetProof { object, response } => {
                let proof = self.proof_for_object_via_worker(object).await;
                let _ = response.send(proof);
            }
            core_message => {
                let now = context.current().epoch_millis();
                let relay = &self.relay;
                let effects = self
                    .core
                    .on_message(core_message, now, &|sender| relay.validator_index(sender));
                self.apply_core_effects(effects).await;
            }
        }
    }

    pub(crate) fn start(mut self) -> (Handle<()>, AppMailbox) {
        let context = self.context.take();
        let mailbox_capacity =
            NonZeroUsize::new(Self::MAILBOX_CAPACITY).expect("mailbox capacity must be non-zero");
        let (mailbox, service) =
            ServiceBuilder::new(self).build_with_capacity(context, mailbox_capacity);
        (service.start(), mailbox)
    }
}

impl<E, T> Actor<E> for Application<E, T>
where
    E: Clock + Spawner + Storage + Metrics,
    T: ShardTransport,
{
    type Mailbox = AppMailbox;
    type Ingress = AppMailboxMessage;
    type Error = Infallible;
    type Snapshot = ();
    type Args = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    async fn on_startup(&mut self, context: &mut E, _args: &mut Self::Args) {
        self.start_persistence_worker(context);
    }

    async fn on_shutdown(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.shutdown_persistence_worker().await;
        debug!("application shutting down");
    }

    async fn on_read_write(
        &mut self,
        context: &mut E,
        _args: &mut Self::Args,
        message: AppMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        self.on_mailbox_message(context, message).await;
        Ok(())
    }

    async fn on_external(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
    ) -> Option<AppMailboxReadWriteMessage> {
        select! {
            shard = self.shard_rx.next() => {
                match shard {
                    Some(message) => {
                        self.pending_external
                            .push_back(ExternalEvent::Shard(Box::new(message)));
                        Some(AppMailboxReadWriteMessage::DrainExternalEvents)
                    }
                    None => {
                        warn!("shard relay closed");
                        None
                    }
                }
            },
            finalized = self.finalization_rx.next() => {
                match finalized {
                    Some(finalization) => {
                        self.pending_external
                            .push_back(ExternalEvent::Finalization(finalization));
                        Some(AppMailboxReadWriteMessage::DrainExternalEvents)
                    }
                    None => {
                        warn!("finalization channel closed");
                        None
                    }
                }
            },
            persistence = self.persistence_rx.next() => {
                match persistence {
                    Some(event) => {
                        self.pending_external
                            .push_back(ExternalEvent::Persistence(event));
                        Some(AppMailboxReadWriteMessage::DrainExternalEvents)
                    }
                    None => {
                        warn!("persistence worker event channel closed");
                        None
                    }
                }
            },
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
    use hellas_types::{Context, PrivateKey, PublicKey};
    use proptest::prelude::*;
    use std::{sync::Arc, time::Duration};
    use tokio::sync::oneshot::error::TryRecvError;

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

    fn build_payload_case(
        epoch: u16,
        view: u16,
        parent: [u8; 32],
        timestamp: u64,
    ) -> (Round, Digest, Bytes, Digest) {
        let round = make_round(epoch, view);
        let parent = Digest::from(parent);
        let contents = encode_payload(round, parent, timestamp);
        let payload = payload_digest(&contents);
        (round, parent, contents, payload)
    }

    fn parent_payload_contents(epoch: u16, view: u16, timestamp: u64) -> Bytes {
        let parent_round = make_round(epoch, view.wrapping_sub(1));
        encode_payload(parent_round, Digest::from([0u8; 32]), timestamp)
    }

    fn start_single_validator_app(
        context: &deterministic::Context,
        label: &str,
        key: &PublicKey,
        partition: &str,
        persistence_failures: Option<usize>,
    ) -> (
        Handle<()>,
        AppMailbox,
        mpsc::UnboundedSender<FinalizationNotice>,
    ) {
        let relay = Arc::new(MockShardTransport::new());
        relay.declare(key);
        relay.finalize_validators();

        let (app, finalization_tx) = match persistence_failures {
            Some(failures) => Application::new_with_persistence_failures(
                context.with_label(label),
                relay,
                key,
                vec![key.clone()],
                partition.to_string(),
                failures,
            ),
            None => Application::new(
                context.with_label(label),
                relay,
                key,
                vec![key.clone()],
                partition.to_string(),
            ),
        };
        let (handle, mailbox) = app.start();
        (handle, mailbox, finalization_tx)
    }

    fn start_validator_cluster(
        context: &deterministic::Context,
        participants: &[PublicKey],
        label_prefix: &str,
        partition_prefix: &str,
    ) -> (
        Vec<Handle<()>>,
        Vec<AppMailbox>,
        Vec<mpsc::UnboundedSender<FinalizationNotice>>,
    ) {
        let relay = Arc::new(MockShardTransport::new());
        for participant in participants {
            relay.declare(participant);
        }
        relay.finalize_validators();

        let mut handles = Vec::with_capacity(participants.len());
        let mut mailboxes = Vec::with_capacity(participants.len());
        let mut finalization_txs = Vec::with_capacity(participants.len());

        for (idx, participant) in participants.iter().enumerate() {
            let (app, finalization_tx) = Application::new(
                context.with_label(&format!("{label_prefix}_{idx}")),
                relay.clone(),
                participant,
                participants.to_vec(),
                format!("{partition_prefix}_{idx}"),
            );
            let (handle, mailbox) = app.start();
            handles.push(handle);
            mailboxes.push(mailbox);
            finalization_txs.push(finalization_tx);
        }

        (handles, mailboxes, finalization_txs)
    }

    async fn initialize_cluster_genesis(mailboxes: &mut [AppMailbox], epoch: Epoch) -> Digest {
        let mut genesis = None;
        for mailbox in mailboxes {
            let digest = mailbox.genesis(epoch).await;
            if let Some(existing) = genesis {
                assert_eq!(existing, digest);
            } else {
                genesis = Some(digest);
            }
        }
        genesis.expect("genesis should be set")
    }

    async fn fetch_root(mailbox: &AppMailbox) -> Digest {
        mailbox
            .get_state_root()
            .await
            .expect("state root request should not fail")
            .expect("state root should be set")
    }

    async fn fetch_root_and_proof(
        mailbox: &AppMailbox,
        object: ObjectId,
    ) -> (Digest, mailbox::ProofResponse) {
        let root = fetch_root(mailbox).await;
        let proof = mailbox
            .get_proof(object)
            .await
            .expect("proof request should not fail")
            .expect("proof should exist");
        (root, proof)
    }

    fn assert_coin_proof(
        object: ObjectId,
        expected_coin: Coin,
        proof: &mailbox::ProofResponse,
        root: Digest,
    ) {
        let mut hasher = Sha256::default();
        assert!(
            UtxoDb::<ContextCell<deterministic::Context>>::verify_key_value_proof(
                &mut hasher,
                object,
                expected_coin,
                proof,
                &root,
            )
        );
    }

    struct FinalizedTransfer {
        root_before: Digest,
        recipient_output: ObjectId,
    }

    async fn submit_transfer_and_finalize(
        mailbox: &mut AppMailbox,
        finalization_tx: &mpsc::UnboundedSender<FinalizationNotice>,
        sender: &PrivateKey,
        recipient_pk: &PublicKey,
    ) -> FinalizedTransfer {
        let epoch = Epoch::new(1);
        let genesis = mailbox.genesis(epoch).await;
        let root_before = fetch_root(mailbox).await;

        let tx = Transaction::transfer(sender, genesis_object_id(0), recipient_pk.clone(), 1);
        let tx_digest = Sha256::hash(&tx.encode());
        let recipient_output = output_object_id(&tx_digest, 0);
        mailbox.submit_tx(tx).await;

        let sender_pk = sender.public_key();
        let proposal_context = Context {
            round: Round::new(epoch, View::new(1)),
            leader: sender_pk,
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

        FinalizedTransfer {
            root_before,
            recipient_output,
        }
    }

    proptest! {
        #[test]
        fn payload_with_valid_encoding_and_non_future_timestamp_is_accepted(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
            age in 0u64..=1_000_000u64,
        ) {
            let (round, parent, contents, payload) = build_payload_case(epoch, view, parent, timestamp);
            let parent_contents = default_parent_contents();
            let now = timestamp.saturating_add(age);

            prop_assert!(matches!(
                validate_payload(round, parent, payload, &contents, now, &parent_contents),
                Ok(txs) if txs.is_empty()
            ));
        }

        #[test]
        fn payload_validation_rejects_digest_round_parent_and_future_errors(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
            index in any::<usize>(),
            future_delta in (SYNCHRONY_BOUND + 1)..=(SYNCHRONY_BOUND + 10_000),
        ) {
            let (round, parent, contents, payload) = build_payload_case(epoch, view, parent, timestamp);
            let parent_contents = default_parent_contents();
            let now = timestamp.saturating_add(SYNCHRONY_BOUND);

            let mutated = Bytes::from(mutate_byte(contents.to_vec(), index));
            assert!(matches!(
                validate_payload(round, parent, payload, &mutated, now, &parent_contents),
                Err(PayloadValidationError::DigestMismatch { .. })
            ));

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

            let future_timestamp = timestamp.saturating_add(future_delta);
            let future_contents = encode_payload(round, parent, future_timestamp);
            let future_payload = payload_digest(&future_contents);
            assert!(matches!(
                validate_payload(
                    round,
                    parent,
                    future_payload,
                    &future_contents,
                    timestamp,
                    &parent_contents,
                ),
                Err(PayloadValidationError::FutureTimestamp { .. })
            ));
        }

        #[test]
        fn payload_timestamp_must_be_monotonic_with_parent(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent_digest in any::<[u8; 32]>(),
            parent_ts in 1u64..=(MAX_TIMESTAMP / 2),
            regression in 1u64..=1_000u64,
            advance in 0u64..=1_000u64,
        ) {
            prop_assume!(regression <= parent_ts);

            let round = make_round(epoch, view);
            let parent_digest = Digest::from(parent_digest);
            let parent_contents = parent_payload_contents(epoch, view, parent_ts);

            let regressed_ts = parent_ts - regression;
            let regressed_contents = encode_payload(round, parent_digest, regressed_ts);
            let regressed_payload = payload_digest(&regressed_contents);
            assert!(matches!(
                validate_payload(
                    round,
                    parent_digest,
                    regressed_payload,
                    &regressed_contents,
                    parent_ts.saturating_add(SYNCHRONY_BOUND),
                    &parent_contents,
                ),
                Err(PayloadValidationError::TimestampRegression { .. })
            ));

            let child_ts = parent_ts.saturating_add(advance);
            let contents = encode_payload(round, parent_digest, child_ts);
            let payload = payload_digest(&contents);
            prop_assert!(matches!(
                validate_payload(
                    round,
                    parent_digest,
                    payload,
                    &contents,
                    child_ts.saturating_add(SYNCHRONY_BOUND),
                    &parent_contents,
                ),
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

            let (_handles, mut mailboxes, _finalization_txs) =
                start_validator_cluster(&context, &participants, "app", "test_app");
            let epoch = Epoch::new(1);
            let genesis = initialize_cluster_genesis(&mut mailboxes, epoch).await;

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
                Ok(v) => panic!("verify should not resolve yet, got {:?}", v),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Closed) => panic!("verify receiver canceled unexpectedly"),
            }

            let verify_rx_2 = mailboxes[2].verify(proposal_context, digest).await;
            assert!(verify_rx_2.await.expect("verify 2 should resolve"));
            assert!(verify_rx_1.await.expect("verify 1 should resolve"));
        });
    }

    #[test]
    fn empty_qmdb_bootstraps_genesis_state() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let key = PrivateKey::from_seed(42).public_key();
            let (_handle, mut mailbox, _finalization_tx) = start_single_validator_app(
                &context,
                "bootstrap_app",
                &key,
                "bootstrap_test_partition",
                None,
            );
            let _ = mailbox.genesis(Epoch::new(1)).await;

            let genesis_object = genesis_object_id(0);
            let (root, proof) = fetch_root_and_proof(&mailbox, genesis_object).await;
            assert_coin_proof(
                genesis_object,
                Coin {
                    owner: key,
                    value: GENESIS_BALANCE,
                },
                &proof,
                root,
            );
        });
    }

    #[test]
    fn qmdb_root_and_proof_survive_app_restart() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let key = PrivateKey::from_seed(77).public_key();
            let partition = "restart_test_partition";

            let (app_a_handle, mut mailbox_a, _finalization_tx_a) =
                start_single_validator_app(&context, "restart_app_a", &key, partition, None);
            let _ = mailbox_a.genesis(Epoch::new(1)).await;

            let genesis_object = genesis_object_id(0);
            let (root_a, proof_a) = fetch_root_and_proof(&mailbox_a, genesis_object).await;
            let expected_coin = Coin {
                owner: key.clone(),
                value: GENESIS_BALANCE,
            };
            assert_coin_proof(genesis_object, expected_coin.clone(), &proof_a, root_a);

            app_a_handle.abort();
            let _ = app_a_handle.await;

            let (_app_b_handle, mailbox_b, _finalization_tx_b) =
                start_single_validator_app(&context, "restart_app_b", &key, partition, None);
            let (root_b, proof_b) = fetch_root_and_proof(&mailbox_b, genesis_object).await;
            assert_eq!(root_a, root_b);
            assert_coin_proof(genesis_object, expected_coin, &proof_b, root_b);
        });
    }

    #[test]
    fn persistence_retry_worker_applies_finalized_diffs_without_new_finalizations() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let sender = PrivateKey::from_seed(88);
            let sender_pk = sender.public_key();
            let recipient_pk = PrivateKey::from_seed(89).public_key();
            let (_app_handle, mut mailbox, finalization_tx) = start_single_validator_app(
                &context,
                "retry_worker_app",
                &sender_pk,
                "retry_worker_partition",
                Some(2),
            );
            let finalized = submit_transfer_and_finalize(
                &mut mailbox,
                &finalization_tx,
                &sender,
                &recipient_pk,
            )
            .await;

            // Retries are timer-driven (50ms base with exponential backoff). No additional
            // finalization events are sent here.
            context.sleep(Duration::from_secs(1)).await;

            let (root_after, proof) =
                fetch_root_and_proof(&mailbox, finalized.recipient_output).await;
            assert_ne!(finalized.root_before, root_after);
            assert_coin_proof(
                finalized.recipient_output,
                Coin {
                    owner: recipient_pk,
                    value: 1,
                },
                &proof,
                root_after,
            );
        });
    }

    #[test]
    fn durable_queue_replays_unapplied_finalization_after_restart() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let sender = PrivateKey::from_seed(188);
            let sender_pk = sender.public_key();
            let recipient_pk = PrivateKey::from_seed(189).public_key();
            let partition = "durable_queue_restart_partition";

            let (app_a_handle, mut mailbox_a, finalization_tx_a) = start_single_validator_app(
                &context,
                "durable_queue_app_a",
                &sender_pk,
                partition,
                Some(100),
            );
            let finalized = submit_transfer_and_finalize(
                &mut mailbox_a,
                &finalization_tx_a,
                &sender,
                &recipient_pk,
            )
            .await;

            context.sleep(Duration::from_millis(100)).await;
            let root_during_failures = fetch_root(&mailbox_a).await;
            assert_eq!(finalized.root_before, root_during_failures);

            app_a_handle.abort();
            let _ = app_a_handle.await;

            let (_app_b_handle, mailbox_b, _finalization_tx_b) = start_single_validator_app(
                &context,
                "durable_queue_app_b",
                &sender_pk,
                partition,
                None,
            );

            // No new finalization events are sent after restart. Recovery should come
            // from the durable queue entry left by the first process.
            context.sleep(Duration::from_secs(1)).await;

            let (root_after, proof) =
                fetch_root_and_proof(&mailbox_b, finalized.recipient_output).await;
            assert_ne!(finalized.root_before, root_after);
            assert_coin_proof(
                finalized.recipient_output,
                Coin {
                    owner: recipient_pk,
                    value: 1,
                },
                &proof,
                root_after,
            );
        });
    }
}
