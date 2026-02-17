mod core;
mod mailbox;
mod metrics;
mod payload;
mod persistence;

pub use mailbox::{AppMailbox, FinalizationResponse, ProofResponse};

use hellas_types::ObjectId;
use crate::shard::WireShardMessage;
use crate::shard::protocol::{ShardMessage, coding_config};
use crate::shard::transport::ShardTransport;
use crate::trace::Traced;
use bytes::Bytes;
use commonware_actor::{Actor, service::ServiceBuilder};
use commonware_consensus::Reporter;
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_utils::{
    SystemTimeExt,
    channel::{fallible::OneshotExt, oneshot},
};
use core::{AppCore, CoreEffect, CoreEffects, NetworkEffect};
use futures::{StreamExt, channel::mpsc};
use hellas_types::{Activity, PublicKey};
use mailbox::{AppMailboxMessage, AppMailboxReadWriteMessage};
use metrics::{ApplicationMetrics, CoreMetrics, PersistenceMetrics};
use persistence::{PageCacheConfig, PersistenceCommand, PersistenceEvent, PersistenceWorker};
use std::{convert::Infallible, num::NonZeroUsize, time::Duration};

#[derive(Clone)]
pub(crate) struct FinalizationNotice {
    pub payload: Digest,
    pub parent_payload: Digest,
    pub certificate_bytes: mailbox::FinalizationResponse,
}

// ---------------------------------------------------------------------------
// ApplicationConfig — tunable parameters for the Application actor
// ---------------------------------------------------------------------------

pub(crate) struct ApplicationConfig {
    pub page_cache_size: u16,
    pub page_cache_count: usize,
    pub verify_wait_timeout: Duration,
    pub min_propose_delay: Duration,
}

impl Default for ApplicationConfig {
    fn default() -> Self {
        Self {
            page_cache_size: crate::execution::store::DEFAULT_PAGE_CACHE_SIZE.get(),
            page_cache_count: crate::execution::store::DEFAULT_PAGE_CACHE_COUNT.get(),
            verify_wait_timeout: Duration::from_millis(500),
            min_propose_delay: Duration::ZERO,
        }
    }
}

// ---------------------------------------------------------------------------
// TraceReporter — logs consensus activity
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TraceReporter;

impl Reporter for TraceReporter {
    type Activity = Activity;

    async fn report(&mut self, activity: Self::Activity) {
        debug!(activity = ?activity);
    }
}

// ---------------------------------------------------------------------------
// PersistenceHandle — owns the persistence worker and its channels
// ---------------------------------------------------------------------------

struct PersistenceHandle {
    tx: mpsc::UnboundedSender<Traced<PersistenceCommand>>,
    rx: mpsc::UnboundedReceiver<Traced<PersistenceEvent>>,
    handle: Option<Handle<()>>,
}

impl PersistenceHandle {
    fn spawn<E>(
        context: E,
        partition_prefix: String,
        page_cache_config: PageCacheConfig,
        validators: Vec<PublicKey>,
        metrics: PersistenceMetrics,
    ) -> Self
    where
        E: Clock + Spawner + Storage + Metrics + BufferPooler,
    {
        let (tx, cmd_rx) = mpsc::unbounded();
        let (event_tx, rx) = mpsc::unbounded();
        let handle = context.clone().spawn(move |mut wc| async move {
            let worker = match PersistenceWorker::create(
                &mut wc,
                partition_prefix,
                page_cache_config,
                validators,
                cmd_rx,
                event_tx,
                metrics,
            )
            .await
            {
                Ok(worker) => worker,
                Err(err) => {
                    error!(%err, "persistence worker initialization failed; aborting");
                    std::process::abort();
                }
            };
            worker.run(&mut wc).await;
        });
        Self {
            tx,
            rx,
            handle: Some(handle),
        }
    }

    async fn wait_for_ready(&mut self) -> (Digest, Vec<(Digest, Bytes)>) {
        match self.rx.next().await {
            Some(event) => {
                let (event, _parent_span) = event.into_parts();
                let PersistenceEvent::Ready {
                    root,
                    recovered_payloads,
                } = event
                else {
                    unreachable!("first persistence event must be Ready");
                };
                (root, recovered_payloads)
            }
            None => {
                error!("persistence worker event channel closed before ready");
                std::process::abort();
            }
        }
    }

    fn send(&self, command: PersistenceCommand) {
        if self.tx.unbounded_send(Traced::capture(command)).is_err() {
            error!("persistence worker channel closed; aborting");
            std::process::abort();
        }
    }

    fn enqueue(&self, payload: Digest, diffs: crate::execution::FinalizationDiffs) {
        self.send(PersistenceCommand::Enqueue { payload, diffs });
    }

    async fn query<R, F>(&mut self, build: F) -> R
    where
        F: FnOnce(oneshot::Sender<R>) -> PersistenceCommand,
    {
        let (response, receiver) = oneshot::channel();
        self.send(build(response));
        match receiver.await {
            Ok(value) => value,
            Err(_) => {
                error!("persistence worker dropped response; aborting");
                std::process::abort();
            }
        }
    }

    async fn state_root(&mut self) -> Option<Digest> {
        self.query(|response| PersistenceCommand::GetStateRoot { response })
            .await
    }

    async fn persisted_anchors(&mut self) -> Vec<(Digest, Digest)> {
        self.query(|response| PersistenceCommand::GetPersistedAnchors { response })
            .await
    }

    async fn proof_for_object(
        &mut self,
        object: ObjectId,
    ) -> Option<mailbox::ProofResponse> {
        self.query(move |response| PersistenceCommand::GetProof { object, response })
            .await
    }

    async fn finalization(
        &mut self,
        payload: Digest,
    ) -> Option<mailbox::FinalizationResponse> {
        self.query(move |response| PersistenceCommand::GetFinalization { payload, response })
            .await
    }

    async fn latest_block(&mut self) -> Option<(u64, Digest, Digest)> {
        self.query(|response| PersistenceCommand::GetLatestBlock { response })
            .await
    }

    async fn payload(&mut self, payload: Digest) -> Option<Bytes> {
        self.query(move |response| PersistenceCommand::GetPayload { payload, response })
            .await
    }

    fn record_persisted_root(&self, payload: Digest, root: Digest) {
        self.send(PersistenceCommand::RecordPersistedRoot { payload, root });
    }

    fn record_finalization(
        &self,
        payload: Digest,
        finalization: mailbox::FinalizationResponse,
    ) {
        self.send(PersistenceCommand::RecordFinalization {
            payload,
            finalization,
        });
    }

    fn record_payload(&self, payload: Digest, bytes: Bytes) {
        self.send(PersistenceCommand::RecordPayload { payload, bytes });
    }

    fn take_event_rx(&mut self) -> mpsc::UnboundedReceiver<Traced<PersistenceEvent>> {
        std::mem::replace(&mut self.rx, mpsc::unbounded().1)
    }

    async fn shutdown(&mut self) {
        let (response, receiver) = oneshot::channel();
        if let Err(err) = self
            .tx
            .unbounded_send(Traced::capture(PersistenceCommand::Shutdown { response }))
        {
            warn!(?err, "failed to signal persistence worker shutdown");
        } else if let Err(err) = receiver.await {
            warn!(?err, "persistence worker dropped shutdown response");
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
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

    /// Taken in `on_startup` to spawn the shard bridge task.
    shard_rx: Option<mpsc::UnboundedReceiver<Traced<ShardMessage>>>,

    core: AppCore,

    persistence: PersistenceHandle,

    /// Handle to the shard bridge task.
    shard_bridge_handle: Option<Handle<()>>,

    /// Handle to the persistence bridge task.
    persistence_bridge_handle: Option<Handle<()>>,

    /// Payload currently enqueued for persistence and awaiting acknowledgment.
    inflight_persistence: Option<Digest>,

    /// Genesis QMDB root captured from the persistence worker's `Ready` event
    /// during startup. Consumed by `seed_genesis_anchor_root` to avoid a
    /// redundant round-trip to the worker.
    startup_root: Digest,

    /// Optional delay applied before emitting a proposal (development throttle).
    min_propose_delay: Duration,

    app_metrics: ApplicationMetrics,
}

impl<E, T> Application<E, T>
where
    E: Clock + Spawner + Storage + Metrics + BufferPooler,
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
        config: ApplicationConfig,
    ) -> Self {
        let page_cache_config = PageCacheConfig {
            size: config.page_cache_size,
            count: config.page_cache_count,
        };
        Self::new_inner(
            context,
            relay,
            me,
            validators,
            partition_prefix,
            page_cache_config,
            config.verify_wait_timeout,
            config.min_propose_delay,
        )
    }

    fn new_inner(
        context: E,
        relay: std::sync::Arc<T>,
        me: &PublicKey,
        validators: Vec<PublicKey>,
        partition_prefix: String,
        page_cache_config: PageCacheConfig,
        verify_wait_timeout: Duration,
        min_propose_delay: Duration,
    ) -> Self {
        let shard_rx = relay.register(me);
        let my_index = relay.validator_index(me).unwrap_or_else(|| {
            warn!("validator index unavailable for local key; defaulting to index 0");
            0
        });
        let coding_config = coding_config(relay.validator_count());
        let strategy = crate::coding_strategy();
        let app_metrics = ApplicationMetrics::register(&context.with_label("app_actor"));
        let core_metrics = CoreMetrics::register(&context.with_label("app_core"));
        let persistence_metrics =
            PersistenceMetrics::register(&context.with_label("app_persistence"));
        let core = AppCore::new(
            me,
            validators.clone(),
            my_index,
            coding_config,
            verify_wait_timeout
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            strategy,
            core_metrics,
            &context,
        );
        let persistence = PersistenceHandle::spawn(
            context.clone(),
            partition_prefix,
            page_cache_config,
            validators,
            persistence_metrics,
        );

        Self {
            context: ContextCell::new(context),
            relay,
            shard_rx: Some(shard_rx),
            core,
            persistence,
            shard_bridge_handle: None,
            persistence_bridge_handle: None,
            inflight_persistence: None,
            startup_root: Digest::from([0u8; 32]),
            min_propose_delay,
            app_metrics,
        }
    }

    fn apply_reply_effect(effect: CoreEffect) {
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
                if let Some(key) = message.key() {
                    debug!(
                        payload = ?key.digest,
                        round = ?key.round,
                        "broadcasting shard message"
                    );
                } else {
                    debug!("broadcasting payload repair message");
                }
                self.relay.broadcast_except(self.core.me(), *message).await;
            }
            NetworkEffect::SendShard { recipient, message } => {
                if let Some(key) = message.key() {
                    debug!(
                        payload = ?key.digest,
                        round = ?key.round,
                        recipient = ?recipient,
                        "sending shard message"
                    );
                } else {
                    debug!(recipient = ?recipient, "sending payload repair message");
                }
                self.relay.send_to(&recipient, *message).await;
            }
            NetworkEffect::DistributeShards {
                key,
                commitment,
                shards,
            } => {
                let shard_count = shards.len();
                debug!(
                    payload = ?key.digest,
                    round = ?key.round,
                    shard_count,
                    "distributing proposal shards"
                );
                self.relay
                    .distribute_shards(self.core.me(), key, commitment, shards)
                    .await;
            }
        }
    }

    async fn apply_core_effects(&mut self, mut effects: CoreEffects, now: u64) {
        let mut local_resolved_total = 0u64;
        loop {
            for effect in effects.replies {
                Self::apply_reply_effect(effect);
            }

            let mut resolved_any = false;
            let mut resolve_effects = core::CoreEffects::new();
            for effect in effects.network {
                // Fallback: before broadcasting a FetchPayload to the network,
                // check local persistence (Freezer).  Most payloads are hydrated
                // proactively at startup via `recover_payload_chain`, but payloads
                // finalized after the latest anchor (not yet QMDB-committed) may
                // still need this path.
                if let NetworkEffect::BroadcastShard(ref message) = effect
                    && let WireShardMessage::FetchPayload { digest } = &message.body
                {
                    if let Some(payload) = self.persistence.payload(*digest).await {
                        self.core
                            .resolve_payload_locally(*digest, payload, now, &mut resolve_effects);
                        resolved_any = true;
                        local_resolved_total += 1;
                        continue;
                    }
                }
                self.apply_network_effect(effect).await;
            }

            // Dispatch any reply effects produced by waiter retries during
            // local resolution (e.g. verify responses for deferred verifications).
            for effect in resolve_effects.replies {
                Self::apply_reply_effect(effect);
            }
            for effect in resolve_effects.network {
                self.apply_network_effect(effect).await;
            }

            if !resolved_any {
                break;
            }

            if local_resolved_total % 1000 == 0 {
                info!(
                    local_resolved_total,
                    "resolving payload dependencies from local persistence"
                );
            }

            // Re-run maintenance so the core discovers the next missing ancestor
            // and emits further FetchPayload effects that we can again try to
            // resolve locally.  This chains through the entire ancestor history
            // without returning to the event loop.
            effects = core::CoreEffects::new();
            self.core.run_maintenance(now, &mut effects);
        }
        if local_resolved_total > 0 {
            info!(
                local_resolved_total,
                "completed local persistence resolution for payload dependencies"
            );
        }
    }

    fn dispatch_next_persistence_if_idle(&mut self) {
        if self.inflight_persistence.is_some() {
            return;
        }
        let Some((payload, diffs)) = self.core.next_unpersisted_finalization() else {
            return;
        };
        self.persistence.enqueue(payload, diffs.clone());
        self.inflight_persistence = Some(payload);
        self.app_metrics.persistence_dispatch_total.inc();
        self.app_metrics.inflight_persistence.set(1);
    }

    fn on_persisted(&mut self, payload: Digest, root: Digest, now: u64) -> CoreEffects {
        let _span = info_span!(
            "app.persistence_ack",
            payload = ?payload,
            root = ?root,
            inflight = ?self.inflight_persistence,
            now_ms = now
        )
        .entered();
        self.app_metrics.persistence_ack_total.inc();
        if self.inflight_persistence != Some(payload) {
            self.app_metrics.persistence_ack_unexpected_total.inc();
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
            self.app_metrics.inflight_persistence.set(0);
        }
        let effects = self.core.on_persisted_root(payload, root, now);
        self.dispatch_next_persistence_if_idle();
        effects
    }

    fn drain_persistable_payloads_to_worker(&mut self) {
        for (payload, bytes) in self.core.drain_persistable_payloads() {
            self.persistence.record_payload(payload, bytes);
        }
    }

    async fn hydrate_anchor_index_from_worker(&mut self) {
        for (payload, root) in self.persistence.persisted_anchors().await {
            self.core.note_persisted_root(payload, root);
        }
    }

    fn seed_genesis_anchor_root(&mut self, digest: Digest) {
        if self.core.has_persisted_roots() {
            return;
        }
        let root = self.startup_root;
        self.core.note_persisted_root(digest, root);
        self.persistence.record_persisted_root(digest, root);
        self.app_metrics.genesis_anchor_seeded_total.inc();
    }

    async fn on_mailbox_message(&mut self, context: &mut E, message: AppMailboxReadWriteMessage) {
        debug!(kind = message.kind(), "processing mailbox message");
        match message {
            AppMailboxReadWriteMessage::ShardEvent { message } => {
                self.app_metrics.external_events_total.inc();
                self.app_metrics.shard_messages_received_total.inc();
                let now = context.current().epoch_millis();
                if let WireShardMessage::FetchPayload { digest } = &message.body
                    && self.core.payload_bytes(digest).is_none()
                {
                    if let Some(payload) = self.persistence.payload(*digest).await {
                        let sender = message.sender().clone();
                        self.relay
                            .send_to(
                                &sender,
                                ShardMessage::payload_response(
                                    self.core.me(),
                                    *digest,
                                    payload,
                                ),
                            )
                            .await;
                    }
                    self.drain_persistable_payloads_to_worker();
                    return;
                }
                if let Some(key) = message.key() {
                    debug!(
                        payload = ?key.digest,
                        round = ?key.round,
                        sender = ?message.sender(),
                        "received shard message"
                    );
                } else {
                    debug!(
                        sender = ?message.sender(),
                        "received payload repair message"
                    );
                }
                let relay = &self.relay;
                let effects =
                    self.core
                        .on_shard_message(message, now, &|sender| relay.validator_index(sender));
                self.apply_core_effects(effects, now).await;
            }
            AppMailboxReadWriteMessage::FinalizationEvent { notice } => {
                self.app_metrics.external_events_total.inc();
                self.app_metrics.finalization_notices_total.inc();
                let now = context.current().epoch_millis();
                let FinalizationNotice {
                    payload,
                    parent_payload,
                    certificate_bytes,
                } = notice;
                let effects = {
                    let _span = info_span!(
                        "app.finalization_notice",
                        payload = ?payload,
                        parent_payload = ?parent_payload,
                    )
                    .entered();
                    self.core.on_finalized(payload, parent_payload, now)
                };
                self.persistence.record_finalization(payload, certificate_bytes);
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
                self.apply_core_effects(effects, now).await;
            }
            AppMailboxReadWriteMessage::Persisted { payload, root } => {
                self.app_metrics.external_events_total.inc();
                let now = context.current().epoch_millis();
                let effects = self.on_persisted(payload, root, now);
                self.apply_core_effects(effects, now).await;
            }
            AppMailboxReadWriteMessage::Genesis { epoch, response } => {
                let digest = self.core.genesis(epoch);
                self.seed_genesis_anchor_root(digest);
                response.send_lossy(digest);
            }
            AppMailboxReadWriteMessage::GetStateRoot { response } => {
                let _ = response.send(self.persistence.state_root().await);
            }
            AppMailboxReadWriteMessage::GetProof { object, response } => {
                let _ = response.send(self.persistence.proof_for_object(object).await);
            }
            AppMailboxReadWriteMessage::GetFinalization { payload, response } => {
                let _ = response.send(self.persistence.finalization(payload).await);
            }
            AppMailboxReadWriteMessage::GetLatestBlock { response } => {
                let block = self.persistence.latest_block().await.map(
                    |(height, payload, state_root)| {
                        hellas_types::rpc::LatestBlock {
                            height,
                            payload,
                            state_root,
                        }
                    },
                );
                let _ = response.send(block);
            }
            message @ AppMailboxReadWriteMessage::Propose { .. } if !self.min_propose_delay.is_zero() => {
                self.app_metrics.propose_throttled_total.inc();
                context.sleep(self.min_propose_delay).await;
                let now = context.current().epoch_millis();
                let relay = &self.relay;
                let effects = self
                    .core
                    .on_message(message, now, &|sender| relay.validator_index(sender));
                self.apply_core_effects(effects, now).await;
            }
            core_message => {
                let now = context.current().epoch_millis();
                let relay = &self.relay;
                let effects = self
                    .core
                    .on_message(core_message, now, &|sender| relay.validator_index(sender));
                self.apply_core_effects(effects, now).await;
            }
        }
        self.drain_persistable_payloads_to_worker();

        // Run maintenance after every mailbox message (replaces the old periodic
        // ticker).  Called here rather than inside core.on_message so it gets its
        // own stack frame and doesn't compound with the primary handler's stack.
        let now = context.current().epoch_millis();
        let mut maintenance_effects = core::CoreEffects::new();
        self.core.run_maintenance(now, &mut maintenance_effects);
        self.apply_core_effects(maintenance_effects, now).await;
    }

    pub(crate) fn start(mut self) -> (Handle<()>, AppMailbox) {
        let context = self.context.take();
        let mailbox_capacity =
            NonZeroUsize::new(Self::MAILBOX_CAPACITY).expect("mailbox capacity must be non-zero");
        let (mailbox, service) =
            ServiceBuilder::new(self).build_with_capacity(context, mailbox_capacity);
        (service.start_with(mailbox.clone()), mailbox)
    }
}

impl<E, T> Actor<E> for Application<E, T>
where
    E: Clock + Spawner + Storage + Metrics + BufferPooler,
    T: ShardTransport,
{
    type Mailbox = AppMailbox;
    type Ingress = AppMailboxMessage;
    type Error = Infallible;
    type Snapshot = ();
    type Args = AppMailbox;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    async fn on_startup(&mut self, context: &mut E, args: &mut AppMailbox) {
        // Wait for persistence ready (reads from the event channel before bridge takes over).
        let (root, recovered_payloads) = self.persistence.wait_for_ready().await;
        self.startup_root = root;
        self.hydrate_anchor_index_from_worker().await;

        // Hydrate seen from recovered payloads (proactive startup resolution).
        // The PersistenceWorker walks backward from the latest anchor through the
        // Freezer and bundles all payload bytes into the Ready event.  This avoids
        // per-ancestor network round trips after an unclean restart.
        if !recovered_payloads.is_empty() {
            info!(
                count = recovered_payloads.len(),
                "hydrating seen from recovered payloads"
            );
            for (digest, bytes) in recovered_payloads {
                self.core.note_payload_seen(digest, bytes, 0);
            }
        }

        // Spawn persistence bridge: persistence.rx → mailbox.
        let persistence_rx = self.persistence.take_event_rx();
        let mailbox = args.clone();
        self.persistence_bridge_handle = Some(context.clone().spawn(move |_| async move {
            let mut rx = persistence_rx;
            while let Some(traced) = rx.next().await {
                let (event, _span) = traced.into_parts();
                match event {
                    PersistenceEvent::Persisted { payload, root } => {
                        if !mailbox.tell_persisted(payload, root).await {
                            break;
                        }
                    }
                    PersistenceEvent::Ready { .. } => {}
                }
            }
        }));

        // Spawn shard bridge: shard_rx → mailbox.
        if let Some(shard_rx) = self.shard_rx.take() {
            let mailbox = args.clone();
            self.shard_bridge_handle = Some(context.clone().spawn(move |_| async move {
                let mut rx = shard_rx;
                while let Some(traced) = rx.next().await {
                    let (msg, _span) = traced.into_parts();
                    if !mailbox.tell_shard_event(msg).await {
                        break;
                    }
                }
            }));
        }

    }

    async fn on_shutdown(&mut self, _context: &mut E, _args: &mut AppMailbox) {
        self.core.shutdown_shard_recoverer();
        self.shard_bridge_handle.take();
        self.persistence_bridge_handle.take();
        self.persistence.shutdown().await;
        debug!("application shutting down");
    }

    async fn on_read_write(
        &mut self,
        context: &mut E,
        _args: &mut AppMailbox,
        message: AppMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        self.on_mailbox_message(context, message).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::payload::{
        PayloadValidationError, SYNCHRONY_BOUND, SeenBlock, encode_payload, genesis_payload,
        payload_digest,
    };
    use super::*;
    use crate::execution::store::UtxoDb;
    use hellas_types::{Address, Coin, GENESIS_BALANCE, Transaction, genesis_object_id};
    use crate::shard::mock::MockShardTransport;
    use bytes::Bytes;
    use commonware_consensus::minimmit::scheme::ed25519 as minimmit_ed25519;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_consensus::{Automaton, Relay};
    use commonware_cryptography::certificate::mocks::Fixture;
    use commonware_cryptography::{Sha256, Signer};
    use commonware_runtime::{Clock, ContextCell, Metrics, Runner, deterministic};
    use hellas_types::{Context, PrivateKey, PublicKey};
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

    fn build_payload_case(
        epoch: u16,
        view: u16,
        parent: [u8; 32],
        timestamp: u64,
        anchor_payload: [u8; 32],
        anchor_root: [u8; 32],
    ) -> (Round, Digest, Bytes, Digest) {
        let round = make_round(epoch, view);
        let parent = Digest::from(parent);
        let anchor_payload = Digest::from(anchor_payload);
        let anchor_root = Digest::from(anchor_root);
        let contents = encode_payload(round, parent, timestamp, anchor_payload, anchor_root, &[]);
        let payload = payload_digest(&contents);
        (round, parent, contents, payload)
    }

    fn start_single_validator_app(
        context: &deterministic::Context,
        label: &str,
        key: &PublicKey,
        partition: &str,
    ) -> (Handle<()>, AppMailbox) {
        let relay = Arc::new(MockShardTransport::new());
        relay.declare(key);
        relay.finalize_validators();

        let app = Application::new(
            context.with_label(label),
            relay,
            key,
            vec![key.clone()],
            partition.to_string(),
            ApplicationConfig::default(),
        );
        let (handle, mailbox) = app.start();
        (handle, mailbox)
    }

    fn start_validator_cluster(
        context: &deterministic::Context,
        participants: &[PublicKey],
        label_prefix: &str,
        partition_prefix: &str,
    ) -> (Vec<Handle<()>>, Vec<AppMailbox>) {
        let relay = Arc::new(MockShardTransport::new());
        for participant in participants {
            relay.declare(participant);
        }
        relay.finalize_validators();

        let mut handles = Vec::with_capacity(participants.len());
        let mut mailboxes = Vec::with_capacity(participants.len());

        for (idx, participant) in participants.iter().enumerate() {
            let app = Application::new(
                context.with_label(&format!("{label_prefix}_{idx}")),
                relay.clone(),
                participant,
                participants.to_vec(),
                format!("{partition_prefix}_{idx}"),
                ApplicationConfig::default(),
            );
            let (handle, mailbox) = app.start();
            handles.push(handle);
            mailboxes.push(mailbox);
        }

        (handles, mailboxes)
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

    async fn fetch_finalization(
        mailbox: &AppMailbox,
        payload: Digest,
    ) -> mailbox::FinalizationResponse {
        mailbox
            .get_finalization(payload)
            .await
            .expect("finalization request should not fail")
            .expect("finalization should exist")
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

    async fn submit_transfer_and_finalize(
        mailbox: &mut AppMailbox,
        sender: &PrivateKey,
        recipient_pk: &PublicKey,
    ) {
        let epoch = Epoch::new(1);
        let genesis = mailbox.genesis(epoch).await;

        let tx = Transaction::transfer(sender, genesis_object_id(0), hellas_types::Address::from(recipient_pk.clone()), 1);
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

        mailbox
            .finalize(FinalizationNotice {
                payload,
                parent_payload: genesis,
                certificate_bytes: vec![0u8; 0].into(),
            })
            .await;
    }

    proptest! {
        #[test]
        fn payload_with_valid_encoding_and_non_future_timestamp_is_accepted(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
            anchor_payload in any::<[u8; 32]>(),
            anchor_root in any::<[u8; 32]>(),
            age in 0u64..=1_000_000u64,
        ) {
            prop_assume!(anchor_payload != [0u8; 32] || anchor_root != [0u8; 32]);
            let (round, parent, contents, payload) = build_payload_case(
                epoch,
                view,
                parent,
                timestamp,
                anchor_payload,
                anchor_root,
            );
            let now = timestamp.saturating_add(age);
            let block = SeenBlock::decode(contents, 0).expect("valid encoding");
            prop_assert!(block.into_validated(
                round,
                parent,
                payload,
                now,
                0, // parent timestamp (genesis = 0)
                Digest::from(anchor_root),
            ).is_ok());
        }

        #[test]
        fn payload_validation_rejects_digest_round_parent_and_future_errors(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent in any::<[u8; 32]>(),
            timestamp in 0u64..=MAX_TIMESTAMP,
            anchor_payload in any::<[u8; 32]>(),
            anchor_root in any::<[u8; 32]>(),
            index in any::<usize>(),
            future_delta in (SYNCHRONY_BOUND + 1)..=(SYNCHRONY_BOUND + 10_000),
        ) {
            prop_assume!(anchor_payload != [0u8; 32] || anchor_root != [0u8; 32]);
            let (round, parent, contents, payload) = build_payload_case(
                epoch,
                view,
                parent,
                timestamp,
                anchor_payload,
                anchor_root,
            );
            let ar = Digest::from(anchor_root);
            let now = timestamp.saturating_add(SYNCHRONY_BOUND);

            // Digest mismatch: mutated bytes still decode, but digest won't match
            let mutated = Bytes::from(mutate_byte(contents.to_vec(), index));
            if let Some(block) = SeenBlock::decode(mutated, 0) {
                assert!(matches!(
                    block.into_validated(round, parent, payload, now, 0, ar),
                    Err(PayloadValidationError::DigestMismatch { .. })
                ));
            }
            // (if decode fails, that's also a valid rejection)

            // Round mismatch
            let block = SeenBlock::decode(contents.clone(), 0).expect("valid encoding");
            let wrong_round = make_round(epoch.wrapping_add(1), view);
            assert!(matches!(
                block.into_validated(wrong_round, parent, payload, now, 0, ar),
                Err(PayloadValidationError::RoundMismatch { .. })
            ));

            // Parent mismatch
            let block = SeenBlock::decode(contents.clone(), 0).expect("valid encoding");
            let mut wrong_parent = parent.0;
            wrong_parent[0] ^= 0x01;
            assert!(matches!(
                block.into_validated(round, Digest::from(wrong_parent), payload, now, 0, ar),
                Err(PayloadValidationError::ParentMismatch { .. })
            ));

            // Future timestamp
            let future_timestamp = timestamp.saturating_add(future_delta);
            let future_contents = encode_payload(
                round,
                parent,
                future_timestamp,
                Digest::from(anchor_payload),
                ar,
                &[],
            );
            let future_payload = payload_digest(&future_contents);
            let block = SeenBlock::decode(future_contents, 0).expect("valid encoding");
            assert!(matches!(
                block.into_validated(round, parent, future_payload, timestamp, 0, ar),
                Err(PayloadValidationError::FutureTimestamp { .. })
            ));
        }

        #[test]
        fn payload_timestamp_must_be_monotonic_with_parent(
            epoch in any::<u16>(),
            view in any::<u16>(),
            parent_digest in any::<[u8; 32]>(),
            anchor_payload in any::<[u8; 32]>(),
            anchor_root in any::<[u8; 32]>(),
            parent_ts in 1u64..=(MAX_TIMESTAMP / 2),
            regression in 1u64..=1_000u64,
            advance in 0u64..=1_000u64,
        ) {
            prop_assume!(regression <= parent_ts);
            prop_assume!(anchor_payload != [0u8; 32] || anchor_root != [0u8; 32]);

            let round = make_round(epoch, view);
            let parent_digest = Digest::from(parent_digest);
            let anchor_payload = Digest::from(anchor_payload);
            let anchor_root = Digest::from(anchor_root);

            let regressed_ts = parent_ts - regression;
            let regressed_contents = encode_payload(
                round,
                parent_digest,
                regressed_ts,
                anchor_payload,
                anchor_root,
                &[],
            );
            let regressed_payload = payload_digest(&regressed_contents);
            let block = SeenBlock::decode(regressed_contents, 0).expect("valid encoding");
            assert!(matches!(
                block.into_validated(
                    round,
                    parent_digest,
                    regressed_payload,
                    parent_ts.saturating_add(SYNCHRONY_BOUND),
                    parent_ts,
                    anchor_root,
                ),
                Err(PayloadValidationError::TimestampRegression { .. })
            ));

            let child_ts = parent_ts.saturating_add(advance);
            let contents = encode_payload(
                round,
                parent_digest,
                child_ts,
                anchor_payload,
                anchor_root,
                &[],
            );
            let payload = payload_digest(&contents);
            let block = SeenBlock::decode(contents, 0).expect("valid encoding");
            prop_assert!(block.into_validated(
                round,
                parent_digest,
                payload,
                child_ts.saturating_add(SYNCHRONY_BOUND),
                parent_ts,
                anchor_root,
            ).is_ok());
        }
    }

    #[test_log::test]
    fn invalid_encoding_is_rejected() {
        let contents = Bytes::from_static(b"not-a-valid-payload");
        assert!(SeenBlock::decode(contents, 0).is_none());
    }

    #[test_log::test]
    fn genesis_has_zero_timestamp() {
        let epoch = Epoch::new(1);
        let payload = genesis_payload(epoch);
        let block = SeenBlock::decode(payload, 0).expect("genesis should decode");
        assert_eq!(block.data().timestamp, 0);
    }

    #[test_log::test]
    fn preleader_shards_drain_after_verify() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let Fixture { participants, .. }: Fixture<hellas_types::Scheme> =
                minimmit_ed25519::fixture(&mut context, b"app-shard-test", 6);

            let (_handles, mut mailboxes) =
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

            let verify_rx_1 = mailboxes[1].verify(proposal_context.clone(), digest).await;

            let verify_rx_2 = mailboxes[2].verify(proposal_context, digest).await;
            assert!(verify_rx_2.await.expect("verify 2 should resolve"));
            assert!(verify_rx_1.await.expect("verify 1 should resolve"));
        });
    }

    #[test_log::test]
    fn empty_qmdb_bootstraps_genesis_state() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let key = PrivateKey::from_seed(42).public_key();
            let (_handle, mut mailbox) = start_single_validator_app(
                &context,
                "bootstrap_app",
                &key,
                "bootstrap_test_partition",
            );
            let _ = mailbox.genesis(Epoch::new(1)).await;

            let genesis_object = genesis_object_id(0);
            let (root, proof) = fetch_root_and_proof(&mailbox, genesis_object).await;
            assert_coin_proof(
                genesis_object,
                Coin {
                    owner: Address::from(key),
                    value: GENESIS_BALANCE,
                },
                &proof,
                root,
            );
        });
    }

    #[test_log::test]
    fn qmdb_root_and_proof_survive_app_restart() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let key = PrivateKey::from_seed(77).public_key();
            let partition = "restart_test_partition";

            let (app_a_handle, mut mailbox_a) =
                start_single_validator_app(&context, "restart_app_a", &key, partition);
            let _ = mailbox_a.genesis(Epoch::new(1)).await;

            let genesis_object = genesis_object_id(0);
            let (root_a, proof_a) = fetch_root_and_proof(&mailbox_a, genesis_object).await;
            let expected_coin = Coin {
                owner: Address::from(key.clone()),
                value: GENESIS_BALANCE,
            };
            assert_coin_proof(genesis_object, expected_coin.clone(), &proof_a, root_a);

            app_a_handle.abort();
            let _ = app_a_handle.await;

            let (_app_b_handle, mailbox_b) =
                start_single_validator_app(&context, "restart_app_b", &key, partition);
            let (root_b, proof_b) = fetch_root_and_proof(&mailbox_b, genesis_object).await;
            assert_eq!(root_a, root_b);
            assert_coin_proof(genesis_object, expected_coin, &proof_b, root_b);
        });
    }

    #[test_log::test]
    fn finalization_certificate_is_retrievable() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let key = PrivateKey::from_seed(177).public_key();
            let partition = format!("finalization_restart_partition_{}", std::process::id());
            let encoded_finalization = vec![0xde, 0xad, 0xbe, 0xef];

            let (_app_a_handle, mut mailbox_a) =
                start_single_validator_app(&context, "finalization_app_a", &key, &partition);
            let epoch = Epoch::new(1);
            let genesis = mailbox_a.genesis(epoch).await;
            let proposal_context = Context {
                round: Round::new(epoch, View::new(1)),
                leader: key.clone(),
                parent: (View::zero(), genesis),
            };
            let payload = mailbox_a
                .propose(proposal_context)
                .await
                .await
                .expect("proposal should resolve");

            mailbox_a
                .finalize(FinalizationNotice {
                    payload,
                    parent_payload: genesis,
                    certificate_bytes: encoded_finalization.clone().into(),
                })
                .await;
            context.sleep(Duration::from_millis(50)).await;
            let stored = fetch_finalization(&mailbox_a, payload).await;
            assert_eq!(stored.as_slice(), encoded_finalization.as_slice());
        });
    }

    #[test_log::test]
    fn metrics_are_populated_after_propose_and_finalize() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let sender = PrivateKey::from_seed(300);
            let sender_pk = sender.public_key();
            let recipient_pk = PrivateKey::from_seed(301).public_key();

            let (_handle, mut mailbox) = start_single_validator_app(
                &context,
                "metrics_app",
                &sender_pk,
                "metrics_partition",
            );

            submit_transfer_and_finalize(&mut mailbox, &sender, &recipient_pk).await;

            // Allow persistence to complete so persistence metrics fire.
            context.sleep(Duration::from_secs(1)).await;

            let encoded = context.encode();

            // Core metrics — propose and verify are exercised by
            // submit_transfer_and_finalize.
            assert!(
                encoded.contains("propose_total"),
                "expected propose_total metric in encoded output"
            );

            // Application metrics — finalization notice should have been
            // processed.
            assert!(
                encoded.contains("finalization_notices_total"),
                "expected finalization_notices_total metric in encoded output"
            );

            // Persistence metrics — the worker should have started and
            // persisted at least the genesis + one finalized diff.
            assert!(
                encoded.contains("persist_success_total"),
                "expected persist_success_total metric in encoded output"
            );

            // Verify counters are non-zero by checking for a value > 0.
            // prometheus_client encodes counters as: metric_name_total N
            // where N is the count.
            for metric in [
                "propose_total",
                "finalization_notices_total",
                "persist_success_total",
            ] {
                let value = encoded
                    .lines()
                    .find(|line| line.contains(metric) && !line.starts_with('#'))
                    .unwrap_or_else(|| panic!("{metric} line not found in metrics output"));
                let count: f64 = value
                    .split_whitespace()
                    .last()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0.0);
                assert!(
                    count > 0.0,
                    "{metric} should be > 0 after propose+finalize, got {count}"
                );
            }
        });
    }

    /// Two independent QMDB instances applying the same operations must produce
    /// identical roots.  This catches non-determinism in floor-raising, bitmap
    /// merkleization, or any other commit-time side effect.
    #[test_log::test]
    fn two_qmdb_instances_agree_on_roots() {
        use crate::execution::store::{utxo_db_config, DEFAULT_PAGE_CACHE_COUNT, DEFAULT_PAGE_CACHE_SIZE};
        use crate::execution::genesis_state;

        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let validators: Vec<PublicKey> = (0..6)
                .map(|seed| PrivateKey::from_seed(seed).public_key())
                .collect();

            // Create two completely independent DBs.
            let cfg_a = utxo_db_config(
                &context,
                "determinism_a",
                DEFAULT_PAGE_CACHE_SIZE.get(),
                DEFAULT_PAGE_CACHE_COUNT.get(),
            );
            let cfg_b = utxo_db_config(
                &context,
                "determinism_b",
                DEFAULT_PAGE_CACHE_SIZE.get(),
                DEFAULT_PAGE_CACHE_COUNT.get(),
            );
            let mut db_a = UtxoDb::init(context.with_label("db_a"), cfg_a)
                .await
                .expect("db_a init");
            let mut db_b = UtxoDb::init(context.with_label("db_b"), cfg_b)
                .await
                .expect("db_b init");

            // --- Round 0: genesis bootstrap ---
            let genesis = genesis_state(&validators);
            let batch: Vec<(ObjectId, Option<Coin>)> = genesis
                .created
                .iter()
                .map(|(id, coin)| (*id, Some(coin.clone())))
                .collect();

            let apply = |db: UtxoDb<_>, batch: Vec<(ObjectId, Option<Coin>)>| async move {
                let mut db = db.into_mutable();
                db.write_batch(batch).await.unwrap();
                let (db, _range) = db.commit(None).await.unwrap();
                let db = db.into_merkleized().await.unwrap();
                let root = db.root();
                (db, root)
            };

            let (da, root_a) = apply(db_a, batch.clone()).await;
            let (db, root_b) = apply(db_b, batch).await;
            db_a = da;
            db_b = db;
            assert_eq!(root_a, root_b, "genesis roots must match");

            // --- Rounds 1..5: synthetic diffs ---
            for round in 1u16..=5 {
                // Delete the first validator's coin from a previous round
                // and create a replacement with an incremented value.
                let delete_id = genesis_object_id(round - 1);
                let create_id = genesis_object_id(round + 100);
                let coin = Coin {
                    owner: Address::from(validators[0].clone()),
                    value: GENESIS_BALANCE + u64::from(round),
                };
                let batch = vec![(delete_id, None), (create_id, Some(coin))];

                let (da, root_a) = apply(db_a, batch.clone()).await;
                let (db, root_b) = apply(db_b, batch).await;
                db_a = da;
                db_b = db;
                assert_eq!(
                    root_a, root_b,
                    "roots must match after round {round}"
                );
            }
        });
    }

    /// QMDB commit metadata IS part of the Merkle root (it is hashed into
    /// the authenticated log).  Two instances that apply identical diffs but
    /// commit with different metadata will produce DIFFERENT roots.
    ///
    /// This means we must NEVER pass node-local values (like queue position)
    /// as commit metadata — doing so would cause state divergence across
    /// validators.  The persistence layer must always use `commit(None)`.
    #[test_log::test]
    fn commit_metadata_affects_root() {
        use crate::execution::store::{utxo_db_config, DEFAULT_PAGE_CACHE_COUNT, DEFAULT_PAGE_CACHE_SIZE};
        use crate::execution::genesis_state;

        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let validators: Vec<PublicKey> = (0..6)
                .map(|seed| PrivateKey::from_seed(seed).public_key())
                .collect();

            let cfg_a = utxo_db_config(
                &context,
                "meta_a",
                DEFAULT_PAGE_CACHE_SIZE.get(),
                DEFAULT_PAGE_CACHE_COUNT.get(),
            );
            let cfg_b = utxo_db_config(
                &context,
                "meta_b",
                DEFAULT_PAGE_CACHE_SIZE.get(),
                DEFAULT_PAGE_CACHE_COUNT.get(),
            );
            let mut db_a = UtxoDb::init(context.with_label("meta_a"), cfg_a)
                .await
                .expect("db_a init");
            let mut db_b = UtxoDb::init(context.with_label("meta_b"), cfg_b)
                .await
                .expect("db_b init");

            let genesis = genesis_state(&validators);
            let batch: Vec<(ObjectId, Option<Coin>)> = genesis
                .created
                .iter()
                .map(|(id, coin)| (*id, Some(coin.clone())))
                .collect();

            // db_a commits with metadata, db_b commits without.
            let meta = Some(Coin {
                owner: Address::from(validators[0].clone()),
                value: 42,
            });

            let mut db = db_a.into_mutable();
            db.write_batch(batch.clone()).await.unwrap();
            let (db, _) = db.commit(meta).await.unwrap();
            db_a = db.into_merkleized().await.unwrap();

            let mut db = db_b.into_mutable();
            db.write_batch(batch).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            db_b = db.into_merkleized().await.unwrap();

            assert_ne!(
                db_a.root(),
                db_b.root(),
                "commit metadata is part of the Merkle root; different metadata must produce different roots"
            );
        });
    }

    /// QMDB empty commits still change the root.
    ///
    /// Even when the write batch is empty and metadata is `None`, each
    /// `into_mutable → write_batch([]) → commit(None) → into_merkleized`
    /// cycle advances an internal sequence number that is hashed into the
    /// Merkle root.  This means that nodes with different persistence
    /// queue depths will diverge even when no state has changed.
    ///
    /// The persistence layer must therefore **skip the QMDB commit when
    /// the diff batch is empty**, preserving root determinism.
    #[test_log::test]
    fn empty_commit_changes_root() {
        use crate::execution::store::{utxo_db_config, DEFAULT_PAGE_CACHE_COUNT, DEFAULT_PAGE_CACHE_SIZE};
        use crate::execution::genesis_state;

        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let validators: Vec<PublicKey> = (0..6)
                .map(|seed| PrivateKey::from_seed(seed).public_key())
                .collect();

            let cfg = utxo_db_config(
                &context,
                "empty_commit",
                DEFAULT_PAGE_CACHE_SIZE.get(),
                DEFAULT_PAGE_CACHE_COUNT.get(),
            );
            let mut db = UtxoDb::init(context.with_label("empty_commit"), cfg)
                .await
                .expect("db init");

            // Bootstrap genesis.
            let genesis = genesis_state(&validators);
            let batch: Vec<(ObjectId, Option<Coin>)> = genesis
                .created
                .iter()
                .map(|(id, coin)| (*id, Some(coin.clone())))
                .collect();
            let mut m = db.into_mutable();
            m.write_batch(batch).await.unwrap();
            let (d, _) = m.commit(None).await.unwrap();
            db = d.into_merkleized().await.unwrap();
            let root_before = db.root();

            // Empty commit — no writes, no metadata.
            let mut m = db.into_mutable();
            m.write_batch(Vec::<(ObjectId, Option<Coin>)>::new()).await.unwrap();
            let (d, _) = m.commit(None).await.unwrap();
            db = d.into_merkleized().await.unwrap();
            let root_after = db.root();

            assert_ne!(
                root_before, root_after,
                "empty QMDB commit changes the root (internal sequence is hashed)"
            );
        });
    }

    /// After persisting a finalization (genesis + one transfer), restarting the
    /// Application from the same partition must recover the identical state root.
    #[test_log::test]
    fn root_survives_restart_after_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let sender = PrivateKey::from_seed(500);
            let sender_pk = sender.public_key();
            let recipient_pk = PrivateKey::from_seed(501).public_key();
            let partition = "restart_after_finalize";

            let (handle_a, mut mailbox_a) =
                start_single_validator_app(&context, "raf_a", &sender_pk, partition);

            submit_transfer_and_finalize(&mut mailbox_a, &sender, &recipient_pk).await;

            // Let persistence complete.
            context.sleep(Duration::from_secs(2)).await;

            let root_before = fetch_root(&mailbox_a).await;
            assert_ne!(
                root_before,
                Digest::from([0u8; 32]),
                "root should be non-zero after finalization"
            );

            // Kill then restart from the same partition.
            handle_a.abort();
            let _ = handle_a.await;

            let (_handle_b, mailbox_b) =
                start_single_validator_app(&context, "raf_b", &sender_pk, partition);

            let root_after = fetch_root(&mailbox_b).await;
            assert_eq!(
                root_before, root_after,
                "QMDB root must be identical after restart"
            );
        });
    }

    /// Minimal reproduction: a single UtxoDb synced to disk and reopened from
    /// the same partition must report the same root.  This isolates the QMDB
    /// journal-replay non-determinism without any Application-level machinery.
    #[test_log::test]
    fn qmdb_root_survives_sync_and_reopen() {
        use crate::execution::store::{utxo_db_config, DEFAULT_PAGE_CACHE_COUNT, DEFAULT_PAGE_CACHE_SIZE};
        use crate::execution::genesis_state;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let validators: Vec<PublicKey> = (0..6)
                .map(|seed| PrivateKey::from_seed(seed).public_key())
                .collect();
            let partition = "reopen_determinism";

            let cfg = utxo_db_config(
                &context,
                partition,
                DEFAULT_PAGE_CACHE_SIZE.get(),
                DEFAULT_PAGE_CACHE_COUNT.get(),
            );
            let db = UtxoDb::init(context.with_label("db_init"), cfg)
                .await
                .expect("init");

            // Bootstrap genesis.
            let genesis = genesis_state(&validators);
            let batch: Vec<(ObjectId, Option<Coin>)> = genesis
                .created
                .iter()
                .map(|(id, coin)| (*id, Some(coin.clone())))
                .collect();
            let mut db = db.into_mutable();
            db.write_batch(batch).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db = db.into_merkleized().await.unwrap();
            let root_before = db.root();

            // Flush to disk.
            db.sync().await.unwrap();
            drop(db);

            // Reopen from the same partition.
            let cfg = utxo_db_config(
                &context,
                partition,
                DEFAULT_PAGE_CACHE_SIZE.get(),
                DEFAULT_PAGE_CACHE_COUNT.get(),
            );
            let db = UtxoDb::init(context.with_label("db_reopen"), cfg)
                .await
                .expect("reopen");

            let root_after = db.root();
            assert_eq!(
                root_before, root_after,
                "QMDB root must survive sync + reopen"
            );
        });
    }

    /// Same as above, but drops the DB *without* calling sync() first —
    /// simulating a crash.  The journal is durable after commit(), but the MMR
    /// may lag, requiring replay on reopen.
    #[test_log::test]
    fn qmdb_root_survives_crash_and_reopen() {
        use crate::execution::store::{utxo_db_config, DEFAULT_PAGE_CACHE_COUNT, DEFAULT_PAGE_CACHE_SIZE};
        use crate::execution::genesis_state;

        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let validators: Vec<PublicKey> = (0..6)
                .map(|seed| PrivateKey::from_seed(seed).public_key())
                .collect();
            let partition = "crash_determinism";

            let cfg = utxo_db_config(
                &context,
                partition,
                DEFAULT_PAGE_CACHE_SIZE.get(),
                DEFAULT_PAGE_CACHE_COUNT.get(),
            );
            let mut db = UtxoDb::init(context.with_label("db_init"), cfg)
                .await
                .expect("init");

            // Bootstrap genesis.
            let genesis = genesis_state(&validators);
            let batch: Vec<(ObjectId, Option<Coin>)> = genesis
                .created
                .iter()
                .map(|(id, coin)| (*id, Some(coin.clone())))
                .collect();
            let mut mutable = db.into_mutable();
            mutable.write_batch(batch).await.unwrap();
            let (committed, _) = mutable.commit(None).await.unwrap();
            db = committed.into_merkleized().await.unwrap();

            // Apply a second round of diffs (simulating one finalized payload).
            let delete_id = genesis_object_id(0);
            let create_id = genesis_object_id(200);
            let coin = Coin {
                owner: Address::from(validators[1].clone()),
                value: 42,
            };
            let batch = vec![(delete_id, None), (create_id, Some(coin))];
            let mut mutable = db.into_mutable();
            mutable.write_batch(batch).await.unwrap();
            let (committed, _) = mutable.commit(None).await.unwrap();
            db = committed.into_merkleized().await.unwrap();

            let root_before = db.root();

            // Simulate crash: drop WITHOUT sync.
            drop(db);

            // Reopen — journal replay should recover the same root.
            let cfg = utxo_db_config(
                &context,
                partition,
                DEFAULT_PAGE_CACHE_SIZE.get(),
                DEFAULT_PAGE_CACHE_COUNT.get(),
            );
            let db = UtxoDb::init(context.with_label("db_crash_reopen"), cfg)
                .await
                .expect("reopen after crash");

            let root_after = db.root();
            assert_eq!(
                root_before, root_after,
                "QMDB root must survive crash (no sync) + reopen"
            );
        });
    }

    #[test_log::test]
    fn local_light_client_returns_genesis_proof() {
        use crate::rpc::{self, LocalLightClient};
        use hellas_types::rpc::LightClient;

        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|context| async move {
            let key = PrivateKey::from_seed(42).public_key();
            let (_handle, mut mailbox) = start_single_validator_app(
                &context,
                "lc_app",
                &key,
                "lc_partition",
            );
            let _ = mailbox.genesis(Epoch::new(1)).await;

            let lc = LocalLightClient::new(mailbox, vec![]);

            // State root should be available after genesis.
            let root = lc
                .get_state_root()
                .await
                .expect("query should succeed")
                .expect("root should exist");
            assert_ne!(root, Digest::from([0u8; 32]));

            // Proof for genesis coin should round-trip through encode/decode.
            let genesis_object = genesis_object_id(0);
            let proof_bytes = lc
                .get_proof(genesis_object)
                .await
                .expect("query should succeed")
                .expect("proof should exist");

            let proof = rpc::decode_proof(&proof_bytes)
                .expect("proof should decode");

            let mut hasher = Sha256::default();
            assert!(
                UtxoDb::<ContextCell<deterministic::Context>>::verify_key_value_proof(
                    &mut hasher,
                    genesis_object,
                    Coin {
                        owner: Address::from(key),
                        value: GENESIS_BALANCE,
                    },
                    &proof,
                    &root,
                )
            );
        });
    }

    #[test_log::test]
    fn grpc_light_client_round_trip() {
        use crate::rpc::{self, LocalLightClient};
        use commonware_runtime::tokio as cw_tokio;
        use hellas_rpc::client::RemoteLightClient;
        use hellas_types::rpc::LightClient;

        let tmp_dir = std::env::temp_dir().join(format!(
            "hellas_grpc_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let runtime_cfg =
            cw_tokio::Config::new().with_storage_directory(tmp_dir.to_str().unwrap());
        let runner = cw_tokio::Runner::new(runtime_cfg);

        runner.start(|context| async move {
            let key = PrivateKey::from_seed(99).public_key();
            let relay = Arc::new(MockShardTransport::new());
            relay.declare(&key);
            relay.finalize_validators();

            let app = Application::new(
                context.with_label("grpc_app"),
                relay,
                &key,
                vec![key.clone()],
                "grpc_partition".to_string(),
                ApplicationConfig::default(),
            );
            let (_handle, mut mailbox) = app.start();
            let _ = mailbox.genesis(Epoch::new(1)).await;

            let light_client = LocalLightClient::new(mailbox, vec![]);

            // Start ws-mux server on a random port.
            let (activity_tx, _) = tokio::sync::broadcast::channel::<hellas_types::rpc::ConsensusActivity>(16);
            let svc = hellas_rpc::mux::MuxServiceDispatch::new(
                crate::rpc::LightClientGrpcServer::new(light_client, activity_tx)
                    .into_service(),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("failed to bind");
            let addr = listener.local_addr().expect("should have local addr");

            ::tokio::spawn(async move {
                use futures::StreamExt;
                let (tcp, _) = listener.accept().await.expect("accept");
                let ws = tokio_tungstenite::accept_async(tcp).await.expect("ws handshake");
                let (write, read) = ws.split();
                let sink = ws_mux::NativeWsSink::new(write);
                let recv = ws_mux::NativeWsRecv::new(read);
                ws_mux::serve(svc, recv, sink).await.expect("serve");
            });

            // Connect RemoteLightClient via ws-mux.
            let client = RemoteLightClient::connect(format!("ws://{addr}"))
                .await
                .expect("failed to connect to ws-mux server");

            let root = client
                .get_state_root()
                .await
                .expect("get_state_root should succeed")
                .expect("root should exist");
            assert_ne!(root, Digest::from([0u8; 32]));

            let genesis_object = genesis_object_id(0);
            let proof_bytes = client
                .get_proof(genesis_object)
                .await
                .expect("get_proof should succeed")
                .expect("proof should exist");

            let proof =
                rpc::decode_proof(&proof_bytes).expect("proof should decode");
            let mut hasher = Sha256::default();
            assert!(
                UtxoDb::<ContextCell<cw_tokio::Context>>::verify_key_value_proof(
                    &mut hasher,
                    genesis_object,
                    Coin {
                        owner: Address::from(key),
                        value: GENESIS_BALANCE,
                    },
                    &proof,
                    &root,
                )
            );
        });

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
