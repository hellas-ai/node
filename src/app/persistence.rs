use super::{mailbox, metrics::PersistenceMetrics};
use crate::execution::store::{UtxoDb, utxo_db_config};
use crate::execution::{FinalizationDiffs, genesis_state};
use crate::object::{Coin, ObjectId};
use crate::trace::Traced;
use bytes::Buf;
use commonware_codec::{RangeCfg, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::{
    Persistable,
    metadata::{Config as MetadataConfig, Metadata},
    queue::{Config as QueueConfig, Queue},
};
use commonware_utils::{SystemTimeExt, channel::oneshot, sequence::U64};
use futures::{StreamExt, channel::mpsc};
use hellas_types::PublicKey;
use indexmap::IndexMap;
use std::{
    collections::VecDeque,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::Instrument;

pub(super) enum PersistenceCommand {
    Enqueue {
        payload: Digest,
        diffs: FinalizationDiffs,
    },
    GetStateRoot {
        response: oneshot::Sender<Option<Digest>>,
    },
    GetProof {
        object: ObjectId,
        response: oneshot::Sender<Option<mailbox::ProofResponse>>,
    },
    GetPersistedAnchors {
        response: oneshot::Sender<Vec<(Digest, Digest)>>,
    },
    RecordPersistedRoot {
        payload: Digest,
        root: Digest,
    },
    GetFinalization {
        payload: Digest,
        response: oneshot::Sender<Option<mailbox::FinalizationResponse>>,
    },
    RecordFinalization {
        payload: Digest,
        finalization: mailbox::FinalizationResponse,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

#[derive(Clone, Copy)]
pub(super) enum PersistenceEvent {
    Ready {
        root: Option<Digest>,
    },
    Persisted {
        payload: Digest,
        root: Option<Digest>,
    },
}

#[derive(Clone, Copy)]
pub(super) struct PageCacheConfig {
    pub(super) size: u16,
    pub(super) count: usize,
}

type PersistenceQueue<E> = Queue<E, Vec<u8>>;
type AnchorIndex<E> = Metadata<E, U64, Vec<u8>>;
type FinalizationIndex<E> = Metadata<E, Digest, Vec<u8>>;

#[derive(Clone, Copy)]
struct AnchorEntry {
    sequence: u64,
    payload: Digest,
    root: Digest,
}

pub(super) struct PersistenceWorker<E>
where
    E: Clock + Spawner + Storage + Metrics,
{
    partition_prefix: String,
    page_cache: PageCacheConfig,
    validators: Vec<PublicKey>,
    command_rx: mpsc::UnboundedReceiver<Traced<PersistenceCommand>>,
    event_tx: mpsc::UnboundedSender<Traced<PersistenceEvent>>,
    metrics: PersistenceMetrics,
    pending: Option<(Digest, FinalizationDiffs)>,
    retry_delay: Duration,
    next_retry_at_ms: Option<u64>,
    db: Option<UtxoDb<E>>,
    queue: Option<PersistenceQueue<E>>,
    anchor_index: Option<AnchorIndex<E>>,
    anchor_history: VecDeque<AnchorEntry>,
    next_anchor_sequence: u64,
    finalization_index: Option<FinalizationIndex<E>>,
    volatile_finalizations: IndexMap<Digest, mailbox::FinalizationResponse>,
    #[cfg(test)]
    persistence_failures_remaining: usize,
}

impl<E> PersistenceWorker<E>
where
    E: Clock + Spawner + Storage + Metrics,
{
    const RETRY_BASE: Duration = Duration::from_millis(50);
    const RETRY_MAX: Duration = Duration::from_secs(5);
    const IDLE_SLEEP: Duration = Duration::from_secs(3600);
    const QUEUE_ITEMS_PER_SECTION: NonZeroU64 = NonZeroU64::new(256).unwrap();
    const QUEUE_WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(8192).unwrap();
    const MAX_QUEUE_ITEM_BYTES: usize = 1 << 20;
    const MAX_QUEUE_DIFF_ENTRIES: usize = 32_768;
    const MAX_ANCHOR_RECORD_BYTES: usize = 128;
    const MAX_ANCHOR_HISTORY: usize = 2048;
    const MAX_FINALIZATION_RECORD_BYTES: usize = 1 << 20;
    const MAX_VOLATILE_FINALIZATIONS: usize = 4096;

    pub(super) fn new(
        partition_prefix: String,
        page_cache: PageCacheConfig,
        validators: Vec<PublicKey>,
        command_rx: mpsc::UnboundedReceiver<Traced<PersistenceCommand>>,
        event_tx: mpsc::UnboundedSender<Traced<PersistenceEvent>>,
        metrics: PersistenceMetrics,
        #[cfg(test)] persistence_failures_remaining: usize,
    ) -> Self {
        Self {
            partition_prefix,
            page_cache,
            validators,
            command_rx,
            event_tx,
            metrics,
            pending: None,
            retry_delay: Self::RETRY_BASE,
            next_retry_at_ms: None,
            db: None,
            queue: None,
            anchor_index: None,
            anchor_history: VecDeque::new(),
            next_anchor_sequence: 0,
            finalization_index: None,
            volatile_finalizations: IndexMap::new(),
            #[cfg(test)]
            persistence_failures_remaining,
        }
    }

    pub(super) async fn run(mut self, context: &mut E) {
        self.initialize_queue(context).await;
        self.initialize_db(context).await;
        self.initialize_anchor_index(context).await;
        self.initialize_finalization_index(context).await;
        self.metrics.worker_ready_total.inc();
        if let Err(err) = self
            .event_tx
            .unbounded_send(Traced::capture(PersistenceEvent::Ready {
                root: self.state_root(),
            }))
        {
            warn!(
                ?err,
                "failed to notify application that persistence worker is ready"
            );
            return;
        }
        loop {
            if !self.drain_ready_commands().await {
                break;
            }

            let now_ms = context.current().epoch_millis();
            if self.should_attempt_persist(now_ms) {
                self.persist_next_pending(context, now_ms).await;
            }

            let sleep_duration = self.persistence_sleep_duration(context.current().epoch_millis());
            select! {
                command = self.command_rx.next() => {
                    let Some(command) = command else {
                        break;
                    };
                    if !self.process_traced_command(command).await {
                        break;
                    }
                },
                _ = context.sleep(sleep_duration) => {},
            }
        }

        self.sync_db_on_shutdown().await;
    }

    async fn drain_ready_commands(&mut self) -> bool {
        loop {
            match self.command_rx.try_next() {
                Ok(Some(command)) => {
                    if !self.process_traced_command(command).await {
                        return false;
                    }
                }
                Ok(None) => return false,
                Err(_) => return true,
            }
        }
    }

    async fn process_traced_command(&mut self, command: Traced<PersistenceCommand>) -> bool {
        let (command, parent_span) = command.into_parts();
        let _entered = parent_span.enter();
        self.handle_command(command).await
    }

    fn should_attempt_persist(&self, now_ms: u64) -> bool {
        if self.pending.is_none() && self.queue_is_empty() {
            return false;
        }
        match self.next_retry_at_ms {
            None => true,
            Some(deadline_ms) => now_ms >= deadline_ms,
        }
    }

    fn persistence_sleep_duration(&self, now_ms: u64) -> Duration {
        if self.pending.is_none() && self.queue_is_empty() {
            return Self::IDLE_SLEEP;
        }
        let Some(deadline_ms) = self.next_retry_at_ms else {
            return Duration::from_millis(0);
        };
        Duration::from_millis(deadline_ms.saturating_sub(now_ms))
    }

    fn queue_is_empty(&self) -> bool {
        self.queue.as_ref().map_or(true, PersistenceQueue::is_empty)
    }

    fn schedule_retry(&mut self, now_ms: u64) {
        let delay_ms = u64::try_from(self.retry_delay.as_millis()).unwrap_or(u64::MAX);
        self.next_retry_at_ms = Some(now_ms.saturating_add(delay_ms));
        self.retry_delay = (self.retry_delay * 2).min(Self::RETRY_MAX);
    }

    fn clear_retry(&mut self) {
        self.next_retry_at_ms = None;
        self.retry_delay = Self::RETRY_BASE;
    }

    #[tracing::instrument(
        name = "app.persistence.persist_next_pending",
        level = "info",
        skip_all,
        fields(now_ms = now_ms)
    )]
    async fn persist_next_pending(&mut self, context: &mut E, now_ms: u64) {
        if let Some((payload, diffs)) = self.pending.take() {
            self.metrics.staged_pending.set(0);
            if !self.enqueue_pending_intent(payload, &diffs).await {
                self.pending = Some((payload, diffs));
                self.metrics.staged_pending.set(1);
                self.metrics.persist_failure_total.inc();
                self.schedule_retry(now_ms);
                return;
            }
        }

        let dequeued = {
            let Some(queue) = self.queue.as_mut() else {
                warn!("persistence queue unavailable; cannot drain finalized diffs");
                self.schedule_retry(now_ms);
                return;
            };
            match queue.dequeue().await {
                Ok(item) => item,
                Err(err) => {
                    error!(?err, "failed to dequeue persistence intent");
                    self.schedule_retry(now_ms);
                    return;
                }
            }
        };

        let Some((position, encoded)) = dequeued else {
            self.clear_retry();
            return;
        };

        let Some((payload, diffs)) = Self::decode_queue_item(encoded.as_slice()) else {
            error!(
                position,
                "invalid persistence queue item; entering fail-stop"
            );
            std::process::abort();
        };
        async {
            self.metrics.persist_attempt_total.inc();

            #[cfg(test)]
            if self.persistence_failures_remaining > 0 {
                self.persistence_failures_remaining -= 1;
                warn!(
                    remaining = self.persistence_failures_remaining,
                    "injecting persistence failure for retry-path test"
                );
                self.metrics.persist_failure_total.inc();
                if let Some(queue) = self.queue.as_mut() {
                    queue.reset();
                }
                self.schedule_retry(now_ms);
                return;
            }

            if !self.apply_diffs_to_db(context, &diffs).await {
                warn!(?payload, "failed to persist finalized state");
                self.metrics.persist_failure_total.inc();
                if let Some(queue) = self.queue.as_mut() {
                    queue.reset();
                }
                self.schedule_retry(now_ms);
                return;
            }

            let ack_result = {
                let Some(queue) = self.queue.as_mut() else {
                    warn!("persistence queue unavailable during ack");
                    self.schedule_retry(now_ms);
                    return;
                };
                if let Err(err) = queue.ack(position) {
                    error!(?err, position, ?payload, "failed to ack persistence intent");
                    queue.reset();
                    self.metrics.persist_failure_total.inc();
                    self.schedule_retry(now_ms);
                    return;
                }
                queue.sync().await
            };
            if let Err(err) = ack_result {
                error!(?err, position, ?payload, "failed to sync persistence queue");
                if let Some(queue) = self.queue.as_mut() {
                    queue.reset();
                }
                self.metrics.persist_failure_total.inc();
                self.schedule_retry(now_ms);
                return;
            }

            self.clear_retry();
            self.metrics.persist_success_total.inc();
            let root = self.state_root();
            if let Some(root) = root {
                self.record_persisted_anchor(payload, root).await;
            }
            if let Err(err) =
                self.event_tx
                    .unbounded_send(Traced::capture(PersistenceEvent::Persisted {
                        payload,
                        root,
                    }))
            {
                warn!(
                    ?err,
                    ?payload,
                    "failed to notify application of persisted finalization"
                );
            }
        }
        .instrument(info_span!(
            "app.persistence.persist_intent",
            payload = ?payload,
            queue_position = position,
            created = diffs.created.len(),
            deleted = diffs.deleted.len()
        ))
        .await;
    }

    async fn enqueue_pending_intent(&mut self, payload: Digest, diffs: &FinalizationDiffs) -> bool {
        let Some(queue) = self.queue.as_mut() else {
            warn!("persistence queue unavailable; cannot enqueue finalized diffs");
            return false;
        };
        let encoded = Self::encode_queue_item(payload, diffs);
        match queue.enqueue(encoded).await {
            Ok(_) => true,
            Err(err) => {
                error!(?err, ?payload, "failed to enqueue persistence intent");
                false
            }
        }
    }

    fn encode_queue_item(payload: Digest, diffs: &FinalizationDiffs) -> Vec<u8> {
        let mut encoded = Vec::new();
        payload.write(&mut encoded);
        diffs.created.write(&mut encoded);
        diffs.deleted.write(&mut encoded);
        encoded
    }

    fn decode_queue_item(encoded: &[u8]) -> Option<(Digest, FinalizationDiffs)> {
        let mut reader = encoded;
        let payload = Digest::read(&mut reader).ok()?;
        let created =
            Vec::<(ObjectId, Coin)>::read_range(&mut reader, 0..=Self::MAX_QUEUE_DIFF_ENTRIES)
                .ok()?;
        let deleted =
            Vec::<ObjectId>::read_range(&mut reader, 0..=Self::MAX_QUEUE_DIFF_ENTRIES).ok()?;
        if reader.has_remaining() {
            return None;
        }
        Some((payload, FinalizationDiffs { created, deleted }))
    }

    fn encode_anchor_record(payload: Digest, root: Digest) -> Vec<u8> {
        let mut encoded = Vec::new();
        payload.write(&mut encoded);
        root.write(&mut encoded);
        encoded
    }

    fn decode_anchor_record(encoded: &[u8]) -> Option<(Digest, Digest)> {
        let mut reader = encoded;
        let payload = Digest::read(&mut reader).ok()?;
        let root = Digest::read(&mut reader).ok()?;
        if reader.has_remaining() {
            return None;
        }
        Some((payload, root))
    }

    async fn handle_command(&mut self, command: PersistenceCommand) -> bool {
        match command {
            PersistenceCommand::Enqueue { payload, diffs } => {
                self.metrics.enqueue_commands_total.inc();
                if self
                    .pending
                    .as_ref()
                    .is_some_and(|(candidate, _)| *candidate == payload)
                {
                    return true;
                }
                if let Some((existing_payload, _)) = self.pending.as_ref() {
                    error!(
                        existing = ?existing_payload,
                        incoming = ?payload,
                        "received enqueue while a staged persistence intent is still pending; entering fail-stop"
                    );
                    std::process::abort();
                }
                self.pending = Some((payload, diffs));
                self.metrics.staged_pending.set(1);
                self.clear_retry();
                true
            }
            PersistenceCommand::GetStateRoot { response } => {
                let _ = response.send(self.state_root());
                true
            }
            PersistenceCommand::GetProof { object, response } => {
                let proof = self.proof_for_object(object).await;
                let _ = response.send(proof);
                true
            }
            PersistenceCommand::GetPersistedAnchors { response } => {
                let _ = response.send(self.persisted_anchor_history());
                true
            }
            PersistenceCommand::RecordPersistedRoot { payload, root } => {
                self.record_persisted_anchor(payload, root).await;
                true
            }
            PersistenceCommand::GetFinalization { payload, response } => {
                let _ = response.send(self.finalization(payload));
                true
            }
            PersistenceCommand::RecordFinalization {
                payload,
                finalization,
            } => {
                self.record_finalization(payload, finalization).await;
                true
            }
            PersistenceCommand::Shutdown { response } => {
                let _ = response.send(());
                false
            }
        }
    }

    #[tracing::instrument(
        name = "app.persistence.apply_diffs_to_db",
        level = "debug",
        skip_all,
        fields(
            created = diffs.created.len(),
            deleted = diffs.deleted.len(),
        )
    )]
    async fn apply_diffs_to_db(&mut self, context: &mut E, diffs: &FinalizationDiffs) -> bool {
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

        if let Err(err) = db.write_batch(batch).await {
            error!(?err, "QMDB write_batch failed");
            self.reopen_db_after_failure(context, "write_batch").await;
            return false;
        }

        let (db, _range) = match db.commit(None).await {
            Ok(result) => result,
            Err(err) => {
                error!(?err, "QMDB commit failed");
                self.reopen_db_after_failure(context, "commit").await;
                return false;
            }
        };
        let db = match db.into_merkleized().await {
            Ok(db) => db,
            Err(err) => {
                error!(?err, "QMDB merkleize failed");
                self.reopen_db_after_failure(context, "merkleize").await;
                return false;
            }
        };
        self.db = Some(db);
        true
    }

    async fn reopen_db_after_failure(&mut self, context: &mut E, stage: &'static str) {
        let config = utxo_db_config(
            &self.partition_prefix,
            self.page_cache.size,
            self.page_cache.count,
        );
        match UtxoDb::init(context.with_label("utxo_db_recover"), config).await {
            Ok(db) => {
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

    async fn bootstrap_genesis_state_if_empty(&mut self, context: &mut E) {
        let Some(db) = self.db.as_ref() else {
            return;
        };
        if !db.is_empty() {
            return;
        }

        let genesis_execution = genesis_state(&self.validators);
        let diffs = FinalizationDiffs {
            created: genesis_execution.created,
            deleted: genesis_execution.deleted,
        };
        let _ = self.apply_diffs_to_db(context, &diffs).await;
    }

    fn state_root(&self) -> Option<Digest> {
        let db = self.db.as_ref()?;
        if db.is_empty() { None } else { Some(db.root()) }
    }

    async fn proof_for_object(&self, object: ObjectId) -> Option<mailbox::ProofResponse> {
        let db = self.db.as_ref()?;
        let mut hasher = Sha256::default();
        db.key_value_proof(&mut hasher, object).await.ok()
    }

    fn finalization(&mut self, payload: Digest) -> Option<mailbox::FinalizationResponse> {
        if let Some(finalization) = self.volatile_finalizations.get(&payload) {
            return Some(finalization.clone());
        }
        let stored = self
            .finalization_index
            .as_ref()
            .and_then(|index| index.get(&payload).cloned())
            .map(mailbox::FinalizationResponse::from);
        if let Some(ref finalization) = stored {
            self.cache_finalization(payload, finalization.clone());
        }
        stored
    }

    fn cache_finalization(&mut self, payload: Digest, finalization: mailbox::FinalizationResponse) {
        self.volatile_finalizations.insert(payload, finalization);
        while self.volatile_finalizations.len() > Self::MAX_VOLATILE_FINALIZATIONS {
            let Some((_oldest, _)) = self.volatile_finalizations.shift_remove_index(0) else {
                break;
            };
        }
        self.metrics
            .finalization_cache_entries
            .set(i64::try_from(self.volatile_finalizations.len()).unwrap_or(i64::MAX));
    }

    fn persisted_anchor_history(&self) -> Vec<(Digest, Digest)> {
        self.anchor_history
            .iter()
            .map(|entry| (entry.payload, entry.root))
            .collect()
    }

    async fn record_persisted_anchor(&mut self, payload: Digest, root: Digest) {
        if let Some(existing) = self
            .anchor_history
            .iter()
            .find(|entry| entry.payload == payload)
        {
            if existing.root != root {
                error!(
                    ?payload,
                    existing_root = ?existing.root,
                    new_root = ?root,
                    "detected conflicting persisted roots for payload; entering fail-stop"
                );
                std::process::abort();
            }
            return;
        }

        let sequence = self.next_anchor_sequence;
        self.next_anchor_sequence = self.next_anchor_sequence.checked_add(1).unwrap_or_else(|| {
            error!("anchor sequence counter overflowed");
            std::process::abort();
        });

        self.anchor_history.push_back(AnchorEntry {
            sequence,
            payload,
            root,
        });

        if let Some(index) = self.anchor_index.as_mut() {
            index.put(
                U64::new(sequence),
                Self::encode_anchor_record(payload, root),
            );
            while self.anchor_history.len() > Self::MAX_ANCHOR_HISTORY {
                let Some(oldest) = self.anchor_history.pop_front() else {
                    break;
                };
                index.remove(&U64::new(oldest.sequence));
            }
            if let Err(err) = index.sync().await {
                warn!(?err, ?payload, "failed to sync persisted anchor index");
            }
        } else {
            while self.anchor_history.len() > Self::MAX_ANCHOR_HISTORY {
                self.anchor_history.pop_front();
            }
        }
    }

    async fn record_finalization(
        &mut self,
        payload: Digest,
        finalization: mailbox::FinalizationResponse,
    ) {
        if let Some(existing) = self.volatile_finalizations.get(&payload) {
            if existing != &finalization {
                error!(
                    ?payload,
                    "detected conflicting finalization certificates for payload; entering fail-stop"
                );
                std::process::abort();
            }
            return;
        }

        if let Some(index) = self.finalization_index.as_mut() {
            if let Some(existing) = index.get(&payload) {
                if existing.as_slice() != finalization.as_slice() {
                    error!(
                        ?payload,
                        "detected conflicting stored finalization certificate for payload; entering fail-stop"
                    );
                    std::process::abort();
                }
                self.cache_finalization(payload, finalization);
                return;
            }
            index.put(payload, finalization.as_slice().to_vec());
            if let Err(err) = index.sync().await {
                warn!(
                    ?err,
                    ?payload,
                    "failed to sync finalization certificate index"
                );
            }
        }

        self.cache_finalization(payload, finalization);
    }

    fn anchor_metadata_config(&self) -> MetadataConfig<(RangeCfg<usize>, ())> {
        MetadataConfig {
            partition: format!("{prefix}_anchor_roots", prefix = self.partition_prefix),
            codec_config: ((0..=Self::MAX_ANCHOR_RECORD_BYTES).into(), ()),
        }
    }

    fn finalization_metadata_config(&self) -> MetadataConfig<(RangeCfg<usize>, ())> {
        MetadataConfig {
            partition: format!(
                "{prefix}_finalizations_by_payload",
                prefix = self.partition_prefix
            ),
            codec_config: ((0..=Self::MAX_FINALIZATION_RECORD_BYTES).into(), ()),
        }
    }

    fn queue_config(&self) -> QueueConfig<(RangeCfg<usize>, ())> {
        let page_cache_size = NonZeroU16::new(self.page_cache.size)
            .unwrap_or(crate::execution::store::DEFAULT_PAGE_CACHE_SIZE);
        let page_cache_count = NonZeroUsize::new(self.page_cache.count)
            .unwrap_or(crate::execution::store::DEFAULT_PAGE_CACHE_COUNT);
        QueueConfig {
            partition: format!("{prefix}_persistence_queue", prefix = self.partition_prefix),
            items_per_section: Self::QUEUE_ITEMS_PER_SECTION,
            compression: None,
            codec_config: ((0..=Self::MAX_QUEUE_ITEM_BYTES).into(), ()),
            page_cache: CacheRef::new(page_cache_size, page_cache_count),
            write_buffer: Self::QUEUE_WRITE_BUFFER,
        }
    }

    async fn initialize_anchor_index(&mut self, context: &mut E) {
        let config = self.anchor_metadata_config();
        match AnchorIndex::init(context.with_label("anchor_index"), config).await {
            Ok(mut index) => {
                let mut recovered = VecDeque::new();
                let mut keys: Vec<U64> = index.keys().cloned().collect();
                keys.sort();
                for key in keys {
                    let sequence = u64::from(&key);
                    let Some(encoded) = index.get(&key).cloned() else {
                        continue;
                    };
                    let Some((payload, root)) = Self::decode_anchor_record(encoded.as_slice())
                    else {
                        warn!(sequence, "invalid anchor index entry; removing");
                        index.remove(&key);
                        continue;
                    };
                    recovered.push_back(AnchorEntry {
                        sequence,
                        payload,
                        root,
                    });
                }

                while recovered.len() > Self::MAX_ANCHOR_HISTORY {
                    let Some(oldest) = recovered.pop_front() else {
                        break;
                    };
                    index.remove(&U64::new(oldest.sequence));
                }

                self.next_anchor_sequence = recovered
                    .back()
                    .map(|entry| entry.sequence.saturating_add(1))
                    .unwrap_or(0);
                self.anchor_history = recovered;
                if let Err(err) = index.sync().await {
                    warn!(?err, "failed to sync recovered anchor index");
                }
                self.anchor_index = Some(index);
            }
            Err(err) => {
                error!(
                    ?err,
                    "anchor index initialization failed; restart-time anchor recovery disabled"
                );
            }
        }
    }

    async fn initialize_finalization_index(&mut self, context: &mut E) {
        let config = self.finalization_metadata_config();
        match FinalizationIndex::init(context.with_label("finalization_index"), config).await {
            Ok(index) => {
                self.finalization_index = Some(index);
            }
            Err(err) => {
                error!(
                    ?err,
                    "finalization index initialization failed; certificate recovery disabled"
                );
            }
        }
    }

    async fn initialize_queue(&mut self, context: &mut E) {
        let config = self.queue_config();
        match PersistenceQueue::init(context.with_label("persistence_queue"), config).await {
            Ok(queue) => {
                self.queue = Some(queue);
            }
            Err(err) => {
                error!(
                    ?err,
                    "persistence queue initialization failed; finalized diffs cannot be durably buffered"
                );
            }
        }
    }

    async fn initialize_db(&mut self, context: &mut E) {
        let config = utxo_db_config(
            &self.partition_prefix,
            self.page_cache.size,
            self.page_cache.count,
        );
        match UtxoDb::init(context.with_label("utxo_db"), config).await {
            Ok(db) => {
                self.db = Some(db);
                self.bootstrap_genesis_state_if_empty(context).await;
            }
            Err(err) => {
                error!(
                    ?err,
                    "QMDB initialization failed; running without persistence"
                );
            }
        }
    }

    async fn sync_db_on_shutdown(&mut self) {
        if let Some(queue) = self.queue.as_mut()
            && let Err(err) = queue.sync().await
        {
            warn!(?err, "persistence queue sync on shutdown failed");
        }
        if let Some(mut db) = self.db.take()
            && let Err(err) = db.sync().await
        {
            warn!(?err, "QMDB sync on shutdown failed");
        }
        if let Some(index) = self.anchor_index.as_mut()
            && let Err(err) = index.sync().await
        {
            warn!(?err, "anchor index sync on shutdown failed");
        }
        if let Some(index) = self.finalization_index.as_mut()
            && let Err(err) = index.sync().await
        {
            warn!(?err, "finalization index sync on shutdown failed");
        }
    }
}
