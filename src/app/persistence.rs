use super::{mailbox, metrics::{PersistenceMetrics, gauge_set_len}};
use crate::execution::store::{UtxoDb, utxo_db_config};
use crate::execution::{FinalizationDiffs, genesis_state};
use hellas_types::{Coin, ObjectId};
use crate::trace::Traced;
use bytes::{Buf, Bytes};
use commonware_codec::{RangeCfg, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef,
};
use commonware_storage::{
    Persistable,
    metadata::{Config as MetadataConfig, Metadata},
    queue::{Config as QueueConfig, Queue},
};
use commonware_utils::{channel::oneshot, sequence::U64};
use futures::{StreamExt, channel::mpsc};
use hellas_types::PublicKey;
use indexmap::IndexMap;
use std::{
    collections::VecDeque,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::LazyLock,
};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(super) struct Fatal(String);

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
    GetPayload {
        payload: Digest,
        response: oneshot::Sender<Option<Bytes>>,
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
    RecordPayload {
        payload: Digest,
        bytes: Bytes,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

#[derive(Clone, Copy)]
pub(super) enum PersistenceEvent {
    Ready {
        root: Digest,
    },
    Persisted {
        payload: Digest,
        root: Digest,
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
type PayloadIndex<E> = Metadata<E, Digest, Vec<u8>>;

/// Ed25519 basepoint (RFC 8032 §5.1) — always a valid public key.
static QUEUE_CURSOR_OWNER: LazyLock<PublicKey> = LazyLock::new(|| {
    let bytes: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    ];
    PublicKey::read(&mut bytes.as_slice())
        .expect("ed25519 basepoint is always valid")
});

/// Safe wrapper around [`UtxoDb`] that encapsulates the QMDB type-state
/// machine and provides crash-safe commit semantics.
///
/// Every commit atomically records the originating queue position in the
/// QMDB journal metadata.  On restart, [`was_committed`] lets callers
/// skip queue items that were already applied before a crash.
struct UtxoStore<E: Clock + Spawner + Storage + Metrics + BufferPooler> {
    db: Option<UtxoDb<E>>,
    last_committed_position: Option<u64>,
}

impl<E: Clock + Spawner + Storage + Metrics + BufferPooler> UtxoStore<E> {
    async fn init(
        context: &mut E,
        partition_prefix: &str,
        page_cache_config: PageCacheConfig,
    ) -> Result<Self, Fatal> {
        let config = utxo_db_config(
            context,
            partition_prefix,
            page_cache_config.size,
            page_cache_config.count,
        );
        let db = UtxoDb::init(context.with_label("utxo_db"), config)
            .await
            .map_err(|err| Fatal(format!("QMDB initialization failed: {err:?}")))?;

        let last_committed_position = if db.is_empty() {
            None
        } else {
            match db.get_metadata().await {
                Ok(Some(coin)) => Some(coin.value),
                Ok(None) => None,
                Err(err) => {
                    return Err(Fatal(format!("QMDB get_metadata failed: {err:?}")))
                }
            }
        };

        Ok(Self {
            db: Some(db),
            last_committed_position,
        })
    }

    fn was_committed(&self, queue_position: u64) -> bool {
        self.last_committed_position
            .is_some_and(|last| queue_position <= last)
    }

    fn diffs_to_batch(
        created: &[(ObjectId, Coin)],
        deleted: &[ObjectId],
    ) -> Vec<(ObjectId, Option<Coin>)> {
        deleted
            .iter()
            .map(|id| (*id, None))
            .chain(created.iter().map(|(id, coin)| (*id, Some(coin.clone()))))
            .collect()
    }

    async fn apply_diffs(
        &mut self,
        batch: Vec<(ObjectId, Option<Coin>)>,
        queue_position: Option<u64>,
        label: &str,
    ) -> Result<Digest, Fatal> {
        let db = self
            .db
            .take()
            .expect("db is always present outside apply_diffs");

        let metadata = queue_position.map(|pos| Coin {
            owner: QUEUE_CURSOR_OWNER.clone(),
            value: pos,
        });

        let mut db = db.into_mutable();

        db.write_batch(batch).await.map_err(|err| {
            Fatal(format!("QMDB write_batch failed for {label}: {err:?}"))
        })?;

        let (db, _range) = db.commit(metadata).await.map_err(|err| {
            Fatal(format!("QMDB commit failed for {label}: {err:?}"))
        })?;

        let db = db.into_merkleized().await.map_err(|err| {
            Fatal(format!("QMDB merkleize failed for {label}: {err:?}"))
        })?;

        let root = db.root();

        if let Some(pos) = queue_position {
            self.last_committed_position = Some(pos);
        }
        self.db = Some(db);
        Ok(root)
    }

    fn root(&self) -> Digest {
        self.db
            .as_ref()
            .expect("db is always present outside apply_diffs")
            .root()
    }

    fn is_empty(&self) -> bool {
        self.db
            .as_ref()
            .expect("db is always present outside apply_diffs")
            .is_empty()
    }

    async fn key_value_proof(
        &self,
        hasher: &mut Sha256,
        object: ObjectId,
    ) -> Option<mailbox::ProofResponse> {
        self.db
            .as_ref()
            .expect("db is always present outside apply_diffs")
            .key_value_proof(hasher, object)
            .await
            .ok()
    }

    async fn sync(&mut self) -> Result<(), Fatal> {
        self.db
            .as_mut()
            .expect("db is always present outside apply_diffs")
            .sync()
            .await
            .map_err(|err| Fatal(format!("QMDB sync failed: {err:?}")))
    }
}

#[derive(Clone, Copy)]
struct AnchorEntry {
    sequence: u64,
    payload: Digest,
    root: Digest,
}

pub(super) struct PersistenceWorker<E>
where
    E: Clock + Spawner + Storage + Metrics + BufferPooler,
{
    command_rx: mpsc::UnboundedReceiver<Traced<PersistenceCommand>>,
    event_tx: mpsc::UnboundedSender<Traced<PersistenceEvent>>,
    metrics: PersistenceMetrics,
    store: UtxoStore<E>,
    queue: PersistenceQueue<E>,
    anchor_index: AnchorIndex<E>,
    anchor_history: VecDeque<AnchorEntry>,
    next_anchor_sequence: u64,
    finalization_index: FinalizationIndex<E>,
    volatile_finalizations: IndexMap<Digest, mailbox::FinalizationResponse>,
    payload_index: PayloadIndex<E>,
    volatile_payloads: IndexMap<Digest, Bytes>,
}

impl<E> PersistenceWorker<E>
where
    E: Clock + Spawner + Storage + Metrics + BufferPooler,
{
    const QUEUE_ITEMS_PER_SECTION: NonZeroU64 = NonZeroU64::new(256).unwrap();
    const QUEUE_WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(8192).unwrap();
    const MAX_QUEUE_ITEM_BYTES: usize = 1 << 20;
    const MAX_QUEUE_DIFF_ENTRIES: usize = 32_768;
    const MAX_ANCHOR_RECORD_BYTES: usize = 128;
    const MAX_ANCHOR_HISTORY: usize = 2048;
    const MAX_FINALIZATION_RECORD_BYTES: usize = 1 << 20;
    const MAX_VOLATILE_FINALIZATIONS: usize = 4096;
    const MAX_PAYLOAD_RECORD_BYTES: usize = 1 << 20;
    const MAX_VOLATILE_PAYLOADS: usize = 4096;

    pub(super) async fn create(
        context: &mut E,
        partition_prefix: String,
        page_cache_config: PageCacheConfig,
        validators: Vec<PublicKey>,
        command_rx: mpsc::UnboundedReceiver<Traced<PersistenceCommand>>,
        event_tx: mpsc::UnboundedSender<Traced<PersistenceEvent>>,
        metrics: PersistenceMetrics,
    ) -> Result<Self, Fatal> {
        let queue = Self::initialize_queue(context, &partition_prefix, page_cache_config).await?;
        let mut store = UtxoStore::init(context, &partition_prefix, page_cache_config).await?;
        let (anchor_index, anchor_history, next_anchor_sequence) =
            Self::initialize_anchor_index(context, &partition_prefix).await?;
        let finalization_index =
            Self::initialize_finalization_index(context, &partition_prefix).await?;
        let payload_index = Self::initialize_payload_index(context, &partition_prefix).await?;

        if store.is_empty() {
            let genesis = genesis_state(&validators);
            let batch = UtxoStore::<E>::diffs_to_batch(&genesis.created, &genesis.deleted);
            store.apply_diffs(batch, None, "genesis bootstrap").await?;
        }

        Ok(Self {
            command_rx,
            event_tx,
            metrics,
            store,
            queue,
            anchor_index,
            anchor_history,
            next_anchor_sequence,
            finalization_index,
            volatile_finalizations: IndexMap::new(),
            payload_index,
            volatile_payloads: IndexMap::new(),
        })
    }

    pub(super) async fn run(mut self, _context: &mut E) {
        self.metrics.worker_ready_total.inc();
        let root = self.store.root();
        if let Err(err) = self
            .event_tx
            .unbounded_send(Traced::capture(PersistenceEvent::Ready { root }))
        {
            warn!(
                ?err,
                "failed to notify application that persistence worker is ready"
            );
            return;
        }
        loop {
            // Drain any buffered commands before attempting persistence.
            loop {
                match self.command_rx.try_next() {
                    Ok(Some(command)) => match self.process_command(command).await {
                        Ok(true) => {}
                        Ok(false) => {
                            self.sync_or_abort().await;
                            return;
                        }
                        Err(err) => Self::abort(err),
                    },
                    Ok(None) => {
                        self.sync_or_abort().await;
                        return;
                    }
                    Err(_) => break,
                }
            }

            // Persist any pending work from the durable queue.
            if self.has_pending_work().await {
                self = match self.persist_next_pending().await {
                    Ok(s) => s,
                    Err(err) => Self::abort(err),
                };
                continue;
            }

            // No work; block until a command arrives.
            let Some(command) = self.command_rx.next().await else {
                break;
            };
            match self.process_command(command).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(err) => Self::abort(err),
            }
        }

        self.sync_or_abort().await;
    }

    fn abort(err: Fatal) -> ! {
        error!(%err, "irrecoverable persistence error; aborting");
        std::process::abort()
    }

    async fn sync_or_abort(&mut self) {
        if let Err(err) = self.sync_on_shutdown().await {
            Self::abort(err);
        }
    }

    async fn process_command(
        &mut self,
        command: Traced<PersistenceCommand>,
    ) -> Result<bool, Fatal> {
        let (command, parent_span) = command.into_parts();
        let _entered = parent_span.enter();
        self.handle_command(command).await
    }

    async fn has_pending_work(&self) -> bool {
        !self.queue.is_empty().await
    }

    #[tracing::instrument(
        name = "app.persistence.persist_next_pending",
        level = "info",
        skip_all,
    )]
    async fn persist_next_pending(mut self) -> Result<Self, Fatal> {
        let (position, encoded) = match self.queue.dequeue().await {
            Ok(Some(item)) => item,
            Ok(None) => return Ok(self),
            Err(err) => {
                return Err(Fatal(format!(
                    "failed to dequeue persistence intent: {err:?}"
                )))
            }
        };

        let Some((payload, diffs)) = Self::decode_queue_item(encoded.as_slice()) else {
            return Err(Fatal(format!(
                "invalid persistence queue item at position {position}"
            )));
        };

        // Skip queue items already committed before a crash.
        if self.store.was_committed(position) {
            info!(?payload, position, "skipping already-committed queue item");
            self.queue.ack(position).await.map_err(|err| {
                Fatal(format!(
                    "failed to ack persistence intent at position {position} for {payload:?}: {err:?}"
                ))
            })?;
            self.queue.sync().await.map_err(|err| {
                Fatal(format!(
                    "failed to sync persistence queue after ack for {payload:?}: {err:?}"
                ))
            })?;
            // Re-record anchor (may have been lost if crash was between
            // commit and anchor sync). record_persisted_anchor is idempotent
            // when payload+root match.
            let root = self.store.root();
            self.record_persisted_anchor(payload, root).await?;
            self.metrics.persist_success_total.inc();
            let _ = self.event_tx.unbounded_send(
                Traced::capture(PersistenceEvent::Persisted { payload, root }),
            );
            return Ok(self);
        }

        info!(
            ?payload,
            queue_position = position,
            created = diffs.created.len(),
            deleted = diffs.deleted.len(),
            "persisting finalization diffs"
        );

        self.metrics.persist_attempt_total.inc();

        let batch = UtxoStore::<E>::diffs_to_batch(&diffs.created, &diffs.deleted);
        let label = format!("{payload:?}");
        let root = self.store.apply_diffs(batch, Some(position), &label).await?;

        // Ack the queue item so it won't be replayed on restart.
        self.queue.ack(position).await.map_err(|err| {
            Fatal(format!(
                "failed to ack persistence intent at position {position} for {payload:?}: {err:?}"
            ))
        })?;
        self.queue.sync().await.map_err(|err| {
            Fatal(format!(
                "failed to sync persistence queue after ack for {payload:?}: {err:?}"
            ))
        })?;

        self.metrics.persist_success_total.inc();
        self.record_persisted_anchor(payload, root).await?;
        if let Err(err) = self
            .event_tx
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

        Ok(self)
    }

    async fn enqueue_pending(
        &mut self,
        payload: &Digest,
        diffs: &FinalizationDiffs,
    ) -> Result<(), Fatal> {
        let encoded = Self::encode_queue_item(*payload, diffs);
        self.queue
            .enqueue(encoded)
            .await
            .map(|_| ())
            .map_err(|err| {
                Fatal(format!(
                    "failed to enqueue persistence intent for {payload:?}: {err:?}"
                ))
            })
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

    async fn handle_command(&mut self, command: PersistenceCommand) -> Result<bool, Fatal> {
        match command {
            PersistenceCommand::Enqueue { payload, diffs } => {
                self.metrics.enqueue_commands_total.inc();
                self.enqueue_pending(&payload, &diffs).await?;
                Ok(true)
            }
            PersistenceCommand::GetStateRoot { response } => {
                let _ = response.send(Some(self.store.root()));
                Ok(true)
            }
            PersistenceCommand::GetProof { object, response } => {
                let proof = self.proof_for_object(object).await;
                let _ = response.send(proof);
                Ok(true)
            }
            PersistenceCommand::GetPayload { payload, response } => {
                let _ = response.send(self.payload(payload));
                Ok(true)
            }
            PersistenceCommand::GetPersistedAnchors { response } => {
                let _ = response.send(self.persisted_anchor_history());
                Ok(true)
            }
            PersistenceCommand::RecordPersistedRoot { payload, root } => {
                self.record_persisted_anchor(payload, root).await?;
                Ok(true)
            }
            PersistenceCommand::GetFinalization { payload, response } => {
                let _ = response.send(self.finalization(payload));
                Ok(true)
            }
            PersistenceCommand::RecordFinalization {
                payload,
                finalization,
            } => {
                self.record_finalization(payload, finalization).await?;
                Ok(true)
            }
            PersistenceCommand::RecordPayload { payload, bytes } => {
                self.record_payload(payload, bytes).await?;
                Ok(true)
            }
            PersistenceCommand::Shutdown { response } => {
                let _ = response.send(());
                Ok(false)
            }
        }
    }



    async fn proof_for_object(&self, object: ObjectId) -> Option<mailbox::ProofResponse> {
        let mut hasher = Sha256::default();
        self.store.key_value_proof(&mut hasher, object).await
    }

    fn finalization(&mut self, payload: Digest) -> Option<mailbox::FinalizationResponse> {
        if let Some(finalization) = self.volatile_finalizations.get(&payload) {
            return Some(finalization.clone());
        }
        let stored = self
            .finalization_index
            .get(&payload)
            .cloned()
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
        gauge_set_len(&self.metrics.finalization_cache_entries, self.volatile_finalizations.len());
    }

    fn payload(&mut self, payload: Digest) -> Option<Bytes> {
        if let Some(bytes) = self.volatile_payloads.get(&payload) {
            return Some(bytes.clone());
        }
        let stored = self
            .payload_index
            .get(&payload)
            .cloned()
            .map(Bytes::from);
        if let Some(ref bytes) = stored {
            self.cache_payload(payload, bytes.clone());
        }
        stored
    }

    fn cache_payload(&mut self, payload: Digest, bytes: Bytes) {
        self.volatile_payloads.insert(payload, bytes);
        while self.volatile_payloads.len() > Self::MAX_VOLATILE_PAYLOADS {
            let Some((_oldest, _)) = self.volatile_payloads.shift_remove_index(0) else {
                break;
            };
        }
    }

    fn persisted_anchor_history(&self) -> Vec<(Digest, Digest)> {
        self.anchor_history
            .iter()
            .map(|entry| (entry.payload, entry.root))
            .collect()
    }

    async fn record_persisted_anchor(
        &mut self,
        payload: Digest,
        root: Digest,
    ) -> Result<(), Fatal> {
        if let Some(existing) = self
            .anchor_history
            .iter()
            .find(|entry| entry.payload == payload)
        {
            if existing.root != root {
                return Err(Fatal(format!(
                    "conflicting persisted roots for {payload:?}: existing={:?}, new={root:?}",
                    existing.root
                )));
            }
            return Ok(());
        }

        let sequence = self.next_anchor_sequence;
        self.next_anchor_sequence =
            self.next_anchor_sequence
                .checked_add(1)
                .ok_or_else(|| Fatal("anchor sequence counter overflowed".into()))?;

        self.anchor_history.push_back(AnchorEntry {
            sequence,
            payload,
            root,
        });

        self.anchor_index.put(
            U64::new(sequence),
            Self::encode_anchor_record(payload, root),
        );
        while self.anchor_history.len() > Self::MAX_ANCHOR_HISTORY {
            let Some(oldest) = self.anchor_history.pop_front() else {
                break;
            };
            self.anchor_index.remove(&U64::new(oldest.sequence));
        }
        self.anchor_index.sync().await.map_err(|err| {
            Fatal(format!(
                "failed to sync persisted anchor index for {payload:?}: {err:?}"
            ))
        })
    }

    async fn record_finalization(
        &mut self,
        payload: Digest,
        finalization: mailbox::FinalizationResponse,
    ) -> Result<(), Fatal> {
        if let Some(existing) = self.volatile_finalizations.get(&payload) {
            if existing != &finalization {
                return Err(Fatal(format!(
                    "conflicting finalization certificates for {payload:?}"
                )));
            }
            return Ok(());
        }

        if let Some(existing) = self.finalization_index.get(&payload) {
            if existing.as_slice() != finalization.as_slice() {
                return Err(Fatal(format!(
                    "conflicting stored finalization certificate for {payload:?}"
                )));
            }
            self.cache_finalization(payload, finalization);
            return Ok(());
        }
        self.finalization_index
            .put(payload, finalization.as_slice().to_vec());
        self.finalization_index.sync().await.map_err(|err| {
            Fatal(format!(
                "failed to sync finalization certificate index for {payload:?}: {err:?}"
            ))
        })?;

        self.cache_finalization(payload, finalization);
        Ok(())
    }

    async fn record_payload(&mut self, payload: Digest, bytes: Bytes) -> Result<(), Fatal> {
        if let Some(existing) = self.volatile_payloads.get(&payload) {
            if existing != &bytes {
                return Err(Fatal(format!(
                    "conflicting payload bytes for {payload:?}"
                )));
            }
            return Ok(());
        }

        if let Some(existing) = self.payload_index.get(&payload) {
            if existing.as_slice() != bytes.as_ref() {
                return Err(Fatal(format!(
                    "conflicting stored payload bytes for {payload:?}"
                )));
            }
            self.cache_payload(payload, bytes);
            return Ok(());
        }
        self.payload_index.put(payload, bytes.as_ref().to_vec());
        self.payload_index.sync().await.map_err(|err| {
            Fatal(format!(
                "failed to sync payload index for {payload:?}: {err:?}"
            ))
        })?;

        self.cache_payload(payload, bytes);
        Ok(())
    }

    fn anchor_metadata_config(
        partition_prefix: &str,
    ) -> MetadataConfig<(RangeCfg<usize>, ())> {
        MetadataConfig {
            partition: format!("{partition_prefix}_anchor_roots"),
            codec_config: ((0..=Self::MAX_ANCHOR_RECORD_BYTES).into(), ()),
        }
    }

    fn finalization_metadata_config(
        partition_prefix: &str,
    ) -> MetadataConfig<(RangeCfg<usize>, ())> {
        MetadataConfig {
            partition: format!("{partition_prefix}_finalizations_by_payload"),
            codec_config: ((0..=Self::MAX_FINALIZATION_RECORD_BYTES).into(), ()),
        }
    }

    fn payload_metadata_config(
        partition_prefix: &str,
    ) -> MetadataConfig<(RangeCfg<usize>, ())> {
        MetadataConfig {
            partition: format!("{partition_prefix}_payloads_by_digest"),
            codec_config: ((0..=Self::MAX_PAYLOAD_RECORD_BYTES).into(), ()),
        }
    }

    fn queue_config(
        context: &E,
        partition_prefix: &str,
        page_cache_config: PageCacheConfig,
    ) -> QueueConfig<(RangeCfg<usize>, ())> {
        let page_cache_size = NonZeroU16::new(page_cache_config.size)
            .unwrap_or(crate::execution::store::DEFAULT_PAGE_CACHE_SIZE);
        let page_cache_count = NonZeroUsize::new(page_cache_config.count)
            .unwrap_or(crate::execution::store::DEFAULT_PAGE_CACHE_COUNT);
        QueueConfig {
            partition: format!("{partition_prefix}_persistence_queue"),
            items_per_section: Self::QUEUE_ITEMS_PER_SECTION,
            compression: None,
            codec_config: ((0..=Self::MAX_QUEUE_ITEM_BYTES).into(), ()),
            page_cache: CacheRef::from_pooler(context, page_cache_size, page_cache_count),
            write_buffer: Self::QUEUE_WRITE_BUFFER,
        }
    }

    async fn initialize_anchor_index(
        context: &mut E,
        partition_prefix: &str,
    ) -> Result<(AnchorIndex<E>, VecDeque<AnchorEntry>, u64), Fatal> {
        let config = Self::anchor_metadata_config(partition_prefix);
        let mut index = AnchorIndex::init(context.with_label("anchor_index"), config)
            .await
            .map_err(|err| Fatal(format!("anchor index initialization failed: {err:?}")))?;

        let mut recovered = VecDeque::new();
        let mut keys: Vec<U64> = index.keys().cloned().collect();
        keys.sort();
        for key in keys {
            let sequence = u64::from(&key);
            let Some(encoded) = index.get(&key).cloned() else {
                continue;
            };
            let Some((payload, root)) = Self::decode_anchor_record(encoded.as_slice()) else {
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

        let next_sequence = recovered
            .back()
            .map(|entry| entry.sequence.saturating_add(1))
            .unwrap_or(0);
        index.sync().await.map_err(|err| {
            Fatal(format!("failed to sync recovered anchor index: {err:?}"))
        })?;
        Ok((index, recovered, next_sequence))
    }

    async fn initialize_finalization_index(
        context: &mut E,
        partition_prefix: &str,
    ) -> Result<FinalizationIndex<E>, Fatal> {
        let config = Self::finalization_metadata_config(partition_prefix);
        FinalizationIndex::init(context.with_label("finalization_index"), config)
            .await
            .map_err(|err| {
                Fatal(format!(
                    "finalization index initialization failed: {err:?}"
                ))
            })
    }

    async fn initialize_payload_index(
        context: &mut E,
        partition_prefix: &str,
    ) -> Result<PayloadIndex<E>, Fatal> {
        let config = Self::payload_metadata_config(partition_prefix);
        PayloadIndex::init(context.with_label("payload_index"), config)
            .await
            .map_err(|err| Fatal(format!("payload index initialization failed: {err:?}")))
    }

    async fn initialize_queue(
        context: &mut E,
        partition_prefix: &str,
        page_cache_config: PageCacheConfig,
    ) -> Result<PersistenceQueue<E>, Fatal> {
        let config = Self::queue_config(context, partition_prefix, page_cache_config);
        PersistenceQueue::init(context.with_label("persistence_queue"), config)
            .await
            .map_err(|err| {
                Fatal(format!(
                    "persistence queue initialization failed: {err:?}"
                ))
            })
    }

    async fn sync_on_shutdown(&mut self) -> Result<(), Fatal> {
        self.queue.sync().await.map_err(|err| {
            Fatal(format!(
                "persistence queue sync on shutdown failed: {err:?}"
            ))
        })?;
        self.store.sync().await?;
        self.anchor_index.sync().await.map_err(|err| {
            Fatal(format!(
                "anchor index sync on shutdown failed: {err:?}"
            ))
        })?;
        self.finalization_index.sync().await.map_err(|err| {
            Fatal(format!(
                "finalization index sync on shutdown failed: {err:?}"
            ))
        })?;
        self.payload_index.sync().await.map_err(|err| {
            Fatal(format!(
                "payload index sync on shutdown failed: {err:?}"
            ))
        })
    }
}
