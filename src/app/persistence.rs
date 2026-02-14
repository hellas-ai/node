use super::{mailbox, metrics::PersistenceMetrics};
use crate::execution::store::{UtxoDb, utxo_db_config};
use crate::gauged::{GaugedIndexMap, GaugedVecDeque};
use crate::execution::{FinalizationDiffs, genesis_state};
use hellas_types::{Coin, ObjectId};
use crate::trace::Traced;
use bytes::{Buf, Bytes};
use commonware_codec::{FixedSize, RangeCfg, Read as CodecRead, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef,
};
use commonware_storage::{
    Persistable,
    freezer::{
        Checkpoint as FreezerCheckpoint, Config as FreezerConfig, Cursor as FreezerCursor, Freezer,
        Identifier as FreezerIdentifier,
    },
    metadata::{Config as MetadataConfig, Metadata},
    queue::{Config as QueueConfig, Queue},
};
use commonware_utils::{channel::oneshot, sequence::U64};
use futures::{StreamExt, channel::mpsc};
use tracing::Instrument;
use hellas_types::PublicKey;
use std::{
    collections::{HashMap, VecDeque},
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

#[derive(Clone)]
pub(super) enum PersistenceEvent {
    Ready {
        root: Digest,
        recovered_payloads: Vec<(Digest, Bytes)>,
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
type FinalizationIndex<E> = Freezer<E, Digest, Vec<u8>>;
type PayloadIndex<E> = Freezer<E, Digest, Vec<u8>>;

/// Well-known key used to store the queue cursor position in the
/// dedicated metadata partition.
static QUEUE_CURSOR_KEY: LazyLock<Digest> = LazyLock::new(|| {
    let mut bytes = [0u8; 32];
    bytes[0] = b'q';
    bytes[1] = b'c';
    Digest::from(bytes)
});

/// Well-known key for the finalization Freezer checkpoint.
static FINALIZATION_CHECKPOINT_KEY: LazyLock<Digest> = LazyLock::new(|| {
    let mut bytes = [0u8; 32];
    bytes[0] = b'f';
    bytes[1] = b'c';
    Digest::from(bytes)
});

/// Well-known key for the payload Freezer checkpoint.
static PAYLOAD_CHECKPOINT_KEY: LazyLock<Digest> = LazyLock::new(|| {
    let mut bytes = [0u8; 32];
    bytes[0] = b'p';
    bytes[1] = b'c';
    Digest::from(bytes)
});

/// Safe wrapper around [`UtxoDb`] that encapsulates the QMDB type-state
/// machine and provides crash-safe commit semantics.
///
/// The last successfully committed queue position is persisted in a
/// separate [`Metadata`] partition (not in QMDB commit metadata, which
/// would pollute the Merkle root).  On restart, [`was_committed`] lets
/// callers skip queue items that were already applied before a crash.
struct UtxoStore<E: Clock + Spawner + Storage + Metrics + BufferPooler> {
    db: Option<UtxoDb<E>>,
    cursor_index: Metadata<E, Digest, Vec<u8>>,
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

        let cursor_index = Metadata::init(
            context.with_label("queue_cursor"),
            MetadataConfig {
                partition: format!("{partition_prefix}_queue_cursor"),
                codec_config: ((0..=FreezerCheckpoint::SIZE).into(), ()),
            },
        )
        .await
        .map_err(|err| Fatal(format!("queue cursor init failed: {err:?}")))?;

        let last_committed_position = cursor_index
            .get(&*QUEUE_CURSOR_KEY)
            .map(|bytes: &Vec<u8>| {
                let arr: [u8; 8] = bytes[..8]
                    .try_into()
                    .expect("queue cursor value is 8 bytes");
                u64::from_le_bytes(arr)
            });

        Ok(Self {
            db: Some(db),
            cursor_index,
            last_committed_position,
        })
    }

    fn load_checkpoint(&self, key: &Digest) -> Option<FreezerCheckpoint> {
        self.cursor_index.get(key).and_then(|bytes| {
            FreezerCheckpoint::read_cfg(&mut bytes.as_slice(), &()).ok()
        })
    }

    fn save_checkpoint(&mut self, key: Digest, cp: FreezerCheckpoint) {
        let mut buf = Vec::with_capacity(FreezerCheckpoint::SIZE);
        cp.write(&mut buf);
        self.cursor_index.put(key, buf);
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
        // QMDB advances an internal sequence on every commit, changing the
        // Merkle root even when the batch is empty.  Skip the commit entirely
        // when there are no state changes to preserve root determinism across
        // validators with different persistence queue depths.
        if batch.is_empty() {
            if let Some(pos) = queue_position {
                self.cursor_index.put(
                    *QUEUE_CURSOR_KEY,
                    pos.to_le_bytes().to_vec(),
                );
                self.cursor_index.sync().await.map_err(|err| {
                    Fatal(format!("queue cursor sync failed for {label}: {err:?}"))
                })?;
                self.last_committed_position = Some(pos);
            }
            return Ok(self.root());
        }

        let db = self
            .db
            .take()
            .expect("db is always present outside apply_diffs");

        let mut db = db.into_mutable();

        db.write_batch(batch).await.map_err(|err| {
            Fatal(format!("QMDB write_batch failed for {label}: {err:?}"))
        })?;

        let (db, _range) = db.commit(None).await.map_err(|err| {
            Fatal(format!("QMDB commit failed for {label}: {err:?}"))
        })?;

        let db = db.into_merkleized().await.map_err(|err| {
            Fatal(format!("QMDB merkleize failed for {label}: {err:?}"))
        })?;

        let root = db.root();

        if let Some(pos) = queue_position {
            self.cursor_index.put(
                *QUEUE_CURSOR_KEY,
                pos.to_le_bytes().to_vec(),
            );
            self.cursor_index.sync().await.map_err(|err| {
                Fatal(format!("queue cursor sync failed for {label}: {err:?}"))
            })?;
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
    anchor_history: GaugedVecDeque<AnchorEntry>,
    next_anchor_sequence: u64,
    finalization_index: Option<FinalizationIndex<E>>,
    finalization_cursors: HashMap<Digest, FreezerCursor>,
    volatile_finalizations: GaugedIndexMap<Digest, mailbox::FinalizationResponse>,
    payload_index: Option<PayloadIndex<E>>,
    payload_cursors: HashMap<Digest, FreezerCursor>,
    volatile_payloads: GaugedIndexMap<Digest, Bytes>,
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

        let fin_checkpoint = store.load_checkpoint(&FINALIZATION_CHECKPOINT_KEY);
        let pay_checkpoint = store.load_checkpoint(&PAYLOAD_CHECKPOINT_KEY);

        let finalization_index = Self::initialize_finalization_index(
            context,
            &partition_prefix,
            page_cache_config,
            fin_checkpoint,
        )
        .await?;
        let payload_index = Self::initialize_payload_index(
            context,
            &partition_prefix,
            page_cache_config,
            pay_checkpoint,
        )
        .await?;

        if store.is_empty() {
            let genesis = genesis_state(&validators);
            let batch = UtxoStore::<E>::diffs_to_batch(&genesis.created, &genesis.deleted);
            store.apply_diffs(batch, None, "genesis bootstrap").await?;
        }

        let mut anchor_history_gauged = GaugedVecDeque::new(metrics.anchor_history_entries.clone());
        anchor_history_gauged.replace(anchor_history);

        Ok(Self {
            command_rx,
            event_tx,
            store,
            queue,
            anchor_index,
            anchor_history: anchor_history_gauged,
            next_anchor_sequence,
            finalization_index: Some(finalization_index),
            finalization_cursors: HashMap::new(),
            volatile_finalizations: GaugedIndexMap::new(metrics.finalization_cache_entries.clone()),
            payload_index: Some(payload_index),
            payload_cursors: HashMap::new(),
            volatile_payloads: GaugedIndexMap::new(metrics.payload_cache_entries.clone()),
            metrics,
        })
    }

    pub(super) async fn run(mut self, _context: &mut E) {
        self.metrics.worker_ready_total.inc();
        if let Some(pos) = self.store.last_committed_position {
            self.metrics.utxo_committed_position.set(pos as i64);
        }
        self.update_queue_depth().await;
        let root = self.store.root();
        let recovered_payloads = self.recover_payload_chain().await;
        if let Err(err) = self.event_tx.unbounded_send(Traced::capture(
            PersistenceEvent::Ready {
                root,
                recovered_payloads,
            },
        )) {
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
        // Box::pin to keep the Freezer close() futures off the run() stack.
        if let Err(err) = Box::pin(self.sync_on_shutdown()).await {
            Self::abort(err);
        }
    }

    async fn process_command(
        &mut self,
        command: Traced<PersistenceCommand>,
    ) -> Result<bool, Fatal> {
        let (command, parent_span) = command.into_parts();
        // Box::pin to keep the Freezer get/put/sync futures off the run() stack.
        Box::pin(self.handle_command(command))
            .instrument(parent_span)
            .await
    }

    async fn has_pending_work(&self) -> bool {
        !self.queue.is_empty().await
    }

    async fn update_queue_depth(&self) {
        let depth = self.queue.size().await.saturating_sub(self.queue.ack_floor());
        self.metrics.queue_depth.set(depth as i64);
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
            self.update_queue_depth().await;
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
        self.metrics.utxo_committed_position.set(position as i64);

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
        self.update_queue_depth().await;
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
            })?;
        self.update_queue_depth().await;
        Ok(())
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
                let _ = response.send(self.payload(payload).await);
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
                let _ = response.send(self.finalization(payload).await);
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

    async fn finalization(&mut self, payload: Digest) -> Option<mailbox::FinalizationResponse> {
        if let Some(finalization) = self.volatile_finalizations.get(&payload) {
            return Some(finalization.clone());
        }
        let identifier = match self.finalization_cursors.get(&payload) {
            Some(cursor) => FreezerIdentifier::Cursor(*cursor),
            None => FreezerIdentifier::Key(&payload),
        };
        let stored = self
            .finalization_index
            .as_ref()
            .expect("not shut down")
            .get(identifier)
            .await
            .ok()
            .flatten()
            .map(mailbox::FinalizationResponse::from);
        if let Some(ref finalization) = stored {
            self.cache_finalization(payload, finalization.clone());
        }
        stored
    }

    fn cache_finalization(&mut self, payload: Digest, finalization: mailbox::FinalizationResponse) {
        self.volatile_finalizations.insert(payload, finalization);
        for _ in self.volatile_finalizations.enforce_capacity(Self::MAX_VOLATILE_FINALIZATIONS) {
            self.metrics.finalization_cache_evictions_total.inc();
        }
    }

    async fn payload(&mut self, payload: Digest) -> Option<Bytes> {
        if let Some(bytes) = self.volatile_payloads.get(&payload) {
            return Some(bytes.clone());
        }
        let identifier = match self.payload_cursors.get(&payload) {
            Some(cursor) => FreezerIdentifier::Cursor(*cursor),
            None => FreezerIdentifier::Key(&payload),
        };
        let stored = self
            .payload_index
            .as_ref()
            .expect("not shut down")
            .get(identifier)
            .await
            .ok()
            .flatten()
            .map(Bytes::from);
        if let Some(ref bytes) = stored {
            self.cache_payload(payload, bytes.clone());
        }
        stored
    }

    fn cache_payload(&mut self, payload: Digest, bytes: Bytes) {
        self.volatile_payloads.insert(payload, bytes);
        for _ in self.volatile_payloads.enforce_capacity(Self::MAX_VOLATILE_PAYLOADS) {
            self.metrics.payload_cache_evictions_total.inc();
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
        for oldest in self.anchor_history.enforce_capacity(Self::MAX_ANCHOR_HISTORY) {
            self.anchor_index.remove(&U64::new(oldest.sequence));
            self.metrics.anchor_history_evictions_total.inc();
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

        let fin_identifier = match self.finalization_cursors.get(&payload) {
            Some(cursor) => FreezerIdentifier::Cursor(*cursor),
            None => FreezerIdentifier::Key(&payload),
        };
        let fin = self
            .finalization_index
            .as_ref()
            .expect("not shut down")
            .get(fin_identifier)
            .await
            .map_err(|err| {
                Fatal(format!(
                    "failed to read finalization index for {payload:?}: {err:?}"
                ))
            })?;
        if let Some(existing) = fin {
            if existing.as_slice() != finalization.as_slice() {
                return Err(Fatal(format!(
                    "conflicting stored finalization certificate for {payload:?}"
                )));
            }
            self.cache_finalization(payload, finalization);
            return Ok(());
        }
        let cursor = self
            .finalization_index
            .as_mut()
            .expect("not shut down")
            .put(payload, finalization.as_slice().to_vec())
            .await
            .map_err(|err| {
                Fatal(format!(
                    "failed to put finalization certificate for {payload:?}: {err:?}"
                ))
            })?;
        self.finalization_cursors.insert(payload, cursor);
        let cp = self
            .finalization_index
            .as_mut()
            .expect("not shut down")
            .sync()
            .await
            .map_err(|err| {
                Fatal(format!(
                    "failed to sync finalization certificate index for {payload:?}: {err:?}"
                ))
            })?;
        self.store.save_checkpoint(*FINALIZATION_CHECKPOINT_KEY, cp);
        self.store.cursor_index.sync().await.map_err(|err| {
            Fatal(format!(
                "failed to sync cursor index after finalization checkpoint for {payload:?}: {err:?}"
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

        let pay_identifier = match self.payload_cursors.get(&payload) {
            Some(cursor) => FreezerIdentifier::Cursor(*cursor),
            None => FreezerIdentifier::Key(&payload),
        };
        let existing = self
            .payload_index
            .as_ref()
            .expect("not shut down")
            .get(pay_identifier)
            .await
            .map_err(|err| {
                Fatal(format!(
                    "failed to read payload index for {payload:?}: {err:?}"
                ))
            })?;
        if let Some(existing) = existing {
            if existing.as_slice() != bytes.as_ref() {
                return Err(Fatal(format!(
                    "conflicting stored payload bytes for {payload:?}"
                )));
            }
            self.cache_payload(payload, bytes);
            return Ok(());
        }
        let cursor = self
            .payload_index
            .as_mut()
            .expect("not shut down")
            .put(payload, bytes.as_ref().to_vec())
            .await
            .map_err(|err| {
                Fatal(format!(
                    "failed to put payload for {payload:?}: {err:?}"
                ))
            })?;
        self.payload_cursors.insert(payload, cursor);
        let cp = self
            .payload_index
            .as_mut()
            .expect("not shut down")
            .sync()
            .await
            .map_err(|err| {
                Fatal(format!(
                    "failed to sync payload index for {payload:?}: {err:?}"
                ))
            })?;
        self.store.save_checkpoint(*PAYLOAD_CHECKPOINT_KEY, cp);
        self.store.cursor_index.sync().await.map_err(|err| {
            Fatal(format!(
                "failed to sync cursor index after payload checkpoint for {payload:?}: {err:?}"
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

    fn finalization_freezer_config(
        context: &E,
        partition_prefix: &str,
        page_cache_config: PageCacheConfig,
    ) -> FreezerConfig<(RangeCfg<usize>, ())> {
        let page_cache_size = NonZeroU16::new(page_cache_config.size)
            .unwrap_or(crate::execution::store::DEFAULT_PAGE_CACHE_SIZE);
        let page_cache_count = NonZeroUsize::new(page_cache_config.count)
            .unwrap_or(crate::execution::store::DEFAULT_PAGE_CACHE_COUNT);
        FreezerConfig {
            key_partition: format!("{partition_prefix}_fin_key"),
            key_write_buffer: NonZeroUsize::new(64 * 1024).unwrap(),
            key_page_cache: CacheRef::from_pooler(context, page_cache_size, page_cache_count),
            value_partition: format!("{partition_prefix}_fin_val"),
            value_compression: Some(3),
            value_write_buffer: NonZeroUsize::new(256 * 1024).unwrap(),
            value_target_size: 100 * 1024 * 1024,
            table_partition: format!("{partition_prefix}_fin_tbl"),
            table_initial_size: 65536,
            table_resize_frequency: 2,
            table_resize_chunk_size: 4096,
            table_replay_buffer: NonZeroUsize::new(64 * 1024).unwrap(),
            codec_config: ((0..=Self::MAX_FINALIZATION_RECORD_BYTES).into(), ()),
        }
    }

    fn payload_freezer_config(
        context: &E,
        partition_prefix: &str,
        page_cache_config: PageCacheConfig,
    ) -> FreezerConfig<(RangeCfg<usize>, ())> {
        let page_cache_size = NonZeroU16::new(page_cache_config.size)
            .unwrap_or(crate::execution::store::DEFAULT_PAGE_CACHE_SIZE);
        let page_cache_count = NonZeroUsize::new(page_cache_config.count)
            .unwrap_or(crate::execution::store::DEFAULT_PAGE_CACHE_COUNT);
        FreezerConfig {
            key_partition: format!("{partition_prefix}_pay_key"),
            key_write_buffer: NonZeroUsize::new(64 * 1024).unwrap(),
            key_page_cache: CacheRef::from_pooler(context, page_cache_size, page_cache_count),
            value_partition: format!("{partition_prefix}_pay_val"),
            value_compression: Some(3),
            value_write_buffer: NonZeroUsize::new(256 * 1024).unwrap(),
            value_target_size: 100 * 1024 * 1024,
            table_partition: format!("{partition_prefix}_pay_tbl"),
            table_initial_size: 65536,
            table_resize_frequency: 2,
            table_resize_chunk_size: 4096,
            table_replay_buffer: NonZeroUsize::new(64 * 1024).unwrap(),
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
        page_cache_config: PageCacheConfig,
        checkpoint: Option<FreezerCheckpoint>,
    ) -> Result<FinalizationIndex<E>, Fatal> {
        let config =
            Self::finalization_freezer_config(context, partition_prefix, page_cache_config);
        Freezer::init_with_checkpoint(
            context.with_label("finalization_index"),
            config,
            checkpoint,
        )
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
        page_cache_config: PageCacheConfig,
        checkpoint: Option<FreezerCheckpoint>,
    ) -> Result<PayloadIndex<E>, Fatal> {
        let config = Self::payload_freezer_config(context, partition_prefix, page_cache_config);
        Freezer::init_with_checkpoint(
            context.with_label("payload_index"),
            config,
            checkpoint,
        )
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

    /// Walk backward from the latest anchor through the payload Freezer,
    /// collecting all `(digest, bytes)` pairs in chain order (oldest first).
    /// Used at startup to proactively hydrate `AppCore.seen` before consensus
    /// begins, avoiding per-ancestor network round trips after an unclean
    /// restart.
    async fn recover_payload_chain(&mut self) -> Vec<(Digest, Bytes)> {
        let Some(tip) = self.anchor_history.back() else {
            return Vec::new();
        };
        let zero_digest = Digest::from([0u8; 32]);
        let mut chain = Vec::new();
        let mut current = tip.payload;
        loop {
            let Some(bytes) = self.payload(current).await else {
                warn!(
                    ?current,
                    recovered = chain.len(),
                    "payload chain walk stopped: missing payload in Freezer"
                );
                break;
            };
            let Some(block) = super::payload::SeenBlock::decode(bytes.clone()) else {
                warn!(
                    ?current,
                    recovered = chain.len(),
                    "payload chain walk stopped: malformed payload bytes"
                );
                break;
            };
            let parent = block.data().parent;
            chain.push((current, bytes));
            if parent == zero_digest {
                break;
            }
            current = parent;
        }
        chain.reverse();
        info!(
            payloads = chain.len(),
            "recovered payload chain from local persistence"
        );
        chain
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

        let fin_cp = self
            .finalization_index
            .take()
            .expect("not shut down")
            .close()
            .await
            .map_err(|err| {
                Fatal(format!(
                    "finalization index close on shutdown failed: {err:?}"
                ))
            })?;
        let pay_cp = self
            .payload_index
            .take()
            .expect("not shut down")
            .close()
            .await
            .map_err(|err| {
                Fatal(format!(
                    "payload index close on shutdown failed: {err:?}"
                ))
            })?;

        self.store
            .save_checkpoint(*FINALIZATION_CHECKPOINT_KEY, fin_cp);
        self.store
            .save_checkpoint(*PAYLOAD_CHECKPOINT_KEY, pay_cp);
        self.store.cursor_index.sync().await.map_err(|err| {
            Fatal(format!(
                "cursor index sync on shutdown failed: {err:?}"
            ))
        })
    }
}
