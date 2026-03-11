use super::{ProofResponse, metrics::PersistenceMetrics};
use crate::execution::store::{UtxoDb, utxo_db_config};
use crate::execution::{StateDiff, genesis_state};
use crate::trace::Traced;
use bytes::Buf;
use commonware_codec::{RangeCfg, ReadExt, ReadRangeExt, Write};
use commonware_consensus::types::Height;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::{
    Persistable,
    metadata::{Config as MetadataConfig, Metadata},
    queue::{Config as QueueConfig, Queue},
};
use commonware_utils::{channel::oneshot, sequence::U64};
use futures::{StreamExt, channel::mpsc};
use hellas_types::{Address, Coin, ObjectId};
use std::{
    collections::VecDeque,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::LazyLock,
};
use tracing::Instrument;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(super) struct Fatal(String);

pub(super) enum PersistenceCommand {
    Enqueue {
        height: Height,
        payload: Digest,
        diffs: StateDiff,
    },
    GetStateRoot {
        response: oneshot::Sender<Option<Digest>>,
    },
    GetProof {
        object: ObjectId,
        response: oneshot::Sender<Option<ProofResponse>>,
    },
    GetPersistedAnchors {
        response: oneshot::Sender<Vec<(Height, Digest, Digest)>>,
    },
    GetLatestBlock {
        response: oneshot::Sender<Option<(u64, Digest, Digest)>>,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
pub(super) enum PersistenceEvent {
    Ready {
        root: Digest,
    },
    Persisted {
        height: Height,
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

static QUEUE_CURSOR_KEY: LazyLock<Digest> = LazyLock::new(|| {
    let mut bytes = [0u8; 32];
    bytes[0] = b'q';
    bytes[1] = b'c';
    Digest::from(bytes)
});

struct UtxoStore<E: Clock + Spawner + Storage + Metrics + BufferPooler> {
    db: UtxoDb<E>,
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
                codec_config: ((0..=8).into(), ()),
            },
        )
        .await
        .map_err(|err| Fatal(format!("queue cursor init failed: {err:?}")))?;

        let last_committed_position =
            cursor_index.get(&*QUEUE_CURSOR_KEY).map(|bytes: &Vec<u8>| {
                let arr: [u8; 8] = bytes[..8]
                    .try_into()
                    .expect("queue cursor value is 8 bytes");
                u64::from_le_bytes(arr)
            });

        Ok(Self {
            db,
            cursor_index,
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
    ) -> Result<(), Fatal> {
        if batch.is_empty() {
            if let Some(pos) = queue_position {
                self.cursor_index
                    .put(*QUEUE_CURSOR_KEY, pos.to_le_bytes().to_vec());
                self.cursor_index.sync().await.map_err(|err| {
                    Fatal(format!("queue cursor sync failed for {label}: {err:?}"))
                })?;
                self.last_committed_position = Some(pos);
            }
            return Ok(());
        }

        let mut pending = self.db.new_batch();
        for (object_id, coin) in batch {
            pending = pending.write(object_id, coin);
        }
        let finalized = pending
            .merkleize(None)
            .await
            .map_err(|err| Fatal(format!("QMDB merkleize failed for {label}: {err:?}")))?
            .finalize();
        self.db
            .apply_batch(finalized)
            .await
            .map_err(|err| Fatal(format!("QMDB apply_batch failed for {label}: {err:?}")))?;
        self.db
            .sync()
            .await
            .map_err(|err| Fatal(format!("QMDB sync failed for {label}: {err:?}")))?;

        if let Some(pos) = queue_position {
            self.cursor_index
                .put(*QUEUE_CURSOR_KEY, pos.to_le_bytes().to_vec());
            self.cursor_index
                .sync()
                .await
                .map_err(|err| Fatal(format!("queue cursor sync failed for {label}: {err:?}")))?;
            self.last_committed_position = Some(pos);
        }

        Ok(())
    }

    fn root(&self) -> Digest {
        self.db.root()
    }

    fn is_empty(&self) -> bool {
        self.db.is_empty()
    }

    async fn key_value_proof(
        &self,
        hasher: &mut Sha256,
        object: ObjectId,
    ) -> Option<ProofResponse> {
        self.db.key_value_proof(hasher, object).await.ok()
    }

    async fn sync(&mut self) -> Result<(), Fatal> {
        self.db
            .sync()
            .await
            .map_err(|err| Fatal(format!("QMDB sync failed: {err:?}")))
    }
}

#[derive(Clone, Copy)]
struct AnchorEntry {
    sequence: u64,
    height: Height,
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
}

impl<E> PersistenceWorker<E>
where
    E: Clock + Spawner + Storage + Metrics + BufferPooler,
{
    const QUEUE_ITEMS_PER_SECTION: NonZeroU64 = NonZeroU64::new(256).unwrap();
    const QUEUE_WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(8192).unwrap();
    const MAX_QUEUE_ITEM_BYTES: usize = 1 << 20;
    const MAX_QUEUE_DIFF_ENTRIES: usize = 32_768;
    const MAX_ANCHOR_RECORD_BYTES: usize = 160;
    const MAX_ANCHOR_HISTORY: usize = 2048;

    pub(super) async fn create(
        context: &mut E,
        partition_prefix: String,
        page_cache_config: PageCacheConfig,
        genesis_allocations: Vec<(Address, u64)>,
        command_rx: mpsc::UnboundedReceiver<Traced<PersistenceCommand>>,
        event_tx: mpsc::UnboundedSender<Traced<PersistenceEvent>>,
        metrics: PersistenceMetrics,
    ) -> Result<Self, Fatal> {
        let queue = Self::initialize_queue(context, &partition_prefix, page_cache_config).await?;
        let mut store = UtxoStore::init(context, &partition_prefix, page_cache_config).await?;
        let (anchor_index, anchor_history, next_anchor_sequence) =
            Self::initialize_anchor_index(context, &partition_prefix).await?;

        if store.is_empty() {
            let genesis = genesis_state(&genesis_allocations);
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
        })
    }

    pub(super) async fn run(mut self, _context: &mut E) {
        self.metrics.worker_ready_total.inc();
        if let Some(pos) = self.store.last_committed_position {
            self.metrics.utxo_committed_position.set(pos as i64);
        }
        self.metrics
            .anchor_history_entries
            .set(self.anchor_history.len() as i64);
        self.update_queue_depth().await;

        if let Err(err) = self
            .event_tx
            .unbounded_send(Traced::capture(PersistenceEvent::Ready {
                root: self.store.root(),
            }))
        {
            warn!(
                ?err,
                "failed to notify application that persistence worker is ready"
            );
            return;
        }

        'outer: loop {
            loop {
                match self.command_rx.try_recv() {
                    Ok(command) => match self.process_command(command).await {
                        Ok(true) => {}
                        Ok(false) => break 'outer,
                        Err(err) => Self::abort(err),
                    },
                    Err(mpsc::TryRecvError::Closed) => break 'outer,
                    Err(mpsc::TryRecvError::Empty) => break,
                }
            }

            if self.has_pending_work().await {
                self = match self.persist_next_pending().await {
                    Ok(worker) => worker,
                    Err(err) => Self::abort(err),
                };
                continue;
            }

            let Some(command) = self.command_rx.next().await else {
                break;
            };
            match self.process_command(command).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(err) => Self::abort(err),
            }
        }

        if let Err(err) = self.shutdown().await {
            Self::abort(err);
        }
    }

    fn abort(err: Fatal) -> ! {
        error!(%err, "irrecoverable persistence error; aborting");
        std::process::abort();
    }

    async fn process_command(
        &mut self,
        command: Traced<PersistenceCommand>,
    ) -> Result<bool, Fatal> {
        let (command, parent_span) = command.into_parts();
        Box::pin(self.handle_command(command))
            .instrument(parent_span)
            .await
    }

    async fn has_pending_work(&self) -> bool {
        !self.queue.is_empty().await
    }

    async fn update_queue_depth(&self) {
        let depth = self
            .queue
            .size()
            .await
            .saturating_sub(self.queue.ack_floor());
        self.metrics.queue_depth.set(depth as i64);
    }

    #[tracing::instrument(
        name = "app.persistence.persist_next_pending",
        level = "info",
        skip_all
    )]
    async fn persist_next_pending(mut self) -> Result<Self, Fatal> {
        let (position, encoded) = match self.queue.dequeue().await {
            Ok(Some(item)) => item,
            Ok(None) => return Ok(self),
            Err(err) => {
                return Err(Fatal(format!(
                    "failed to dequeue persistence intent: {err:?}"
                )));
            }
        };

        let Some((height, payload, diffs)) = Self::decode_queue_item(encoded.as_slice()) else {
            return Err(Fatal(format!(
                "invalid persistence queue item at position {position}"
            )));
        };

        if self.store.was_committed(position) {
            info!(height = %height, ?payload, position, "skipping already-committed queue item");
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
            let root = self.store.root();
            self.record_persisted_anchor(height, payload, root).await?;
            self.metrics.persist_success_total.inc();
            self.update_queue_depth().await;
            let _ = self
                .event_tx
                .unbounded_send(Traced::capture(PersistenceEvent::Persisted {
                    height,
                    payload,
                    root,
                }));
            return Ok(self);
        }

        self.metrics.persist_attempt_total.inc();
        let batch = UtxoStore::<E>::diffs_to_batch(&diffs.created, &diffs.deleted);
        self.store
            .apply_diffs(batch, Some(position), &format!("{payload:?}"))
            .await?;

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
        self.update_queue_depth().await;

        let root = self.store.root();
        self.record_persisted_anchor(height, payload, root).await?;
        self.metrics.persist_success_total.inc();

        if let Err(err) =
            self.event_tx
                .unbounded_send(Traced::capture(PersistenceEvent::Persisted {
                    height,
                    payload,
                    root,
                }))
        {
            warn!(
                ?err,
                ?payload,
                "failed to notify application of persisted block"
            );
        }

        Ok(self)
    }

    async fn enqueue_pending(
        &mut self,
        height: Height,
        payload: Digest,
        diffs: &StateDiff,
    ) -> Result<(), Fatal> {
        let encoded = Self::encode_queue_item(height, payload, diffs);
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

    fn encode_queue_item(height: Height, payload: Digest, diffs: &StateDiff) -> Vec<u8> {
        let mut encoded = Vec::new();
        height.write(&mut encoded);
        payload.write(&mut encoded);
        diffs.created.write(&mut encoded);
        diffs.deleted.write(&mut encoded);
        encoded
    }

    fn decode_queue_item(encoded: &[u8]) -> Option<(Height, Digest, StateDiff)> {
        let mut reader = encoded;
        let height = Height::read(&mut reader).ok()?;
        let payload = Digest::read(&mut reader).ok()?;
        let created =
            Vec::<(ObjectId, Coin)>::read_range(&mut reader, 0..=Self::MAX_QUEUE_DIFF_ENTRIES)
                .ok()?;
        let deleted =
            Vec::<ObjectId>::read_range(&mut reader, 0..=Self::MAX_QUEUE_DIFF_ENTRIES).ok()?;
        if reader.has_remaining() {
            return None;
        }
        Some((height, payload, StateDiff { created, deleted }))
    }

    fn encode_anchor_record(height: Height, payload: Digest, root: Digest) -> Vec<u8> {
        let mut encoded = Vec::new();
        height.write(&mut encoded);
        payload.write(&mut encoded);
        root.write(&mut encoded);
        encoded
    }

    fn decode_anchor_record(encoded: &[u8]) -> Option<(Height, Digest, Digest)> {
        let mut reader = encoded;
        let height = Height::read(&mut reader).ok()?;
        let payload = Digest::read(&mut reader).ok()?;
        let root = Digest::read(&mut reader).ok()?;
        if reader.has_remaining() {
            return None;
        }
        Some((height, payload, root))
    }

    async fn handle_command(&mut self, command: PersistenceCommand) -> Result<bool, Fatal> {
        match command {
            PersistenceCommand::Enqueue {
                height,
                payload,
                diffs,
            } => {
                self.metrics.enqueue_commands_total.inc();
                self.enqueue_pending(height, payload, &diffs).await?;
                Ok(true)
            }
            PersistenceCommand::GetStateRoot { response } => {
                let _ = response.send(Some(self.store.root()));
                Ok(true)
            }
            PersistenceCommand::GetProof { object, response } => {
                let _ = response.send(self.proof_for_object(object).await);
                Ok(true)
            }
            PersistenceCommand::GetPersistedAnchors { response } => {
                let _ = response.send(self.persisted_anchor_history());
                Ok(true)
            }
            PersistenceCommand::GetLatestBlock { response } => {
                let result = self
                    .anchor_history
                    .back()
                    .map(|entry| (entry.height.get(), entry.payload, entry.root));
                let _ = response.send(result);
                Ok(true)
            }
            PersistenceCommand::Shutdown { response } => {
                let _ = response.send(());
                Ok(false)
            }
        }
    }

    async fn proof_for_object(&self, object: ObjectId) -> Option<ProofResponse> {
        let mut hasher = Sha256::default();
        self.store.key_value_proof(&mut hasher, object).await
    }

    fn persisted_anchor_history(&self) -> Vec<(Height, Digest, Digest)> {
        self.anchor_history
            .iter()
            .map(|entry| (entry.height, entry.payload, entry.root))
            .collect()
    }

    async fn record_persisted_anchor(
        &mut self,
        height: Height,
        payload: Digest,
        root: Digest,
    ) -> Result<(), Fatal> {
        if let Some(existing) = self
            .anchor_history
            .iter()
            .find(|entry| entry.payload == payload)
        {
            if existing.root != root || existing.height != height {
                return Err(Fatal(format!(
                    "conflicting persisted anchor for {payload:?}: existing=(height={}, root={:?}) new=(height={}, root={root:?})",
                    existing.height, existing.root, height
                )));
            }
            return Ok(());
        }

        let sequence = self.next_anchor_sequence;
        self.next_anchor_sequence = self
            .next_anchor_sequence
            .checked_add(1)
            .ok_or_else(|| Fatal("anchor sequence counter overflowed".into()))?;

        self.anchor_history.push_back(AnchorEntry {
            sequence,
            height,
            payload,
            root,
        });

        self.anchor_index.put(
            U64::new(sequence),
            Self::encode_anchor_record(height, payload, root),
        );
        while self.anchor_history.len() > Self::MAX_ANCHOR_HISTORY {
            let Some(oldest) = self.anchor_history.pop_front() else {
                break;
            };
            self.anchor_index.remove(&U64::new(oldest.sequence));
            self.metrics.anchor_history_evictions_total.inc();
        }

        self.anchor_index.sync().await.map_err(|err| {
            Fatal(format!(
                "failed to sync persisted anchor index for {payload:?}: {err:?}"
            ))
        })?;
        self.metrics
            .anchor_history_entries
            .set(self.anchor_history.len() as i64);
        Ok(())
    }

    fn anchor_metadata_config(partition_prefix: &str) -> MetadataConfig<(RangeCfg<usize>, ())> {
        MetadataConfig {
            partition: format!("{partition_prefix}_anchor_roots"),
            codec_config: ((0..=Self::MAX_ANCHOR_RECORD_BYTES).into(), ()),
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
            let Some((height, payload, root)) = Self::decode_anchor_record(encoded.as_slice())
            else {
                warn!(sequence, "invalid anchor index entry; removing");
                index.remove(&key);
                continue;
            };
            recovered.push_back(AnchorEntry {
                sequence,
                height,
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
        index
            .sync()
            .await
            .map_err(|err| Fatal(format!("failed to sync recovered anchor index: {err:?}")))?;
        Ok((index, recovered, next_sequence))
    }

    async fn initialize_queue(
        context: &mut E,
        partition_prefix: &str,
        page_cache_config: PageCacheConfig,
    ) -> Result<PersistenceQueue<E>, Fatal> {
        let config = Self::queue_config(context, partition_prefix, page_cache_config);
        PersistenceQueue::init(context.with_label("persistence_queue"), config)
            .await
            .map_err(|err| Fatal(format!("persistence queue initialization failed: {err:?}")))
    }

    async fn shutdown(mut self) -> Result<(), Fatal> {
        self.queue.sync().await.map_err(|err| {
            Fatal(format!(
                "persistence queue sync on shutdown failed: {err:?}"
            ))
        })?;
        self.store.sync().await?;
        self.anchor_index
            .sync()
            .await
            .map_err(|err| Fatal(format!("anchor index sync on shutdown failed: {err:?}")))?;
        Ok(())
    }
}
