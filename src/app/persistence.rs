use super::mailbox;
use crate::execution::store::{UtxoDb, utxo_db_config};
use crate::execution::{FinalizationDiffs, genesis_state};
use crate::object::{Coin, ObjectId};
use bytes::Buf;
use commonware_codec::{RangeCfg, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::{
    Persistable,
    queue::{Config as QueueConfig, Queue},
};
use commonware_utils::{SystemTimeExt, channel::oneshot};
use futures::{StreamExt, channel::mpsc};
use hellas_types::PublicKey;
use std::{
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::Duration,
};

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
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

#[derive(Clone, Copy)]
pub(super) enum PersistenceEvent {
    Persisted { payload: Digest },
}

#[derive(Clone, Copy)]
pub(super) struct PageCacheConfig {
    pub(super) size: u16,
    pub(super) count: usize,
}

type PersistenceQueue<E> = Queue<E, Vec<u8>>;

pub(super) struct PersistenceWorker<E>
where
    E: Clock + Spawner + Storage + Metrics,
{
    partition_prefix: String,
    page_cache: PageCacheConfig,
    validators: Vec<PublicKey>,
    command_rx: mpsc::UnboundedReceiver<PersistenceCommand>,
    event_tx: mpsc::UnboundedSender<PersistenceEvent>,
    pending: Option<(Digest, FinalizationDiffs)>,
    retry_delay: Duration,
    next_retry_at_ms: Option<u64>,
    db: Option<UtxoDb<E>>,
    queue: Option<PersistenceQueue<E>>,
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
    const QUEUE_WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(4096).unwrap();
    const MAX_QUEUE_ITEM_BYTES: usize = 1 << 20;
    const MAX_QUEUE_DIFF_ENTRIES: usize = 32_768;

    pub(super) fn new(
        partition_prefix: String,
        page_cache: PageCacheConfig,
        validators: Vec<PublicKey>,
        command_rx: mpsc::UnboundedReceiver<PersistenceCommand>,
        event_tx: mpsc::UnboundedSender<PersistenceEvent>,
        #[cfg(test)] persistence_failures_remaining: usize,
    ) -> Self {
        Self {
            partition_prefix,
            page_cache,
            validators,
            command_rx,
            event_tx,
            pending: None,
            retry_delay: Self::RETRY_BASE,
            next_retry_at_ms: None,
            db: None,
            queue: None,
            #[cfg(test)]
            persistence_failures_remaining,
        }
    }

    pub(super) async fn run(mut self, context: &mut E) {
        self.initialize_queue(context).await;
        self.initialize_db(context).await;
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
                    if !self.handle_command(command).await {
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
                    if !self.handle_command(command).await {
                        return false;
                    }
                }
                Ok(None) => return false,
                Err(_) => return true,
            }
        }
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

    async fn persist_next_pending(&mut self, context: &mut E, now_ms: u64) {
        if let Some((payload, diffs)) = self.pending.take() {
            if !self.enqueue_pending_intent(payload, &diffs).await {
                self.pending = Some((payload, diffs));
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

        if !self.apply_diffs_to_db(context, &diffs, true).await {
            warn!(?payload, "failed to persist finalized state");
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
            self.schedule_retry(now_ms);
            return;
        }

        self.clear_retry();
        if let Err(err) = self
            .event_tx
            .unbounded_send(PersistenceEvent::Persisted { payload })
        {
            warn!(
                ?err,
                ?payload,
                "failed to notify application of persisted finalization"
            );
        }
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

    async fn handle_command(&mut self, command: PersistenceCommand) -> bool {
        match command {
            PersistenceCommand::Enqueue { payload, diffs } => {
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
            PersistenceCommand::Shutdown { response } => {
                let _ = response.send(());
                false
            }
        }
    }

    async fn apply_diffs_to_db(
        &mut self,
        context: &mut E,
        diffs: &FinalizationDiffs,
        _inject_failures: bool,
    ) -> bool {
        #[cfg(test)]
        if _inject_failures && self.persistence_failures_remaining > 0 {
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
        let _ = self.apply_diffs_to_db(context, &diffs, false).await;
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
    }
}
