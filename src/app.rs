mod block;
mod metrics;
mod persistence;

pub use block::HellasBlock;
pub type ProofResponse = commonware_storage::qmdb::current::proof::OperationProof<Digest, 32>;

use crate::execution::{
    ExecutionEngine, ExecutionQueryError, StateDiff, execute_block, execute_transaction,
    genesis_state,
};
use crate::gauged::{GaugedIndexMap, GaugedVecDeque};
use crate::trace::Traced;
use block::ValidationError;
use commonware_codec::Encode;
use commonware_consensus::{
    Application as ConsensusApplication, Block as _, Heightable, Reporter, VerifyingApplication,
    marshal::{
        self, Update, ancestry::AncestorStream, core::Mailbox as MarshalCoreMailbox, standard,
    },
    types::{Context, Height},
};
use commonware_cryptography::{Digestible, sha256::Digest};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use commonware_storage::archive::{Archive, Identifier as ArchiveIdentifier, immutable};
use commonware_utils::{
    SystemTimeExt,
    acknowledgement::{Acknowledgement, Exact},
    channel::oneshot,
    sync::AsyncMutex,
};
use futures::{StreamExt, channel::mpsc};
use hellas_types::rpc::{LatestBlock, QueryError};
use hellas_types::{
    Activity, Address, Coin, MAX_TXS_PER_BLOCK, ObjectId, PublicKey, Scheme, Transaction,
};
use indexmap::IndexMap;
use metrics::{ApplicationMetrics, PersistenceMetrics};
use persistence::{PageCacheConfig, PersistenceCommand, PersistenceEvent, PersistenceWorker};
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::sync::oneshot as tokio_oneshot;

pub(crate) type MarshalVariant = standard::StandardMinimmit<HellasBlock, Scheme>;
pub(crate) type MarshalMailbox = MarshalCoreMailbox<MarshalVariant>;

pub(crate) struct ApplicationConfig {
    pub page_cache_size: u16,
    pub page_cache_count: usize,
    pub min_propose_delay: Duration,
    pub execution_retention_depth: usize,
}

impl Default for ApplicationConfig {
    fn default() -> Self {
        Self {
            page_cache_size: crate::execution::store::DEFAULT_PAGE_CACHE_SIZE.get(),
            page_cache_count: crate::execution::store::DEFAULT_PAGE_CACHE_COUNT.get(),
            min_propose_delay: Duration::ZERO,
            execution_retention_depth: 10,
        }
    }
}

#[derive(Clone)]
pub struct TraceReporter;

impl Reporter for TraceReporter {
    type Activity = Activity;

    async fn report(&mut self, activity: Self::Activity) {
        debug!(activity = ?activity);
    }
}

#[derive(Clone)]
struct PersistenceClient {
    tx: mpsc::UnboundedSender<Traced<PersistenceCommand>>,
}

impl PersistenceClient {
    fn send(&self, command: PersistenceCommand) {
        if self.tx.unbounded_send(Traced::capture(command)).is_err() {
            error!("persistence worker channel closed; aborting");
            std::process::abort();
        }
    }

    async fn query<R, F>(&self, build: F) -> R
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

    async fn state_root(&self) -> Option<Digest> {
        self.query(|response| PersistenceCommand::GetStateRoot { response })
            .await
    }

    async fn proof_for_object(&self, object: ObjectId) -> Option<ProofResponse> {
        self.query(move |response| PersistenceCommand::GetProof { object, response })
            .await
    }

    async fn persisted_anchors(&self) -> Vec<(Height, Digest, Digest)> {
        self.query(|response| PersistenceCommand::GetPersistedAnchors { response })
            .await
    }

    async fn latest_block(&self) -> Option<(u64, Digest, Digest)> {
        self.query(|response| PersistenceCommand::GetLatestBlock { response })
            .await
    }

    fn enqueue(&self, height: Height, payload: Digest, diffs: StateDiff) {
        self.send(PersistenceCommand::Enqueue {
            height,
            payload,
            diffs,
        });
    }

    async fn shutdown(&self) {
        let (response, receiver) = oneshot::channel();
        if let Err(err) = self
            .tx
            .unbounded_send(Traced::capture(PersistenceCommand::Shutdown { response }))
        {
            warn!(?err, "failed to signal persistence worker shutdown");
            return;
        }
        if let Err(err) = receiver.await {
            warn!(?err, "persistence worker dropped shutdown response");
        }
    }
}

struct PendingPersistence {
    block: HellasBlock,
    diffs: StateDiff,
    ack: Exact,
}

struct AppState {
    blocks: IndexMap<Digest, HellasBlock>,
    execution: ExecutionEngine,
    persisted_roots: GaugedIndexMap<Digest, Digest>,
    latest_anchor: Option<(Height, Digest, Digest)>,
    mempool: GaugedVecDeque<Transaction>,
    pending_anchor_waiters: IndexMap<Digest, Vec<tokio_oneshot::Sender<()>>>,
    pending_persistence: Option<PendingPersistence>,
    startup_root: Digest,
    metrics: ApplicationMetrics,
}

impl AppState {
    const MAX_PERSISTED_ROOTS: usize = 2048;

    fn new(
        genesis_allocations: Vec<(Address, u64)>,
        startup_root: Digest,
        execution_retention_depth: usize,
        metrics: ApplicationMetrics,
    ) -> Self {
        let mempool = GaugedVecDeque::new(metrics.mempool_size.clone());
        let persisted_roots = GaugedIndexMap::new(metrics.persisted_roots.clone());
        let genesis = HellasBlock::genesis(hellas_types::EPOCH);
        let execution = ExecutionEngine::from_genesis(
            genesis.digest(),
            genesis_state(&genesis_allocations),
            execution_retention_depth,
        );
        let mut state = Self {
            blocks: IndexMap::new(),
            execution,
            persisted_roots,
            latest_anchor: None,
            mempool,
            pending_anchor_waiters: IndexMap::new(),
            pending_persistence: None,
            startup_root,
            metrics,
        };
        state.note_block(genesis);
        state
    }

    fn genesis_block(&self) -> HellasBlock {
        HellasBlock::genesis(hellas_types::EPOCH)
    }

    fn has_execution(&self, digest: Digest) -> bool {
        self.execution.contains_payload(digest)
    }

    fn persisted_root(&self, payload: Digest) -> Option<Digest> {
        self.persisted_roots.get(&payload).copied()
    }

    fn ensure_genesis_anchor_root(&mut self) {
        if self.persisted_roots.is_empty() {
            let genesis = self.genesis_block();
            self.note_persisted_root(genesis.height(), genesis.digest(), self.startup_root);
            self.metrics.genesis_anchor_seeded_total.inc();
        }
    }

    fn note_block(&mut self, block: HellasBlock) {
        let digest = block.digest();
        if let Some(existing) = self.blocks.get(&digest) {
            if existing.encode() != block.encode() {
                error!(
                    ?digest,
                    "digest collision detected for block contents; aborting"
                );
                std::process::abort();
            }
            return;
        }
        self.blocks.insert(digest, block);
    }

    fn note_blocks(&mut self, blocks: &[HellasBlock]) {
        for block in blocks {
            self.note_block(block.clone());
        }
    }

    fn ensure_execution_materialized(&mut self, digest: Digest) -> bool {
        self.execution.ensure_executed(digest, &|candidate| {
            let block = self.blocks.get(&candidate)?;
            Some((block.parent(), block.txs().to_vec()))
        })
    }

    fn note_persisted_root(&mut self, height: Height, payload: Digest, root: Digest) {
        self.persisted_roots.insert(payload, root);
        for _ in self
            .persisted_roots
            .enforce_capacity(Self::MAX_PERSISTED_ROOTS)
        {}
        self.latest_anchor = Some((height, payload, root));
        self.wake_anchor_waiters(payload);
    }

    fn wake_anchor_waiters(&mut self, payload: Digest) {
        for waiter in self
            .pending_anchor_waiters
            .shift_remove(&payload)
            .unwrap_or_default()
        {
            let _ = waiter.send(());
        }
    }

    fn wait_for_anchor(&mut self, payload: Digest) -> tokio_oneshot::Receiver<()> {
        let (tx, rx) = tokio_oneshot::channel();
        self.pending_anchor_waiters
            .entry(payload)
            .or_default()
            .push(tx);
        rx
    }

    fn queue_persistence(&mut self, block: HellasBlock, diffs: StateDiff, ack: Exact) {
        if self.pending_persistence.is_some() {
            error!("received a second finalized block while persistence was inflight; aborting");
            std::process::abort();
        }
        self.pending_persistence = Some(PendingPersistence { block, diffs, ack });
        self.metrics.persistence_dispatch_total.inc();
        self.metrics.inflight_persistence.set(1);
    }

    fn on_persisted(&mut self, height: Height, payload: Digest, root: Digest) {
        self.metrics.persistence_ack_total.inc();
        let Some(pending) = self.pending_persistence.take() else {
            self.metrics.persistence_ack_unexpected_total.inc();
            warn!(?payload, "received persistence ack with no inflight block");
            return;
        };
        if pending.block.digest() != payload || pending.block.height() != height {
            self.metrics.persistence_ack_unexpected_total.inc();
            warn!(
                expected_payload = ?pending.block.digest(),
                expected_height = %pending.block.height(),
                ?payload,
                persisted_height = %height,
                "received persistence ack for unexpected block"
            );
            self.pending_persistence = Some(pending);
            return;
        }

        self.metrics
            .finalization_timestamp_drift
            .set((root_timestamp_now() as i64).wrapping_sub(pending.block.timestamp() as i64));
        match self.execution.diff(payload) {
            Some(recorded) if recorded == &pending.diffs => {}
            Some(_) => {
                error!(
                    ?payload,
                    "persisted diff does not match execution overlay; aborting"
                );
                std::process::abort();
            }
            None => {
                error!(
                    ?payload,
                    "persisted payload missing execution overlay; aborting"
                );
                std::process::abort();
            }
        }
        let pruned = self.execution.finalize(payload);
        self.note_persisted_root(height, payload, root);
        for digest in pruned {
            self.blocks.shift_remove(&digest);
        }
        self.metrics.inflight_persistence.set(0);
        pending.ack.acknowledge();
    }

    fn get_coin(
        &mut self,
        payload: Digest,
        object: ObjectId,
    ) -> Result<Option<Coin>, ExecutionQueryError> {
        self.execution.get_coin(payload, object)
    }

    fn build_block(
        &mut self,
        context: &Context<Digest, PublicKey>,
        now: u64,
    ) -> Option<HellasBlock> {
        self.metrics.propose_total.inc();
        self.ensure_genesis_anchor_root();

        let parent = self.blocks.get(&context.parent.1)?.clone();
        if !self.ensure_execution_materialized(parent.digest()) {
            return None;
        }
        let parent_state = self.execution.state_clone(parent.digest())?;

        let (anchor_height, anchor_payload, anchor_root) = self
            .latest_anchor
            .or_else(|| {
                let genesis = self.genesis_block();
                self.persisted_root(genesis.digest())
                    .map(|root| (Height::zero(), genesis.digest(), root))
            })
            .or_else(|| {
                self.persisted_root(parent.digest())
                    .map(|root| (parent.height(), parent.digest(), root))
            })?;

        let proposal_timestamp = now.max(parent.timestamp());
        let mut txs = Vec::new();
        let mut running_state = parent_state.clone();
        let mut retained = std::collections::VecDeque::new();
        while let Some(tx) = self.mempool.pop_front() {
            if txs.len() >= MAX_TXS_PER_BLOCK {
                retained.push_back(tx);
                continue;
            }
            match execute_transaction(&mut running_state, &tx) {
                Ok(()) => txs.push(tx),
                Err(crate::execution::ExecutionError::ObjectNotFound { .. }) => {
                    retained.push_back(tx);
                }
                Err(err) => {
                    warn!(?err, "dropping permanently invalid tx from mempool");
                }
            }
        }
        self.mempool.replace(retained);

        let height = parent.height().next();
        let block = HellasBlock::new(
            height,
            context.round,
            parent.digest(),
            proposal_timestamp,
            anchor_payload,
            anchor_root,
            txs.clone(),
        );
        self.note_block(block.clone());

        match execute_block(&parent_state, &txs) {
            Ok(exec) => self
                .execution
                .insert_executed(block.digest(), parent.digest(), exec),
            Err(err) => {
                error!(
                    ?err,
                    height = %block.height(),
                    ?anchor_height,
                    "failed to execute locally built block; aborting"
                );
                std::process::abort();
            }
        }

        Some(block)
    }

    fn verify_block(
        &mut self,
        context: &Context<Digest, PublicKey>,
        block: &HellasBlock,
        now: u64,
        local_anchor_root: Digest,
    ) -> bool {
        self.metrics.verify_requests_total.inc();
        let Some(parent) = self.blocks.get(&block.parent()).cloned() else {
            warn!(parent = ?block.parent(), "missing parent block during verify");
            self.metrics.verify_invalid_total.inc();
            return false;
        };
        if !self.ensure_execution_materialized(parent.digest()) {
            warn!(parent = ?parent.digest(), "missing parent execution during verify");
            self.metrics.verify_invalid_total.inc();
            return false;
        }
        let Some(parent_state) = self.execution.state_clone(parent.digest()) else {
            self.metrics.verify_invalid_total.inc();
            return false;
        };

        if let Err(err) = block.validate(
            parent.height().next(),
            context.round,
            context.parent.1,
            now,
            parent.timestamp(),
            local_anchor_root,
        ) {
            if matches!(err, ValidationError::AnchorRootMismatch { .. }) {
                self.metrics.anchor_mismatch_total.inc();
            }
            warn!(%err, payload = ?block.digest(), "block validation failed");
            self.metrics.verify_invalid_total.inc();
            return false;
        }

        self.metrics
            .validation_timestamp_drift
            .set((now as i64).wrapping_sub(block.timestamp() as i64));

        if self.execution.contains_payload(block.digest()) {
            self.metrics.verify_valid_total.inc();
            return true;
        }

        match execute_block(&parent_state, block.txs()) {
            Ok(exec) => {
                self.execution
                    .insert_executed(block.digest(), parent.digest(), exec);
                self.metrics.verify_valid_total.inc();
                true
            }
            Err(err) => {
                warn!(?err, payload = ?block.digest(), "block execution failed");
                self.metrics.verify_invalid_total.inc();
                false
            }
        }
    }

    fn restore_block(&mut self, block: HellasBlock) {
        self.note_block(block.clone());
        let parent = block.parent();
        let Some(parent_state) = self.execution.state_clone(parent) else {
            error!(
                parent = ?parent,
                height = %block.height(),
                "missing parent execution while restoring finalized chain; aborting"
            );
            std::process::abort();
        };
        let exec = execute_block(&parent_state, block.txs()).unwrap_or_else(|err| {
            error!(?err, height = %block.height(), "failed to replay finalized block; aborting");
            std::process::abort();
        });
        self.execution.insert_executed(block.digest(), parent, exec);
        let pruned = self.execution.finalize(block.digest());
        for digest in pruned {
            self.blocks.shift_remove(&digest);
        }
    }
}

#[derive(Clone)]
pub struct Application {
    inner: Arc<AsyncMutex<AppState>>,
    persistence: PersistenceClient,
    marshal: Arc<OnceLock<MarshalMailbox>>,
    min_propose_delay: Duration,
}

impl Application {
    pub(crate) async fn new<E>(
        context: E,
        _me: &PublicKey,
        genesis_allocations: Vec<(Address, u64)>,
        partition_prefix: String,
        config: ApplicationConfig,
        finalized_blocks: &immutable::Archive<E, Digest, HellasBlock>,
    ) -> Self
    where
        E: Clock + Spawner + Storage + Metrics + BufferPooler,
    {
        let page_cache_config = PageCacheConfig {
            size: config.page_cache_size,
            count: config.page_cache_count,
        };
        let app_metrics = ApplicationMetrics::register(&context.with_label("app"));
        let persistence_metrics = PersistenceMetrics::register(&context.with_label("persistence"));
        let (tx, cmd_rx) = mpsc::unbounded();
        let (event_tx, mut event_rx) = mpsc::unbounded();
        let persistence = PersistenceClient { tx };

        let worker_context = context.clone();
        let worker_genesis_allocations = genesis_allocations.clone();
        worker_context.clone().spawn(move |mut wc| async move {
            let worker = match PersistenceWorker::create(
                &mut wc,
                partition_prefix,
                page_cache_config,
                worker_genesis_allocations,
                cmd_rx,
                event_tx,
                persistence_metrics,
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

        let ready = match event_rx.next().await {
            Some(event) => {
                let (event, _) = event.into_parts();
                event
            }
            None => {
                error!("persistence worker event channel closed before ready");
                std::process::abort();
            }
        };
        let PersistenceEvent::Ready { root } = ready else {
            unreachable!("first persistence event must be Ready");
        };

        let mut state = AppState::new(
            genesis_allocations,
            root,
            config.execution_retention_depth,
            app_metrics,
        );
        let anchors = persistence.persisted_anchors().await;
        for (height, payload, anchor_root) in &anchors {
            state.note_persisted_root(*height, *payload, *anchor_root);
        }
        if let Some((latest_height, _, _)) = anchors.last().copied() {
            Self::recover_persisted_chain(&mut state, finalized_blocks, latest_height).await;
        }

        let application = Self {
            inner: Arc::new(AsyncMutex::new(state)),
            persistence: persistence.clone(),
            marshal: Arc::new(OnceLock::new()),
            min_propose_delay: config.min_propose_delay,
        };

        let app_for_events = application.clone();
        context.clone().spawn(move |_| async move {
            while let Some(traced) = event_rx.next().await {
                let (event, _) = traced.into_parts();
                if let PersistenceEvent::Persisted {
                    height,
                    payload,
                    root,
                } = event
                {
                    let mut inner = app_for_events.inner.lock().await;
                    inner.on_persisted(height, payload, root);
                }
            }
        });

        let shutdown_client = persistence.clone();
        context.spawn(move |ctx| async move {
            let _ = ctx.stopped().await;
            shutdown_client.shutdown().await;
        });

        application
    }

    async fn recover_persisted_chain<E>(
        state: &mut AppState,
        finalized_blocks: &immutable::Archive<E, Digest, HellasBlock>,
        latest_height: Height,
    ) where
        E: Clock + Storage + Metrics + BufferPooler,
    {
        for index in 1..=latest_height.get() {
            let height = Height::new(index);
            let Some(block) = finalized_blocks
                .get(ArchiveIdentifier::Index(height.get()))
                .await
                .expect("failed to recover finalized block")
            else {
                error!(height = %height, "missing finalized block during recovery; aborting");
                std::process::abort();
            };
            state.restore_block(block);
        }
    }

    pub(crate) fn attach_marshal(&self, mailbox: MarshalMailbox) {
        if self.marshal.set(mailbox).is_err() {
            error!("marshal mailbox attached twice; aborting");
            std::process::abort();
        }
    }

    fn marshal(&self) -> &MarshalMailbox {
        self.marshal
            .get()
            .expect("marshal mailbox must be attached before use")
    }

    pub async fn submit_tx(&self, tx: Transaction) {
        let mut inner = self.inner.lock().await;
        inner.mempool.push_back(tx);
    }

    pub async fn get_state_root(&self) -> Option<Digest> {
        self.persistence.state_root().await
    }

    pub async fn get_proof(&self, object: ObjectId) -> Option<ProofResponse> {
        self.persistence.proof_for_object(object).await
    }

    pub async fn get_finalization(&self, payload: Digest) -> Option<Vec<u8>> {
        let (height, _) = self.marshal().get_info(&payload).await?;
        self.marshal()
            .get_finalization(height)
            .await
            .map(|finalization| finalization.encode().to_vec())
    }

    pub async fn get_latest_block(&self) -> Option<LatestBlock> {
        self.persistence
            .latest_block()
            .await
            .map(|(height, payload, root)| LatestBlock {
                height,
                payload,
                state_root: root,
            })
    }

    pub async fn get_coin(
        &self,
        payload: Digest,
        object: ObjectId,
    ) -> Result<Option<Coin>, QueryError> {
        let mut inner = self.inner.lock().await;
        inner
            .get_coin(payload, object)
            .map_err(|err| QueryError::StateUnavailable(err.to_string()))
    }

    pub async fn get_coins_by_owner(&self, owner: Address) -> Vec<(ObjectId, u64)> {
        let inner = self.inner.lock().await;
        inner.execution.coins_by_owner(&owner)
    }

    async fn collect_relevant_ancestry<A>(
        &self,
        ancestry: &mut AncestorStream<A, HellasBlock>,
    ) -> Vec<HellasBlock>
    where
        A: marshal::ancestry::BlockProvider<Block = HellasBlock>,
    {
        let mut blocks = Vec::new();
        while let Some(block) = ancestry.next().await {
            let stop = {
                let inner = self.inner.lock().await;
                inner.has_execution(block.parent()) || block.height() <= Height::new(1)
            };
            blocks.push(block);
            if stop {
                break;
            }
        }
        blocks
    }
}

impl<E> ConsensusApplication<E> for Application
where
    E: rand::Rng + Spawner + Metrics + Clock,
{
    type SigningScheme = Scheme;
    type Context = Context<Digest, PublicKey>;
    type Block = HellasBlock;

    async fn genesis(&mut self) -> Self::Block {
        let mut inner = self.inner.lock().await;
        inner.ensure_genesis_anchor_root();
        inner.genesis_block()
    }

    async fn propose<A: marshal::ancestry::BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
    ) -> Option<Self::Block> {
        let (runtime, consensus_context) = context;
        if !self.min_propose_delay.is_zero() {
            {
                let inner = self.inner.lock().await;
                inner.metrics.propose_throttled_total.inc();
            }
            runtime.sleep(self.min_propose_delay).await;
        }

        let recovered = self.collect_relevant_ancestry(&mut ancestry).await;
        let Some(parent) = recovered.first().cloned() else {
            return None;
        };

        let mut inner = self.inner.lock().await;
        inner.note_blocks(&recovered);
        if !inner.ensure_execution_materialized(parent.digest()) {
            warn!(
                parent = ?parent.digest(),
                "missing parent execution after ancestry recovery"
            );
            return None;
        }
        let block = inner.build_block(&consensus_context, runtime.current().epoch_millis());
        if block.is_none() {
            inner.metrics.propose_missing_anchor_total.inc();
        }
        block
    }
}

impl<E> VerifyingApplication<E> for Application
where
    E: rand::Rng + Spawner + Metrics + Clock,
{
    async fn verify<A: marshal::ancestry::BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
    ) -> bool {
        let (runtime, consensus_context) = context;
        let recovered = self.collect_relevant_ancestry(&mut ancestry).await;
        let Some(block) = recovered.first().cloned() else {
            return false;
        };
        let Some(parent) = recovered.get(1).cloned() else {
            return false;
        };

        loop {
            let maybe_anchor = {
                let mut inner = self.inner.lock().await;
                inner.note_blocks(&recovered);
                if !inner.ensure_execution_materialized(parent.digest()) {
                    return false;
                }
                inner.persisted_root(block.anchor_payload())
            };

            let Some(anchor_root) = maybe_anchor else {
                let waiter = {
                    let mut inner = self.inner.lock().await;
                    inner.metrics.verify_deferred_anchor_total.inc();
                    inner.wait_for_anchor(block.anchor_payload())
                };
                if waiter.await.is_err() {
                    return false;
                }
                continue;
            };

            let mut inner = self.inner.lock().await;
            return inner.verify_block(
                &consensus_context,
                &block,
                runtime.current().epoch_millis(),
                anchor_root,
            );
        }
    }
}

impl Reporter for Application {
    type Activity = Update<HellasBlock>;

    async fn report(&mut self, update: Self::Activity) {
        match update {
            Update::Tip(_, _, _) => {}
            Update::Block(block, ack) => {
                let mut inner = self.inner.lock().await;
                inner.note_block(block.clone());
                if inner.persisted_root(block.digest()).is_some() {
                    ack.acknowledge();
                    return;
                }
                let parent = block.parent();
                if !inner.ensure_execution_materialized(parent) {
                    error!(
                        height = %block.height(),
                        parent = ?parent,
                        "missing parent execution for finalized block; aborting"
                    );
                    std::process::abort();
                }
                if !inner.execution.contains_payload(block.digest()) {
                    let Some(parent_state) = inner.execution.state_clone(parent) else {
                        error!(parent = ?parent, "missing parent state for finalized block; aborting");
                        std::process::abort();
                    };
                    let exec = execute_block(&parent_state, block.txs()).unwrap_or_else(|err| {
                        error!(?err, height = %block.height(), "failed to execute finalized block; aborting");
                        std::process::abort();
                    });
                    inner
                        .execution
                        .insert_executed(block.digest(), parent, exec);
                }

                let Some(diffs) = inner.execution.diff(block.digest()).cloned() else {
                    error!(payload = ?block.digest(), "finalized block missing execution diff; aborting");
                    std::process::abort();
                };
                inner.queue_persistence(block.clone(), diffs.clone(), ack);
                drop(inner);
                self.persistence
                    .enqueue(block.height(), block.digest(), diffs);
            }
        }
    }
}

fn root_timestamp_now() -> u64 {
    use commonware_utils::SystemTimeExt;
    std::time::SystemTime::now().epoch_millis()
}
