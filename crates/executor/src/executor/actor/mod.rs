mod execution;
mod quote;

use crate::artifacts::{ArtifactStoreConfig, EvaluateArtifactStore};
use crate::backend;
use crate::fetch::{FetchCallerPolicy, FetchStateMachine, FetchTranscriptStoreBackend};
use crate::fetch_policy::{FetchAccessPolicy, FetchQuotaStoreBackend};
use crate::fetch_registry::FetchRouteRegistry;
use crate::metrics::ExecutorMetrics;
use crate::state::{ExecutorState, LocalModelStatus, ModelLocator};
use crate::worker::{ExecuteJob, ExecuteWorker};
use catgrad::prelude::Dtype;
use hellas_core::ProducerSigningKey;
use hellas_rpc::ExecutorError;
use hellas_rpc::pb::courtesy::{GetModelStatsResponse, GetStatsResponse, ModelTokenStats};
use hellas_rpc::policy::ExecutePolicy;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::{ExecutorHandle, ExecutorMessage, PendingFetch};

pub struct Executor {
    pub(super) rx: mpsc::UnboundedReceiver<ExecutorMessage>,
    pub(super) tx: mpsc::UnboundedSender<ExecutorMessage>,
    pub(super) store: ExecutorState,
    pub(super) artifacts: EvaluateArtifactStore,
    pub(super) pending_executions: VecDeque<ExecuteJob>,
    pub(super) queue_capacity: usize,
    pub(super) models: HashMap<ModelLocator, LocalModelStatus>,
    pub(super) worker: ExecuteWorker,
    pub(super) execute_policy: ExecutePolicy,
    pub(super) metrics: Arc<ExecutorMetrics>,
    pub(super) producer_key: Arc<ProducerSigningKey>,
    pub(super) fetch_state: FetchStateMachine<FetchTranscriptStoreBackend>,
    pub(super) fetch_access_policy: FetchAccessPolicy,
    pub(super) fetch_routes: FetchRouteRegistry,
    pub(super) pending_fetches: VecDeque<PendingFetch>,
    pub(super) fetch_max_in_flight: usize,
    pub(super) fetch_queue_capacity: usize,
    pub(super) active_fetches: usize,
    /// Dtypes this executor will accept. The first entry is the *preferred*
    /// dtype, used whenever the executor itself constructs a program.
    pub(super) supported_dtypes: Vec<Dtype>,
}

pub struct ExecutorSpawnConfig {
    pub execute_policy: ExecutePolicy,
    pub queue_capacity: usize,
    pub supported_dtypes: Vec<Dtype>,
    pub metrics: Arc<ExecutorMetrics>,
    pub producer_key: Arc<ProducerSigningKey>,
    pub fetch_access_policy: FetchAccessPolicy,
    pub fetch_routes: FetchRouteRegistry,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
    pub artifact_store: ArtifactStoreConfig,
}

struct ExecutorRuntimeConfig {
    execute_policy: ExecutePolicy,
    queue_capacity: usize,
    supported_dtypes: Vec<Dtype>,
    metrics: Arc<ExecutorMetrics>,
    producer_key: Arc<ProducerSigningKey>,
    fetch_access_policy: FetchAccessPolicy,
    fetch_routes: FetchRouteRegistry,
    fetch_max_in_flight: usize,
    fetch_queue_capacity: usize,
    artifacts: EvaluateArtifactStore,
    fetch_store: FetchTranscriptStoreBackend,
}

impl Executor {
    pub fn spawn_with_producer_key(
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
        producer_key: ProducerSigningKey,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let producer_key = Arc::new(producer_key);
        Self::spawn_runtime(ExecutorRuntimeConfig {
            execute_policy,
            queue_capacity,
            supported_dtypes,
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key: producer_key.clone(),
            fetch_access_policy: FetchAccessPolicy::trusted_callers([producer_key.public_key()]),
            fetch_routes: FetchRouteRegistry::default(),
            fetch_max_in_flight: hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT,
            fetch_queue_capacity: hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY,
            artifacts: EvaluateArtifactStore::memory(),
            fetch_store: FetchTranscriptStoreBackend::memory(),
        })
    }

    pub fn spawn_with_fetch_routes(
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
        producer_key: ProducerSigningKey,
        fetch_routes: FetchRouteRegistry,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let producer_key = Arc::new(producer_key);
        Self::spawn_runtime(ExecutorRuntimeConfig {
            execute_policy,
            queue_capacity,
            supported_dtypes,
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key: producer_key.clone(),
            fetch_access_policy: FetchAccessPolicy::trusted_callers([producer_key.public_key()]),
            fetch_routes,
            fetch_max_in_flight: hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT,
            fetch_queue_capacity: hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY,
            artifacts: EvaluateArtifactStore::memory(),
            fetch_store: FetchTranscriptStoreBackend::memory(),
        })
    }

    pub async fn spawn_configured(
        config: ExecutorSpawnConfig,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let fetch_store = fetch_store_from_artifact_config(&config.artifact_store);
        let fetch_quota_store = fetch_quota_store_from_artifact_config(&config.artifact_store);
        let artifacts = EvaluateArtifactStore::open(config.artifact_store).await?;
        Self::spawn_runtime(ExecutorRuntimeConfig {
            execute_policy: config.execute_policy,
            queue_capacity: config.queue_capacity,
            supported_dtypes: config.supported_dtypes,
            metrics: config.metrics,
            producer_key: config.producer_key,
            fetch_access_policy: config.fetch_access_policy.with_store(fetch_quota_store),
            fetch_routes: config.fetch_routes,
            fetch_max_in_flight: config.fetch_max_in_flight,
            fetch_queue_capacity: config.fetch_queue_capacity,
            artifacts,
            fetch_store,
        })
    }

    fn spawn_runtime(config: ExecutorRuntimeConfig) -> Result<ExecutorHandle, ExecutorError> {
        assert!(
            !config.supported_dtypes.is_empty(),
            "executor must support at least one dtype"
        );
        assert!(
            config.fetch_max_in_flight > 0,
            "fetch_max_in_flight must be greater than zero"
        );
        let preferred_dtype = config.supported_dtypes[0];
        let (tx, rx) = mpsc::unbounded_channel();
        backend::create_backend()?;
        // Make the fetch store root durable before any ticket can run, so
        // running markers always link into an already-durable directory.
        config.fetch_store.init().map_err(|err| {
            ExecutorError::ArtifactStore(format!("fetch transcript store init failed: {err}"))
        })?;
        let fetch_caller_policy = FetchCallerPolicy::new(config.fetch_access_policy.caller_keys());
        let executor = Self {
            rx,
            tx: tx.clone(),
            store: ExecutorState::new(),
            artifacts: config.artifacts,
            pending_executions: VecDeque::new(),
            queue_capacity: config.queue_capacity,
            models: HashMap::new(),
            worker: ExecuteWorker::spawn(tx.clone()),
            execute_policy: config.execute_policy,
            metrics: config.metrics,
            producer_key: config.producer_key,
            fetch_state: FetchStateMachine::new(config.fetch_store, fetch_caller_policy),
            fetch_access_policy: config.fetch_access_policy,
            fetch_routes: config.fetch_routes,
            pending_fetches: VecDeque::new(),
            fetch_max_in_flight: config.fetch_max_in_flight,
            fetch_queue_capacity: config.fetch_queue_capacity,
            active_fetches: 0,
            supported_dtypes: config.supported_dtypes,
        };
        tokio::spawn(executor.run());
        Ok(ExecutorHandle {
            tx,
            preferred_dtype,
        })
    }

    /// First entry of [`Executor::supported_dtypes`]. Used when this
    /// executor must pick a dtype itself.
    pub(super) fn preferred_dtype(&self) -> Dtype {
        self.supported_dtypes[0]
    }

    async fn run(mut self) {
        while let Some(message) = self.rx.recv().await {
            match message {
                ExecutorMessage::QuoteEvaluate { request, reply } => {
                    let _ = reply.send(self.handle_quote_evaluate(request).await);
                }
                ExecutorMessage::QuoteFetch { request, reply } => {
                    let _ = reply.send(self.handle_quote_fetch(request).await);
                }
                ExecutorMessage::QuotePrompt { request, reply } => {
                    let _ = reply.send(self.handle_quote_prompt(request).await);
                }
                ExecutorMessage::QuotePreparedText { request, reply } => {
                    let _ = reply.send(self.handle_quote_prepared_text(request).await);
                }
                ExecutorMessage::QuoteChatPrompt { request, reply } => {
                    let _ = reply.send(self.handle_quote_chat_prompt(request).await);
                }
                ExecutorMessage::PutArtifact { request, reply } => {
                    let _ = reply.send(self.handle_put_artifact(request).await);
                }
                ExecutorMessage::GetArtifact { request, reply } => {
                    let _ = reply.send(self.handle_get_artifact(request).await);
                }
                ExecutorMessage::LoadModelMetadata { model, reply } => {
                    let _ = reply.send(self.handle_load_model_metadata(model).await);
                }
                ExecutorMessage::Execute { request, reply } => {
                    let _ = reply.send(self.handle_execute(request).await);
                }
                ExecutorMessage::WorkerFinished(completion) => {
                    self.handle_worker_finished(completion).await;
                }
                ExecutorMessage::FetchFinished(completion) => {
                    self.handle_fetch_finished(completion).await;
                }
                ExecutorMessage::ListModels { reply } => {
                    let _ = reply.send(Ok(self.handle_list_models().await));
                }
                ExecutorMessage::GetStats { reply } => {
                    let model_stats = self
                        .metrics
                        .known_model_ids()
                        .into_iter()
                        .map(|model_id| ModelTokenStats {
                            stats: Some(self.metrics.model_snapshot(&model_id)),
                            model_id,
                        })
                        .collect();
                    let _ = reply.send(Ok(GetStatsResponse {
                        stats: Some(self.metrics.global_snapshot()),
                        model_stats,
                    }));
                }
                ExecutorMessage::GetModelStats { request, reply } => {
                    let _ = reply.send(Ok(GetModelStatsResponse {
                        stats: Some(self.metrics.model_snapshot(&request.model_id)),
                        model_id: request.model_id,
                    }));
                }
            }
        }
    }
}

fn fetch_store_from_artifact_config(config: &ArtifactStoreConfig) -> FetchTranscriptStoreBackend {
    match config {
        ArtifactStoreConfig::Memory => FetchTranscriptStoreBackend::memory(),
        ArtifactStoreConfig::Fs(path) => {
            FetchTranscriptStoreBackend::fs(path.join("fetch-transcripts"))
        }
    }
}

fn fetch_quota_store_from_artifact_config(config: &ArtifactStoreConfig) -> FetchQuotaStoreBackend {
    match config {
        ArtifactStoreConfig::Memory => FetchQuotaStoreBackend::memory(),
        ArtifactStoreConfig::Fs(path) => FetchQuotaStoreBackend::fs(path.join("fetch-quota")),
    }
}
