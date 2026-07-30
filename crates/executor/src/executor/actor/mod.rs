mod execution;
mod quote;

use crate::ExecutorError;
#[cfg(feature = "evaluate")]
use crate::artifacts::EvaluateArtifactStore;
#[cfg(feature = "evaluate")]
use crate::backend;
use crate::chain::ChainView;
use hellas_chain::staked::Channel;
#[cfg(feature = "evaluate")]
use crate::evaluate::EvaluateEngine;
use crate::fetch::{FetchCallerPolicy, FetchStateMachine, FetchTranscriptStoreBackend};
use crate::fetch_policy::{FetchAccessPolicy, FetchQuotaStoreBackend};
use crate::fetch_registry::FetchRouteRegistry;
use crate::metrics::ExecutorMetrics;
use crate::scheme::SchemeEngine;
use crate::state::{ArtifactStoreConfig, ExecutorState};
use hellas_rpc::pb::courtesy::{GetModelStatsResponse, GetStatsResponse, ModelTokenStats};
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::{Assurance, Dtype, ProducerSigningKey};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::mpsc;

use super::{ExecutorHandle, ExecutorMessage, PendingFetch, ProviderContext};

pub struct Executor {
    pub(super) rx: mpsc::UnboundedReceiver<ExecutorMessage>,
    pub(super) tx: mpsc::UnboundedSender<ExecutorMessage>,
    pub(super) store: ExecutorState,
    pub(super) evaluate: Option<Box<dyn SchemeEngine>>,
    pub(super) metrics: Arc<ExecutorMetrics>,
    pub(super) provider: ProviderContext,
    pub(super) fetch_state: FetchStateMachine<FetchTranscriptStoreBackend>,
    pub(super) fetch_access_policy: FetchAccessPolicy,
    pub(super) fetch_routes: FetchRouteRegistry,
    pub(super) pending_fetches: VecDeque<PendingFetch>,
    pub(super) fetch_max_in_flight: usize,
    pub(super) fetch_queue_capacity: usize,
    pub(super) active_fetches: usize,
    pub(super) chain_view: Option<Arc<dyn ChainView>>,
    /// The provider's side of the staked pairing, when configured.
    pub(super) staked: Option<Channel>,
}

pub struct ExecutorSpawnConfig {
    pub execute_policy: ExecutePolicy,
    pub queue_capacity: usize,
    pub supported_dtypes: Vec<Dtype>,
    pub metrics: Arc<ExecutorMetrics>,
    pub producer_key: Arc<ProducerSigningKey>,
    pub provider_genesis: Arc<Vec<u8>>,
    pub assurance: Assurance,
    pub fetch_access_policy: FetchAccessPolicy,
    pub fetch_routes: FetchRouteRegistry,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
    pub artifact_store: ArtifactStoreConfig,
    /// Chain connection for the staked job flow. `None` runs the
    /// executor without a chain view, exactly as before.
    pub chain_view: Option<Arc<dyn ChainView>>,
    /// The provider's side of the staked pairing. `Some` makes every
    /// execution require an admissible client-signed job acceptance
    /// (and a chain view for the deadline height).
    pub staked_channel: Option<Channel>,
}

struct ExecutorRuntimeConfig {
    #[cfg_attr(not(feature = "evaluate"), allow(dead_code))]
    execute_policy: ExecutePolicy,
    #[cfg_attr(not(feature = "evaluate"), allow(dead_code))]
    queue_capacity: usize,
    #[cfg_attr(not(feature = "evaluate"), allow(dead_code))]
    supported_dtypes: Vec<Dtype>,
    metrics: Arc<ExecutorMetrics>,
    provider: ProviderContext,
    fetch_access_policy: FetchAccessPolicy,
    fetch_routes: FetchRouteRegistry,
    fetch_max_in_flight: usize,
    fetch_queue_capacity: usize,
    #[cfg(feature = "evaluate")]
    artifacts: EvaluateArtifactStore,
    fetch_store: FetchTranscriptStoreBackend,
    chain_view: Option<Arc<dyn ChainView>>,
    staked_channel: Option<Channel>,
}

impl Executor {
    pub fn spawn_with_producer_key(
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
        producer_key: ProducerSigningKey,
        provider_genesis: Vec<u8>,
        assurance: Assurance,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let producer_key = Arc::new(producer_key);
        Self::spawn_runtime(ExecutorRuntimeConfig {
            execute_policy,
            queue_capacity,
            supported_dtypes,
            metrics: Arc::new(ExecutorMetrics::default()),
            provider: ProviderContext {
                producer_key: producer_key.clone(),
                genesis: Arc::new(provider_genesis),
                assurance,
            },
            fetch_access_policy: FetchAccessPolicy::trusted_callers([producer_key.public_key()]),
            fetch_routes: FetchRouteRegistry::default(),
            fetch_max_in_flight: hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT,
            fetch_queue_capacity: hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY,
            #[cfg(feature = "evaluate")]
            artifacts: EvaluateArtifactStore::memory(),
            fetch_store: FetchTranscriptStoreBackend::memory(),
            chain_view: None,
            staked_channel: None,
        })
    }

    pub fn spawn_with_fetch_routes(
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
        producer_key: ProducerSigningKey,
        provider_genesis: Vec<u8>,
        assurance: Assurance,
        fetch_routes: FetchRouteRegistry,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let producer_key = Arc::new(producer_key);
        Self::spawn_runtime(ExecutorRuntimeConfig {
            execute_policy,
            queue_capacity,
            supported_dtypes,
            metrics: Arc::new(ExecutorMetrics::default()),
            provider: ProviderContext {
                producer_key: producer_key.clone(),
                genesis: Arc::new(provider_genesis),
                assurance,
            },
            fetch_access_policy: FetchAccessPolicy::trusted_callers([producer_key.public_key()]),
            fetch_routes,
            fetch_max_in_flight: hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT,
            fetch_queue_capacity: hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY,
            #[cfg(feature = "evaluate")]
            artifacts: EvaluateArtifactStore::memory(),
            fetch_store: FetchTranscriptStoreBackend::memory(),
            chain_view: None,
            staked_channel: None,
        })
    }

    pub async fn spawn_configured(
        config: ExecutorSpawnConfig,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let fetch_store = fetch_store_from_artifact_config(&config.artifact_store);
        let fetch_quota_store = fetch_quota_store_from_artifact_config(&config.artifact_store);
        #[cfg(feature = "evaluate")]
        let artifacts = EvaluateArtifactStore::open(config.artifact_store).await?;
        Self::spawn_runtime(ExecutorRuntimeConfig {
            execute_policy: config.execute_policy,
            queue_capacity: config.queue_capacity,
            supported_dtypes: config.supported_dtypes,
            metrics: config.metrics,
            provider: ProviderContext {
                producer_key: config.producer_key,
                genesis: config.provider_genesis,
                assurance: config.assurance,
            },
            fetch_access_policy: config.fetch_access_policy.with_store(fetch_quota_store),
            fetch_routes: config.fetch_routes,
            fetch_max_in_flight: config.fetch_max_in_flight,
            fetch_queue_capacity: config.fetch_queue_capacity,
            #[cfg(feature = "evaluate")]
            artifacts,
            fetch_store,
            chain_view: config.chain_view,
            staked_channel: config.staked_channel,
        })
    }

    fn spawn_runtime(config: ExecutorRuntimeConfig) -> Result<ExecutorHandle, ExecutorError> {
        assert!(
            config.fetch_max_in_flight > 0,
            "fetch_max_in_flight must be greater than zero"
        );
        #[cfg(feature = "evaluate")]
        let preferred_dtype = config
            .supported_dtypes
            .first()
            .copied()
            .unwrap_or(Dtype::F32);
        let (tx, rx) = mpsc::unbounded_channel();
        // Make the fetch store root durable before any ticket can run, so
        // running markers always link into an already-durable directory.
        config.fetch_store.init().map_err(|err| {
            ExecutorError::ArtifactStore(format!("fetch transcript store init failed: {err}"))
        })?;
        let fetch_caller_policy = FetchCallerPolicy::new(config.fetch_access_policy.caller_keys());
        #[cfg(feature = "evaluate")]
        let evaluate: Option<Box<dyn SchemeEngine>> = {
            assert!(
                !config.supported_dtypes.is_empty(),
                "executor with evaluate enabled must support at least one dtype"
            );
            backend::create_backend()?;
            Some(Box::new(EvaluateEngine::new(
                config.artifacts,
                config.supported_dtypes,
                config.queue_capacity,
                config.execute_policy,
                config.metrics.clone(),
                config.provider.clone(),
                tx.clone(),
            )))
        };
        #[cfg(not(feature = "evaluate"))]
        let evaluate: Option<Box<dyn SchemeEngine>> = None;
        let executor = Self {
            rx,
            tx: tx.clone(),
            store: ExecutorState::new(),
            evaluate,
            metrics: config.metrics,
            provider: config.provider,
            fetch_state: FetchStateMachine::new(config.fetch_store, fetch_caller_policy),
            fetch_access_policy: config.fetch_access_policy,
            fetch_routes: config.fetch_routes,
            pending_fetches: VecDeque::new(),
            fetch_max_in_flight: config.fetch_max_in_flight,
            fetch_queue_capacity: config.fetch_queue_capacity,
            active_fetches: 0,
            chain_view: config.chain_view,
            staked: config.staked_channel,
        };
        tokio::spawn(executor.run());
        Ok(ExecutorHandle {
            tx,
            #[cfg(feature = "evaluate")]
            preferred_dtype,
        })
    }

    async fn run(mut self) {
        while let Some(message) = self.rx.recv().await {
            match message {
                ExecutorMessage::QuoteEvaluate { request, reply } => {
                    let result = match self.evaluate.as_mut() {
                        Some(engine) => engine.quote_evaluate(&mut self.store, request).await,
                        None => Err(evaluate_disabled()),
                    };
                    let _ = reply.send(result);
                }
                ExecutorMessage::QuoteFetch { request, reply } => {
                    let _ = reply.send(self.handle_quote_fetch(request).await);
                }
                ExecutorMessage::QuotePrompt { request, reply } => {
                    let result = match self.evaluate.as_mut() {
                        Some(engine) => engine.quote_prompt(&mut self.store, request).await,
                        None => Err(evaluate_disabled()),
                    };
                    let _ = reply.send(result);
                }
                ExecutorMessage::QuotePreparedText { request, reply } => {
                    let result = match self.evaluate.as_mut() {
                        Some(engine) => engine.quote_prepared_text(&mut self.store, request).await,
                        None => Err(evaluate_disabled()),
                    };
                    let _ = reply.send(result);
                }
                ExecutorMessage::QuoteChatPrompt { request, reply } => {
                    let result = match self.evaluate.as_mut() {
                        Some(engine) => engine.quote_chat_prompt(&mut self.store, request).await,
                        None => Err(evaluate_disabled()),
                    };
                    let _ = reply.send(result);
                }
                ExecutorMessage::PutArtifact { request, reply } => {
                    let result = match self.evaluate.as_mut() {
                        Some(engine) => engine.put_artifact(request).await,
                        None => Err(evaluate_disabled()),
                    };
                    let _ = reply.send(result);
                }
                ExecutorMessage::GetArtifact { request, reply } => {
                    let result = match self.evaluate.as_mut() {
                        Some(engine) => engine.get_artifact(request).await,
                        None => Err(evaluate_disabled()),
                    };
                    let _ = reply.send(result);
                }
                ExecutorMessage::LoadModelMetadata { model, reply } => {
                    let result = match self.evaluate.as_mut() {
                        Some(engine) => engine.load_model_metadata(model).await,
                        None => Err(evaluate_disabled()),
                    };
                    let _ = reply.send(result);
                }
                ExecutorMessage::Execute { request, reply } => {
                    let _ = reply.send(self.handle_execute(request).await);
                }
                #[cfg(feature = "evaluate")]
                ExecutorMessage::SchemeFinished(completion) => {
                    if let Some(engine) = self.evaluate.as_mut() {
                        engine.on_completion(completion).await;
                    }
                }
                ExecutorMessage::FetchFinished(completion) => {
                    self.handle_fetch_finished(completion).await;
                }
                ExecutorMessage::ListModels { reply } => {
                    let models = match self.evaluate.as_ref() {
                        Some(engine) => engine.list_models().await,
                        None => Default::default(),
                    };
                    let _ = reply.send(Ok(models));
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

fn evaluate_disabled() -> ExecutorError {
    ExecutorError::PolicyDenied("evaluate scheme is not enabled on this node".to_string())
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
