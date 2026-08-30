mod execution;
mod quote;

use crate::ExecutorError;
#[cfg(feature = "evaluate")]
use crate::artifact_store::ArtifactStoreConfig;
#[cfg(feature = "evaluate")]
use crate::artifacts::EvaluateArtifactStore;
#[cfg(feature = "evaluate")]
use crate::evaluate::EvaluateEngine;
use crate::fetch::{FetchCallerPolicy, FetchStateMachine, FetchTranscriptStoreBackend};
use crate::fetch_policy::FetchAccessPolicy;
use crate::fetch_registry::FetchRouteRegistry;
use crate::metrics::ExecutorMetrics;
use crate::scheme::SchemeEngine;
use crate::state::ExecutorState;
use hellas_rpc::pb::courtesy::{GetPackageStatsResponse, GetStatsResponse, PackageTokenStats};
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::{Assurance, ProducerSigningKey};
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
}

pub struct ExecutorSpawnConfig {
    pub execute_policy: ExecutePolicy,
    pub queue_capacity: usize,
    pub metrics: Arc<ExecutorMetrics>,
    pub producer_key: Arc<ProducerSigningKey>,
    pub provider_genesis: Arc<Vec<u8>>,
    pub assurance: Assurance,
    pub fetch_access_policy: FetchAccessPolicy,
    pub fetch_routes: FetchRouteRegistry,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
    pub fetch_store: FetchTranscriptStoreBackend,
    #[cfg(feature = "evaluate")]
    pub artifact_store: ArtifactStoreConfig,
}

struct ExecutorRuntimeConfig {
    #[cfg_attr(not(feature = "evaluate"), allow(dead_code))]
    execute_policy: ExecutePolicy,
    #[cfg_attr(not(feature = "evaluate"), allow(dead_code))]
    queue_capacity: usize,
    metrics: Arc<ExecutorMetrics>,
    provider: ProviderContext,
    fetch_access_policy: FetchAccessPolicy,
    fetch_routes: FetchRouteRegistry,
    fetch_max_in_flight: usize,
    fetch_queue_capacity: usize,
    #[cfg(feature = "evaluate")]
    artifacts: EvaluateArtifactStore,
    fetch_store: FetchTranscriptStoreBackend,
}

impl Executor {
    pub fn spawn_with_producer_key(
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        producer_key: ProducerSigningKey,
        provider_genesis: Vec<u8>,
        assurance: Assurance,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let producer_key = Arc::new(producer_key);
        Self::spawn_runtime(ExecutorRuntimeConfig {
            execute_policy,
            queue_capacity,
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
        })
    }

    pub fn spawn_with_fetch_routes(
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        producer_key: ProducerSigningKey,
        provider_genesis: Vec<u8>,
        assurance: Assurance,
        fetch_routes: FetchRouteRegistry,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let producer_key = Arc::new(producer_key);
        Self::spawn_runtime(ExecutorRuntimeConfig {
            execute_policy,
            queue_capacity,
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
        })
    }

    pub async fn spawn_configured(
        config: ExecutorSpawnConfig,
    ) -> Result<ExecutorHandle, ExecutorError> {
        #[cfg(feature = "evaluate")]
        let artifacts = EvaluateArtifactStore::open(config.artifact_store).await?;
        Self::spawn_runtime(ExecutorRuntimeConfig {
            execute_policy: config.execute_policy,
            queue_capacity: config.queue_capacity,
            metrics: config.metrics,
            provider: ProviderContext {
                producer_key: config.producer_key,
                genesis: config.provider_genesis,
                assurance: config.assurance,
            },
            fetch_access_policy: config.fetch_access_policy,
            fetch_routes: config.fetch_routes,
            fetch_max_in_flight: config.fetch_max_in_flight,
            fetch_queue_capacity: config.fetch_queue_capacity,
            #[cfg(feature = "evaluate")]
            artifacts,
            fetch_store: config.fetch_store,
        })
    }

    fn spawn_runtime(config: ExecutorRuntimeConfig) -> Result<ExecutorHandle, ExecutorError> {
        assert!(
            config.fetch_max_in_flight > 0,
            "fetch_max_in_flight must be greater than zero"
        );
        let (tx, rx) = mpsc::unbounded_channel();
        // Make the fetch store root durable before any ticket can run, so
        // running markers always link into an already-durable directory.
        config.fetch_store.init().map_err(|err| {
            ExecutorError::ArtifactStore(format!("fetch transcript store init failed: {err}"))
        })?;
        let fetch_caller_policy = FetchCallerPolicy::new(config.fetch_access_policy.caller_keys());
        #[cfg(feature = "evaluate")]
        let evaluate: Option<Box<dyn SchemeEngine>> = {
            Some(Box::new(EvaluateEngine::new(
                config.artifacts,
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
        };
        tokio::spawn(executor.run());
        Ok(ExecutorHandle { tx })
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
                ExecutorMessage::QuoteTokens { request, reply } => {
                    let result = match self.evaluate.as_mut() {
                        Some(engine) => engine.quote_tokens(&mut self.store, request).await,
                        None => Err(evaluate_disabled()),
                    };
                    let _ = reply.send(result);
                }
                #[cfg(feature = "evaluate")]
                ExecutorMessage::PublishCanonicalArtifact {
                    canonical_artifact,
                    reply,
                } => {
                    let result = match self.evaluate.as_mut() {
                        Some(engine) => engine.publish_canonical_artifact(canonical_artifact).await,
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
                #[cfg(feature = "evaluate")]
                ExecutorMessage::MaterializePackage { source, reply } => {
                    let result = match self.evaluate.as_mut() {
                        Some(engine) => engine.materialize_package(source).await,
                        None => Err(evaluate_disabled()),
                    };
                    let _ = reply.send(result);
                }
                ExecutorMessage::Execute { request, reply } => {
                    let _ = reply.send(self.handle_execute(request).await);
                }
                ExecutorMessage::RunPaidEvaluate { request, reply } => {
                    let result = match self.evaluate.as_mut() {
                        Some(engine) => engine.start_request(request).await,
                        None => Err(evaluate_disabled()),
                    };
                    let _ = reply.send(result);
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
                ExecutorMessage::ListPackages { reply } => {
                    let packages = match self.evaluate.as_ref() {
                        Some(engine) => engine.list_packages().await,
                        None => Default::default(),
                    };
                    let _ = reply.send(Ok(packages));
                }
                ExecutorMessage::GetStats { reply } => {
                    let package_stats = self
                        .metrics
                        .known_execution_names("evaluate")
                        .into_iter()
                        .map(|package| PackageTokenStats {
                            stats: Some(self.metrics.execution_snapshot("evaluate", &package)),
                            package,
                        })
                        .collect();
                    let _ = reply.send(Ok(GetStatsResponse {
                        stats: Some(self.metrics.global_snapshot()),
                        package_stats,
                    }));
                }
                ExecutorMessage::GetPackageStats { request, reply } => {
                    let _ = reply.send(Ok(GetPackageStatsResponse {
                        stats: Some(
                            self.metrics
                                .execution_snapshot("evaluate", &request.package),
                        ),
                        package: request.package,
                    }));
                }
            }
        }
    }
}

fn evaluate_disabled() -> ExecutorError {
    ExecutorError::PolicyDenied("evaluate scheme is not enabled on this node".to_string())
}
