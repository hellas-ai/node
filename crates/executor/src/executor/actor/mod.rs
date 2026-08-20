mod execution;
mod quote;

use crate::ExecutorError;
#[cfg(feature = "evaluate")]
use crate::artifact_store::ArtifactStoreConfig;
#[cfg(feature = "evaluate")]
use crate::artifacts::EvaluateArtifactStore;
#[cfg(feature = "evaluate")]
use crate::backend;
#[cfg(feature = "evaluate")]
use crate::evaluate::EvaluateEngine;
use crate::fetch::{FetchCallerPolicy, FetchStateMachine, FetchTranscriptStoreBackend};
use crate::fetch_policy::FetchAccessPolicy;
use crate::fetch_registry::FetchRouteRegistry;
use crate::metrics::ExecutorMetrics;
use crate::scheme::SchemeEngine;
use crate::state::ExecutorState;
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
    pub fetch_store: FetchTranscriptStoreBackend,
    #[cfg(feature = "evaluate")]
    pub artifact_store: ArtifactStoreConfig,
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
            supported_dtypes: config.supported_dtypes,
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

    fn spawn_runtime(
        #[allow(unused_mut, reason = "only the evaluate build narrows the dtypes")]
        mut config: ExecutorRuntimeConfig,
    ) -> Result<ExecutorHandle, ExecutorError> {
        assert!(
            config.fetch_max_in_flight > 0,
            "fetch_max_in_flight must be greater than zero"
        );
        // Advertise only what the device that was actually selected can
        // run. The build features chose which backend was compiled in;
        // they do not know whether a GPU is present, and BF16 on a CPU
        // device is a panic inside candle rather than an error. Filtering
        // here means an operator learns at startup, instead of every
        // accepted job failing after reading gigabytes.
        #[cfg(feature = "evaluate")]
        {
            assert!(
                !config.supported_dtypes.is_empty(),
                "executor with evaluate enabled must support at least one dtype"
            );
            let backend = backend::create_backend()?;
            let runnable = backend::runnable_dtypes(&backend, &config.supported_dtypes);
            if runnable.is_empty() {
                return Err(crate::BackendInitError::new(format!(
                    "this node was asked to serve {:?}, and the backend it selected ({backend:?}) \
                     can run none of them; pass --dtype f32",
                    config.supported_dtypes,
                ))
                .into());
            }
            if runnable.len() != config.supported_dtypes.len() {
                tracing::warn!(
                    asked = ?config.supported_dtypes,
                    serving = ?runnable,
                    "the selected backend cannot run every dtype this node was asked to serve",
                );
            }
            config.supported_dtypes = runnable;
        }
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
                ExecutorMessage::MaterializeModel { model, reply } => {
                    let result = match self.evaluate.as_mut() {
                        Some(engine) => engine.materialize_model(model).await,
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

#[cfg(all(
    test,
    feature = "evaluate",
    not(any(feature = "candle-cuda", feature = "candle-metal"))
))]
mod tests {
    use super::*;

    fn key() -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([7; 32]).expect("valid test key")
    }

    fn spawn(dtypes: Vec<Dtype>) -> Result<ExecutorHandle, ExecutorError> {
        Executor::spawn_with_producer_key(
            ExecutePolicy::Eager,
            1,
            dtypes,
            key(),
            b"genesis".to_vec(),
            Assurance::ProducerSigned,
        )
    }

    /// On this build the backend is the CPU device, where BF16 is a
    /// panic inside candle rather than an error. A node that can serve
    /// nothing it was asked to serve must say so at startup instead of
    /// accepting jobs it will fail after reading the weights.
    ///
    /// The second half is the control: the same call with a dtype the
    /// device can run must start, so this is a fact about BF16 and not
    /// about spawning.
    #[tokio::test]
    async fn a_cpu_node_refuses_to_advertise_bf16() {
        let message = match spawn(vec![Dtype::BF16]) {
            Err(refused) => refused.to_string(),
            Ok(_) => panic!("bf16 on a cpu device must not be advertised"),
        };
        assert!(message.contains("BF16"), "{message}");
        assert!(message.contains("--dtype f32"), "{message}");

        assert!(
            spawn(vec![Dtype::F32]).is_ok(),
            "f32 is servable on any device",
        );
    }
}
