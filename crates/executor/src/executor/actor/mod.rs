mod execution;
mod quote;

use crate::artifacts::{ArtifactStoreConfig, SymbolicArtifactStore};
use crate::backend;
use crate::metrics::ExecutorMetrics;
use crate::state::{ExecutorState, LocalModelStatus, ModelLocator};
use crate::worker::{ExecuteJob, ExecuteWorker};
use catgrad::prelude::Dtype;
use hellas_core::ProducerSigningKey;
use hellas_rpc::pb::courtesy::{GetModelStatsResponse, GetStatsResponse, ModelTokenStats};
use hellas_rpc::ExecutorError;
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::{ExecutorHandle, ExecutorMessage};

pub struct Executor {
    pub(super) rx: mpsc::UnboundedReceiver<ExecutorMessage>,
    pub(super) store: ExecutorState,
    pub(super) artifacts: SymbolicArtifactStore,
    pub(super) pending_executions: VecDeque<ExecuteJob>,
    pub(super) queue_capacity: usize,
    pub(super) models: HashMap<ModelLocator, LocalModelStatus>,
    pub(super) worker: ExecuteWorker,
    pub(super) execute_policy: ExecutePolicy,
    pub(super) metrics: Arc<ExecutorMetrics>,
    pub(super) producer_key: Arc<ProducerSigningKey>,
    /// Dtypes this executor will accept. The first entry is the *preferred*
    /// dtype, used whenever the executor itself constructs a program (e.g.
    /// the `QuotePromptRequest` convenience path or `handle_preload`, which
    /// don't carry a wire dtype).
    pub(super) supported_dtypes: Vec<Dtype>,
}

impl Executor {
    pub fn spawn(
        download_policy: DownloadPolicy,
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
    ) -> Result<ExecutorHandle, ExecutorError> {
        Self::spawn_with_metrics(
            download_policy,
            execute_policy,
            queue_capacity,
            supported_dtypes,
            Arc::new(ExecutorMetrics::default()),
        )
    }

    pub fn spawn_with_producer_key(
        download_policy: DownloadPolicy,
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
        producer_key: ProducerSigningKey,
    ) -> Result<ExecutorHandle, ExecutorError> {
        Self::spawn_with_metrics_and_producer_key(
            download_policy,
            execute_policy,
            queue_capacity,
            supported_dtypes,
            Arc::new(ExecutorMetrics::default()),
            Arc::new(producer_key),
        )
    }

    pub fn spawn_with_metrics(
        download_policy: DownloadPolicy,
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
        metrics: Arc<ExecutorMetrics>,
    ) -> Result<ExecutorHandle, ExecutorError> {
        Self::spawn_with_metrics_and_producer_key(
            download_policy,
            execute_policy,
            queue_capacity,
            supported_dtypes,
            metrics,
            Arc::new(ProducerSigningKey::generate()),
        )
    }

    pub fn spawn_with_metrics_and_producer_key(
        _download_policy: DownloadPolicy,
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
        metrics: Arc<ExecutorMetrics>,
        producer_key: Arc<ProducerSigningKey>,
    ) -> Result<ExecutorHandle, ExecutorError> {
        Self::spawn_with_metrics_producer_key_and_artifacts(
            execute_policy,
            queue_capacity,
            supported_dtypes,
            metrics,
            producer_key,
            SymbolicArtifactStore::memory(),
        )
    }

    pub async fn spawn_with_metrics_and_producer_key_and_artifact_store(
        _download_policy: DownloadPolicy,
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
        metrics: Arc<ExecutorMetrics>,
        producer_key: Arc<ProducerSigningKey>,
        artifact_store: ArtifactStoreConfig,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let artifacts = SymbolicArtifactStore::open(artifact_store).await?;
        Self::spawn_with_metrics_producer_key_and_artifacts(
            execute_policy,
            queue_capacity,
            supported_dtypes,
            metrics,
            producer_key,
            artifacts,
        )
    }

    fn spawn_with_metrics_producer_key_and_artifacts(
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
        metrics: Arc<ExecutorMetrics>,
        producer_key: Arc<ProducerSigningKey>,
        artifacts: SymbolicArtifactStore,
    ) -> Result<ExecutorHandle, ExecutorError> {
        assert!(
            !supported_dtypes.is_empty(),
            "executor must support at least one dtype"
        );
        let (tx, rx) = mpsc::unbounded_channel();
        backend::create_backend()?;
        let executor = Self {
            rx,
            store: ExecutorState::new(),
            artifacts,
            pending_executions: VecDeque::new(),
            queue_capacity,
            models: HashMap::new(),
            worker: ExecuteWorker::spawn(tx.clone()),
            execute_policy,
            metrics,
            producer_key,
            supported_dtypes,
        };
        tokio::spawn(executor.run());
        Ok(ExecutorHandle { tx })
    }

    /// First entry of [`Executor::supported_dtypes`]. Used when this
    /// executor must pick a dtype itself (e.g. preload, prompt-build
    /// convenience RPCs).
    pub(super) fn preferred_dtype(&self) -> Dtype {
        self.supported_dtypes[0]
    }

    async fn run(mut self) {
        while let Some(message) = self.rx.recv().await {
            match message {
                ExecutorMessage::QuoteSymbolic { request, reply } => {
                    let _ = reply.send(self.handle_quote_symbolic(request).await);
                }
                ExecutorMessage::QuoteOpaque { request, reply } => {
                    let _ = reply.send(self.handle_quote_opaque(request).await);
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
                ExecutorMessage::Preload { model, reply } => {
                    let _ = reply.send(self.handle_preload(model).await);
                }
                ExecutorMessage::Execute { request, reply } => {
                    let _ = reply.send(self.handle_execute(request).await);
                }
                ExecutorMessage::WorkerFinished(completion) => {
                    self.handle_worker_finished(completion).await;
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
