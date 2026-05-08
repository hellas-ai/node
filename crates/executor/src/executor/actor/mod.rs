mod execution;
mod quote;

#[cfg(test)]
mod tests;

use crate::artifacts::InMemoryArtifactStore;
use crate::backend;
use crate::metrics::ExecutorMetrics;
use crate::programs;
use crate::state::ExecutorState;
use crate::worker::{ExecuteJob, ExecuteWorker};
use catgrad::prelude::Dtype;
use hellas_core::ProducerSigningKey;
use hellas_pb::hellas::{GetStatsResponse, ModelTokenStats};
use hellas_rpc::ExecutorError;
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::{ExecutorHandle, ExecutorMessage};

pub struct Executor {
    pub(super) rx: mpsc::UnboundedReceiver<ExecutorMessage>,
    pub(super) store: ExecutorState,
    pub(super) pending_executions: VecDeque<ExecuteJob>,
    pub(super) queue_capacity: usize,
    pub(super) artifacts: InMemoryArtifactStore,
    pub(super) symbolic_contexts: HashMap<
        catgrad::cid::Cid<catgrad::runtime::ProgramBinding>,
        Arc<programs::ExecutionContext>,
    >,
    pub(super) programs: programs::Cache,
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

    pub fn spawn_with_metrics(
        download_policy: DownloadPolicy,
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
        metrics: Arc<ExecutorMetrics>,
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
            pending_executions: VecDeque::new(),
            queue_capacity,
            artifacts: InMemoryArtifactStore::default(),
            symbolic_contexts: HashMap::new(),
            programs: programs::Cache::new(download_policy),
            worker: ExecuteWorker::spawn(tx.clone()),
            execute_policy,
            metrics,
            producer_key: Arc::new(ProducerSigningKey::generate()),
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
                ExecutorMessage::Quote { request, reply } => {
                    let _ = reply.send(self.handle_quote(request).await);
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
                ExecutorMessage::Preload { model, reply } => {
                    let _ = reply.send(self.handle_preload(model).await);
                }
                ExecutorMessage::Execute { request, reply } => {
                    let _ = reply.send(self.handle_execute(request).await);
                }
                ExecutorMessage::WorkerIdle => {
                    self.dispatch_next_execution();
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
                    let _ = reply.send(Ok(hellas_pb::hellas::GetModelStatsResponse {
                        stats: Some(self.metrics.model_snapshot(&request.model_id)),
                        model_id: request.model_id,
                    }));
                }
            }
        }
    }
}
