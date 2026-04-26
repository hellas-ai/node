mod execution;
mod quote;
mod subscriptions;

#[cfg(test)]
mod tests;

use crate::backend;
use crate::inputs::{self, HuggingFaceLocator};
use crate::metrics::ExecutorMetrics;
use crate::programs;
use crate::state::{ExecutionStatus, ExecutorState};
use crate::worker::{ExecuteJob, ExecuteWorker};
use catgrad::prelude::Dtype;
use hellas_rpc::ExecutorError;
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc;

use hellas_rpc::pb::hellas::{GetModelStatsResponse, GetStatsResponse, ModelTokenStats};

use super::stream::SubscriptionSet;
use super::{ExecutorHandle, ExecutorMessage};

pub struct Executor {
    pub(super) notify_tx: mpsc::WeakUnboundedSender<ExecutorMessage>,
    pub(super) rx: mpsc::UnboundedReceiver<ExecutorMessage>,
    pub(super) store: ExecutorState,
    pub(super) subscriptions: HashMap<String, SubscriptionSet>,
    pub(super) pending_executions: VecDeque<ExecuteJob>,
    pub(super) queue_capacity: usize,
    pub(super) programs: programs::Cache,
    pub(super) worker: ExecuteWorker,
    pub(super) execute_policy: ExecutePolicy,
    pub(super) metrics: Arc<ExecutorMetrics>,
    /// Dtypes this executor will accept. The first entry is the *preferred*
    /// dtype, used whenever the executor itself constructs a program (e.g.
    /// the `QuotePromptRequest` convenience path or `handle_preload`, which
    /// don't carry a wire dtype). Other entries are also accepted for any
    /// `GetQuoteRequest` whose program bytes name them.
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
            notify_tx: tx.downgrade(),
            rx,
            store: ExecutorState::new(),
            subscriptions: HashMap::new(),
            pending_executions: VecDeque::new(),
            queue_capacity,
            programs: programs::Cache::new(download_policy),
            worker: ExecuteWorker::spawn(tx.clone()),
            execute_policy,
            metrics,
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
                ExecutorMessage::QuoteChatPrompt { request, reply } => {
                    let _ = reply.send(self.handle_quote_chat_prompt(request).await);
                }
                ExecutorMessage::Preload { model, reply } => {
                    let _ = reply.send(self.handle_preload(model).await);
                }
                ExecutorMessage::Subscribe {
                    execution_id,
                    reply,
                } => {
                    let _ = reply.send(self.handle_subscribe(execution_id));
                }
                ExecutorMessage::Execute { request, reply } => {
                    let _ = reply.send(self.handle_execute(request).await);
                }
                ExecutorMessage::Status { request, reply } => {
                    let _ = reply.send(self.handle_status(&request));
                }
                ExecutorMessage::Result { request, reply } => {
                    let _ = reply.send(self.handle_result(&request));
                }
                ExecutorMessage::Progress {
                    execution_id,
                    output_chunk,
                    progress,
                } => {
                    let _ = self
                        .store
                        .append_output_chunk(&execution_id, &output_chunk, progress);
                    self.send_progress(
                        &execution_id,
                        ExecutionStatus::Running,
                        progress,
                        output_chunk,
                        None,
                    );
                }
                ExecutorMessage::Complete {
                    execution_id,
                    output,
                    status,
                    error,
                } => {
                    self.handle_complete(&execution_id, output, status, error);
                    self.dispatch_next_execution();
                }
                ExecutorMessage::SubscriptionsClosed { execution_id } => {
                    self.handle_subscriptions_closed(&execution_id);
                }
                ExecutorMessage::ListModels { reply } => {
                    let _ = reply.send(Ok(self.handle_list_models().await));
                }
                ExecutorMessage::GetStats { reply } => {
                    let _ = reply.send(Ok(self.handle_get_stats()));
                }
                ExecutorMessage::GetModelStats { request, reply } => {
                    let _ = reply.send(Ok(self.handle_get_model_stats(request)));
                }
            }
        }
    }
}

impl Executor {
    fn handle_get_stats(&self) -> GetStatsResponse {
        let model_stats = self
            .metrics
            .known_model_ids()
            .into_iter()
            .map(|model_id| ModelTokenStats {
                stats: Some(self.metrics.model_snapshot(&model_id)),
                model_id,
            })
            .collect();
        GetStatsResponse {
            stats: Some(self.metrics.global_snapshot()),
            model_stats,
        }
    }

    fn handle_get_model_stats(
        &self,
        request: hellas_rpc::pb::hellas::GetModelStatsRequest,
    ) -> GetModelStatsResponse {
        GetModelStatsResponse {
            stats: Some(self.metrics.model_snapshot(&request.model_id)),
            model_id: request.model_id,
        }
    }
}

fn weights_not_ready_error(locator: &HuggingFaceLocator) -> ExecutorError {
    ExecutorError::WeightsNotReady(locator.to_string())
}

fn map_weights_error(locator: &HuggingFaceLocator, error: inputs::Error) -> ExecutorError {
    match error {
        inputs::Error::NotReady | inputs::Error::UnknownKey => weights_not_ready_error(locator),
        inputs::Error::Failed(message) => ExecutorError::WeightsError(message),
    }
}
