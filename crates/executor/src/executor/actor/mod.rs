mod execution;
mod quote;
mod subscriptions;

#[cfg(test)]
mod tests;

use crate::ExecutorError;
use crate::backend;
use crate::policy::{DownloadPolicy, ExecutePolicy};
use crate::state::{ExecutionStatus, ExecutorState};
use crate::weights::{RuntimeManager, WeightsError, WeightsLocator};
use crate::worker::{ExecuteJob, ExecuteWorker};
use std::collections::{HashMap, VecDeque};
use tokio::sync::mpsc;

use hellas_rpc::pb::hellas::{GetModelStatsResponse, GetStatsResponse, ModelTokenStats};

use super::stream::SubscriptionSet;
use super::{ExecutorHandle, ExecutorMessage};

#[derive(Default, Clone)]
pub(super) struct TokenStats {
    pub executions_started: u64,
    pub executions_completed: u64,
    pub executions_failed: u64,
    pub prompt_tokens: u64,
    pub cached_prompt_tokens: u64,
    pub cached_output_tokens: u64,
    pub prefill_tokens: u64,
    pub generated_tokens: u64,
}

impl TokenStats {
    fn to_proto(&self) -> hellas_rpc::pb::hellas::TokenStats {
        hellas_rpc::pb::hellas::TokenStats {
            executions_started: self.executions_started,
            executions_completed: self.executions_completed,
            executions_failed: self.executions_failed,
            prompt_tokens: self.prompt_tokens,
            cached_prompt_tokens: self.cached_prompt_tokens,
            cached_output_tokens: self.cached_output_tokens,
            prefill_tokens: self.prefill_tokens,
            generated_tokens: self.generated_tokens,
        }
    }
}

pub struct Executor {
    pub(super) notify_tx: mpsc::WeakUnboundedSender<ExecutorMessage>,
    pub(super) rx: mpsc::UnboundedReceiver<ExecutorMessage>,
    pub(super) store: ExecutorState,
    pub(super) subscriptions: HashMap<String, SubscriptionSet>,
    pub(super) pending_executions: VecDeque<ExecuteJob>,
    pub(super) queue_capacity: usize,
    pub(super) runtime_manager: RuntimeManager,
    pub(super) worker: ExecuteWorker,
    pub(super) execute_policy: ExecutePolicy,
    pub(super) stats: TokenStats,
    pub(super) model_stats: HashMap<String, TokenStats>,
}

impl Executor {
    pub fn spawn(
        download_policy: DownloadPolicy,
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let (tx, rx) = mpsc::unbounded_channel();
        backend::create_backend()?;
        let executor = Self {
            notify_tx: tx.downgrade(),
            rx,
            store: ExecutorState::new(),
            subscriptions: HashMap::new(),
            pending_executions: VecDeque::new(),
            queue_capacity,
            runtime_manager: RuntimeManager::new(download_policy),
            worker: ExecuteWorker::spawn(tx.clone()),
            execute_policy,
            stats: TokenStats::default(),
            model_stats: HashMap::new(),
        };
        tokio::spawn(executor.run());
        Ok(ExecutorHandle { tx })
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
            .model_stats
            .iter()
            .map(|(model_id, stats)| ModelTokenStats {
                model_id: model_id.clone(),
                stats: Some(stats.to_proto()),
            })
            .collect();
        GetStatsResponse {
            stats: Some(self.stats.to_proto()),
            model_stats,
        }
    }

    fn handle_get_model_stats(
        &self,
        request: hellas_rpc::pb::hellas::GetModelStatsRequest,
    ) -> GetModelStatsResponse {
        let model_id = request.model_id;
        let stats = self.model_stats.get(&model_id).cloned().unwrap_or_default();
        GetModelStatsResponse {
            model_id,
            stats: Some(stats.to_proto()),
        }
    }
}

fn weights_not_ready_error(locator: &WeightsLocator) -> ExecutorError {
    ExecutorError::WeightsNotReady(locator.to_string())
}

fn map_weights_error(locator: &WeightsLocator, error: WeightsError) -> ExecutorError {
    match error {
        WeightsError::NotReady | WeightsError::UnknownKey => weights_not_ready_error(locator),
        WeightsError::Failed(message) => ExecutorError::WeightsError(message),
    }
}
