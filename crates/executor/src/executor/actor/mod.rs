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

use super::stream::SubscriptionSet;
use super::{ExecutorHandle, ExecutorMessage};

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
                    );
                }
                ExecutorMessage::Complete {
                    execution_id,
                    output,
                    status,
                } => {
                    self.handle_complete(&execution_id, output, status);
                    self.dispatch_next_execution();
                }
                ExecutorMessage::SubscriptionsClosed { execution_id } => {
                    self.handle_subscriptions_closed(&execution_id);
                }
                ExecutorMessage::ListModels { reply } => {
                    let _ = reply.send(Ok(self.handle_list_models().await));
                }
            }
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
