use crate::state::ExecutionStatus;
use crate::worker::{EnqueueError, ExecuteJob};
use crate::ExecutorError;
use hellas_rpc::pb::hellas::{
    ExecuteRequest, ExecuteResponse, ExecuteResultRequest, ExecuteResultResponse,
    ExecuteStatusRequest, ExecuteStatusResponse,
};
use std::time::Instant;

use super::Executor;

impl Executor {
    pub(super) async fn handle_execute(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<ExecuteResponse, ExecutorError> {
        let quote_id = request.quote_id;
        let stream_batch_size = request.stream_batch_size.unwrap_or(1).max(1);
        self.store.prune_expired_quotes(Instant::now());
        let quote = self.store.get_quote(&quote_id, Instant::now())?.clone();
        let execution_id = self.store.create_execution();
        let job = ExecuteJob {
            execution_id: execution_id.clone(),
            plan: quote.plan.clone(),
            program: quote.program.clone(),
            start_snapshot: quote.start_snapshot.clone(),
            start_prefix_len: quote.start_prefix_len,
            start_prefix_hash: quote.start_prefix_hash,
            start_next_token: quote.start_next_token,
            stream_batch_size,
        };

        let queued = match self.accept_execution(job) {
            Ok(queued) => queued,
            Err(error) => {
                let _ = self.store.remove_execution(&execution_id);
                return Err(error);
            }
        };
        let _ = self.store.remove_quote(&quote_id);

        info!(
            %execution_id,
            %quote_id,
            queued,
            queue_len = self.pending_executions.len(),
            "accepted execution"
        );

        Ok(ExecuteResponse {
            execution_id,
            quote_id,
        })
    }

    pub(super) fn handle_status(
        &self,
        request: &ExecuteStatusRequest,
    ) -> Result<ExecuteStatusResponse, ExecutorError> {
        self.status_response(&request.execution_id)
    }

    pub(super) fn handle_result(
        &self,
        request: &ExecuteResultRequest,
    ) -> Result<ExecuteResultResponse, ExecutorError> {
        let output = self.store.output(&request.execution_id)?;
        Ok(ExecuteResultResponse {
            output: output.to_vec(),
        })
    }

    fn accept_execution(&mut self, job: ExecuteJob) -> Result<bool, ExecutorError> {
        match self.try_start_execution(job) {
            Ok(()) => Ok(false),
            Err(StartExecutionError::Busy(job)) => {
                if self.pending_executions.len() >= self.queue_capacity {
                    return Err(ExecutorError::QueueFull {
                        capacity: self.queue_capacity,
                    });
                }
                self.pending_executions.push_back(job);
                Ok(true)
            }
            Err(StartExecutionError::Closed) => Err(ExecutorError::ChannelClosed),
            Err(StartExecutionError::Other(error)) => Err(error),
        }
    }

    fn try_start_execution(&mut self, job: ExecuteJob) -> Result<(), StartExecutionError> {
        let execution_id = job.execution_id.clone();
        match self.worker.try_enqueue(job) {
            Ok(()) => {
                self.store
                    .mark_running(&execution_id)
                    .map_err(ExecutorError::from)?;
                self.send_status(&execution_id, ExecutionStatus::Running);
                Ok(())
            }
            Err(EnqueueError::Busy(job)) => Err(StartExecutionError::Busy(job)),
            Err(EnqueueError::Stopped(_job)) => {
                self.handle_complete(&execution_id, None, ExecutionStatus::Failed);
                Err(StartExecutionError::Closed)
            }
        }
    }

    pub(super) fn dispatch_next_execution(&mut self) {
        while let Some(job) = self.pending_executions.pop_front() {
            match self.try_start_execution(job) {
                Ok(()) => return,
                Err(StartExecutionError::Busy(job)) => {
                    self.pending_executions.push_front(job);
                    return;
                }
                Err(StartExecutionError::Closed) => {
                    warn!("failed to start queued execution: executor channel closed");
                }
                Err(StartExecutionError::Other(error)) => {
                    warn!("failed to start queued execution: {error:#}");
                }
            }
        }
    }

    pub(super) fn cancel_pending_execution(&mut self, execution_id: &str) {
        let original_len = self.pending_executions.len();
        self.pending_executions
            .retain(|job| job.execution_id != execution_id);

        if self.pending_executions.len() != original_len {
            info!(%execution_id, "cancelled queued execution without active watchers");
            self.handle_complete(execution_id, None, ExecutionStatus::Failed);
        }
    }

    pub(super) fn handle_complete(
        &mut self,
        execution_id: &str,
        output: Option<Vec<u8>>,
        status: ExecutionStatus,
    ) {
        let success = matches!(status, ExecutionStatus::Completed);
        info!(%execution_id, success, "execution finished");

        if let Err(error) = self.store.complete_execution(execution_id, status, output) {
            warn!("failed to update completion state for {execution_id}: {error}");
        }

        self.send_status(execution_id, status);
    }
}

enum StartExecutionError {
    Busy(ExecuteJob),
    Closed,
    Other(ExecutorError),
}

impl From<ExecutorError> for StartExecutionError {
    fn from(error: ExecutorError) -> Self {
        StartExecutionError::Other(error)
    }
}
