use hellas_rpc::pb::hellas::{ExecuteRequest, ExecuteResponse};

use crate::execute_worker::{EnqueueError, ExecuteJob, ExecuteWorkerError};
use crate::state::ExecutionStatus;
use crate::weights::WeightsError;
use crate::{Executor, ExecutorError};

impl Executor {
    pub(super) async fn handle_execute(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<ExecuteResponse, ExecutorError> {
        let quote_id = request.quote_id;
        let stream_batch_size = request.stream_batch_size.unwrap_or(1).max(1);
        let plan = self.state.get_quote(&quote_id)?.clone();
        let key = plan.weights_key.clone();
        let bundle = self.weights.bundle(&key).await.map_err(|e| match e {
            WeightsError::NotReady => ExecutorError::WeightsNotReady(key.to_string()),
            WeightsError::Failed(msg) => ExecutorError::WeightsError(msg),
            other => ExecutorError::WeightsError(other.to_string()),
        })?;

        let execution_id = self.state.create_execution(quote_id.clone())?;
        let job = ExecuteJob {
            execution_id: execution_id.clone(),
            plan,
            bundle,
            stream_batch_size,
        };

        let queued = match self.accept_execution(job) {
            Ok(queued) => queued,
            Err(err) => {
                let _ = self.state.remove_execution(&execution_id);
                return Err(err);
            }
        };

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

    fn accept_execution(&mut self, job: ExecuteJob) -> Result<bool, ExecutorError> {
        match self.try_start_execution(job) {
            Ok(()) => Ok(false),
            Err(StartExecutionError::Busy(job)) => {
                if self.pending_executions.len() >= self.queue_capacity {
                    return Err(ExecutorError::QueueFull {
                        capacity: self.queue_capacity,
                    });
                }

                self.pending_executions.push_back(*job);
                Ok(true)
            }
            Err(StartExecutionError::Closed) => Err(ExecutorError::ChannelClosed),
            Err(StartExecutionError::Other(err)) => Err(err),
        }
    }

    fn try_start_execution(&mut self, job: ExecuteJob) -> Result<(), StartExecutionError> {
        let execution_id = job.execution_id.clone();
        match self.execute_worker.try_enqueue(job) {
            Ok(()) => {
                self.state
                    .set_status(&execution_id, ExecutionStatus::Running)
                    .map_err(ExecutorError::from)?;
                self.send_status(&execution_id, ExecutionStatus::Running);
                Ok(())
            }
            Err(EnqueueError {
                error: ExecuteWorkerError::Busy,
                job,
            }) => Err(StartExecutionError::Busy(job)),
            Err(EnqueueError {
                error: ExecuteWorkerError::Stopped,
                job: _job,
            }) => {
                self.handle_complete(execution_id, None, ExecutionStatus::Failed);
                Err(StartExecutionError::Closed)
            }
        }
    }

    pub(super) fn dispatch_next_execution(&mut self) {
        while let Some(job) = self.pending_executions.pop_front() {
            match self.try_start_execution(job) {
                Ok(()) => return,
                Err(StartExecutionError::Busy(job)) => {
                    // Another execution started before the completion event was processed.
                    // Re-queue the job at the front and stop trying for now.
                    self.pending_executions.push_front(*job);
                    return;
                }
                Err(StartExecutionError::Closed) => {
                    warn!("failed to start queued execution: executor channel closed");
                }
                Err(StartExecutionError::Other(err)) => {
                    warn!("failed to start queued execution: {err:#}");
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
            self.handle_complete(execution_id.to_string(), None, ExecutionStatus::Failed);
        }
    }
}

enum StartExecutionError {
    Busy(Box<ExecuteJob>),
    Closed,
    Other(ExecutorError),
}

impl From<ExecutorError> for StartExecutionError {
    fn from(err: ExecutorError) -> Self {
        StartExecutionError::Other(err)
    }
}
