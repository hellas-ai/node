use crate::ExecutorError;
use crate::executor::ExecutorMessage;
use crate::runner;
use crate::state::{ExecutionStatus, Invocation};
use crate::weights::{ExecutionContext, ExecutionStart};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::time::Instant;
use tracing::{info, warn};

pub(crate) struct ExecuteWorker {
    tx: SyncSender<ExecuteJob>,
}

pub(crate) enum EnqueueError {
    Busy(ExecuteJob),
    Stopped(ExecuteJob),
}

pub(crate) struct ExecuteJob {
    pub execution_id: String,
    pub invocation: Invocation,
    pub execution: Arc<ExecutionContext>,
    pub start: ExecutionStart,
    pub stream_batch_size: u32,
    pub accepted_at: Instant,
}

struct WorkerThread {
    rx: Receiver<ExecuteJob>,
    executor_tx: tokio::sync::mpsc::UnboundedSender<ExecutorMessage>,
}

impl ExecuteWorker {
    pub(crate) fn spawn(executor_tx: tokio::sync::mpsc::UnboundedSender<ExecutorMessage>) -> Self {
        let (tx, rx) = mpsc::sync_channel::<ExecuteJob>(0);
        WorkerThread::spawn(rx, executor_tx);
        Self { tx }
    }

    pub(crate) fn try_enqueue(&self, job: ExecuteJob) -> Result<(), EnqueueError> {
        match self.tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(job)) => Err(EnqueueError::Busy(job)),
            Err(TrySendError::Disconnected(job)) => Err(EnqueueError::Stopped(job)),
        }
    }

    #[cfg(test)]
    pub(crate) fn stopped() -> Self {
        let (tx, rx) = mpsc::sync_channel::<ExecuteJob>(0);
        drop(rx);
        Self { tx }
    }
}

impl WorkerThread {
    fn spawn(
        rx: Receiver<ExecuteJob>,
        executor_tx: tokio::sync::mpsc::UnboundedSender<ExecutorMessage>,
    ) {
        std::thread::Builder::new()
            .name("hellas-execute-worker".to_string())
            .spawn(move || Self { rx, executor_tx }.run())
            .expect("failed to spawn execute worker thread");
    }

    fn run(self) {
        let Self { rx, executor_tx } = self;
        while let Ok(job) = rx.recv() {
            let execution_id = job.execution_id.clone();
            let status = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Self::run_job(job, &executor_tx)
            })) {
                Ok(Ok(())) => ExecutionStatus::Completed,
                Ok(Err(err)) => {
                    warn!("execute worker job {execution_id} failed: {err}");
                    ExecutionStatus::Failed
                }
                Err(_) => {
                    warn!("execute worker job {execution_id} panicked");
                    ExecutionStatus::Failed
                }
            };

            Self::send_completion(&executor_tx, execution_id, status);
        }
    }

    fn run_job(
        job: ExecuteJob,
        executor_tx: &tokio::sync::mpsc::UnboundedSender<ExecutorMessage>,
    ) -> Result<(), ExecutorError> {
        let ExecuteJob {
            execution_id,
            invocation,
            execution,
            start,
            stream_batch_size,
            accepted_at,
        } = job;

        info!(execution_id = %execution_id, "execute worker running plan");
        debug!(
            execution_id = %execution_id,
            queue_wait_ms = accepted_at.elapsed().as_millis(),
            prompt_tokens = invocation.input_ids.len(),
            cached_prompt_tokens = start.transcript.len(),
            cached_output_tokens = start.cached_output_tokens.as_ref().map_or(0, |tokens| tokens.len()),
            "execute worker starting"
        );

        runner::run_cached_program_streaming(
            execution.as_ref(),
            &start,
            &invocation,
            stream_batch_size,
            |progress, chunk| {
                let _ = executor_tx.send(ExecutorMessage::Progress {
                    execution_id: execution_id.clone(),
                    output_chunk: chunk.to_vec(),
                    progress,
                });
            },
        )
    }

    fn send_completion(
        executor_tx: &tokio::sync::mpsc::UnboundedSender<ExecutorMessage>,
        execution_id: String,
        status: ExecutionStatus,
    ) {
        let _ = executor_tx.send(ExecutorMessage::Complete {
            execution_id,
            output: None,
            status,
        });
    }
}
