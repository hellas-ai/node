use crate::executor::ExecutorMessage;
use crate::runner;
use crate::state::{ExecutionPlan, ExecutionStatus};
use crate::weights::WeightsBundle;
use crate::ExecutorError;
use catgrad_llm::Program;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
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
    pub plan: ExecutionPlan,
    pub bundle: Arc<WeightsBundle>,
    pub stream_batch_size: u32,
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
            plan,
            bundle,
            stream_batch_size,
        } = job;
        let program: Program =
            serde_json::from_slice(&plan.program).map_err(ExecutorError::InvalidProgram)?;

        info!(execution_id = %execution_id, "execute worker running plan");

        runner::run_program_streaming(
            bundle.as_ref(),
            &plan,
            program,
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
