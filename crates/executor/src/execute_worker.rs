use crate::catgrad_support;
use crate::state::ExecutionPlan;
use crate::weights::ModelBundle;
use catgrad::category::lang::TypedTerm;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use tracing::{info, warn};

use super::{ExecutorError, ExecutorMessage};

pub struct ExecuteWorker {
    tx: mpsc::Sender<ExecuteJob>,
    busy: Arc<AtomicBool>,
}

pub struct ExecuteReservation {
    tx: mpsc::Sender<ExecuteJob>,
    busy: Arc<AtomicBool>,
    committed: bool,
}

struct BusyGuard {
    busy: Arc<AtomicBool>,
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.busy.store(false, Ordering::Release);
    }
}

#[derive(Debug)]
pub enum ExecuteWorkerError {
    Busy,
    Stopped,
}

impl Drop for ExecuteReservation {
    fn drop(&mut self) {
        if !self.committed {
            self.busy.store(false, Ordering::Release);
        }
    }
}

impl ExecuteReservation {
    pub fn enqueue(mut self, job: ExecuteJob) -> Result<(), ExecuteWorkerError> {
        if self.tx.send(job).is_err() {
            self.busy.store(false, Ordering::Release);
            return Err(ExecuteWorkerError::Stopped);
        }
        self.committed = true;
        Ok(())
    }
}

pub struct ExecuteJob {
    pub execution_id: String,
    pub plan: ExecutionPlan,
    pub bundle: Arc<ModelBundle>,
    pub stream_batch_size: u32,
}

impl ExecuteWorker {
    pub fn spawn(executor_tx: tokio::sync::mpsc::UnboundedSender<ExecutorMessage>) -> Self {
        let (tx, rx) = mpsc::channel::<ExecuteJob>();
        let busy = Arc::new(AtomicBool::new(false));

        let busy2 = busy.clone();
        std::thread::Builder::new()
            .name("hellas-execute-worker".to_string())
            .spawn(move || worker_loop(rx, executor_tx, busy2))
            .expect("failed to spawn execute worker thread");

        Self { tx, busy }
    }

    pub fn reserve(&self) -> Result<ExecuteReservation, ExecuteWorkerError> {
        match self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(false) => Ok(ExecuteReservation {
                tx: self.tx.clone(),
                busy: self.busy.clone(),
                committed: false,
            }),
            _ => Err(ExecuteWorkerError::Busy),
        }
    }
}

fn worker_loop(
    rx: mpsc::Receiver<ExecuteJob>,
    executor_tx: tokio::sync::mpsc::UnboundedSender<ExecutorMessage>,
    busy: Arc<AtomicBool>,
) {
    while let Ok(job) = rx.recv() {
        let _busy_guard = BusyGuard { busy: busy.clone() };
        let exec_id = job.execution_id.clone();

        // Candle backend types are not `UnwindSafe`; treat panic as job failure and continue.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_job(job, executor_tx.clone())
        }));
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                warn!("execute worker job {exec_id} failed: {err}");
                let _ = executor_tx.send(ExecutorMessage::Complete {
                    execution_id: exec_id,
                    result: None,
                    status: crate::state::ExecutionStatus::Failed,
                });
            }
            Err(_) => {
                warn!("execute worker job {exec_id} panicked");
                let _ = executor_tx.send(ExecutorMessage::Complete {
                    execution_id: exec_id,
                    result: None,
                    status: crate::state::ExecutionStatus::Failed,
                });
            }
        }
    }
}

fn run_job(
    job: ExecuteJob,
    tx: tokio::sync::mpsc::UnboundedSender<ExecutorMessage>,
) -> Result<(), ExecutorError> {
    let execution_id = job.execution_id;
    execute_plan_sync(
        &execution_id,
        job.plan,
        job.bundle.as_ref(),
        job.stream_batch_size,
        &tx,
    )?;
    let _ = tx.send(ExecutorMessage::Complete {
        execution_id,
        result: None,
        status: crate::state::ExecutionStatus::Completed,
    });
    Ok(())
}

fn execute_plan_sync(
    execution_id: &str,
    plan: ExecutionPlan,
    bundle: &ModelBundle,
    stream_batch_size: u32,
    tx: &tokio::sync::mpsc::UnboundedSender<ExecutorMessage>,
) -> Result<(), ExecutorError> {
    let term: TypedTerm =
        serde_json::from_slice(&plan.graph).map_err(ExecutorError::InvalidGraph)?;

    info!(execution_id, "execute worker running plan");

    catgrad_support::run_graph_streaming(
        bundle,
        &plan.model_config_json,
        &plan.input,
        &term,
        plan.prompt_tokens,
        plan.max_new_tokens,
        &plan.stop_token_ids,
        stream_batch_size,
        |progress, chunk| {
            let _ = tx.send(ExecutorMessage::Progress {
                execution_id: execution_id.to_string(),
                chunk: chunk.to_vec(),
                progress,
            });
        },
    )?;

    Ok(())
}
