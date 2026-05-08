use crate::executor::ExecutorMessage;
use crate::metrics::ExecutorMetrics;
use crate::programs::{ExecutionContext, ExecutionStart};
use crate::runner;
use crate::state::{Invocation, Termination};
use hellas_core::{
    Digest, ProducerSigningKey, SignedEvidenceReceipt, SymbolicEvidence, SymbolicOutput,
    SymbolicRequest,
};
use hellas_pb::hellas::{
    WorkChunk as PbChunk, WorkEvent as PbWorkEvent, work_event::Kind as PbEvent,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::time::Instant;
use tokio::sync::mpsc as tokio_mpsc;
use tokio_util::sync::CancellationToken;
use tonic::Status;
use tracing::warn;

pub(crate) struct ExecuteWorker {
    tx: SyncSender<ExecuteJob>,
}

pub(crate) enum EnqueueError {
    Busy(ExecuteJob),
    Stopped(ExecuteJob),
}

pub(crate) struct ExecuteJob {
    pub execution_id: String,
    pub model_id: String,
    pub symbolic_request: SymbolicRequest,
    pub invocation: Invocation,
    pub execution: Arc<ExecutionContext>,
    pub start: ExecutionStart,
    pub stream_batch_size: u32,
    pub accepted_at: Instant,
    /// Cooperative cancel signal. The runner polls between decode steps.
    /// The worker also fires it from inside the on_progress callback when
    /// the per-execution sender returns Err (consumer dropped).
    pub cancel: CancellationToken,
    /// Per-execution sender. Worker pushes Chunk frames here as decode
    /// progresses, and the terminal Outcome at the end. Receiver lives
    /// with the streaming-RPC consumer; dropping it is the cancel signal.
    pub sender: tokio_mpsc::Sender<Result<PbWorkEvent, Status>>,
    pub metrics: Arc<ExecutorMetrics>,
    pub producer_key: Arc<ProducerSigningKey>,
}

impl ExecuteWorker {
    pub(crate) fn spawn(executor_tx: tokio_mpsc::UnboundedSender<ExecutorMessage>) -> Self {
        let (tx, rx) = mpsc::sync_channel::<ExecuteJob>(0);
        std::thread::Builder::new()
            .name("hellas-execute-worker".to_string())
            .spawn(move || worker_loop(rx, executor_tx))
            .expect("failed to spawn execute worker thread");
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

fn worker_loop(
    rx: Receiver<ExecuteJob>,
    executor_tx: tokio_mpsc::UnboundedSender<ExecutorMessage>,
) {
    while let Ok(job) = rx.recv() {
        let execution_id = job.execution_id.clone();
        let model_id = job.model_id.clone();
        let metrics = Arc::clone(&job.metrics);
        let sender = job.sender.clone();
        let cancel = job.cancel.clone();
        let symbolic_request = job.symbolic_request.clone();
        let producer_key = Arc::clone(&job.producer_key);

        // Track the last reported position so a Failed termination can
        // honestly report tokens emitted before the error.
        let position = Arc::new(AtomicU64::new(0));
        let on_progress = make_on_progress(
            Arc::clone(&position),
            sender.clone(),
            cancel.clone(),
            execution_id.clone(),
        );

        let termination = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_job(job, on_progress)
        })) {
            Ok(Ok(outcome)) => {
                match completed_termination(&symbolic_request, &producer_key, outcome) {
                    Ok(termination) => termination,
                    Err(err) => {
                        let msg = format!("{err:#}");
                        warn!(
                            "execute worker job {execution_id} failed while signing receipt: {msg}"
                        );
                        Termination::Failed {
                            position: position.load(Ordering::Relaxed),
                            error: msg,
                        }
                    }
                }
            }
            Ok(Err(err)) => {
                let msg = format!("{err:#}");
                warn!("execute worker job {execution_id} failed: {msg}");
                Termination::Failed {
                    position: position.load(Ordering::Relaxed),
                    error: msg,
                }
            }
            Err(panic) => {
                let msg = format!("worker panicked: {}", crate::backend::panic_message(&panic));
                warn!("execute worker job {execution_id} {msg}");
                Termination::Failed {
                    position: position.load(Ordering::Relaxed),
                    error: msg,
                }
            }
        };

        // Metrics fire on the worker thread — actor doesn't need to know
        // success/failure, only that the slot is free.
        let generated = termination.position();
        if termination.is_completed() {
            metrics.record_execution_completed(&model_id, generated);
        } else {
            metrics.record_execution_failed(&model_id, generated);
        }

        // Send the terminal frame; ignore Err (consumer already dropped).
        let _ = sender.blocking_send(Ok(termination.into_pb()));

        // Signal the actor that the worker is free for the next pending
        // job. Failure here means the actor is shutting down; nothing to
        // recover.
        let _ = executor_tx.send(ExecutorMessage::WorkerIdle);
    }
}

fn completed_termination(
    symbolic_request: &SymbolicRequest,
    producer_key: &ProducerSigningKey,
    outcome: runner::DecodeOutcome,
) -> Result<Termination, hellas_rpc::ExecutorError> {
    let receipt_bytes = *outcome.receipt_cid.as_bytes();
    let symbolic_output = SymbolicOutput {
        text_receipt_cid: Digest::from_bytes(receipt_bytes),
    };
    let evidence = SymbolicEvidence::TextReceiptCid(Digest::from_bytes(receipt_bytes));
    let receipt = SignedEvidenceReceipt::sign_symbolic(
        symbolic_request,
        &symbolic_output,
        evidence,
        producer_key,
    )
    .map_err(|err| {
        hellas_rpc::ExecutorError::WeightsError(format!("receipt signing failed: {err}"))
    })?;
    let envelope = hellas_core::ReceiptEnvelope::Symbolic(receipt);
    let receipt_dag_cbor = hellas_core::canonical_dag_cbor(&envelope).map_err(|err| {
        hellas_rpc::ExecutorError::WeightsError(format!("receipt encoding failed: {err}"))
    })?;

    Ok(Termination::Completed {
        stop_reason: outcome.stop_reason,
        output_tokens: outcome.output_tokens,
        receipt_dag_cbor,
    })
}

fn run_job(
    job: ExecuteJob,
    on_progress: impl FnMut(u64, &[u8]),
) -> Result<runner::DecodeOutcome, hellas_rpc::ExecutorError> {
    let ExecuteJob {
        execution_id,
        invocation,
        execution,
        start,
        stream_batch_size,
        accepted_at,
        cancel,
        ..
    } = job;

    debug!(execution_id = %execution_id, "execute worker running plan");
    debug!(
        execution_id = %execution_id,
        commitment_id = %start.commitment_id,
        queue_wait_ms = accepted_at.elapsed().as_millis(),
        prompt_tokens = invocation.input_ids.len(),
        cached_output_tokens = start.cached.as_ref().map_or(0, |c| c.output_tokens.len()),
        "execute worker starting"
    );

    runner::run_cached_program_streaming(
        execution.as_ref(),
        &start,
        &invocation,
        stream_batch_size,
        &cancel,
        on_progress,
    )
}

/// Build the per-chunk callback the runner invokes. It pushes a `Chunk`
/// frame onto the per-execution sender and, on send failure (consumer
/// dropped the receiver), fires the cancel token so the runner exits at
/// the next decode boundary.
fn make_on_progress(
    position: Arc<AtomicU64>,
    sender: tokio_mpsc::Sender<Result<PbWorkEvent, Status>>,
    cancel: CancellationToken,
    execution_id: String,
) -> impl FnMut(u64, &[u8]) + Send {
    move |progress: u64, chunk: &[u8]| {
        position.store(progress, Ordering::Relaxed);
        let event = PbWorkEvent {
            kind: Some(PbEvent::Chunk(PbChunk {
                position: progress,
                bytes: chunk.to_vec(),
            })),
        };
        if sender.blocking_send(Ok(event)).is_err() {
            debug!(%execution_id, "consumer dropped; cancelling worker");
            cancel.cancel();
        }
    }
}
