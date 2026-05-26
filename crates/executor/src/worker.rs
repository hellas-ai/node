use crate::catnix_bridge::text_state_value_id_for_tokens;
use crate::executor::ExecutorMessage;
use crate::metrics::ExecutorMetrics;
use crate::programs::{ExecutionContext, ExecutionStart};
use crate::runner;
use crate::state::{Invocation, StopReason as RuntimeStopReason, Termination};
use catnix::{
    Canonical, Digest as CatnixDigest, StopReason as CatnixStopReason, TermId, TextRunOutput,
    TokenIds,
};
use hellas_core::ProducerSigningKey;
use hellas_core::adaptors::catgrad_text::CatgradText;
use hellas_core::protocol::{Call, EvidenceBinding, ProjectResult, Receipt};
use hellas_rpc::pb::hellas::{
    Chunk as PbChunk, ExecuteStreamEvent, execute_stream_event::Event as PbEvent,
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
    pub sender: tokio_mpsc::Sender<Result<ExecuteStreamEvent, Status>>,
    pub metrics: Arc<ExecutorMetrics>,
    /// Catnix projection captured from the corresponding quote. Used to
    /// build and sign the terminal catnix `Receipt`.
    pub catnix_call: Option<Call>,
    /// Producer signing key (ephemeral today). Used to sign the catnix
    /// `Receipt` for audit logging.
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
        // Capture state needed for the post-run catnix audit Receipt
        // before `job` is moved into `run_job`.
        let catnix_call = job.catnix_call.clone();
        let producer_key = Arc::clone(&job.producer_key);
        let prompt_token_ids = job.invocation.input_ids.clone();

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
                let catnix_receipt_commitment = build_catnix_audit_receipt(
                    &execution_id,
                    catnix_call.as_ref(),
                    &producer_key,
                    &outcome,
                    &prompt_token_ids,
                );
                Termination::Completed {
                    total_tokens: outcome.total_tokens,
                    stop_reason: outcome.stop_reason,
                    receipt_cid: outcome.receipt_cid,
                    catnix_receipt_commitment,
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
        let _ = sender.blocking_send(Ok(ExecuteStreamEvent {
            event: Some(PbEvent::Outcome(termination.into_pb())),
        }));

        // Signal the actor that the worker is free for the next pending
        // job. Failure here means the actor is shutting down; nothing to
        // recover.
        let _ = executor_tx.send(ExecutorMessage::WorkerIdle);
    }
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

/// Map the runtime's `StopReason` enum onto catnix's `StopReason`
/// newtype. Byte values intentionally align with the wire
/// `hellas.v1.FinishStatus` proto enum so any future swap goes through
/// here, not at the wire boundary.
fn map_stop_reason(reason: RuntimeStopReason) -> CatnixStopReason {
    match reason {
        RuntimeStopReason::EndOfSequence => CatnixStopReason::END_OF_SEQUENCE,
        RuntimeStopReason::MaxNewTokens => CatnixStopReason::MAX_OUTPUT,
        RuntimeStopReason::Cancelled => CatnixStopReason::CANCELLED,
    }
}

/// Build a catnix `TextRunOutput` from the runtime's decode outcome,
/// project it through CatgradText's `project_result`, and sign a
/// `Receipt` with the executor's producer key. Any failure is logged and
/// returned as `None` so the execution can still complete.
fn build_catnix_audit_receipt(
    execution_id: &str,
    catnix_call: Option<&Call>,
    producer_key: &ProducerSigningKey,
    outcome: &runner::DecodeOutcome,
    prompt_token_ids: &[u32],
) -> Option<[u8; 32]> {
    let Some(call) = catnix_call else {
        debug!(%execution_id, "no catnix call captured at quote time; skipping audit receipt");
        return None;
    };

    // For CatgradText, the Call's payload bytes ARE a Term's canonical
    // bytes, so its TermId is the BLAKE3 of those bytes.
    let term_id = TermId::from_digest(CatnixDigest::from_canonical_bytes(call.payload.as_bytes()));

    // Absolute final decoder position: initial state + prompt prefill +
    // generated tokens. For a cold start initial_state is genesis (len 0),
    // so position = prompt_tokens + outcome.total_tokens. Continuation
    // runs would add the previous state's position; not yet wired.
    let absolute_position = (prompt_token_ids.len() as u64).saturating_add(outcome.total_tokens);

    // The output state is the catnix TextState over the full cold-start
    // token history: prompt prefill + generated tokens. Anchored
    // continuations will need to prepend the prior state's token history
    // when that path is wired.
    let state_value_id = text_state_value_id_for_tokens(
        prompt_token_ids
            .iter()
            .copied()
            .chain(outcome.output_tokens.iter().copied()),
    );

    let tokens_value = TokenIds::from_u32s(outcome.output_tokens.iter().copied());
    let tokens_value_id = tokens_value.value_id();

    let stop_reason = map_stop_reason(outcome.stop_reason);

    let text_run_output = TextRunOutput::new(
        term_id,
        absolute_position,
        state_value_id,
        tokens_value_id,
        stop_reason,
    );

    let result = match CatgradText::project_result(&text_run_output, call) {
        Ok(r) => r,
        Err(err) => {
            warn!(%execution_id, error = %err, "catnix project_result failed (audit, non-fatal)");
            return None;
        }
    };

    let receipt = match Receipt::sign_delivery(call, &result, EvidenceBinding::None, producer_key) {
        Ok(r) => r,
        Err(err) => {
            warn!(%execution_id, error = %err, "catnix Receipt::sign_delivery failed (audit, non-fatal)");
            return None;
        }
    };

    // Receipt commitment = BLAKE3 of the canonical signed-Claim body.
    let receipt_commitment_digest = receipt.claim.signature_preimage();

    // Surface the key audit invariants in structured logs.
    let call_commitment = receipt.claim.call_commitment.digest();
    let result_commitment = receipt.claim.result_commitment.digest();
    let producer_id = receipt.claim.producer.digest();
    let term_id_str = format!("{term_id}");
    info!(
        %execution_id,
        audit_only = true,
        catnix_receipt_persisted = false,
        catnix_receipt_commitment_in_outcome = true,
        producer_key_ephemeral = true,
        producer_id = %producer_id,
        catnix_term_id = %term_id_str,
        catnix_call_commitment = %call_commitment,
        catnix_result_commitment = %result_commitment,
        catnix_receipt_commitment = %receipt_commitment_digest,
        catnix_position = absolute_position,
        catnix_total_generated = outcome.total_tokens,
        catnix_stop_reason = ?stop_reason,
        catnix_tokens_value_id = %tokens_value_id.digest(),
        "catnix audit receipt signed and attached to terminal outcome"
    );

    Some(*receipt_commitment_digest.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::map_stop_reason;
    use crate::state::StopReason as RuntimeStopReason;
    use catnix::StopReason as CatnixStopReason;

    #[test]
    fn stop_reason_mapping_covers_all_runtime_variants() {
        assert_eq!(
            map_stop_reason(RuntimeStopReason::EndOfSequence),
            CatnixStopReason::END_OF_SEQUENCE,
        );
        assert_eq!(
            map_stop_reason(RuntimeStopReason::MaxNewTokens),
            CatnixStopReason::MAX_OUTPUT,
        );
        assert_eq!(
            map_stop_reason(RuntimeStopReason::Cancelled),
            CatnixStopReason::CANCELLED,
        );
    }
}

/// Build the per-chunk callback the runner invokes. It pushes a `Chunk`
/// frame onto the per-execution sender and, on send failure (consumer
/// dropped the receiver), fires the cancel token so the runner exits at
/// the next decode boundary.
fn make_on_progress(
    position: Arc<AtomicU64>,
    sender: tokio_mpsc::Sender<Result<ExecuteStreamEvent, Status>>,
    cancel: CancellationToken,
    execution_id: String,
) -> impl FnMut(u64, &[u8]) + Send {
    move |progress: u64, chunk: &[u8]| {
        position.store(progress, Ordering::Relaxed);
        let event = ExecuteStreamEvent {
            event: Some(PbEvent::Chunk(PbChunk {
                position: progress,
                tokens: chunk.to_vec(),
            })),
        };
        if sender.blocking_send(Ok(event)).is_err() {
            debug!(%execution_id, "consumer dropped; cancelling worker");
            cancel.cancel();
        }
    }
}
