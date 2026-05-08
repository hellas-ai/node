use crate::executor::ExecutorMessage;
use crate::metrics::ExecutorMetrics;
use crate::state::{Invocation, ModelLocator, StopReason, Termination};
use catnix::OutputAddressed;
use chatgrad::PreparedPrompt;
use chatgrad::run::{GenerationControl, GenerationTermination, ModelEngine};
use hellas_core::{
    Digest, ProducerSigningKey, SignedEvidenceReceipt, SymbolicEvidence, SymbolicOutput,
    SymbolicRequest, hash_tuple,
};
use hellas_pb::hellas::{
    WorkChunk as PbChunk, WorkEvent as PbWorkEvent, work_event::Kind as PbEvent,
};
use std::collections::HashMap;
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
    pub locator: ModelLocator,
    pub invocation: Invocation,
    pub stream_batch_size: u32,
    pub accepted_at: Instant,
    pub cancel: CancellationToken,
    pub sender: tokio_mpsc::Sender<Result<PbWorkEvent, Status>>,
    pub metrics: Arc<ExecutorMetrics>,
    pub producer_key: Arc<ProducerSigningKey>,
}

struct DecodeOutcome {
    stop_reason: StopReason,
    output_tokens: Vec<u32>,
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
}

fn worker_loop(
    rx: Receiver<ExecuteJob>,
    executor_tx: tokio_mpsc::UnboundedSender<ExecutorMessage>,
) {
    let mut engines: HashMap<ModelLocator, ModelEngine> = HashMap::new();
    while let Ok(job) = rx.recv() {
        let execution_id = job.execution_id.clone();
        let model_id = job.model_id.clone();
        let metrics = Arc::clone(&job.metrics);
        let sender = job.sender.clone();
        let cancel = job.cancel.clone();
        let symbolic_request = job.symbolic_request.clone();
        let producer_key = Arc::clone(&job.producer_key);

        let position = Arc::new(AtomicU64::new(0));
        let on_progress = make_on_progress(
            Arc::clone(&position),
            sender.clone(),
            cancel.clone(),
            execution_id.clone(),
        );

        let termination = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_job(job, on_progress, &mut engines)
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

        let generated = termination.position();
        if termination.is_completed() {
            metrics.record_execution_completed(&model_id, generated);
        } else {
            metrics.record_execution_failed(&model_id, generated);
        }

        let _ = sender.blocking_send(Ok(termination.into_pb()));
        let _ = executor_tx.send(ExecutorMessage::WorkerIdle);
    }
}

fn completed_termination(
    symbolic_request: &SymbolicRequest,
    producer_key: &ProducerSigningKey,
    outcome: DecodeOutcome,
) -> Result<Termination, hellas_rpc::ExecutorError> {
    let text_artifact_cid =
        text_artifact_cid(symbolic_request.text_execution_cid, &outcome.output_tokens);
    let symbolic_output = SymbolicOutput { text_artifact_cid };
    let evidence = SymbolicEvidence::TextArtifactCid(text_artifact_cid);
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

fn text_artifact_cid(text_execution_cid: Digest, output_tokens: &[u32]) -> Digest {
    let execution_id = catnix::TextExecutionId::from_digest(to_catnix_digest(text_execution_cid));
    let generated_tokens_id = catnix::TokenIds::from(output_tokens.to_vec()).output_id();
    // The text-state bytes will live in the artifact resolver. Until that
    // lands, derive a stable local state id from the execution and generated
    // token artifact so the TextArtifact identity has the right shape.
    let state_digest = hash_tuple(
        "hellas.executor.synthetic_text_state.v1",
        &[
            text_execution_cid.as_bytes(),
            generated_tokens_id.as_bytes(),
        ],
    );
    let state_id = catnix::TextStateId::from_digest(to_catnix_digest(state_digest));
    let artifact = catnix::TextArtifact::output(
        execution_id,
        output_tokens.len() as u64,
        state_id,
        generated_tokens_id,
    );
    from_catnix_digest(artifact.output_id().digest())
}

fn to_catnix_digest(digest: Digest) -> catnix::Digest {
    catnix::Digest::from_bytes(digest.into_bytes())
}

fn from_catnix_digest(digest: catnix::Digest) -> Digest {
    Digest::from_bytes(*digest.as_bytes())
}

fn run_job(
    job: ExecuteJob,
    mut on_progress: impl FnMut(u64, &[u8]),
    engines: &mut HashMap<ModelLocator, ModelEngine>,
) -> Result<DecodeOutcome, hellas_rpc::ExecutorError> {
    let ExecuteJob {
        execution_id,
        locator,
        invocation,
        stream_batch_size,
        accepted_at,
        cancel,
        ..
    } = job;

    debug!(execution_id = %execution_id, "execute worker running model");
    debug!(
        execution_id = %execution_id,
        queue_wait_ms = accepted_at.elapsed().as_millis(),
        prompt_tokens = invocation.input_ids.len(),
        "execute worker starting"
    );

    let engine = match engines.get(&locator) {
        Some(engine) => engine.clone(),
        None => {
            let backend = crate::backend::create_backend()?;
            let engine = ModelEngine::new_with_backend(
                &locator.model_id,
                &locator.revision,
                backend,
                true,
                locator.dtype,
            )
            .map_err(|err| hellas_rpc::ExecutorError::WeightsError(err.to_string()))?;
            engines.insert(locator.clone(), engine.clone());
            engine
        }
    };
    let prepared = PreparedPrompt::new(
        input_ids_to_i32(&invocation.input_ids)?,
        invocation.stop_token_ids,
    );
    let batch_size = usize::try_from(stream_batch_size.max(1))
        .unwrap_or(usize::MAX)
        .max(1);
    let mut output_tokens = Vec::new();
    let mut pending = Vec::with_capacity(batch_size);
    let mut generated = 0u64;

    let generated_output = engine
        .generate_tokens_from_prepared(&prepared, invocation.max_new_tokens, |token| {
            generated = generated.saturating_add(1);
            output_tokens.push(token.token_id);
            pending.push(token.token_id);
            if pending.len() >= batch_size {
                on_progress(generated, &hellas_rpc::encode_token_ids(&pending));
                pending.clear();
            }
            if cancel.is_cancelled() {
                Ok(GenerationControl::Cancel)
            } else {
                Ok(GenerationControl::Continue)
            }
        })
        .map_err(|err| hellas_rpc::ExecutorError::WeightsError(err.to_string()))?;

    if !pending.is_empty() {
        on_progress(generated, &hellas_rpc::encode_token_ids(&pending));
    }

    let stop_reason = match generated_output.termination {
        GenerationTermination::Stop => StopReason::EndOfSequence,
        GenerationTermination::MaxTokens => StopReason::MaxNewTokens,
        GenerationTermination::Cancelled => StopReason::Cancelled,
    };

    Ok(DecodeOutcome {
        stop_reason,
        output_tokens,
    })
}

fn input_ids_to_i32(input_ids: &[u32]) -> Result<Vec<i32>, hellas_rpc::ExecutorError> {
    input_ids
        .iter()
        .copied()
        .map(|token| {
            i32::try_from(token).map_err(|_| {
                hellas_rpc::ExecutorError::InvalidTokenPayload(format!(
                    "token id {token} exceeds i32 range"
                ))
            })
        })
        .collect()
}

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
