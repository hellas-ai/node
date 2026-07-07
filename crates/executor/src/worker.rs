use crate::executor::ExecutorMessage;
use crate::state::{Invocation, ModelLocator, StopReason};
use chatgrad::PreparedPrompt;
use chatgrad::run::{GenerationControl, GenerationTermination, ModelEngine};
use hellas_rpc::evaluate::{EvaluateOutputTranscriptBuilder, input_commitment};
use hellas_rpc::pb::execute::{
    WorkChunk as PbChunk, WorkEvent as PbWorkEvent, work_event::Kind as PbEvent,
};
use hellas_rpc::stream::output_event_to_pb;
use hellas_rpc::{EvaluateRequest, OutputEventEnvelope, ProducerSigningKey};
use hellas_wire::WireStatus;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::time::Instant;
use tokio::sync::mpsc as tokio_mpsc;
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub(crate) struct ExecuteWorker {
    tx: SyncSender<ExecuteJob>,
}

pub(crate) enum EnqueueError {
    Busy(Box<ExecuteJob>),
    Stopped(Box<ExecuteJob>),
}

pub(crate) struct ExecuteJob {
    pub execution_id: String,
    pub request_commitment: [u8; 32],
    pub model_id: String,
    pub evaluate_request: EvaluateRequest,
    pub locator: ModelLocator,
    pub invocation: Invocation,
    pub stream_batch_size: u32,
    pub accepted_at: Instant,
    pub cancel: CancellationToken,
    pub sender: tokio_mpsc::Sender<Result<PbWorkEvent, WireStatus>>,
    pub producer_key: Arc<ProducerSigningKey>,
}

struct DecodeOutcome {
    stop_reason: StopReason,
    output_tokens: Vec<u32>,
}

pub(crate) struct WorkerCompletion {
    pub execution_id: String,
    pub request_commitment: [u8; 32],
    pub model_id: String,
    pub evaluate_request: EvaluateRequest,
    pub invocation: Invocation,
    pub sender: tokio_mpsc::Sender<Result<PbWorkEvent, WireStatus>>,
    pub result: WorkerCompletionResult,
}

pub(crate) enum WorkerCompletionResult {
    Completed {
        stop_reason: StopReason,
        output_tokens: Vec<u32>,
        output_events: Vec<OutputEventEnvelope>,
    },
    Failed {
        position: u64,
        error: String,
    },
}

impl WorkerCompletionResult {
    pub(crate) fn position(&self) -> u64 {
        match self {
            Self::Completed { output_tokens, .. } => output_tokens.len() as u64,
            Self::Failed { position, .. } => *position,
        }
    }
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
            Err(TrySendError::Full(job)) => Err(EnqueueError::Busy(Box::new(job))),
            Err(TrySendError::Disconnected(job)) => Err(EnqueueError::Stopped(Box::new(job))),
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
        let request_commitment = job.request_commitment;
        let model_id = job.model_id.clone();
        let sender = job.sender.clone();
        let cancel = job.cancel.clone();
        let evaluate_request = job.evaluate_request.clone();
        let invocation = job.invocation.clone();
        let producer_key = job.producer_key.clone();

        let position = Arc::new(AtomicU64::new(0));
        let mut output_builder = EvaluateOutputTranscriptBuilder::new(
            input_commitment(&evaluate_request),
            &producer_key,
        );
        let mut output_events = Vec::new();
        let on_progress = make_on_progress(
            Arc::clone(&position),
            sender.clone(),
            cancel.clone(),
            execution_id.clone(),
            &mut output_builder,
            &mut output_events,
        );

        let termination = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_job(job, on_progress, &mut engines)
        })) {
            Ok(Ok(outcome)) => WorkerCompletionResult::Completed {
                stop_reason: outcome.stop_reason,
                output_tokens: outcome.output_tokens,
                output_events,
            },
            Ok(Err(err)) => {
                let msg = format!("{err:#}");
                warn!("execute worker job {execution_id} failed: {msg}");
                WorkerCompletionResult::Failed {
                    position: position.load(Ordering::Relaxed),
                    error: msg,
                }
            }
            Err(panic) => {
                let msg = format!("worker panicked: {}", crate::backend::panic_message(&panic));
                warn!("execute worker job {execution_id} {msg}");
                WorkerCompletionResult::Failed {
                    position: position.load(Ordering::Relaxed),
                    error: msg,
                }
            }
        };

        let _ = executor_tx.send(ExecutorMessage::SchemeFinished(Box::new(
            WorkerCompletion {
                execution_id,
                request_commitment,
                model_id,
                evaluate_request,
                invocation,
                sender,
                result: termination,
            },
        )));
    }
}

fn run_job(
    job: ExecuteJob,
    mut on_progress: impl FnMut(u64, Vec<u32>) -> Result<(), hellas_rpc::ExecutorError>,
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
                hellas_rpc::model::to_catgrad_dtype(locator.dtype),
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
    let mut progress_error = None;

    let generated_output = engine
        .generate_tokens_from_prepared(&prepared, invocation.max_new_tokens, |token| {
            generated = generated.saturating_add(1);
            output_tokens.push(token.token_id);
            pending.push(token.token_id);
            if pending.len() >= batch_size
                && let Err(err) = on_progress(generated, std::mem::take(&mut pending))
            {
                progress_error = Some(err);
                cancel.cancel();
                return Ok(GenerationControl::Cancel);
            }
            if cancel.is_cancelled() {
                Ok(GenerationControl::Cancel)
            } else {
                Ok(GenerationControl::Continue)
            }
        })
        .map_err(|err| hellas_rpc::ExecutorError::WeightsError(err.to_string()))?;

    if let Some(err) = progress_error {
        return Err(err);
    }

    if !pending.is_empty() {
        on_progress(generated, pending)?;
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

fn make_on_progress<'a, 'b>(
    position: Arc<AtomicU64>,
    sender: tokio_mpsc::Sender<Result<PbWorkEvent, WireStatus>>,
    cancel: CancellationToken,
    execution_id: String,
    output_builder: &'a mut EvaluateOutputTranscriptBuilder<'b>,
    output_events: &'a mut Vec<OutputEventEnvelope>,
) -> impl FnMut(u64, Vec<u32>) -> Result<(), hellas_rpc::ExecutorError> + Send + 'a {
    move |progress: u64, token_ids: Vec<u32>| {
        position.store(progress, Ordering::Relaxed);
        let output_event = output_builder
            .push_token_delta(token_ids)
            .map_err(|err| hellas_rpc::ExecutorError::WeightsError(err.to_string()))?;
        let event = PbWorkEvent {
            kind: Some(PbEvent::Chunk(PbChunk {
                output_event: Some(output_event_to_pb(&output_event)),
            })),
        };
        if sender.blocking_send(Ok(event)).is_err() {
            debug!(%execution_id, "consumer dropped; cancelling worker");
            cancel.cancel();
            return Err(hellas_rpc::ExecutorError::ChannelClosed);
        }
        output_events.push(output_event);
        Ok(())
    }
}
