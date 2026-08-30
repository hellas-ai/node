use crate::artifacts::PreparedTextArtifacts;
use crate::engine::{GenerationTermination, PackageEngine};
use crate::executor::ExecutorMessage;
use crate::package::PackageSource;
use crate::state::{Invocation, LoadedPackage, PackageLocator, StopReason};
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
use tokio::sync::{mpsc as tokio_mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::warn;
use zeroize::Zeroize;

pub(crate) struct ExecuteWorker {
    tx: SyncSender<WorkerCommand>,
}

enum WorkerCommand {
    LoadPackage(LoadPackage),
    Execute(Box<ExecuteJob>),
}

struct LoadPackage {
    source: PackageSource,
    reply: oneshot::Sender<Result<LoadedPackage, crate::ExecutorError>>,
}

pub(crate) enum EnqueueError {
    Busy(Box<ExecuteJob>),
    Stopped(Box<ExecuteJob>),
}

pub(crate) struct ExecuteJob {
    pub execution_id: String,
    pub request_commitment: [u8; 32],
    pub package_name: String,
    pub evaluate_request: EvaluateRequest,
    pub locator: PackageLocator,
    pub invocation: Invocation,
    pub prepared_artifacts: Option<PreparedTextArtifacts>,
    pub stream_batch_size: u32,
    pub accepted_at: Instant,
    pub cancel: CancellationToken,
    pub sender: tokio_mpsc::Sender<Result<PbWorkEvent, WireStatus>>,
    pub producer_key: Arc<ProducerSigningKey>,
}

struct GenerationOutcome {
    stop_reason: StopReason,
    output_tokens: Vec<u32>,
}

struct SensitiveInputIds(Vec<u32>);

impl SensitiveInputIds {
    fn new(input_ids: Vec<u32>) -> Self {
        Self(input_ids)
    }
}

impl Drop for SensitiveInputIds {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct WorkerCompletion {
    pub execution_id: String,
    pub request_commitment: [u8; 32],
    pub package_name: String,
    pub evaluate_request: EvaluateRequest,
    pub invocation: Invocation,
    pub prepared_artifacts: Option<PreparedTextArtifacts>,
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
        let (tx, rx) = mpsc::sync_channel::<WorkerCommand>(0);
        std::thread::Builder::new()
            .name("hellas-execute-worker".to_string())
            .spawn(move || worker_loop(rx, executor_tx))
            .expect("failed to spawn execute worker thread");
        Self { tx }
    }

    pub(crate) fn try_enqueue(&self, job: ExecuteJob) -> Result<(), EnqueueError> {
        match self.tx.try_send(WorkerCommand::Execute(Box::new(job))) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(WorkerCommand::Execute(job))) => Err(EnqueueError::Busy(job)),
            Err(TrySendError::Disconnected(WorkerCommand::Execute(job))) => {
                Err(EnqueueError::Stopped(job))
            }
            Err(TrySendError::Full(WorkerCommand::LoadPackage(_)))
            | Err(TrySendError::Disconnected(WorkerCommand::LoadPackage(_))) => {
                unreachable!("try_enqueue sent an execute command")
            }
        }
    }

    /// Materialize, verify, and compile a package on the dedicated execution
    /// thread. This is called only through the in-process owner handle.
    pub(crate) async fn load_package(
        &self,
        source: PackageSource,
    ) -> Result<LoadedPackage, crate::ExecutorError> {
        let (reply, receive) = oneshot::channel();
        let tx = self.tx.clone();
        tokio::task::spawn_blocking(move || {
            tx.send(WorkerCommand::LoadPackage(LoadPackage { source, reply }))
        })
        .await
        .map_err(|error| {
            crate::ExecutorError::PackageLoad(format!(
                "package loader rendezvous panicked: {error}"
            ))
        })?
        .map_err(|_| crate::ExecutorError::ChannelClosed)?;
        receive
            .await
            .map_err(|_| crate::ExecutorError::ChannelClosed)?
    }
}

fn worker_loop(
    rx: Receiver<WorkerCommand>,
    executor_tx: tokio_mpsc::UnboundedSender<ExecutorMessage>,
) {
    let mut engines: HashMap<hellas_rpc::ExecutionPackageId, PackageEngine> = HashMap::new();
    while let Ok(command) = rx.recv() {
        let job = match command {
            WorkerCommand::LoadPackage(load) => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    load_package(load.source, &mut engines)
                }))
                .unwrap_or_else(|_| {
                    Err(crate::ExecutorError::PackageLoad(
                        "package loader panicked; sensitive details suppressed".to_string(),
                    ))
                });
                let _ = load.reply.send(result);
                continue;
            }
            WorkerCommand::Execute(job) => *job,
        };
        let execution_id = job.execution_id.clone();
        let request_commitment = job.request_commitment;
        let package_name = job.package_name.clone();
        let sender = job.sender.clone();
        let cancel = job.cancel.clone();
        let evaluate_request = job.evaluate_request.clone();
        let invocation = job.invocation.clone();
        let prepared_artifacts = job.prepared_artifacts.clone();
        let producer_key = job.producer_key.clone();

        let position = Arc::new(AtomicU64::new(0));
        let mut output_builder = EvaluateOutputTranscriptBuilder::new(
            input_commitment(&evaluate_request),
            evaluate_request.assurance,
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
                warn!(%execution_id, "execute worker job failed");
                WorkerCompletionResult::Failed {
                    position: position.load(Ordering::Relaxed),
                    error: msg,
                }
            }
            Err(_) => {
                let msg = "worker panicked; sensitive details suppressed".to_string();
                warn!(%execution_id, "execute worker stopped without content logging");
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
                package_name,
                evaluate_request,
                invocation,
                prepared_artifacts,
                sender,
                result: termination,
            },
        )));
    }
}

fn run_job(
    job: ExecuteJob,
    mut on_progress: impl FnMut(u64, Vec<u32>) -> Result<(), crate::ExecutorError>,
    engines: &mut HashMap<hellas_rpc::ExecutionPackageId, PackageEngine>,
) -> Result<GenerationOutcome, crate::ExecutorError> {
    let ExecuteJob {
        execution_id,
        locator,
        invocation,
        stream_batch_size,
        accepted_at,
        cancel,
        ..
    } = job;

    debug!(execution_id = %execution_id, "execute worker running Catena package");
    debug!(
        execution_id = %execution_id,
        queue_wait_ms = accepted_at.elapsed().as_millis(),
        prompt_tokens = invocation.input_ids.len(),
        "execute worker starting"
    );

    let engine = engines.get(&locator.execution_package).ok_or_else(|| {
        crate::ExecutorError::PackageNotLoaded(locator.execution_package.to_string())
    })?;
    let input_ids = SensitiveInputIds::new(invocation.input_ids);
    let batch_size = usize::try_from(stream_batch_size.max(1))
        .unwrap_or(usize::MAX)
        .max(1);
    let mut output_tokens = Vec::new();
    let mut pending = Vec::with_capacity(batch_size);
    let mut generated = 0u64;
    let mut progress_error = None;

    let termination = engine
        .generate(
            &input_ids.0,
            &invocation.stop_token_ids,
            invocation.max_new_tokens,
            |token| {
                generated = generated.saturating_add(1);
                output_tokens.push(token);
                pending.push(token);
                if pending.len() >= batch_size
                    && let Err(err) = on_progress(generated, std::mem::take(&mut pending))
                {
                    progress_error = Some(err);
                    cancel.cancel();
                    return false;
                }
                !cancel.is_cancelled()
            },
        )
        .map_err(|err| crate::ExecutorError::Execution(err.to_string()))?;

    if let Some(err) = progress_error {
        return Err(err);
    }

    if !pending.is_empty() {
        on_progress(generated, pending)?;
    }

    let stop_reason = match termination {
        GenerationTermination::StopToken => StopReason::StopToken,
        GenerationTermination::MaxTokens => StopReason::MaxNewTokens,
        GenerationTermination::Cancelled => StopReason::Cancelled,
    };

    Ok(GenerationOutcome {
        stop_reason,
        output_tokens,
    })
}

fn load_package(
    source: PackageSource,
    engines: &mut HashMap<hellas_rpc::ExecutionPackageId, PackageEngine>,
) -> Result<LoadedPackage, crate::ExecutorError> {
    let package = crate::package::fetch_verified_package(&source)?;
    let execution_package =
        hellas_rpc::ExecutionPackageId::from_bytes(*package.identity().as_bytes());
    if let std::collections::hash_map::Entry::Vacant(entry) = engines.entry(execution_package) {
        let engine = PackageEngine::load(package)
            .map_err(|error| crate::ExecutorError::PackageLoad(format!("{error:#}")))?;
        entry.insert(engine);
    }
    let engine = engines
        .get(&execution_package)
        .expect("package engine was inserted before describing it");
    Ok(LoadedPackage {
        locator: PackageLocator { execution_package },
        vocabulary_size: engine.vocabulary_size(),
        maximum_capacity: engine.maximum_capacity(),
    })
}

fn make_on_progress<'a, 'b>(
    position: Arc<AtomicU64>,
    sender: tokio_mpsc::Sender<Result<PbWorkEvent, WireStatus>>,
    cancel: CancellationToken,
    execution_id: String,
    output_builder: &'a mut EvaluateOutputTranscriptBuilder<'b>,
    output_events: &'a mut Vec<OutputEventEnvelope>,
) -> impl FnMut(u64, Vec<u32>) -> Result<(), crate::ExecutorError> + Send + 'a {
    move |progress: u64, token_ids: Vec<u32>| {
        // Leave one permit for the actor's terminal frame. Without this
        // reservation a perfectly bounded chunk stream can fill the channel
        // and make its own required terminal outcome impossible to deliver.
        if sender.capacity() <= 1 {
            warn!(%execution_id, "consumer stalled; cancelling worker before its channel can block the executor");
            cancel.cancel();
            return Err(crate::ExecutorError::Execution(
                "execution consumer did not drain its bounded event channel".to_string(),
            ));
        }
        let output_event = output_builder
            .push_token_delta(token_ids)
            .map_err(|err| crate::ExecutorError::Execution(err.to_string()))?;
        let event = PbWorkEvent {
            kind: Some(PbEvent::Chunk(PbChunk {
                output_event: Some(output_event_to_pb(&output_event)),
            })),
        };
        match sender.try_send(Ok(event)) {
            Ok(()) => {}
            Err(tokio_mpsc::error::TrySendError::Full(_)) => {
                warn!(%execution_id, "consumer stalled; cancelling worker before its channel can block the executor");
                cancel.cancel();
                return Err(crate::ExecutorError::Execution(
                    "execution consumer did not drain its bounded event channel".to_string(),
                ));
            }
            Err(tokio_mpsc::error::TrySendError::Closed(_)) => {
                debug!(%execution_id, "consumer dropped; cancelling worker");
                cancel.cancel();
                return Err(crate::ExecutorError::ChannelClosed);
            }
        }
        position.store(progress, Ordering::Relaxed);
        output_events.push(output_event);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::{Assurance, ContentId, Digest};

    #[test]
    fn a_stalled_consumer_cancels_instead_of_blocking_the_worker() {
        let producer_key = ProducerSigningKey::from_secret_bytes([7; 32]).unwrap();
        let request = EvaluateRequest {
            text_execution: Digest::from_bytes([1; 32]),
            runner_public_key: producer_key.public_key(),
            execution_environment: ContentId::from_bytes([2; 32]),
            nonce: [3; 32],
            assurance: Assurance::ProducerSigned,
            retain: false,
        };
        let mut builder = EvaluateOutputTranscriptBuilder::new(
            input_commitment(&request),
            request.assurance,
            &producer_key,
        );
        let mut output_events = Vec::new();
        let position = Arc::new(AtomicU64::new(0));
        let (sender, _receiver) = tokio_mpsc::channel(2);
        let cancel = CancellationToken::new();
        let mut progress = make_on_progress(
            Arc::clone(&position),
            sender,
            cancel.clone(),
            "test-execution".to_string(),
            &mut builder,
            &mut output_events,
        );

        progress(1, vec![11]).unwrap();
        let error = progress(2, vec![12]).expect_err("the full channel must not block");
        assert!(matches!(error, crate::ExecutorError::Execution(_)));
        assert!(cancel.is_cancelled());
        assert_eq!(position.load(Ordering::Relaxed), 1);
    }
}
