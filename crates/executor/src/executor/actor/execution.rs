use crate::executor::ExecuteOutcome;
use crate::fetch::{FetchStateError, FetchTranscript};
use crate::state::{QuoteKind, new_execution_id};
use crate::worker::{EnqueueError, ExecuteJob, WorkerCompletion, WorkerCompletionResult};
use hellas_core::{
    Digest, InputCommitment, OutputEventEnvelope, SignedReceipt, canonical_dag_cbor,
};
use hellas_core::{Symbolic, SymbolicOutput};
use hellas_rpc::ExecutorError;
use hellas_rpc::error::StateError;
use hellas_rpc::fetch::{build_output_events, output_body};
use hellas_rpc::pb::execute::{
    FinishStatus, RunTicketRequest, WorkEvent, WorkFinished, work_event,
};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::stream::output_event_to_pb;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::Executor;

/// Backpressure buffer for the per-execution event channel. Small enough
/// that a slow consumer stalls the worker quickly (preventing unbounded
/// memory growth); large enough to absorb minor jitter without blocking
/// decode on every chunk.
const PER_EXECUTION_CHANNEL_CAPACITY: usize = 64;

impl Executor {
    pub(super) async fn handle_execute(
        &mut self,
        request: RunTicketRequest,
    ) -> Result<ExecuteOutcome, ExecutorError> {
        let request_commitment = request.request_commitment;
        let request_commitment_id: [u8; 32] =
            request_commitment.as_slice().try_into().map_err(|_| {
                ExecutorError::State(hellas_rpc::error::StateError::QuoteNotFound(format!(
                    "invalid request_commitment length {}",
                    request_commitment.len()
                )))
            })?;
        let input_commitment =
            InputCommitment::from_digest(Digest::from_bytes(request_commitment_id));
        if let Some(outcome) = self
            .replay_fetch_execution(input_commitment, request_commitment_id)
            .await?
        {
            return Ok(outcome);
        }
        let stream_batch_size = 1;
        self.store.prune_expired_quotes(Instant::now());
        let quote = self
            .store
            .get_quote(&request_commitment, Instant::now())?
            .clone();
        match quote.kind {
            QuoteKind::Symbolic {
                symbolic_request,
                locator,
                invocation,
            } => {
                let provenance = ExecutionProvenance {
                    commitment_id: *quote.request_commitment.as_bytes(),
                };

                let stat_prompt = invocation.input_ids.len() as u64;
                let stat_cached_output = 0;

                let model_id = quote.model_id.clone();
                let execution_id = new_execution_id();
                let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
                let job = ExecuteJob {
                    execution_id: execution_id.clone(),
                    model_id: model_id.clone(),
                    symbolic_request,
                    locator,
                    invocation,
                    stream_batch_size,
                    accepted_at: Instant::now(),
                    cancel: CancellationToken::new(),
                    sender,
                };

                let queued = match self.try_start_execution(job) {
                    Ok(()) => false,
                    Err(StartExecutionError::Busy(job)) => {
                        if self.pending_executions.len() >= self.queue_capacity {
                            return Err(ExecutorError::QueueFull {
                                capacity: self.queue_capacity,
                            });
                        }
                        self.pending_executions.push_back(*job);
                        true
                    }
                    Err(StartExecutionError::Closed) => return Err(ExecutorError::ChannelClosed),
                };

                // Counters update after the queue accepts the job — no rollback path.
                self.metrics.record_execution_started(
                    &model_id,
                    stat_prompt,
                    /* cached_prompt= */ 0,
                    stat_cached_output,
                    /* prefill= */ stat_prompt,
                );
                let _ = self.store.remove_quote(&request_commitment);

                info!(
                    %execution_id,
                    request_commitment = %format_request_commitment(&request_commitment),
                    queued,
                    queue_len = self.pending_executions.len(),
                    "accepted symbolic execution"
                );

                Ok(ExecuteOutcome {
                    provenance,
                    events: receiver,
                })
            }
            QuoteKind::Fetch { output } => {
                let provenance = ExecutionProvenance {
                    commitment_id: request_commitment_id,
                };
                let _fetch_quote = match self.fetch_state.start(input_commitment) {
                    Ok(quote) => quote,
                    Err(FetchStateError::AlreadyCompleted) => {
                        if let Some(outcome) = self
                            .replay_fetch_execution(input_commitment, request_commitment_id)
                            .await?
                        {
                            return Ok(outcome);
                        }
                        return Err(fetch_execute_error(FetchStateError::AlreadyCompleted));
                    }
                    Err(err) => return Err(fetch_execute_error(err)),
                };
                let model_id = quote.model_id.clone();
                let execution_id = new_execution_id();
                let total_units = output.as_bytes().len() as u64;
                let output_events =
                    build_output_events(input_commitment, output.as_bytes(), &self.producer_key)
                        .map_err(|err| {
                            ExecutorError::WeightsError(format!(
                                "fetch output transcript failed: {err}"
                            ))
                        })?;
                let transcript = match self.fetch_state.complete_output(
                    input_commitment,
                    output_events,
                    &self.producer_key.public_key(),
                ) {
                    Ok(transcript) => transcript,
                    Err(err) => {
                        let _ = self.fetch_state.fail(input_commitment, err.to_string());
                        return Err(fetch_execute_error(err));
                    }
                };
                let outcome = fetch_finished_outcome(
                    provenance,
                    transcript.output_events(),
                    FinishStatus::EndOfSequence,
                )
                .await?;

                self.metrics.record_execution_started(
                    &model_id, /* prompt= */ 0, /* cached_prompt= */ 0,
                    /* cached_output= */ 0, /* prefill= */ 0,
                );
                self.metrics
                    .record_execution_completed(&model_id, total_units);
                let _ = self.store.remove_quote(&request_commitment);

                info!(
                    %execution_id,
                    request_commitment = %format_request_commitment(&request_commitment),
                    total_units,
                    "accepted fetch execution"
                );

                Ok(outcome)
            }
        }
    }

    async fn replay_fetch_execution(
        &self,
        input_commitment: InputCommitment,
        request_commitment_id: [u8; 32],
    ) -> Result<Option<ExecuteOutcome>, ExecutorError> {
        let producer_key = self.producer_key.public_key();
        let transcript = match self
            .fetch_state
            .replay_completed(input_commitment, &producer_key)
        {
            Ok(transcript) => transcript,
            Err(FetchStateError::NotFound | FetchStateError::NotCompleted) => return Ok(None),
            Err(err) => return Err(fetch_execute_error(err)),
        };
        let outcome = fetch_transcript_outcome(request_commitment_id, &transcript).await?;
        info!(
            request_commitment = %format_request_commitment(input_commitment.as_bytes()),
            "replayed fetch execution"
        );
        Ok(Some(outcome))
    }

    fn try_start_execution(&mut self, job: ExecuteJob) -> Result<(), StartExecutionError> {
        match self.worker.try_enqueue(job) {
            Ok(()) => Ok(()),
            Err(EnqueueError::Busy(job)) => Err(StartExecutionError::Busy(job)),
            Err(EnqueueError::Stopped(_job)) => Err(StartExecutionError::Closed),
        }
    }

    pub(super) async fn handle_worker_finished(&mut self, completion: WorkerCompletion) {
        let WorkerCompletion {
            execution_id,
            model_id,
            symbolic_request,
            invocation,
            sender,
            result,
        } = completion;

        let generated = result.position();
        let termination = match result {
            WorkerCompletionResult::Completed {
                stop_reason,
                output_tokens,
            } => {
                match self
                    .completed_symbolic_termination(
                        &symbolic_request,
                        &invocation,
                        stop_reason,
                        output_tokens,
                    )
                    .await
                {
                    Ok(termination) => termination,
                    Err(err) => {
                        let msg = format!("{err:#}");
                        warn!(
                            "execute worker job {execution_id} failed while recording/signing receipt: {msg}"
                        );
                        crate::state::Termination::Failed {
                            position: generated,
                            error: msg,
                        }
                    }
                }
            }
            WorkerCompletionResult::Failed { position, error } => {
                crate::state::Termination::Failed { position, error }
            }
        };

        if termination.is_completed() {
            self.metrics
                .record_execution_completed(&model_id, generated);
        } else {
            self.metrics.record_execution_failed(&model_id, generated);
        }

        let _ = sender.send(Ok(termination.into_pb())).await;
        self.dispatch_next_execution();
    }

    async fn completed_symbolic_termination(
        &mut self,
        symbolic_request: &hellas_core::SymbolicRequest,
        invocation: &crate::state::Invocation,
        stop_reason: crate::state::StopReason,
        output_tokens: Vec<u32>,
    ) -> Result<crate::state::Termination, ExecutorError> {
        let text_artifact_cid = self
            .artifacts
            .record_completed_text(symbolic_request, invocation, &output_tokens)
            .await?;
        let symbolic_output = SymbolicOutput { text_artifact_cid };
        let receipt =
            SignedReceipt::sign::<Symbolic>(symbolic_request, &symbolic_output, &self.producer_key)
                .map_err(|err| {
                    ExecutorError::WeightsError(format!("receipt signing failed: {err}"))
                })?;
        let receipt_dag_cbor = canonical_dag_cbor(&receipt).map_err(|err| {
            ExecutorError::WeightsError(format!("receipt encoding failed: {err}"))
        })?;

        Ok(crate::state::Termination::Completed {
            stop_reason,
            output_tokens,
            receipt_dag_cbor,
        })
    }

    /// Pop pending jobs and dispatch the first one whose consumer is still
    /// listening. Stale entries (consumer dropped while queued) are discarded
    /// silently — the consumer already lost interest.
    pub(super) fn dispatch_next_execution(&mut self) {
        while let Some(job) = self.pending_executions.pop_front() {
            if job.sender.is_closed() {
                debug!(
                    execution_id = %job.execution_id,
                    "dropping queued execution: consumer disconnected before dispatch"
                );
                continue;
            }
            match self.try_start_execution(job) {
                Ok(()) => return,
                Err(StartExecutionError::Busy(job)) => {
                    self.pending_executions.push_front(*job);
                    return;
                }
                Err(StartExecutionError::Closed) => {
                    warn!("failed to start queued execution: executor channel closed");
                }
            }
        }
    }
}

fn format_request_commitment(bytes: &[u8]) -> String {
    Digest::from_slice(bytes)
        .map(|digest| digest.to_string())
        .unwrap_or_else(|_| format!("invalid:{}bytes", bytes.len()))
}

async fn fetch_transcript_outcome(
    request_commitment_id: [u8; 32],
    transcript: &FetchTranscript,
) -> Result<ExecuteOutcome, ExecutorError> {
    fetch_finished_outcome(
        ExecutionProvenance {
            commitment_id: request_commitment_id,
        },
        transcript.output_events(),
        FinishStatus::EndOfSequence,
    )
    .await
}

async fn fetch_finished_outcome(
    provenance: ExecutionProvenance,
    output_events: &[OutputEventEnvelope],
    status: FinishStatus,
) -> Result<ExecuteOutcome, ExecutorError> {
    let output = output_body(output_events).map_err(|err| {
        ExecutorError::InvalidQuoteRequest(format!("fetch transcript rejected: {err}"))
    })?;
    let total_units = output.as_bytes().len() as u64;
    let pb_output_events = output_events.iter().map(output_event_to_pb).collect();
    let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
    sender
        .send(Ok(WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                output: output.into_bytes(),
                receipt: None,
                status: status as i32,
                total_units,
                output_events: pb_output_events,
            })),
        }))
        .await
        .map_err(|_| ExecutorError::ChannelClosed)?;

    Ok(ExecuteOutcome {
        provenance,
        events: receiver,
    })
}

fn fetch_execute_error(err: FetchStateError) -> ExecutorError {
    match err {
        FetchStateError::NotFound => {
            ExecutorError::State(StateError::QuoteNotFound(err.to_string()))
        }
        FetchStateError::AlreadyExists
        | FetchStateError::AlreadyRunning
        | FetchStateError::NotRunning
        | FetchStateError::NotCompleted
        | FetchStateError::AlreadyCompleted
        | FetchStateError::Failed => {
            ExecutorError::State(StateError::QuoteExpired(err.to_string()))
        }
        FetchStateError::Store(err) => {
            ExecutorError::ArtifactStore(format!("fetch transcript store error: {err}"))
        }
        FetchStateError::QuoteMismatch
        | FetchStateError::UnauthorizedCaller
        | FetchStateError::Verify(_)
        | FetchStateError::Input(_) => {
            ExecutorError::InvalidQuoteRequest(format!("fetch transcript rejected: {err}"))
        }
    }
}

enum StartExecutionError {
    Busy(Box<ExecuteJob>),
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Executor;
    use catgrad::prelude::Dtype;
    use hellas_core::ProducerSigningKey;
    use hellas_rpc::fetch::build_input_events;
    use hellas_rpc::pb::fetch::FetchRequest;
    use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
    use hellas_rpc::stream::input_event_to_pb;

    fn key() -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([7; 32]).expect("valid test key")
    }

    fn fetch_request(key: &ProducerSigningKey, body: &[u8]) -> FetchRequest {
        let events = build_input_events("echo", "run", body, key).unwrap();
        FetchRequest {
            input: events.iter().map(input_event_to_pb).collect(),
        }
    }

    async fn run_one(handle: &crate::ExecutorHandle, request_commitment: Vec<u8>) -> WorkFinished {
        let mut outcome = handle
            .run_ticket_handle(RunTicketRequest { request_commitment })
            .await
            .unwrap()
            .events;
        let event = outcome.recv().await.unwrap().unwrap();
        match event.kind.unwrap() {
            work_event::Kind::Finished(finished) => finished,
            other => panic!("expected finished event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_execution_replays_completed_transcript() {
        let signing_key = key();
        let request = fetch_request(&signing_key, br#"{"hello":"world"}"#);
        let handle = Executor::spawn_with_producer_key(
            DownloadPolicy::Eager,
            ExecutePolicy::Eager,
            1,
            vec![Dtype::F32],
            key(),
        )
        .unwrap();
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let first = run_one(&handle, ticket.request_commitment.clone()).await;
        let replayed = run_one(&handle, ticket.request_commitment).await;

        assert_eq!(first.output, br#"{"hello":"world"}"#);
        assert_eq!(replayed.output, first.output);
        assert_eq!(replayed.output_events, first.output_events);
    }
}
