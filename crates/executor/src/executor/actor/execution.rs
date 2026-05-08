use crate::executor::ExecuteOutcome;
use crate::state::{QuoteKind, new_execution_id};
use crate::worker::{EnqueueError, ExecuteJob, WorkerCompletion, WorkerCompletionResult};
use hellas_core::{Digest, Opaque, SignedReceipt, canonical_dag_cbor};
use hellas_core::{Symbolic, SymbolicOutput};
use hellas_pb::hellas::{
    FinishStatus, ReceiptEnvelope as PbReceiptEnvelope, RunTicketRequest, WorkEvent, WorkFinished,
    work_event,
};
use hellas_rpc::ExecutorError;
use hellas_rpc::provenance::ExecutionProvenance;
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
                        self.pending_executions.push_back(job);
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
            QuoteKind::Opaque { request, output } => {
                let provenance = ExecutionProvenance {
                    commitment_id: *quote.request_commitment.as_bytes(),
                };
                let model_id = quote.model_id.clone();
                let execution_id = new_execution_id();
                let total_units = output.as_bytes().len() as u64;
                let receipt = SignedReceipt::sign::<Opaque>(&request, &output, &self.producer_key)
                    .map_err(|err| {
                        ExecutorError::WeightsError(format!("opaque receipt signing failed: {err}"))
                    })?;
                let receipt_dag_cbor = canonical_dag_cbor(&receipt).map_err(|err| {
                    ExecutorError::WeightsError(format!("opaque receipt encoding failed: {err}"))
                })?;
                let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
                sender
                    .send(Ok(WorkEvent {
                        kind: Some(work_event::Kind::Finished(WorkFinished {
                            output: output.into_bytes(),
                            receipt: Some(PbReceiptEnvelope {
                                dag_cbor: receipt_dag_cbor,
                            }),
                            status: FinishStatus::EndOfSequence as i32,
                            total_units,
                        })),
                    }))
                    .await
                    .map_err(|_| ExecutorError::ChannelClosed)?;

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
                    "accepted opaque execution"
                );

                Ok(ExecuteOutcome {
                    provenance,
                    events: receiver,
                })
            }
        }
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
                    self.pending_executions.push_front(job);
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

enum StartExecutionError {
    Busy(ExecuteJob),
    Closed,
}
