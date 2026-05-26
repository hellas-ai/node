use crate::executor::ExecuteOutcome;
use crate::state::new_execution_id;
use crate::worker::{EnqueueError, ExecuteJob};
use hellas_rpc::ExecutorError;
use hellas_rpc::pb::hellas::ExecuteRequest;
use hellas_rpc::provenance::{CallCommitment, ExecutionProvenance};
use std::sync::Arc;
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
        request: ExecuteRequest,
    ) -> Result<ExecuteOutcome, ExecutorError> {
        let quote_id = request.quote_id;
        let stream_batch_size = request.stream_batch_size.unwrap_or(1).max(1);
        self.store.prune_expired_quotes(Instant::now());
        let quote = self.store.get_quote(&quote_id, Instant::now())?.clone();
        let provenance = ExecutionProvenance {
            call_commitment: CallCommitment(*quote.call.commitment().digest().as_bytes()),
        };

        let stat_prompt = quote.invocation.input_ids.len() as u64;
        let stat_cached_output = quote
            .start
            .cached
            .as_ref()
            .map_or(0, |c| c.output_tokens.len() as u64);

        let model_id = quote.model_id.clone();
        let execution_id = new_execution_id();
        let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
        let job = ExecuteJob {
            execution_id: execution_id.clone(),
            model_id: model_id.clone(),
            invocation: quote.invocation.clone(),
            execution: quote.execution.clone(),
            start: quote.start.clone(),
            stream_batch_size,
            accepted_at: Instant::now(),
            cancel: CancellationToken::new(),
            sender,
            metrics: Arc::clone(&self.metrics),
            call: quote.call.clone(),
            producer_key: Arc::clone(&self.producer_key),
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
        let _ = self.store.remove_quote(&quote_id);

        info!(
            %execution_id,
            %quote_id,
            runtime_commitment_id = %quote.start.commitment_id,
            queued,
            queue_len = self.pending_executions.len(),
            "accepted execution"
        );

        Ok(ExecuteOutcome {
            provenance,
            events: receiver,
        })
    }

    fn try_start_execution(&mut self, job: ExecuteJob) -> Result<(), StartExecutionError> {
        match self.worker.try_enqueue(job) {
            Ok(()) => Ok(()),
            Err(EnqueueError::Busy(job)) => Err(StartExecutionError::Busy(job)),
            Err(EnqueueError::Stopped(_job)) => Err(StartExecutionError::Closed),
        }
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

enum StartExecutionError {
    Busy(ExecuteJob),
    Closed,
}
