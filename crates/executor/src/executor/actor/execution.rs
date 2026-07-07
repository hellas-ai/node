use crate::executor::{
    ExecuteOutcome, ExecutorMessage, FetchCompletion, FetchProviderFailure, FetchProviderRun,
    PendingFetch,
};
use crate::fetch::{FetchStateError, FetchTranscript};
use crate::fetch_policy::{FetchAccessError, FetchRoute};
use crate::fetch_projection::{FetchProjector, ProjectedFetch};
use crate::fetch_provider::{FetchProvider, FetchProviderError, FetchProviderRequest};
use crate::state::{QuoteKind, new_execution_id};
use futures_util::StreamExt;
use hellas_rpc::ExecutorError;
use hellas_rpc::error::StateError;
use hellas_rpc::fetch::FetchOutputTranscriptBuilder;
use hellas_rpc::pb::execute::{
    FinishStatus, RunTicketRequest, WorkChunk, WorkEvent, WorkFailed, WorkFinished, work_event,
};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::run_ticket::{VerifiedRunTicket, verify_run_ticket};
use hellas_rpc::stream::output_event_to_pb;
use hellas_rpc::{Digest, InputCommitment, OutputEventEnvelope, ProducerSigningKey};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

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
        let verified_run = verify_run_ticket(&request).map_err(|err| {
            ExecutorError::InvalidQuoteRequest(format!("invalid run ticket: {err}"))
        })?;
        let request_commitment_id = verified_run.request_commitment;
        let request_commitment = request_commitment_id.to_vec();
        let input_commitment =
            InputCommitment::from_digest(Digest::from_bytes(request_commitment_id));
        if let Some(outcome) = self
            .replay_fetch_execution(input_commitment, request_commitment_id, &verified_run)
            .await?
        {
            return Ok(outcome);
        }
        #[cfg(feature = "evaluate")]
        if let Some(engine) = self.evaluate.as_ref()
            && let Some(outcome) = engine
                .replay_completed(request_commitment_id, &verified_run.public_key)
                .await?
        {
            info!(
                request_commitment = %format_request_commitment(&request_commitment),
                "replayed evaluate execution"
            );
            return Ok(outcome);
        }
        self.store.prune_expired_quotes(Instant::now());
        let quote = match self.store.get_quote(&request_commitment, Instant::now()) {
            Ok(quote) => quote.clone(),
            Err(err) => {
                // The quote store is transient; after a restart a caller
                // retrying a ticket whose run may have reached the provider
                // must hear "indeterminate", not "quote not found". If the
                // check itself fails, that store error is the truth — not
                // the quote-store miss.
                return Err(match self.fetch_state.is_indeterminate(input_commitment) {
                    Ok(true) => fetch_execute_error(FetchStateError::Indeterminate),
                    Ok(false) => err.into(),
                    Err(state_err) => fetch_execute_error(state_err),
                });
            }
        };
        ensure_authorized_runner(&quote.runner_public_key, &verified_run.public_key)?;
        match quote.kind {
            #[cfg(feature = "evaluate")]
            QuoteKind::Scheme(job) => {
                let execution_id = new_execution_id();
                let engine = self
                    .evaluate
                    .as_mut()
                    .ok_or_else(super::evaluate_disabled)?;
                let outcome = engine.start(
                    job,
                    crate::scheme::SchemeRunContext {
                        execution_id,
                        request_commitment: request_commitment_id,
                    },
                )?;
                let _ = self.store.remove_quote(&request_commitment);
                Ok(outcome)
            }
            QuoteKind::Fetch { request } => {
                let provenance = ExecutionProvenance {
                    commitment_id: request_commitment_id,
                };
                if self.active_fetches >= self.fetch_max_in_flight
                    && self.pending_fetches.len() >= self.fetch_queue_capacity
                {
                    return Err(ExecutorError::QueueFull {
                        capacity: self.fetch_queue_capacity,
                    });
                }
                let route = FetchRoute::new(request.service.clone(), request.method.clone());
                let entry = self
                    .fetch_routes
                    .entry(&route)
                    .cloned()
                    .ok_or_else(|| no_fetch_route_error(&route))?;
                let projection = entry
                    .projector_factory
                    .create(&request)
                    .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;
                let fetch_quote = self
                    .fetch_state
                    .quoted(input_commitment)
                    .map_err(fetch_execute_error)?;
                let execution_id = new_execution_id();
                let admission = self
                    .fetch_access_policy
                    .authorize_admission(
                        &fetch_quote.caller_key,
                        &projection.request_view,
                        now_ms(),
                        execution_id.clone(),
                        &entry.capabilities,
                    )
                    .map_err(fetch_access_error)?;
                let model_id = projection
                    .request_view
                    .model
                    .clone()
                    .unwrap_or_else(|| quote.model_id.clone());
                let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
                let pending = PendingFetch {
                    request,
                    provider: entry.provider,
                    input_commitment,
                    request_commitment_id,
                    quota_reservation: admission.reservation,
                    execution_id: execution_id.clone(),
                    model_id: model_id.clone(),
                    sender,
                    projector: projection.projector,
                };

                let queued = if self.active_fetches < self.fetch_max_in_flight {
                    match self.fetch_state.start(input_commitment) {
                        Ok(_) => {
                            self.start_fetch_execution(pending);
                            false
                        }
                        Err(FetchStateError::AlreadyCompleted) => {
                            let _ = self
                                .fetch_access_policy
                                .cancel_reservation(pending.quota_reservation.as_ref());
                            if let Some(outcome) = self
                                .replay_fetch_execution(
                                    input_commitment,
                                    request_commitment_id,
                                    &verified_run,
                                )
                                .await?
                            {
                                return Ok(outcome);
                            }
                            return Err(fetch_execute_error(FetchStateError::AlreadyCompleted));
                        }
                        Err(err) => {
                            let _ = self
                                .fetch_access_policy
                                .cancel_reservation(pending.quota_reservation.as_ref());
                            return Err(fetch_execute_error(err));
                        }
                    }
                } else {
                    match self.fetch_state.queue(input_commitment) {
                        Ok(_) => {
                            self.pending_fetches.push_back(pending);
                            true
                        }
                        Err(FetchStateError::AlreadyCompleted) => {
                            let _ = self
                                .fetch_access_policy
                                .cancel_reservation(pending.quota_reservation.as_ref());
                            if let Some(outcome) = self
                                .replay_fetch_execution(
                                    input_commitment,
                                    request_commitment_id,
                                    &verified_run,
                                )
                                .await?
                            {
                                return Ok(outcome);
                            }
                            return Err(fetch_execute_error(FetchStateError::AlreadyCompleted));
                        }
                        Err(err) => {
                            let _ = self
                                .fetch_access_policy
                                .cancel_reservation(pending.quota_reservation.as_ref());
                            return Err(fetch_execute_error(err));
                        }
                    }
                };

                self.metrics.record_execution_started(
                    &model_id, /* prompt= */ 0, /* cached_prompt= */ 0,
                    /* cached_output= */ 0, /* prefill= */ 0,
                );
                let _ = self.store.remove_quote(&request_commitment);

                info!(
                    %execution_id,
                    request_commitment = %format_request_commitment(&request_commitment),
                    queued,
                    active_fetches = self.active_fetches,
                    fetch_queue_len = self.pending_fetches.len(),
                    "accepted fetch execution"
                );

                Ok(ExecuteOutcome {
                    provenance,
                    events: receiver,
                })
            }
        }
    }

    async fn replay_fetch_execution(
        &self,
        input_commitment: InputCommitment,
        request_commitment_id: [u8; 32],
        verified_run: &VerifiedRunTicket,
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
        let verified_input = transcript.verify(&producer_key).map_err(|err| {
            ExecutorError::InvalidQuoteRequest(format!("fetch transcript rejected: {err}"))
        })?;
        ensure_authorized_runner(&verified_input.caller_key, &verified_run.public_key)?;
        let outcome = fetch_transcript_outcome(request_commitment_id, &transcript).await?;
        info!(
            request_commitment = %format_request_commitment(input_commitment.as_bytes()),
            "replayed fetch execution"
        );
        Ok(Some(outcome))
    }

    fn start_fetch_execution(&mut self, pending: PendingFetch) {
        self.active_fetches = self.active_fetches.saturating_add(1);
        spawn_fetch_provider(self.tx.clone(), Arc::clone(&self.producer_key), pending);
    }

    fn finish_fetch_slot(&mut self) {
        self.active_fetches = self.active_fetches.saturating_sub(1);
        self.dispatch_next_fetch();
    }

    pub(super) async fn handle_fetch_finished(&mut self, completion: FetchCompletion) {
        let FetchCompletion {
            input_commitment,
            request_commitment_id,
            quota_reservation,
            execution_id,
            model_id,
            sender,
            result,
        } = completion;

        let run = match result {
            Ok(run) => run,
            Err(failure) => {
                let error = failure.error.to_string();
                if let Err(err) = self
                    .fetch_access_policy
                    .reconcile_reservation(quota_reservation.as_ref(), None)
                {
                    warn!(
                        %execution_id,
                        quota_error = %err,
                        "failed to reconcile fetch quota after provider failure"
                    );
                }
                let _ = self.fetch_state.fail(input_commitment, error.clone());
                self.metrics
                    .record_execution_failed(&model_id, failure.position);
                send_fetch_failed(sender, failure.position, error).await;
                self.finish_fetch_slot();
                return;
            }
        };

        let transcript = match self.fetch_state.complete_output(
            input_commitment,
            run.output_events,
            &self.producer_key.public_key(),
        ) {
            Ok(transcript) => transcript,
            Err(err) => {
                let error = fetch_execute_error(err).to_string();
                let _ = self.fetch_state.fail(input_commitment, error.clone());
                let total_units = run.usage.total_or_output();
                self.metrics.record_execution_failed(&model_id, total_units);
                send_fetch_failed(sender, total_units, error).await;
                self.finish_fetch_slot();
                return;
            }
        };

        let total_units = run.usage.total_or_output();
        if let Err(err) = self
            .fetch_access_policy
            .reconcile_reservation(quota_reservation.as_ref(), Some(run.usage))
        {
            warn!(
                %execution_id,
                quota_error = %err,
                "failed to reconcile fetch quota after provider completion"
            );
        }
        let event = match fetch_finished_event(
            transcript.output_events(),
            FinishStatus::EndOfSequence,
            total_units,
        ) {
            Ok(event) => event,
            Err(err) => {
                let error = err.to_string();
                let _ = self.fetch_state.fail(input_commitment, error.clone());
                self.metrics.record_execution_failed(&model_id, total_units);
                send_fetch_failed(sender, total_units, error).await;
                self.finish_fetch_slot();
                return;
            }
        };

        self.metrics
            .record_execution_completed(&model_id, total_units);
        let _ = sender.send(Ok(event)).await;

        info!(
            %execution_id,
            request_commitment = %format_request_commitment(&request_commitment_id),
            total_units,
            "completed fetch execution"
        );
        self.finish_fetch_slot();
    }

    fn dispatch_next_fetch(&mut self) {
        while self.active_fetches < self.fetch_max_in_flight {
            let Some(pending) = self.pending_fetches.pop_front() else {
                return;
            };
            if pending.sender.is_closed() {
                if let Err(err) = self
                    .fetch_access_policy
                    .cancel_reservation(pending.quota_reservation.as_ref())
                {
                    warn!(
                        execution_id = %pending.execution_id,
                        quota_error = %err,
                        "failed to cancel quota reservation for disconnected fetch"
                    );
                }
                if let Err(err) = self.fetch_state.cancel_queued(pending.input_commitment) {
                    warn!(
                        execution_id = %pending.execution_id,
                        state_error = %err,
                        "queued fetch was not cancellable; ticket state is inconsistent"
                    );
                }
                debug!(
                    execution_id = %pending.execution_id,
                    "dropping queued fetch execution: consumer disconnected before dispatch"
                );
                continue;
            }
            match self.fetch_state.start(pending.input_commitment) {
                Ok(_) => {
                    self.start_fetch_execution(pending);
                    return;
                }
                Err(err) => {
                    let _ = self
                        .fetch_access_policy
                        .cancel_reservation(pending.quota_reservation.as_ref());
                    let position = 0;
                    let error = fetch_execute_error(err).to_string();
                    let _ = pending.sender.try_send(Ok(WorkEvent {
                        kind: Some(work_event::Kind::Failed(WorkFailed { position, error })),
                    }));
                }
            }
        }
    }
}

fn ensure_authorized_runner(
    expected: &hellas_rpc::PublicKey,
    actual: &hellas_rpc::PublicKey,
) -> Result<(), ExecutorError> {
    if expected == actual {
        Ok(())
    } else {
        Err(ExecutorError::PolicyDenied(
            "run ticket signer is not authorized for this ticket".to_string(),
        ))
    }
}

fn format_request_commitment(bytes: &[u8]) -> String {
    Digest::from_slice(bytes)
        .map(|digest| digest.to_string())
        .unwrap_or_else(|_| format!("invalid:{}bytes", bytes.len()))
}

fn spawn_fetch_provider(
    tx: mpsc::UnboundedSender<ExecutorMessage>,
    producer_key: Arc<ProducerSigningKey>,
    pending: PendingFetch,
) {
    tokio::spawn(async move {
        let PendingFetch {
            request,
            provider,
            projector,
            quota_reservation,
            input_commitment,
            request_commitment_id,
            execution_id,
            model_id,
            sender,
        } = pending;
        let result = run_fetch_provider(
            provider,
            request,
            projector,
            input_commitment,
            &producer_key,
            sender.clone(),
        )
        .await;
        let _ = tx.send(ExecutorMessage::FetchFinished(FetchCompletion {
            input_commitment,
            request_commitment_id,
            quota_reservation,
            execution_id,
            model_id,
            sender,
            result,
        }));
    });
}

async fn run_fetch_provider(
    provider: Arc<dyn FetchProvider>,
    request: FetchProviderRequest,
    mut projector: Box<dyn FetchProjector>,
    input_commitment: InputCommitment,
    producer_key: &ProducerSigningKey,
    sender: mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
) -> Result<FetchProviderRun, FetchProviderFailure> {
    let mut builder = FetchOutputTranscriptBuilder::new(input_commitment, producer_key);
    let mut position = 0_u64;
    let mut terminal_payload = None;
    let mut stream = provider
        .run(request)
        .await
        .map_err(|error| FetchProviderFailure { position, error })?;

    while let Some(next) = stream.next().await {
        let chunk = next.map_err(|error| FetchProviderFailure { position, error })?;
        let projected = projector
            .project(&chunk)
            .map_err(|err| FetchProviderFailure {
                position,
                error: FetchProviderError::failed(format!("fetch projection failed: {err}")),
            })?;
        process_projected_fetch(
            projected,
            &mut builder,
            &mut terminal_payload,
            &mut position,
            &sender,
        )
        .await?;
    }

    let projected = projector.finish().map_err(|err| FetchProviderFailure {
        position,
        error: FetchProviderError::failed(format!("fetch projection failed: {err}")),
    })?;
    process_projected_fetch(
        projected,
        &mut builder,
        &mut terminal_payload,
        &mut position,
        &sender,
    )
    .await?;
    let terminal_payload = terminal_payload.ok_or_else(|| FetchProviderFailure {
        position,
        error: FetchProviderError::failed(
            "fetch provider ended without terminal event".to_string(),
        ),
    })?;
    let output_events = builder
        .finish(terminal_payload)
        .map_err(|err| FetchProviderFailure {
            position,
            error: FetchProviderError::failed(format!("fetch output transcript failed: {err}")),
        })?;
    Ok(FetchProviderRun {
        output_events,
        usage: projector.usage().unwrap_or_default(),
    })
}

async fn process_projected_fetch(
    projected: Vec<ProjectedFetch>,
    builder: &mut FetchOutputTranscriptBuilder<'_>,
    terminal_payload: &mut Option<Vec<u8>>,
    position: &mut u64,
    sender: &mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
) -> Result<(), FetchProviderFailure> {
    for item in projected {
        match item {
            ProjectedFetch::Event(payload) => {
                if terminal_payload.is_some() {
                    return Err(FetchProviderFailure {
                        position: *position,
                        error: FetchProviderError::failed(
                            "fetch projection emitted an event after terminal".to_string(),
                        ),
                    });
                }
                let output_event =
                    builder
                        .push_event(payload.clone())
                        .map_err(|err| FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed(format!(
                                "fetch output event transcript failed: {err}"
                            )),
                        })?;
                *position = (*position).saturating_add(payload.len() as u64);
                sender
                    .send(Ok(WorkEvent {
                        kind: Some(work_event::Kind::Chunk(WorkChunk {
                            output_event: Some(output_event_to_pb(&output_event)),
                        })),
                    }))
                    .await
                    .map_err(|_| FetchProviderFailure {
                        position: *position,
                        error: FetchProviderError::failed(
                            "fetch stream consumer disconnected".to_string(),
                        ),
                    })?;
            }
            ProjectedFetch::Terminal(payload) => {
                if terminal_payload.replace(payload).is_some() {
                    return Err(FetchProviderFailure {
                        position: *position,
                        error: FetchProviderError::failed(
                            "fetch projection emitted multiple terminal events".to_string(),
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

async fn send_fetch_failed(
    sender: mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
    position: u64,
    error: String,
) {
    let _ = sender
        .send(Ok(WorkEvent {
            kind: Some(work_event::Kind::Failed(WorkFailed { position, error })),
        }))
        .await;
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
        0,
    )
    .await
}

async fn fetch_finished_outcome(
    provenance: ExecutionProvenance,
    output_events: &[OutputEventEnvelope],
    status: FinishStatus,
    total_units: u64,
) -> Result<ExecuteOutcome, ExecutorError> {
    let event = fetch_finished_event(output_events, status, total_units)?;
    let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
    sender
        .send(Ok(event))
        .await
        .map_err(|_| ExecutorError::ChannelClosed)?;

    Ok(ExecuteOutcome {
        provenance,
        events: receiver,
    })
}

fn fetch_finished_event(
    output_events: &[OutputEventEnvelope],
    status: FinishStatus,
    total_units: u64,
) -> Result<WorkEvent, ExecutorError> {
    let pb_output_events = output_events.iter().map(output_event_to_pb).collect();
    Ok(WorkEvent {
        kind: Some(work_event::Kind::Finished(WorkFinished {
            status: status as i32,
            total_units,
            output_events: pb_output_events,
        })),
    })
}

pub(super) fn fetch_execute_error(err: FetchStateError) -> ExecutorError {
    match err {
        FetchStateError::NotFound => {
            ExecutorError::State(StateError::QuoteNotFound(err.to_string()))
        }
        FetchStateError::AlreadyExists
        | FetchStateError::AlreadyQueued
        | FetchStateError::AlreadyRunning
        | FetchStateError::NotRunning
        | FetchStateError::NotCompleted
        | FetchStateError::AlreadyCompleted
        | FetchStateError::Indeterminate
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

pub(super) fn no_fetch_route_error(route: &FetchRoute) -> ExecutorError {
    ExecutorError::PolicyDenied(format!(
        "no fetch route configured for {}/{}",
        route.service, route.method
    ))
}

fn fetch_access_error(err: FetchAccessError) -> ExecutorError {
    match err {
        FetchAccessError::Denied(message) => ExecutorError::PolicyDenied(message),
        FetchAccessError::QuotaExceeded {
            retry_after_ms,
            message,
        } => ExecutorError::QuotaExceeded {
            retry_after_ms,
            message,
        },
        FetchAccessError::Store(message) => {
            ExecutorError::ArtifactStore(format!("fetch quota store error: {message}"))
        }
        FetchAccessError::Io(err) => {
            ExecutorError::ArtifactStore(format!("fetch quota store I/O error: {err}"))
        }
    }
}

fn now_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(elapsed).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ArtifactStoreConfig, CallerAccess, Executor, ExecutorMetrics, ExecutorSpawnConfig,
        FetchAccessPolicy, FetchProjectionError, FetchProjectionSession, FetchProjector,
        FetchProjectorFactory, FetchProvider, FetchProviderFuture, FetchProviderRequest,
        FetchProviderStream, FetchRequestView, FetchRoute, FetchRouteGrant, FetchRoutePolicy,
        FetchUsage, MockFetchProvider, ProjectedFetch,
    };
    use futures_util::stream;
    use hellas_rpc::Dtype;
    use hellas_rpc::ExecutorError;
    use hellas_rpc::ProducerSigningKey;
    use hellas_rpc::fetch::build_input_events;
    use hellas_rpc::pb::fetch::FetchRequest;
    use hellas_rpc::policy::ExecutePolicy;
    use hellas_rpc::stream::input_event_to_pb;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::Notify;
    use tokio::time::{Duration, timeout};

    #[derive(Clone, Debug, Default)]
    struct TestFetchProjectorFactory;

    impl FetchProjectorFactory for TestFetchProjectorFactory {
        fn create(
            &self,
            request: &crate::FetchProviderRequest,
        ) -> Result<FetchProjectionSession, FetchProjectionError> {
            Ok(FetchProjectionSession {
                request_view: FetchRequestView::from_provider_request(request),
                projector: Box::new(TestFetchProjector {
                    terminal_seen: false,
                }),
            })
        }
    }

    #[derive(Clone, Debug)]
    struct FixedViewFetchProjectorFactory {
        view: FetchRequestView,
    }

    impl FetchProjectorFactory for FixedViewFetchProjectorFactory {
        fn create(
            &self,
            _request: &crate::FetchProviderRequest,
        ) -> Result<FetchProjectionSession, FetchProjectionError> {
            Ok(FetchProjectionSession {
                request_view: self.view.clone(),
                projector: Box::new(TestFetchProjector {
                    terminal_seen: false,
                }),
            })
        }
    }

    struct TestFetchProjector {
        terminal_seen: bool,
    }

    impl FetchProjector for TestFetchProjector {
        fn project(&mut self, bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchProjectionError> {
            if let Some(terminal) = bytes.strip_prefix(b"terminal:") {
                self.terminal_seen = true;
                Ok(vec![ProjectedFetch::Terminal(terminal.to_vec())])
            } else {
                Ok(vec![ProjectedFetch::Event(bytes.to_vec())])
            }
        }

        fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchProjectionError> {
            if self.terminal_seen {
                Ok(Vec::new())
            } else {
                Err(FetchProjectionError::failed(
                    "test stream ended without terminal".to_string(),
                ))
            }
        }

        fn usage(&self) -> Option<FetchUsage> {
            None
        }
    }

    #[derive(Clone, Default)]
    struct ReleasableFetchProvider {
        released: Arc<AtomicBool>,
        notify: Arc<Notify>,
        calls: Arc<AtomicUsize>,
    }

    impl ReleasableFetchProvider {
        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            self.notify.notify_waiters();
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl FetchProvider for ReleasableFetchProvider {
        fn run(&self, _request: FetchProviderRequest) -> FetchProviderFuture<'_> {
            let released = Arc::clone(&self.released);
            let notify = Arc::clone(&self.notify);
            let calls = Arc::clone(&self.calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                while !released.load(Ordering::SeqCst) {
                    notify.notified().await;
                }
                Ok(Box::pin(stream::iter([
                    Ok(b"event:ok".to_vec()),
                    Ok(b"terminal:done".to_vec()),
                ])) as FetchProviderStream)
            })
        }
    }

    fn key() -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([7; 32]).expect("valid test key")
    }

    fn fetch_request(
        key: &ProducerSigningKey,
        service: &str,
        method: &str,
        body: &[u8],
    ) -> FetchRequest {
        let events = build_input_events(service, method, body, key).unwrap();
        FetchRequest {
            input: events.iter().map(input_event_to_pb).collect(),
        }
    }

    fn run_ticket_request(request_commitment: &[u8], key: &ProducerSigningKey) -> RunTicketRequest {
        let request_commitment: [u8; 32] = request_commitment
            .try_into()
            .expect("test request commitment is 32 bytes");
        hellas_rpc::run_ticket::sign_run_ticket(request_commitment, key)
            .expect("test run ticket signs")
    }

    async fn run_one(
        handle: &crate::ExecutorHandle,
        request_commitment: Vec<u8>,
        key: &ProducerSigningKey,
    ) -> (Vec<WorkChunk>, WorkFinished) {
        let outcome = handle
            .run_ticket_handle(run_ticket_request(&request_commitment, key))
            .await
            .unwrap();
        drain_outcome(outcome.events).await
    }

    async fn drain_outcome(
        mut outcome: crate::executor::ExecuteEventReceiver,
    ) -> (Vec<WorkChunk>, WorkFinished) {
        let mut chunks = Vec::new();
        loop {
            let event = outcome.recv().await.unwrap().unwrap();
            match event.kind.unwrap() {
                work_event::Kind::Chunk(chunk) => chunks.push(chunk),
                work_event::Kind::Finished(finished) => return (chunks, finished),
                work_event::Kind::Failed(failed) => {
                    panic!("expected finished event, got failure: {failed:?}")
                }
            }
        }
    }

    fn test_routes(
        service: &str,
        method: &str,
        provider: Arc<dyn FetchProvider>,
        projector_factory: Arc<dyn FetchProjectorFactory>,
    ) -> crate::FetchRouteRegistry {
        let mut registry = crate::FetchRouteRegistry::new();
        registry
            .register(
                FetchRoute::new(service, method),
                crate::FetchRouteEntry {
                    provider,
                    projector_factory,
                    capabilities: FetchRoutePolicy::default(),
                },
            )
            .unwrap();
        registry
    }

    async fn spawn_fetch_executor(
        provider: Arc<dyn FetchProvider>,
        fetch_max_in_flight: usize,
        fetch_queue_capacity: usize,
    ) -> crate::ExecutorHandle {
        let producer_key = key();
        let caller_key = producer_key.public_key();
        Executor::spawn_configured(ExecutorSpawnConfig {
            execute_policy: ExecutePolicy::Eager,
            queue_capacity: 1,
            supported_dtypes: vec![Dtype::F32],
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key: Arc::new(producer_key),
            fetch_access_policy: FetchAccessPolicy::trusted_callers([caller_key]),
            fetch_routes: test_routes("echo", "run", provider, Arc::new(TestFetchProjectorFactory)),
            fetch_max_in_flight,
            fetch_queue_capacity,
            artifact_store: ArtifactStoreConfig::Memory,
        })
        .await
        .unwrap()
    }

    async fn run_failed(
        handle: &crate::ExecutorHandle,
        request_commitment: Vec<u8>,
        key: &ProducerSigningKey,
    ) -> WorkFailed {
        let mut outcome = handle
            .run_ticket_handle(run_ticket_request(&request_commitment, key))
            .await
            .unwrap()
            .events;
        loop {
            let event = outcome.recv().await.unwrap().unwrap();
            match event.kind.unwrap() {
                work_event::Kind::Chunk(_) => {}
                work_event::Kind::Finished(finished) => {
                    panic!("expected failed event, got finished: {finished:?}")
                }
                work_event::Kind::Failed(failed) => return failed,
            }
        }
    }

    #[tokio::test]
    async fn fetch_execution_streams_mock_provider_and_replays_completed_transcript() {
        let signing_key = key();
        let input = br#"{"hello":"world"}"#;
        let provider = MockFetchProvider::new();
        provider.insert(
            "echo",
            "run",
            input,
            [b"event:ok".to_vec(), b"terminal:done".to_vec()],
        );
        let request = fetch_request(&signing_key, "echo", "run", input);
        let handle = Executor::spawn_with_fetch_routes(
            ExecutePolicy::Eager,
            1,
            vec![Dtype::F32],
            key(),
            test_routes(
                "echo",
                "run",
                Arc::new(provider.clone()),
                Arc::new(TestFetchProjectorFactory),
            ),
        )
        .unwrap();
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let (chunks, first) =
            run_one(&handle, ticket.request_commitment.clone(), &signing_key).await;
        let (replay_chunks, replayed) =
            run_one(&handle, ticket.request_commitment, &signing_key).await;

        assert_eq!(chunks.len(), 1);
        let chunk_event = chunks[0]
            .output_event
            .as_ref()
            .expect("fetch chunk should carry signed output event");
        assert_eq!(chunk_event.payload, b"event:ok");
        assert!(replay_chunks.is_empty());
        assert_eq!(first.output_events[0], *chunk_event);
        assert_eq!(first.output_events[1].payload, b"done");
        assert_eq!(replayed.output_events, first.output_events);
        assert_eq!(provider.calls("echo", "run", input), 1);
    }

    #[tokio::test]
    async fn fetch_execution_reports_unprogrammed_mock_provider_failure() {
        let signing_key = key();
        let input = br#"{"hello":"world"}"#;
        let provider = MockFetchProvider::new();
        let request = fetch_request(&signing_key, "echo", "run", input);
        let handle = Executor::spawn_with_fetch_routes(
            ExecutePolicy::Eager,
            1,
            vec![Dtype::F32],
            key(),
            test_routes(
                "echo",
                "run",
                Arc::new(provider.clone()),
                Arc::new(TestFetchProjectorFactory),
            ),
        )
        .unwrap();
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let failed = run_failed(&handle, ticket.request_commitment, &signing_key).await;

        assert_eq!(failed.position, 0);
        assert!(failed.error.contains("mock fetch response not programmed"));
        assert_eq!(provider.calls("echo", "run", input), 1);
    }

    #[tokio::test]
    async fn fetch_quote_missing_route_does_not_poison_ticket_state() {
        let signing_key = key();
        let provider = MockFetchProvider::new();
        let handle = spawn_fetch_executor(Arc::new(provider), 1, 1).await;
        let request = fetch_request(&signing_key, "missing", "run", br#"{"hello":"world"}"#);

        for _ in 0..2 {
            let err = handle
                .create_fetch_ticket(request.clone())
                .await
                .unwrap_err();
            assert!(matches!(err, ExecutorError::PolicyDenied(_)));
        }
    }

    #[tokio::test]
    async fn run_ticket_with_recovered_running_marker_reports_indeterminate() {
        use crate::fetch::{FetchRunningRecord, FetchTranscriptStore, FsFetchTranscriptStore};

        let dir = std::env::temp_dir().join(format!(
            "hellas-fetch-actor-indeterminate-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let signing_key = key();
        let events =
            build_input_events("echo", "run", br#"{"hello":"crash"}"#, &signing_key).unwrap();
        let input = hellas_rpc::fetch::verify_input_events(&events)
            .unwrap()
            .input_commitment;

        // Simulate a previous process that crashed mid-run: only the durable
        // running marker survives; the transient quote store is empty.
        let marker_store = FsFetchTranscriptStore::new(dir.join("fetch-transcripts"));
        marker_store.init().unwrap();
        marker_store
            .put_running(
                input,
                &FetchRunningRecord {
                    service: "echo".to_string(),
                    method: "run".to_string(),
                    caller_public_key: String::new(),
                    started_at_unix_ms: 0,
                    idempotency_key: input.digest().to_string(),
                },
            )
            .unwrap();

        let handle = Executor::spawn_configured(ExecutorSpawnConfig {
            execute_policy: ExecutePolicy::Eager,
            queue_capacity: 1,
            supported_dtypes: vec![Dtype::F32],
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key: Arc::new(key()),
            fetch_access_policy: FetchAccessPolicy::trusted_callers([signing_key.public_key()]),
            fetch_routes: test_routes(
                "echo",
                "run",
                Arc::new(MockFetchProvider::new()),
                Arc::new(TestFetchProjectorFactory),
            ),
            fetch_max_in_flight: 1,
            fetch_queue_capacity: 1,
            artifact_store: ArtifactStoreConfig::Fs(dir.clone()),
        })
        .await
        .unwrap();

        let err = handle
            .run_ticket_handle(run_ticket_request(input.digest().as_bytes(), &signing_key))
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("indeterminate"),
            "expected indeterminate, got: {err}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn fetch_policy_denial_does_not_start_provider() {
        let signing_key = key();
        let caller_key = signing_key.public_key();
        let provider = ReleasableFetchProvider::default();
        let policy = FetchAccessPolicy::new([CallerAccess::explicit(
            caller_key,
            [FetchRouteGrant {
                route: FetchRoute::new("codex", "responses"),
                policy: FetchRoutePolicy {
                    allowed_models: Some(BTreeSet::from(["allowed-model".to_string()])),
                    max_output_units: Some(8),
                },
            }],
        )]);
        let projector = FixedViewFetchProjectorFactory {
            view: FetchRequestView {
                service: "codex".to_string(),
                method: "responses".to_string(),
                model: Some("denied-model".to_string()),
                max_output_units: Some(4),
            },
        };
        let handle = Executor::spawn_configured(ExecutorSpawnConfig {
            execute_policy: ExecutePolicy::Eager,
            queue_capacity: 1,
            supported_dtypes: vec![Dtype::F32],
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key: Arc::new(key()),
            fetch_access_policy: policy,
            fetch_routes: test_routes(
                "codex",
                "responses",
                Arc::new(provider.clone()),
                Arc::new(projector),
            ),
            fetch_max_in_flight: 1,
            fetch_queue_capacity: 1,
            artifact_store: ArtifactStoreConfig::Memory,
        })
        .await
        .unwrap();
        let request = fetch_request(&signing_key, "codex", "responses", br#"{"model":"x"}"#);
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let err = handle
            .run_ticket_handle(run_ticket_request(&ticket.request_commitment, &signing_key))
            .await
            .unwrap_err();

        assert!(matches!(err, ExecutorError::PolicyDenied(_)));
        assert_eq!(provider.calls(), 0);
    }

    #[tokio::test]
    async fn fetch_queue_full_leaves_ticket_retryable() {
        let signing_key = key();
        let provider = ReleasableFetchProvider::default();
        let handle = spawn_fetch_executor(Arc::new(provider.clone()), 1, 0).await;
        let first = fetch_request(&signing_key, "echo", "run", br#"{"n":1}"#);
        let second = fetch_request(&signing_key, "echo", "run", br#"{"n":2}"#);
        let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;
        let second_ticket = handle.create_fetch_ticket(second).await.unwrap().response;

        let first_outcome = handle
            .run_ticket_handle(run_ticket_request(
                &first_ticket.request_commitment,
                &signing_key,
            ))
            .await
            .unwrap();
        let error = handle
            .run_ticket_handle(run_ticket_request(
                &second_ticket.request_commitment,
                &signing_key,
            ))
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutorError::QueueFull { capacity: 0 }));

        provider.release();
        let (_, first_finished) =
            timeout(Duration::from_secs(2), drain_outcome(first_outcome.events))
                .await
                .unwrap();
        assert!(!first_finished.output_events.is_empty());

        let (chunks, second_finished) = timeout(
            Duration::from_secs(2),
            run_one(&handle, second_ticket.request_commitment, &signing_key),
        )
        .await
        .unwrap();
        assert_eq!(chunks.len(), 1);
        assert!(!second_finished.output_events.is_empty());
        assert_eq!(provider.calls(), 2);
    }

    #[tokio::test]
    async fn fetch_queue_dispatches_after_active_completion() {
        let signing_key = key();
        let provider = ReleasableFetchProvider::default();
        let handle = spawn_fetch_executor(Arc::new(provider.clone()), 1, 1).await;
        let first = fetch_request(&signing_key, "echo", "run", br#"{"n":1}"#);
        let second = fetch_request(&signing_key, "echo", "run", br#"{"n":2}"#);
        let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;
        let second_ticket = handle.create_fetch_ticket(second).await.unwrap().response;

        let first_outcome = handle
            .run_ticket_handle(run_ticket_request(
                &first_ticket.request_commitment,
                &signing_key,
            ))
            .await
            .unwrap();
        let second_outcome = handle
            .run_ticket_handle(run_ticket_request(
                &second_ticket.request_commitment,
                &signing_key,
            ))
            .await
            .unwrap();

        provider.release();
        let (_, first_finished) =
            timeout(Duration::from_secs(2), drain_outcome(first_outcome.events))
                .await
                .unwrap();
        let (second_chunks, second_finished) =
            timeout(Duration::from_secs(2), drain_outcome(second_outcome.events))
                .await
                .unwrap();

        assert!(!first_finished.output_events.is_empty());
        assert_eq!(second_chunks.len(), 1);
        assert!(!second_finished.output_events.is_empty());
        assert_eq!(provider.calls(), 2);
    }
}
