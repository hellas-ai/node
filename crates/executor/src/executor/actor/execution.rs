//! The executor's execution path: run-ticket validation, backend
//! dispatch, and the signed event stream a job produces.
//!
//! # The terminal event commitment this file used to owe
//!
//! Paid, and the debt is closed. The cutover deleted the Receipt and
//! Settle handlers and took the private `terminal_commitment` helper
//! with them; the note that stood here recorded that, and named
//! `957162c` as where to read the old shape.
//!
//! It came back as `hellas_rpc::protocol::work::terminal_result`, and
//! deliberately not in the shape it left. The deleted helper answered
//! "what is the terminal commitment of my completed transcript for this
//! *request commitment*", by looking one up — Fetch's durable
//! `replay_completed` first, then Evaluate's replayed `WorkFinished`.
//! A lookup by request commitment is the wrong question for a paid job:
//! two accepted jobs can carry one request, and the second would be
//! answered out of the first one's transcript with nothing invoked. The
//! new function is handed the transcript one invocation produced and
//! checks it against the authorization that paid for it, so the three
//! refusals the old one made — no transcript, an empty one, a terminal
//! that does not decode — survive, and two it could not make are added.
//!
//! The Receipt type that owned its only caller is gone for good and did
//! not come back with it.

use crate::ExecutorError;
use crate::StateError;
use crate::executor::{
    ExecuteOutcome, ExecutorCompletion, FetchCompletion, FetchProviderFailure, FetchProviderRun,
    PendingFetch,
};
use crate::fetch::{FetchStateError, FetchStoreError, FetchTranscript, VerifiedFetchReplay};
use crate::fetch_policy::{FetchAccessError, FetchQuotaReservation, FetchRoute};
use crate::fetch_projection::{FetchProjector, ProjectedFetch};
use crate::fetch_provider::{FetchProvider, FetchProviderError, PreparedFetchRequest};
use crate::state::{QuoteKind, new_execution_id, validate_job_terms};
use futures_util::StreamExt;
use hellas_rpc::fetch::{
    FetchOutputTranscriptBuilder, MAX_FETCH_OUTPUT_EVENTS, MAX_FETCH_OUTPUT_PAYLOAD_BYTES,
    decode_fetch_terminal_payload,
};
use hellas_rpc::pb::execute::{
    RunTicketRequest, WorkChunk, WorkEvent, WorkFailed, WorkFinished, work_event,
};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::run_ticket::{VerifiedRunTicket, verify_run_ticket};
use hellas_rpc::stream::output_event_to_pb;
use hellas_rpc::{Digest, InputCommitment, OutputEventEnvelope, ProducerSigningKey};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, mpsc};

use super::{
    DeferredFetchQuotaCancellation, DeferredFetchQuotaSettlement, Executor,
    FETCH_QUOTA_CANCELLATION_RETRIES_PER_TURN, FETCH_QUOTA_SETTLEMENT_RETRIES_PER_TURN,
    MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS,
};

/// Backpressure buffer for the per-execution event channel. The worker keeps
/// one slot reserved for the terminal frame and cancels a consumer that does
/// not drain the rest; it never blocks the sole execution thread.
const PER_EXECUTION_CHANNEL_CAPACITY: usize = 64;
const FETCH_STREAM_STALLED_ERROR: &str =
    "fetch stream consumer did not drain its bounded event channel";

#[derive(Debug, Default)]
struct FetchProjectionBudget {
    events: usize,
    signed_payload_bytes: usize,
}

impl FetchProjectionBudget {
    fn record_event(&mut self, payload_len: usize) -> Result<u64, FetchProviderError> {
        let streamed_event_limit = MAX_FETCH_OUTPUT_EVENTS
            .checked_sub(1)
            .expect("Fetch output limit includes one terminal event");
        self.record(payload_len, streamed_event_limit)
    }

    fn record_terminal(&mut self, payload_len: usize) -> Result<(), FetchProviderError> {
        self.record(payload_len, MAX_FETCH_OUTPUT_EVENTS)
            .map(|_| ())
    }

    fn record(
        &mut self,
        payload_len: usize,
        event_limit: usize,
    ) -> Result<u64, FetchProviderError> {
        let events = self.events.checked_add(1).ok_or_else(|| {
            FetchProviderError::failed(format!(
                "fetch projection exceeded the {event_limit}-event limit"
            ))
        })?;
        let signed_payload_bytes = self
            .signed_payload_bytes
            .checked_add(payload_len)
            .ok_or_else(|| {
                FetchProviderError::failed(format!(
                    "fetch projection exceeded the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
                ))
            })?;
        if events > event_limit {
            return Err(FetchProviderError::failed(format!(
                "fetch projection exceeded the {event_limit}-event limit"
            )));
        }
        if signed_payload_bytes > MAX_FETCH_OUTPUT_PAYLOAD_BYTES {
            return Err(FetchProviderError::failed(format!(
                "fetch projection exceeded the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
            )));
        }

        self.events = events;
        self.signed_payload_bytes = signed_payload_bytes;
        u64::try_from(payload_len)
            .map_err(|_| FetchProviderError::failed("fetch output position overflow"))
    }
}

impl Executor {
    pub(super) async fn handle_execute(
        &mut self,
        request: RunTicketRequest,
    ) -> Result<ExecuteOutcome, ExecutorError> {
        let verified_run = verify_run_ticket(&request).map_err(|err| {
            ExecutorError::InvalidQuoteRequest(format!("invalid run ticket: {err}"))
        })?;
        validate_job_terms(
            &verified_run.terms,
            self.provider.genesis.as_slice(),
            self.provider.assurance,
        )?;
        let request_commitment_id = *verified_run.terms.request.as_bytes();
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
        if let Some(outcome) = self
            .evaluate
            .replay_completed(
                request_commitment_id,
                &verified_run.public_key,
                verified_run.terms.assurance,
            )
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
        if quote.terms != verified_run.terms {
            return Err(ExecutorError::InvalidQuoteRequest(
                "run ticket terms do not match quote".into(),
            ));
        }
        match &quote.kind {
            #[cfg(feature = "evaluate")]
            QuoteKind::Evaluate(job) => {
                if job.evaluate_request.assurance != verified_run.terms.assurance {
                    return Err(ExecutorError::InvalidQuoteRequest(
                        "evaluate request assurance does not match ticket terms".into(),
                    ));
                }
            }
            QuoteKind::Fetch { .. } => {
                let fetch_quote = self
                    .fetch_state
                    .quoted(input_commitment)
                    .map_err(fetch_execute_error)?;
                if fetch_quote.assurance != verified_run.terms.assurance {
                    return Err(ExecutorError::InvalidQuoteRequest(
                        "fetch request assurance does not match ticket terms".into(),
                    ));
                }
            }
        }
        ensure_authorized_runner(&quote.runner_public_key, &verified_run.public_key)?;
        let dispatched: Result<ExecuteOutcome, ExecutorError> = async {
            match quote.kind {
                #[cfg(feature = "evaluate")]
                QuoteKind::Evaluate(job) => {
                    let outcome =
                        self.evaluate
                            .start(*job, new_execution_id(), request_commitment_id)?;
                    let _ = self.store.remove_quote(&request_commitment);
                    Ok(outcome)
                }
                QuoteKind::Fetch { call } => {
                    self.retry_deferred_fetch_quota_settlements();
                    if !self.pending_fetch_quota_settlements.is_empty() {
                        return Err(ExecutorError::ArtifactStore(
                            "fetch quota settlement retries remain unresolved".to_string(),
                        ));
                    }
                    self.retry_deferred_fetch_quota_cancellations();
                    self.ensure_fetch_quota_cancellation_capacity()?;
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
                    let route = FetchRoute::new(call.service.clone(), call.method.clone());
                    let entry = self
                        .fetch_routes
                        .entry(&route)
                        .cloned()
                        .ok_or_else(|| no_fetch_route_error(&route))?;
                    let adapted = entry
                        .adaptor_factory
                        .create(&call)
                        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?;
                    let provider_request = adapted.provider_request;
                    let fetch_quote = self
                        .fetch_state
                        .quoted(input_commitment)
                        .map_err(fetch_execute_error)?;
                    let execution_id = new_execution_id();
                    let admission = match self.fetch_access_policy.authorize_admission(
                        &fetch_quote.caller_key,
                        &adapted.request_view,
                        now_ms(),
                        execution_id.clone(),
                        input_commitment,
                        &entry.capabilities,
                    ) {
                        Ok(admission) => admission,
                        Err(error) => {
                            if let Some(reservation) = error.admission_reservation().cloned()
                                && let Err(cleanup) = self.cancel_or_defer_fetch_quota(
                                    Some(&reservation),
                                    None,
                                    false,
                                )
                            {
                                return Err(ExecutorError::ArtifactStore(format!(
                                    "{error}; failed to retain admission rollback: {cleanup}"
                                )));
                            }
                            return Err(fetch_access_error(error));
                        }
                    };
                    // Route-derived and operator-bounded. Never use the
                    // projected request's arbitrary model string as a
                    // Prometheus label or retain it in the metrics index.
                    let metric_name =
                        format!("{}/{}", provider_request.service, provider_request.method);
                    let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
                    let pending = PendingFetch {
                        request: provider_request,
                        provider: entry.provider,
                        input_commitment,
                        assurance: fetch_quote.assurance,
                        request_commitment_id,
                        quota_reservation: admission.reservation,
                        execution_id: execution_id.clone(),
                        metric_name: metric_name.clone(),
                        sender,
                        projector: adapted.projector,
                    };

                    let queued = if self.active_fetches < self.fetch_max_in_flight {
                        match self.fetch_state.start(input_commitment) {
                            Ok(_) => match self.start_fetch_execution(pending) {
                                Ok(()) => false,
                                Err(error) => {
                                    let (pending, activation_error) = *error;
                                    self.cancel_or_defer_fetch_quota(
                                        pending.quota_reservation.as_ref(),
                                        Some(pending.input_commitment),
                                        true,
                                    )?;
                                    return Err(fetch_access_error(activation_error));
                                }
                            },
                            Err(FetchStateError::AlreadyCompleted) => {
                                self.cancel_or_defer_fetch_quota(
                                    pending.quota_reservation.as_ref(),
                                    None,
                                    false,
                                )?;
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
                                let abort_running =
                                    matches!(&err, FetchStateError::StartMarkerRollback { .. })
                                        .then_some(pending.input_commitment);
                                self.cancel_or_defer_fetch_quota(
                                    pending.quota_reservation.as_ref(),
                                    abort_running,
                                    false,
                                )?;
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
                                self.cancel_or_defer_fetch_quota(
                                    pending.quota_reservation.as_ref(),
                                    None,
                                    false,
                                )?;
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
                                self.cancel_or_defer_fetch_quota(
                                    pending.quota_reservation.as_ref(),
                                    None,
                                    false,
                                )?;
                                return Err(fetch_execute_error(err));
                            }
                        }
                    };

                    self.metrics.record_execution_started(
                        "fetch",
                        &metric_name,
                        /* prompt= */ 0,
                        /* prefill= */ 0,
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
        .await;
        dispatched
    }

    async fn replay_fetch_execution(
        &self,
        input_commitment: InputCommitment,
        request_commitment_id: [u8; 32],
        verified_run: &VerifiedRunTicket,
    ) -> Result<Option<ExecuteOutcome>, ExecutorError> {
        let producer_key = self.provider.producer_key.public_key();
        if !self
            .fetch_state
            .has_completed(input_commitment)
            .map_err(fetch_execute_error)?
        {
            return Ok(None);
        }
        let replay_permit = Arc::clone(&self.fetch_replay_slots)
            .try_acquire_owned()
            .map_err(|_| {
                ExecutorError::ResourceExhausted(
                    "fetch replay concurrency capacity is exhausted".to_string(),
                )
            })?;
        let VerifiedFetchReplay { transcript, input } = match self.fetch_state.replay_completed(
            input_commitment,
            &producer_key,
            &verified_run.public_key,
        ) {
            Ok(replay) => replay,
            Err(FetchStateError::NotFound | FetchStateError::NotCompleted) => return Ok(None),
            Err(error) => return Err(fetch_execute_error(error)),
        };
        if input.assurance != verified_run.terms.assurance {
            return Err(ExecutorError::InvalidQuoteRequest(
                "fetch request assurance does not match ticket terms".into(),
            ));
        }
        ensure_authorized_runner(&input.caller_key, &verified_run.public_key)?;
        let outcome =
            fetch_transcript_outcome(request_commitment_id, transcript, replay_permit).await?;
        info!(
            request_commitment = %format_request_commitment(input_commitment.as_bytes()),
            "replayed fetch execution"
        );
        Ok(Some(outcome))
    }

    /// Cross the durable quota barrier before the task that owns provider
    /// invocation can exist. Keeping activation inside this sole spawn helper
    /// makes a future call-site omission a type-visible `Result`, not a silent
    /// billing-boundary regression.
    fn start_fetch_execution(
        &mut self,
        pending: PendingFetch,
    ) -> Result<(), Box<(PendingFetch, FetchAccessError)>> {
        if let Err(error) = self
            .fetch_access_policy
            .activate_reservation(pending.quota_reservation.as_ref())
        {
            return Err(Box::new((pending, error)));
        }
        self.active_fetches = self.active_fetches.saturating_add(1);
        spawn_fetch_provider(
            self.completion_tx.clone(),
            Arc::clone(&self.provider.producer_key),
            pending,
        );
        Ok(())
    }

    fn finish_fetch_slot(&mut self) {
        self.active_fetches = self.active_fetches.saturating_sub(1);
        self.retry_deferred_fetch_quota_settlements();
        self.retry_deferred_fetch_quota_cancellations();
        self.dispatch_next_fetch();
    }

    fn ensure_fetch_quota_cancellation_capacity(&self) -> Result<(), ExecutorError> {
        let queued_reservations = self
            .pending_fetches
            .iter()
            .filter(|pending| pending.quota_reservation.is_some())
            .count();
        let liabilities = self
            .pending_fetch_quota_cancellations
            .len()
            .saturating_add(queued_reservations);
        if liabilities >= MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS {
            return Err(ExecutorError::ResourceExhausted(format!(
                "fetch quota cancellation retry capacity of {MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS} is exhausted"
            )));
        }
        Ok(())
    }

    fn cancel_or_defer_fetch_quota(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
        abort_running: Option<InputCommitment>,
        allow_dispatched: bool,
    ) -> Result<(), ExecutorError> {
        let Some(reservation) = reservation.cloned() else {
            if let Some(input) = abort_running {
                self.fetch_state
                    .abort_before_dispatch(input)
                    .map_err(fetch_execute_error)?;
            }
            return Ok(());
        };
        let mut cancellation = DeferredFetchQuotaCancellation {
            reservation,
            abort_running,
            allow_dispatched,
        };
        if let Err(error) = self.try_fetch_quota_cancellation(&mut cancellation) {
            if self.pending_fetch_quota_cancellations.len()
                >= MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS
            {
                tracing::error!(
                    reservation = %cancellation.reservation.id,
                    cancellation_error = %error,
                    "fetch quota cancellation retry capacity exhausted; refusing further quota-bearing work until restart recovery"
                );
                return Err(ExecutorError::ResourceExhausted(format!(
                    "fetch quota cancellation retry capacity of {MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS} is exhausted"
                )));
            }
            warn!(
                reservation = %cancellation.reservation.id,
                cancellation_error = %error,
                "deferring failed pre-dispatch Fetch quota cancellation"
            );
            self.pending_fetch_quota_cancellations
                .push_back(cancellation);
            if self.pending_fetch_quota_cancellations.len()
                == MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS
            {
                warn!(
                    capacity = MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS,
                    "fetch quota cancellation retry capacity reached; new quota-bearing work will be refused"
                );
            }
        }
        Ok(())
    }

    fn try_fetch_quota_cancellation(
        &mut self,
        cancellation: &mut DeferredFetchQuotaCancellation,
    ) -> Result<(), String> {
        if cancellation.allow_dispatched {
            self.fetch_access_policy
                .begin_reservation_cancellation(Some(&cancellation.reservation))
                .map_err(|error| format!("quota cancellation intent failed: {error}"))?;
        }
        if let Some(input) = cancellation.abort_running {
            self.fetch_state
                .abort_before_dispatch(input)
                .map_err(|error| format!("Fetch state rollback failed: {error}"))?;
            cancellation.abort_running = None;
        }
        let result = if cancellation.allow_dispatched {
            self.fetch_access_policy
                .finish_reservation_cancellation(Some(&cancellation.reservation))
        } else {
            self.fetch_access_policy
                .cancel_reservation(Some(&cancellation.reservation))
        };
        result.map_err(|error| error.to_string())
    }

    fn retry_deferred_fetch_quota_cancellations(&mut self) {
        let attempts = self
            .pending_fetch_quota_cancellations
            .len()
            .min(FETCH_QUOTA_CANCELLATION_RETRIES_PER_TURN);
        for _ in 0..attempts {
            let mut cancellation = self
                .pending_fetch_quota_cancellations
                .pop_front()
                .expect("retry count was bounded by queue length");
            match self.try_fetch_quota_cancellation(&mut cancellation) {
                Ok(()) => {
                    tracing::debug!(
                        reservation = %cancellation.reservation.id,
                        "retired deferred Fetch quota cancellation"
                    );
                }
                Err(error) => {
                    warn!(
                        reservation = %cancellation.reservation.id,
                        cancellation_error = %error,
                        "Fetch quota cancellation retry remains pending"
                    );
                    self.pending_fetch_quota_cancellations
                        .push_back(cancellation);
                }
            }
        }
    }

    fn reconcile_or_defer_fetch_reservation(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
        billable_units: u64,
    ) -> Result<(), FetchAccessError> {
        let Some(reservation) = reservation else {
            return Ok(());
        };
        match self.fetch_access_policy.reconcile_reservation(
            Some(reservation),
            billable_units,
            now_ms(),
        ) {
            Ok(()) => Ok(()),
            Err(error) => {
                // Once one settlement is unresolved, later admissions stop.
                // Only work already active or queued can add another record,
                // bounding this queue by the configured execution capacities.
                let capacity = self
                    .fetch_max_in_flight
                    .saturating_add(self.fetch_queue_capacity)
                    .max(1);
                if self.pending_fetch_quota_settlements.len() < capacity {
                    self.pending_fetch_quota_settlements
                        .push_back(DeferredFetchQuotaSettlement {
                            reservation: reservation.clone(),
                            billable_units,
                        });
                } else {
                    // The durable Dispatched entry remains the fail-closed
                    // authority and startup will settle it. Reaching this log
                    // means the actor's active+queued invariant was violated.
                    tracing::error!(
                        reservation = %reservation.id,
                        capacity,
                        "fetch quota settlement retry capacity exhausted"
                    );
                }
                Err(error)
            }
        }
    }

    fn retry_deferred_fetch_quota_settlements(&mut self) {
        let attempts = self
            .pending_fetch_quota_settlements
            .len()
            .min(FETCH_QUOTA_SETTLEMENT_RETRIES_PER_TURN);
        for _ in 0..attempts {
            let settlement = self
                .pending_fetch_quota_settlements
                .pop_front()
                .expect("retry count was bounded by queue length");
            if let Err(error) = self.fetch_access_policy.reconcile_reservation(
                Some(&settlement.reservation),
                settlement.billable_units,
                now_ms(),
            ) {
                warn!(
                    reservation = %settlement.reservation.id,
                    quota_error = %error,
                    "Fetch quota settlement retry remains pending"
                );
                self.pending_fetch_quota_settlements.push_back(settlement);
            } else {
                tracing::debug!(
                    reservation = %settlement.reservation.id,
                    "retired deferred Fetch quota settlement"
                );
            }
        }
    }

    /// A dispatched request may have been billed even when no trustworthy
    /// terminal usage survives. Charge the full reservation as actual spend
    /// at failure completion: it remains fail-closed for one spend window,
    /// then ages out like any other completed charge.
    fn reconcile_failed_fetch_reservation(
        &mut self,
        reservation: Option<&FetchQuotaReservation>,
        execution_id: &str,
    ) {
        let Some(reservation) = reservation else {
            return;
        };
        if let Err(err) =
            self.reconcile_or_defer_fetch_reservation(Some(reservation), reservation.reserved_units)
        {
            // Do not follow a failed reconciliation with cancellation or any
            // second ledger mutation: the original reservation remains the
            // fail-closed authority for operator recovery.
            warn!(
                %execution_id,
                reserved_units = reservation.reserved_units,
                quota_error = %err,
                "failed to reconcile fetch quota after failed provider dispatch; leaving reservation intact"
            );
        }
    }

    pub(super) fn handle_fetch_finished(&mut self, completion: FetchCompletion) {
        let FetchCompletion {
            input_commitment,
            request_commitment_id,
            quota_reservation,
            execution_id,
            metric_name,
            sender,
            result,
        } = completion;

        let run = match result {
            Ok(run) => run,
            Err(failure) => {
                let error = failure.error.to_string();
                let _ = self.fetch_state.fail(input_commitment, error.clone());
                self.reconcile_failed_fetch_reservation(quota_reservation.as_ref(), &execution_id);
                self.metrics
                    .record_execution_failed("fetch", &metric_name, 0);
                send_fetch_failed(&sender, failure.position, error);
                self.finish_fetch_slot();
                return;
            }
        };

        let (event, billable_units) = match fetch_finished_event(&run.output_events) {
            Ok(event) => event,
            Err(err) => {
                let error = err.to_string();
                let _ = self.fetch_state.fail(input_commitment, error.clone());
                self.reconcile_failed_fetch_reservation(quota_reservation.as_ref(), &execution_id);
                self.metrics
                    .record_execution_failed("fetch", &metric_name, 0);
                send_fetch_failed(&sender, run.position, error);
                self.finish_fetch_slot();
                return;
            }
        };
        // The accounting transition is the publication barrier. A caller must
        // never receive (or later replay) a successful retained transcript
        // while its known billable usage is still an immortal Dispatched
        // reservation. On failure the running marker and Dispatched entry stay
        // fail-closed; startup settles the latter at the full reservation.
        if let Err(err) =
            self.reconcile_or_defer_fetch_reservation(quota_reservation.as_ref(), billable_units)
        {
            let error = format!("fetch quota reconciliation failed: {err}");
            let _ = self.fetch_state.fail(input_commitment, error.clone());
            self.metrics
                .record_execution_failed("fetch", &metric_name, 0);
            send_fetch_failed(&sender, run.position, error);
            self.finish_fetch_slot();
            return;
        }
        if let Err(err) = self.fetch_state.complete_output(
            input_commitment,
            run.output_events,
            &self.provider.producer_key.public_key(),
        ) {
            let error = fetch_execute_error(err).to_string();
            let _ = self.fetch_state.fail(input_commitment, error.clone());
            self.metrics
                .record_execution_failed("fetch", &metric_name, 0);
            send_fetch_failed(&sender, run.position, error);
            self.finish_fetch_slot();
            return;
        }

        self.metrics
            .record_execution_completed("fetch", &metric_name, 0);
        // Completion runs on the sole actor. A stalled receiver must never
        // wedge every later quote and execution behind an awaited send.
        let _ = sender.try_send(Ok(event));

        info!(
            %execution_id,
            request_commitment = %format_request_commitment(&request_commitment_id),
            billable_units,
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
                if let Err(err) = self.fetch_state.cancel_queued(pending.input_commitment) {
                    warn!(
                        execution_id = %pending.execution_id,
                        state_error = %err,
                        "queued fetch was not cancellable; ticket state is inconsistent"
                    );
                }
                if let Err(err) = self.cancel_or_defer_fetch_quota(
                    pending.quota_reservation.as_ref(),
                    None,
                    false,
                ) {
                    tracing::error!(
                        execution_id = %pending.execution_id,
                        quota_error = %err,
                        "could not retain a quota cancellation for disconnected fetch"
                    );
                }
                debug!(
                    execution_id = %pending.execution_id,
                    "dropping queued fetch execution: consumer disconnected before dispatch"
                );
                continue;
            }
            match self.fetch_state.start(pending.input_commitment) {
                Ok(_) => match self.start_fetch_execution(pending) {
                    Ok(()) => return,
                    Err(error) => {
                        let (pending, activation_error) = *error;
                        let mut error = fetch_access_error(activation_error).to_string();
                        if let Err(cleanup_error) = self.cancel_or_defer_fetch_quota(
                            pending.quota_reservation.as_ref(),
                            Some(pending.input_commitment),
                            true,
                        ) {
                            error =
                                format!("{error}; pre-dispatch cleanup failed: {cleanup_error}");
                        }
                        let _ = pending.sender.try_send(Ok(WorkEvent {
                            kind: Some(work_event::Kind::Failed(WorkFailed { position: 0, error })),
                        }));
                    }
                },
                Err(err) => {
                    let abort_running = matches!(&err, FetchStateError::StartMarkerRollback { .. })
                        .then_some(pending.input_commitment);
                    if abort_running.is_none()
                        && !self.fetch_state.discard_queued(pending.input_commitment)
                    {
                        warn!(
                            execution_id = %pending.execution_id,
                            "failed to discard a queued fetch after dispatch refusal"
                        );
                    }
                    if let Err(error) = self.cancel_or_defer_fetch_quota(
                        pending.quota_reservation.as_ref(),
                        abort_running,
                        false,
                    ) {
                        tracing::error!(
                            execution_id = %pending.execution_id,
                            quota_error = %error,
                            "could not retain a quota cancellation after dispatch refusal"
                        );
                    }
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
    completion_tx: mpsc::Sender<ExecutorCompletion>,
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
            assurance,
            request_commitment_id,
            execution_id,
            metric_name,
            sender,
        } = pending;
        let result = run_fetch_provider(
            provider,
            request,
            projector,
            input_commitment,
            assurance,
            &producer_key,
            sender.clone(),
        )
        .await;
        let _ = completion_tx
            .send(ExecutorCompletion::FetchFinished(Box::new(
                FetchCompletion {
                    input_commitment,
                    request_commitment_id,
                    quota_reservation,
                    execution_id,
                    metric_name,
                    sender,
                    result,
                },
            )))
            .await;
    });
}

async fn run_fetch_provider(
    provider: Arc<dyn FetchProvider>,
    request: PreparedFetchRequest,
    mut projector: Box<dyn FetchProjector>,
    input_commitment: InputCommitment,
    assurance: hellas_rpc::Assurance,
    producer_key: &ProducerSigningKey,
    sender: mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
) -> Result<FetchProviderRun, FetchProviderFailure> {
    let mut builder = FetchOutputTranscriptBuilder::new(input_commitment, assurance, producer_key);
    let mut position = 0_u64;
    let mut terminal = None;
    let mut projection_budget = FetchProjectionBudget::default();
    let response = provider
        .run(request)
        .await
        .map_err(|error| FetchProviderFailure { position, error })?;
    let projected = projector
        .begin(response.head)
        .map_err(|err| FetchProviderFailure {
            position,
            error: FetchProviderError::failed(format!("fetch projection failed: {err}")),
        })?;
    process_projected_fetch(
        projected,
        &mut builder,
        &mut terminal,
        &mut projection_budget,
        &mut position,
        &sender,
    )
    .await?;
    let mut stream = response.stream;

    while let Some(next) = stream.next().await {
        let chunk = next.map_err(|error| FetchProviderFailure { position, error })?;
        let projected = projector
            .project(&chunk)
            .map_err(|err| FetchProviderFailure {
                position,
                error: FetchProviderError::failed(format!("fetch projection failed: {err}")),
            })?;
        let reached_terminal = process_projected_fetch(
            projected,
            &mut builder,
            &mut terminal,
            &mut projection_budget,
            &mut position,
            &sender,
        )
        .await?;
        if reached_terminal {
            // A terminal projection is the trusted end of the operation. Do
            // not let an upstream keep this task, connection, or credential
            // alive after it has supplied the complete result.
            drop(stream);
            break;
        }
    }

    if terminal.is_none() {
        let projected = projector.finish().map_err(|err| FetchProviderFailure {
            position,
            error: FetchProviderError::failed(format!("fetch projection failed: {err}")),
        })?;
        process_projected_fetch(
            projected,
            &mut builder,
            &mut terminal,
            &mut projection_budget,
            &mut position,
            &sender,
        )
        .await?;
    }
    let terminal_payload = terminal.ok_or_else(|| FetchProviderFailure {
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
        position,
    })
}

async fn process_projected_fetch(
    projected: Vec<ProjectedFetch>,
    builder: &mut FetchOutputTranscriptBuilder<'_>,
    terminal: &mut Option<Vec<u8>>,
    projection_budget: &mut FetchProjectionBudget,
    position: &mut u64,
    sender: &mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
) -> Result<bool, FetchProviderFailure> {
    for item in projected {
        match item {
            ProjectedFetch::Event(payload) => {
                if terminal.is_some() {
                    return Err(FetchProviderFailure {
                        position: *position,
                        error: FetchProviderError::failed(
                            "fetch projection emitted an event after terminal".to_string(),
                        ),
                    });
                }
                // The actor needs one guaranteed permit for WorkFinished or
                // WorkFailed. Fail before signing another chunk when only that
                // permit remains; never await a slow consumer here.
                if sender.capacity() <= 1 {
                    return Err(FetchProviderFailure {
                        position: *position,
                        error: FetchProviderError::failed(FETCH_STREAM_STALLED_ERROR),
                    });
                }
                let payload_len =
                    projection_budget
                        .record_event(payload.len())
                        .map_err(|error| FetchProviderFailure {
                            position: *position,
                            error,
                        })?;
                let next_position =
                    position
                        .checked_add(payload_len)
                        .ok_or_else(|| FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed("fetch output position overflow"),
                        })?;
                let output_event =
                    builder
                        .push_event(payload)
                        .map_err(|err| FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed(format!(
                                "fetch output event transcript failed: {err}"
                            )),
                        })?;
                match sender.try_send(Ok(WorkEvent {
                    kind: Some(work_event::Kind::Chunk(WorkChunk {
                        output_event: Some(output_event_to_pb(&output_event)),
                    })),
                })) {
                    Ok(()) => {
                        *position = next_position;
                        // Give the just-returned RPC receiver a scheduling
                        // opportunity before classifying a full burst as a
                        // stalled consumer.
                        tokio::task::yield_now().await;
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        return Err(FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed(FETCH_STREAM_STALLED_ERROR),
                        });
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        return Err(FetchProviderFailure {
                            position: *position,
                            error: FetchProviderError::failed("fetch stream consumer disconnected"),
                        });
                    }
                }
            }
            ProjectedFetch::Terminal(payload) => {
                if terminal.is_some() {
                    return Err(FetchProviderFailure {
                        position: *position,
                        error: FetchProviderError::failed(
                            "fetch projection emitted multiple terminal events".to_string(),
                        ),
                    });
                }
                projection_budget
                    .record_terminal(payload.len())
                    .map_err(|error| FetchProviderFailure {
                        position: *position,
                        error,
                    })?;
                *terminal = Some(payload);
            }
        }
    }
    Ok(terminal.is_some())
}

fn send_fetch_failed(
    sender: &mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
    position: u64,
    error: impl Into<String>,
) {
    let _ = sender.try_send(Ok(WorkEvent {
        kind: Some(work_event::Kind::Failed(WorkFailed {
            position,
            error: error.into(),
        })),
    }));
}

async fn fetch_transcript_outcome(
    request_commitment_id: [u8; 32],
    transcript: FetchTranscript,
    replay_permit: OwnedSemaphorePermit,
) -> Result<ExecuteOutcome, ExecutorError> {
    fetch_finished_outcome_inner(
        ExecutionProvenance {
            commitment_id: request_commitment_id,
        },
        transcript.into_output_events(),
        Some(replay_permit),
    )
    .await
}

#[cfg(test)]
async fn fetch_finished_outcome(
    provenance: ExecutionProvenance,
    output_events: &[OutputEventEnvelope],
) -> Result<ExecuteOutcome, ExecutorError> {
    fetch_finished_outcome_inner(provenance, output_events.to_vec(), None).await
}

async fn fetch_finished_outcome_inner(
    provenance: ExecutionProvenance,
    mut output_events: Vec<OutputEventEnvelope>,
    replay_permit: Option<OwnedSemaphorePermit>,
) -> Result<ExecuteOutcome, ExecutorError> {
    let (finished, _) = fetch_finished_event(&output_events)?;
    output_events
        .pop()
        .ok_or_else(|| ExecutorError::InvalidQuoteRequest("empty fetch transcript".to_string()))?;
    let streamed_prefix = output_events;
    let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        async {
            for output_event in streamed_prefix {
                let event = WorkEvent {
                    kind: Some(work_event::Kind::Chunk(WorkChunk {
                        output_event: Some(output_event_to_pb(&output_event)),
                    })),
                };
                if sender.send(Ok(event)).await.is_err() {
                    return;
                }
            }
            let _ = sender.send(Ok(finished)).await;
        }
        .await;

        // A replay slot represents a live consumer, not merely a producer
        // task. Reserving the channel's entire capacity can succeed only
        // after every buffered event has been consumed, or fail when the
        // receiver is dropped. Keep the owned semaphore permit across that
        // rendezvous so an undrained terminal frame still occupies its slot.
        if let Some(_replay_permit) = replay_permit {
            let _drained_or_dropped = sender.reserve_many(PER_EXECUTION_CHANNEL_CAPACITY).await;
        }
    });

    Ok(ExecuteOutcome {
        provenance,
        events: receiver,
    })
}

fn fetch_finished_event(
    output_events: &[OutputEventEnvelope],
) -> Result<(WorkEvent, u64), ExecutorError> {
    let terminal = output_events
        .last()
        .ok_or_else(|| ExecutorError::InvalidQuoteRequest("empty fetch transcript".to_string()))?;
    let billable_units = decode_fetch_terminal_payload(terminal.payload())
        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?
        .billable_units();
    Ok((
        WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                terminal_output_event: Some(output_event_to_pb(terminal)),
                assurance_evidence: Vec::new(),
            })),
        },
        billable_units,
    ))
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
        | FetchStateError::Indeterminate => {
            ExecutorError::State(StateError::QuoteExpired(err.to_string()))
        }
        FetchStateError::Store(err @ FetchStoreError::Capacity { .. }) => {
            ExecutorError::ResourceExhausted(err.to_string())
        }
        FetchStateError::Store(err) => {
            ExecutorError::ArtifactStore(format!("fetch transcript store error: {err}"))
        }
        FetchStateError::StartMarkerRollback { .. } => {
            ExecutorError::ArtifactStore(err.to_string())
        }
        FetchStateError::TicketCapacity { capacity } => ExecutorError::QueueFull { capacity },
        FetchStateError::InputCapacity { .. } => ExecutorError::ResourceExhausted(err.to_string()),
        FetchStateError::UnauthorizedRunner => ExecutorError::PolicyDenied(err.to_string()),
        FetchStateError::QuoteMismatch
        | FetchStateError::UnauthorizedCaller
        | FetchStateError::InputLengthOverflow
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
        error @ (FetchAccessError::BillableUnitsExceedReservation { .. }
        | FetchAccessError::MissingReservation(_)
        | FetchAccessError::InvalidReservationLifecycle { .. }) => {
            ExecutorError::Execution(error.to_string())
        }
        error @ FetchAccessError::AdmissionReservationIndeterminate { .. } => {
            ExecutorError::ArtifactStore(error.to_string())
        }
        FetchAccessError::Store(message) => {
            ExecutorError::ArtifactStore(format!("fetch quota store error: {message}"))
        }
        FetchAccessError::Io(err) => {
            ExecutorError::ArtifactStore(format!("fetch quota store I/O error: {err}"))
        }
    }
}

pub(super) fn now_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(elapsed).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "evaluate")]
    use crate::ArtifactStoreConfig;
    use crate::ExecutorError;
    #[cfg(feature = "evaluate")]
    use crate::GpuConfig;
    use crate::fetch::{FetchTranscriptStore, MemoryFetchTranscriptStore};
    use crate::fetch_policy::MemoryFetchQuotaStore;
    use crate::{
        CallerAccess, Executor, ExecutorMetrics, ExecutorSpawnConfig, FetchAccessPolicy,
        FetchAdaptorError, FetchAdaptorFactory, FetchAdaptorSession, FetchProjector, FetchProvider,
        FetchProviderFuture, FetchProviderResponse, FetchProviderResponseHead, FetchProviderStream,
        FetchQuotaStoreBackend, FetchRequestView, FetchRoute, FetchRouteGrant, FetchRoutePolicy,
        FetchTranscriptStoreBackend, MockFetchProvider, PreparedFetchRequest, ProjectedFetch,
        SpendLimit,
    };
    use futures_util::stream;
    use hellas_rpc::ProducerSigningKey;
    use hellas_rpc::fetch::build_input_events;
    use hellas_rpc::pb::fetch::FetchRequest;
    use hellas_rpc::policy::ExecutePolicy;
    use hellas_rpc::stream::input_event_to_pb;
    #[cfg(feature = "evaluate")]
    use hellas_store::ContentStore;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::Notify;
    use tokio::time::{Duration, timeout};

    #[derive(Clone, Debug, Default)]
    struct TestFetchAdaptorFactory;

    impl FetchAdaptorFactory for TestFetchAdaptorFactory {
        fn execution_environment(&self) -> hellas_rpc::ContentId {
            test_environment()
        }

        fn create(
            &self,
            request: &crate::FetchCall,
        ) -> Result<FetchAdaptorSession, FetchAdaptorError> {
            Ok(FetchAdaptorSession {
                request_view: FetchRequestView::from_call(request),
                provider_request: PreparedFetchRequest::new(request, request.body.clone()),
                projector: Box::new(TestFetchProjector {
                    terminal_seen: false,
                }),
            })
        }
    }

    #[derive(Clone, Debug)]
    struct FixedViewFetchAdaptorFactory {
        view: FetchRequestView,
    }

    impl FetchAdaptorFactory for FixedViewFetchAdaptorFactory {
        fn execution_environment(&self) -> hellas_rpc::ContentId {
            test_environment()
        }

        fn create(
            &self,
            request: &crate::FetchCall,
        ) -> Result<FetchAdaptorSession, FetchAdaptorError> {
            Ok(FetchAdaptorSession {
                request_view: self.view.clone(),
                provider_request: PreparedFetchRequest::new(request, request.body.clone()),
                projector: Box::new(TestFetchProjector {
                    terminal_seen: false,
                }),
            })
        }
    }

    #[derive(Clone, Debug)]
    struct InvalidTerminalFetchAdaptorFactory {
        view: FetchRequestView,
    }

    impl FetchAdaptorFactory for InvalidTerminalFetchAdaptorFactory {
        fn execution_environment(&self) -> hellas_rpc::ContentId {
            test_environment()
        }

        fn create(
            &self,
            request: &crate::FetchCall,
        ) -> Result<FetchAdaptorSession, FetchAdaptorError> {
            Ok(FetchAdaptorSession {
                request_view: self.view.clone(),
                provider_request: PreparedFetchRequest::new(request, request.body.clone()),
                projector: Box::new(InvalidTerminalFetchProjector),
            })
        }
    }

    struct InvalidTerminalFetchProjector;

    impl FetchProjector for InvalidTerminalFetchProjector {
        fn project(&mut self, _bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
            Ok(vec![ProjectedFetch::Terminal(vec![0xff])])
        }

        fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
            Err(FetchAdaptorError::failed(
                "invalid-terminal fixture received no provider body",
            ))
        }
    }

    struct TestFetchProjector {
        terminal_seen: bool,
    }

    impl FetchProjector for TestFetchProjector {
        fn project(&mut self, bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
            if bytes.strip_prefix(b"terminal:").is_some() {
                self.terminal_seen = true;
                let event = hellas_rpc::output::OutputEvent::Finished {
                    stop_reason: hellas_rpc::output::StopReason::EndOfText,
                    usage: None,
                };
                let payload = hellas_rpc::fetch::encode_fetch_terminal_payload(&event)
                    .map_err(|error| FetchAdaptorError::failed(error.to_string()))?;
                Ok(vec![ProjectedFetch::Terminal(payload)])
            } else {
                Ok(vec![ProjectedFetch::Event(bytes.to_vec())])
            }
        }

        fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
            if self.terminal_seen {
                Ok(Vec::new())
            } else {
                Err(FetchAdaptorError::failed(
                    "test stream ended without terminal".to_string(),
                ))
            }
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
        fn execution_environment(&self) -> hellas_rpc::ContentId {
            test_environment()
        }

        fn run(&self, _request: PreparedFetchRequest) -> FetchProviderFuture<'_> {
            let released = Arc::clone(&self.released);
            let notify = Arc::clone(&self.notify);
            let calls = Arc::clone(&self.calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                while !released.load(Ordering::SeqCst) {
                    notify.notified().await;
                }
                Ok(FetchProviderResponse {
                    head: FetchProviderResponseHead::default(),
                    stream: Box::pin(stream::iter([
                        Ok(b"event:ok".to_vec()),
                        Ok(b"terminal:done".to_vec()),
                    ])) as FetchProviderStream,
                })
            })
        }
    }

    #[derive(Clone, Default)]
    struct TerminalThenPanicFetchProvider {
        polls: Arc<AtomicUsize>,
    }

    impl TerminalThenPanicFetchProvider {
        fn polls(&self) -> usize {
            self.polls.load(Ordering::SeqCst)
        }
    }

    impl FetchProvider for TerminalThenPanicFetchProvider {
        fn execution_environment(&self) -> hellas_rpc::ContentId {
            test_environment()
        }

        fn run(&self, _request: PreparedFetchRequest) -> FetchProviderFuture<'_> {
            let polls = Arc::clone(&self.polls);
            let mut first = true;
            Box::pin(async move {
                Ok(FetchProviderResponse {
                    head: FetchProviderResponseHead::default(),
                    stream: Box::pin(stream::poll_fn(move |_| {
                        polls.fetch_add(1, Ordering::SeqCst);
                        if std::mem::take(&mut first) {
                            std::task::Poll::Ready(Some(Ok(b"terminal:done".to_vec())))
                        } else {
                            panic!("upstream was polled after its terminal event")
                        }
                    })) as FetchProviderStream,
                })
            })
        }
    }

    fn key() -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([7; 32]).expect("valid test key")
    }

    fn test_assurance() -> hellas_rpc::Assurance {
        hellas_rpc::Assurance::ProducerSigned
    }

    fn test_genesis() -> Vec<u8> {
        b"genesis".to_vec()
    }

    fn test_environment() -> hellas_rpc::ContentId {
        hellas_rpc::ContentId::from_bytes([9; 32])
    }

    fn fetch_request(
        key: &ProducerSigningKey,
        service: &str,
        method: &str,
        body: &[u8],
    ) -> FetchRequest {
        fetch_request_and_commitment(key, service, method, body).0
    }

    fn fetch_request_and_commitment(
        key: &ProducerSigningKey,
        service: &str,
        method: &str,
        body: &[u8],
    ) -> (FetchRequest, InputCommitment) {
        let events = build_input_events(
            service,
            method,
            body,
            test_environment(),
            test_assurance(),
            key,
        )
        .unwrap();
        let input_commitment = hellas_rpc::fetch::verify_input_events(&events)
            .unwrap()
            .input_commitment;
        (
            FetchRequest {
                input: events.iter().map(input_event_to_pb).collect(),
            },
            input_commitment,
        )
    }

    fn run_ticket_request(
        ticket: hellas_rpc::pb::execute::Ticket,
        key: &ProducerSigningKey,
    ) -> RunTicketRequest {
        hellas_rpc::run_ticket::sign_run_ticket(ticket, key).expect("test run ticket signs")
    }

    async fn run_one(
        handle: &crate::ExecutorHandle,
        ticket: hellas_rpc::pb::execute::Ticket,
        key: &ProducerSigningKey,
    ) -> (Vec<WorkChunk>, WorkFinished) {
        let outcome = handle
            .run_ticket_handle(run_ticket_request(ticket, key))
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
        adaptor_factory: Arc<dyn FetchAdaptorFactory>,
    ) -> crate::FetchRouteRegistry {
        let mut registry = crate::FetchRouteRegistry::new();
        registry
            .register(
                FetchRoute::new(service, method),
                crate::FetchRouteEntry::new(provider, adaptor_factory, FetchRoutePolicy::default())
                    .expect("test provider and adaptor identities match"),
            )
            .unwrap();
        registry
    }

    async fn spawn_fetch_executor(
        provider: Arc<dyn FetchProvider>,
        fetch_max_in_flight: usize,
        fetch_queue_capacity: usize,
    ) -> crate::ExecutorHandle {
        spawn_fetch_executor_with_bounds(
            provider,
            fetch_max_in_flight,
            fetch_queue_capacity,
            hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
            FetchTranscriptStoreBackend::memory(),
        )
        .await
    }

    async fn spawn_fetch_executor_with_bounds(
        provider: Arc<dyn FetchProvider>,
        fetch_max_in_flight: usize,
        fetch_queue_capacity: usize,
        fetch_replay_max_in_flight: usize,
        fetch_store: FetchTranscriptStoreBackend,
    ) -> crate::ExecutorHandle {
        let producer_key = key();
        let caller_key = producer_key.public_key();
        Executor::spawn_configured(ExecutorSpawnConfig {
            execute_policy: ExecutePolicy::Any,
            queue_capacity: 1,
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key: Arc::new(producer_key),
            provider_genesis: Arc::new(test_genesis()),
            assurance: test_assurance(),
            fetch_access_policy: FetchAccessPolicy::trusted_callers([caller_key]),
            fetch_routes: test_routes("echo", "run", provider, Arc::new(TestFetchAdaptorFactory)),
            fetch_max_in_flight,
            fetch_queue_capacity,
            fetch_replay_max_in_flight,
            fetch_store,
            #[cfg(feature = "evaluate")]
            artifact_store: ArtifactStoreConfig::memory(),
            #[cfg(feature = "evaluate")]
            content_store: ContentStore::new(),
            #[cfg(feature = "evaluate")]
            gpu_config: GpuConfig::default(),
        })
        .await
        .unwrap()
    }

    fn quota_request_view() -> FetchRequestView {
        FetchRequestView {
            service: "echo".to_string(),
            method: "run".to_string(),
            model: None,
            max_output_units: Some(90),
        }
    }

    async fn spawn_quota_fetch_executor(
        provider: Arc<dyn FetchProvider>,
        adaptor_factory: Arc<dyn FetchAdaptorFactory>,
        fetch_store: FetchTranscriptStoreBackend,
    ) -> crate::ExecutorHandle {
        spawn_quota_fetch_executor_with_store(
            provider,
            adaptor_factory,
            fetch_store,
            FetchQuotaStoreBackend::memory(),
        )
        .await
    }

    async fn spawn_quota_fetch_executor_with_store(
        provider: Arc<dyn FetchProvider>,
        adaptor_factory: Arc<dyn FetchAdaptorFactory>,
        fetch_store: FetchTranscriptStoreBackend,
        quota_store: FetchQuotaStoreBackend,
    ) -> crate::ExecutorHandle {
        let signing_key = key();
        let mut caller = CallerAccess::allow_all(signing_key.public_key());
        caller.spend = Some(SpendLimit {
            max_units: 100,
            window: Duration::from_secs(60),
        });
        Executor::spawn_configured(ExecutorSpawnConfig {
            execute_policy: ExecutePolicy::Any,
            queue_capacity: 1,
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key: Arc::new(key()),
            provider_genesis: Arc::new(test_genesis()),
            assurance: test_assurance(),
            fetch_access_policy: FetchAccessPolicy::with_quota_store([caller], quota_store),
            fetch_routes: test_routes("echo", "run", provider, adaptor_factory),
            fetch_max_in_flight: 1,
            fetch_queue_capacity: 1,
            fetch_replay_max_in_flight: hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
            fetch_store,
            #[cfg(feature = "evaluate")]
            artifact_store: ArtifactStoreConfig::memory(),
            #[cfg(feature = "evaluate")]
            content_store: ContentStore::new(),
            #[cfg(feature = "evaluate")]
            gpu_config: GpuConfig::default(),
        })
        .await
        .unwrap()
    }

    async fn run_failed(
        handle: &crate::ExecutorHandle,
        ticket: hellas_rpc::pb::execute::Ticket,
        key: &ProducerSigningKey,
    ) -> WorkFailed {
        let outcome = handle
            .run_ticket_handle(run_ticket_request(ticket, key))
            .await
            .unwrap()
            .events;
        receive_failed(outcome).await
    }

    async fn receive_failed(mut outcome: crate::executor::ExecuteEventReceiver) -> WorkFailed {
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
        let provider = MockFetchProvider::new(test_environment());
        provider.insert(
            "echo",
            "run",
            input,
            [
                b"event:one".to_vec(),
                b"event:two".to_vec(),
                b"terminal:done".to_vec(),
            ],
        );
        let request = fetch_request(&signing_key, "echo", "run", input);
        let handle = Executor::spawn_with_fetch_routes(
            ExecutePolicy::Any,
            1,
            key(),
            test_genesis(),
            test_assurance(),
            test_routes(
                "echo",
                "run",
                Arc::new(provider.clone()),
                Arc::new(TestFetchAdaptorFactory),
            ),
        )
        .unwrap();
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let (chunks, first) = run_one(&handle, ticket.clone(), &signing_key).await;
        let (replay_chunks, replayed) = run_one(&handle, ticket, &signing_key).await;

        assert_eq!(chunks.len(), 2);
        assert_eq!(replay_chunks, chunks);
        for (index, expected_payload) in [b"event:one".as_slice(), b"event:two"]
            .into_iter()
            .enumerate()
        {
            let chunk_event = chunks[index]
                .output_event
                .as_ref()
                .expect("fetch chunk should carry signed output event");
            assert_eq!(chunk_event.payload, expected_payload);
        }
        let first_terminal = first
            .terminal_output_event
            .as_ref()
            .expect("fetch completion should carry its terminal event");
        assert_eq!(
            decode_fetch_terminal_payload(&first_terminal.payload)
                .unwrap()
                .billable_units(),
            0
        );
        assert_eq!(replayed.terminal_output_event, first.terminal_output_event);
        assert_eq!(provider.calls("echo", "run", input), 1);
    }

    #[tokio::test]
    async fn live_fetch_larger_than_buffer_succeeds_for_a_draining_consumer() {
        let signing_key = key();
        let input = br#"{"hello":"many-events"}"#;
        let provider = MockFetchProvider::new(test_environment());
        let event_count = PER_EXECUTION_CHANNEL_CAPACITY * 2;
        let mut response = (0..event_count)
            .map(|_| b"event".to_vec())
            .collect::<Vec<_>>();
        response.push(b"terminal:done".to_vec());
        provider.insert("echo", "run", input, response);
        let request = fetch_request(&signing_key, "echo", "run", input);
        let handle = Executor::spawn_with_fetch_routes(
            ExecutePolicy::Any,
            1,
            key(),
            test_genesis(),
            test_assurance(),
            test_routes(
                "echo",
                "run",
                Arc::new(provider),
                Arc::new(TestFetchAdaptorFactory),
            ),
        )
        .unwrap();
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let (chunks, _) = timeout(
            Duration::from_secs(1),
            run_one(&handle, ticket, &signing_key),
        )
        .await
        .unwrap();
        assert_eq!(chunks.len(), event_count);
    }

    #[tokio::test]
    async fn fetch_execution_reports_unprogrammed_mock_provider_failure() {
        let signing_key = key();
        let input = br#"{"hello":"world"}"#;
        let provider = MockFetchProvider::new(test_environment());
        let request = fetch_request(&signing_key, "echo", "run", input);
        let handle = Executor::spawn_with_fetch_routes(
            ExecutePolicy::Any,
            1,
            key(),
            test_genesis(),
            test_assurance(),
            test_routes(
                "echo",
                "run",
                Arc::new(provider.clone()),
                Arc::new(TestFetchAdaptorFactory),
            ),
        )
        .unwrap();
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let failed = run_failed(&handle, ticket, &signing_key).await;

        assert_eq!(failed.position, 0);
        assert!(failed.error.contains("mock fetch response not programmed"));
        assert_eq!(provider.calls("echo", "run", input), 1);
    }

    #[tokio::test]
    async fn provider_failure_charges_the_maximum_spend_for_the_window() {
        let signing_key = key();
        let provider = MockFetchProvider::new(test_environment());
        let handle = spawn_quota_fetch_executor(
            Arc::new(provider),
            Arc::new(FixedViewFetchAdaptorFactory {
                view: quota_request_view(),
            }),
            FetchTranscriptStoreBackend::memory(),
        )
        .await;
        let first = fetch_request(&signing_key, "echo", "run", br#"{"request":1}"#);
        let second = fetch_request(&signing_key, "echo", "run", br#"{"request":2}"#);
        let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;
        let second_ticket = handle.create_fetch_ticket(second).await.unwrap().response;

        let failed = run_failed(&handle, first_ticket, &signing_key).await;
        assert!(failed.error.contains("mock fetch response not programmed"));

        let error = handle
            .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutorError::QuotaExceeded { .. }));
    }

    #[tokio::test]
    async fn invalid_terminal_charges_the_maximum_spend_for_the_window() {
        let signing_key = key();
        let provider = MockFetchProvider::new(test_environment());
        let first_body = br#"{"request":"invalid-terminal"}"#;
        provider.insert("echo", "run", first_body, [b"provider-body".to_vec()]);
        let handle = spawn_quota_fetch_executor(
            Arc::new(provider),
            Arc::new(InvalidTerminalFetchAdaptorFactory {
                view: quota_request_view(),
            }),
            FetchTranscriptStoreBackend::memory(),
        )
        .await;
        let first = fetch_request(&signing_key, "echo", "run", first_body);
        let second = fetch_request(
            &signing_key,
            "echo",
            "run",
            br#"{"request":"after-invalid-terminal"}"#,
        );
        let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;
        let second_ticket = handle.create_fetch_ticket(second).await.unwrap().response;

        let failed = run_failed(&handle, first_ticket, &signing_key).await;
        assert!(failed.error.contains("invalid quote request"));

        let error = handle
            .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutorError::QuotaExceeded { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn complete_output_failure_keeps_actual_spend_and_running_evidence() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/hellas-fetch-completion-failure")
            .join(uuid::Uuid::new_v4().to_string());
        let signing_key = key();
        let provider = ReleasableFetchProvider::default();
        let handle = spawn_quota_fetch_executor(
            Arc::new(provider.clone()),
            Arc::new(FixedViewFetchAdaptorFactory {
                view: quota_request_view(),
            }),
            FetchTranscriptStoreBackend::fs(&root),
        )
        .await;
        let first = fetch_request(
            &signing_key,
            "echo",
            "run",
            br#"{"request":"completion-store-failure"}"#,
        );
        let second = fetch_request(
            &signing_key,
            "echo",
            "run",
            br#"{"request":"after-completion-store-failure"}"#,
        );
        let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;
        let second_ticket = handle.create_fetch_ticket(second).await.unwrap().response;
        let first_outcome = handle
            .run_ticket_handle(run_ticket_request(first_ticket, &signing_key))
            .await
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while provider.calls() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        std::fs::write(root.join(".retained-transcript-capacity"), b"invalid\n")
            .expect("corrupt completion-store metadata after provider dispatch");
        provider.release();
        let failed = receive_failed(first_outcome.events).await;
        assert!(failed.error.contains("capacity metadata"));

        std::fs::write(
            root.join(".retained-transcript-capacity"),
            format!(
                "{}\n",
                hellas_rpc::DEFAULT_FETCH_RETAINED_TRANSCRIPT_CAPACITY
            ),
        )
        .expect("restore completion-store metadata");
        let second_outcome = handle
            .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
            .await
            .unwrap();
        timeout(Duration::from_secs(2), drain_outcome(second_outcome.events))
            .await
            .unwrap();
        assert_eq!(provider.calls(), 2);

        drop(handle);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn ambiguous_admission_write_is_cancelled_without_calling_provider() {
        let signing_key = key();
        let caller_id = hellas_rpc::ProducerId::from_public_key(&signing_key.public_key());
        let provider = ReleasableFetchProvider::default();
        let transcript_store = MemoryFetchTranscriptStore::default();
        let quota_store = MemoryFetchQuotaStore::default();
        quota_store.fail_put_after_write_number(1);
        let handle = spawn_quota_fetch_executor_with_store(
            Arc::new(provider.clone()),
            Arc::new(FixedViewFetchAdaptorFactory {
                view: quota_request_view(),
            }),
            FetchTranscriptStoreBackend::Memory(transcript_store.clone()),
            FetchQuotaStoreBackend::Memory(quota_store.clone()),
        )
        .await;
        let (request, input) = fetch_request_and_commitment(
            &signing_key,
            "echo",
            "run",
            br#"{"request":"ambiguous-admission"}"#,
        );
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let error = handle
            .run_ticket_handle(run_ticket_request(ticket, &signing_key))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("post-write failure 1"));
        assert_eq!(provider.calls(), 0);
        assert!(!transcript_store.has_running(input).unwrap());
        assert_eq!(quota_store.puts(), 2);
        assert_eq!(quota_store.entry_count(caller_id), 0);
    }

    #[tokio::test]
    async fn ambiguous_running_marker_write_is_rolled_back_before_quota_cancellation() {
        let signing_key = key();
        let caller_id = hellas_rpc::ProducerId::from_public_key(&signing_key.public_key());
        let provider = ReleasableFetchProvider::default();
        let transcript_store = MemoryFetchTranscriptStore::default();
        transcript_store.fail_next_running_put_after_write();
        let quota_store = MemoryFetchQuotaStore::default();
        let handle = spawn_quota_fetch_executor_with_store(
            Arc::new(provider.clone()),
            Arc::new(FixedViewFetchAdaptorFactory {
                view: quota_request_view(),
            }),
            FetchTranscriptStoreBackend::Memory(transcript_store.clone()),
            FetchQuotaStoreBackend::Memory(quota_store.clone()),
        )
        .await;
        let (request, input) = fetch_request_and_commitment(
            &signing_key,
            "echo",
            "run",
            br#"{"request":"ambiguous-marker"}"#,
        );
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let error = handle
            .run_ticket_handle(run_ticket_request(ticket, &signing_key))
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("running-marker post-write failure")
        );
        assert_eq!(provider.calls(), 0);
        assert!(!transcript_store.has_running(input).unwrap());
        assert_eq!(transcript_store.running_removals(), 1);
        assert_eq!(quota_store.puts(), 2);
        assert_eq!(quota_store.entry_count(caller_id), 0);
    }

    #[tokio::test]
    async fn quota_reconciliation_is_a_barrier_before_successful_transcript_publication() {
        let signing_key = key();
        let body = br#"{"request":"accounting-barrier"}"#;
        let provider = MockFetchProvider::new(test_environment());
        provider.insert("echo", "run", body, [b"terminal:done".to_vec()]);
        let transcript_store = MemoryFetchTranscriptStore::default();
        let quota_store = MemoryFetchQuotaStore::default();
        // Admission and activation are puts 1 and 2. Reconciliation is put 3.
        quota_store.fail_put_number(3);
        let handle = spawn_quota_fetch_executor_with_store(
            Arc::new(provider.clone()),
            Arc::new(FixedViewFetchAdaptorFactory {
                view: quota_request_view(),
            }),
            FetchTranscriptStoreBackend::Memory(transcript_store.clone()),
            FetchQuotaStoreBackend::Memory(quota_store.clone()),
        )
        .await;
        let (request, input) = fetch_request_and_commitment(&signing_key, "echo", "run", body);
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let failure = run_failed(&handle, ticket, &signing_key).await;

        assert!(failure.error.contains("quota reconciliation failed"));
        assert_eq!(provider.calls("echo", "run", body), 1);
        assert!(!transcript_store.has_completed(input).unwrap());
        assert!(transcript_store.has_running(input).unwrap());
        assert_eq!(quota_store.puts(), 4);
    }

    #[tokio::test]
    async fn startup_settles_orphaned_dispatched_quota_for_one_fresh_window() {
        let signing_key = key();
        let quota_store = MemoryFetchQuotaStore::default();
        let mut caller = CallerAccess::allow_all(signing_key.public_key());
        caller.spend = Some(SpendLimit {
            max_units: 100,
            window: Duration::from_secs(60),
        });
        let mut previous = FetchAccessPolicy::with_quota_store(
            [caller],
            FetchQuotaStoreBackend::Memory(quota_store.clone()),
        );
        let admission = previous
            .authorize_admission(
                &signing_key.public_key(),
                &quota_request_view(),
                1_000,
                "previous-process".to_string(),
                InputCommitment::from_digest(Digest::from_bytes([4; 32])),
                &FetchRoutePolicy::default(),
            )
            .unwrap();
        previous
            .activate_reservation(admission.reservation.as_ref())
            .unwrap();
        drop(previous);

        let provider = ReleasableFetchProvider::default();
        let handle = spawn_quota_fetch_executor_with_store(
            Arc::new(provider.clone()),
            Arc::new(FixedViewFetchAdaptorFactory {
                view: quota_request_view(),
            }),
            FetchTranscriptStoreBackend::memory(),
            FetchQuotaStoreBackend::Memory(quota_store),
        )
        .await;
        let request = fetch_request(
            &signing_key,
            "echo",
            "run",
            br#"{"request":"fresh-process"}"#,
        );
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let error = handle
            .run_ticket_handle(run_ticket_request(ticket, &signing_key))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            ExecutorError::QuotaExceeded {
                retry_after_ms: Some(_),
                ..
            }
        ));
        assert_eq!(provider.calls(), 0);
    }

    #[tokio::test]
    async fn ambiguous_activation_write_never_calls_provider_and_cleans_running_marker() {
        let signing_key = key();
        let caller_id = hellas_rpc::ProducerId::from_public_key(&signing_key.public_key());
        let provider = ReleasableFetchProvider::default();
        let transcript_store = MemoryFetchTranscriptStore::default();
        let quota_store = MemoryFetchQuotaStore::default();
        // Admission is put 1. Put 2 persists Dispatched, then simulates losing
        // its acknowledgement. Cleanup must therefore accept Dispatched.
        quota_store.fail_put_after_write_number(2);
        let handle = spawn_quota_fetch_executor_with_store(
            Arc::new(provider.clone()),
            Arc::new(FixedViewFetchAdaptorFactory {
                view: quota_request_view(),
            }),
            FetchTranscriptStoreBackend::Memory(transcript_store.clone()),
            FetchQuotaStoreBackend::Memory(quota_store.clone()),
        )
        .await;
        let (request, input) = fetch_request_and_commitment(
            &signing_key,
            "echo",
            "run",
            br#"{"request":"ambiguous-activation"}"#,
        );
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let error = handle
            .run_ticket_handle(run_ticket_request(ticket, &signing_key))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("post-write failure 2"));
        assert_eq!(provider.calls(), 0);
        assert!(!transcript_store.has_running(input).unwrap());
        assert_eq!(transcript_store.running_removals(), 1);
        assert_eq!(quota_store.puts(), 4);
        assert_eq!(quota_store.entry_count(caller_id), 0);
    }

    #[tokio::test]
    async fn failed_activation_cleanup_retries_without_retouching_fetch_state() {
        let signing_key = key();
        let provider = ReleasableFetchProvider::default();
        let transcript_store = MemoryFetchTranscriptStore::default();
        let quota_store = MemoryFetchQuotaStore::default();
        quota_store.fail_put_after_write_number(2);
        // Cancelling intent is put 3. Marker rollback succeeds, but the paired
        // ledger removal (put 4)
        // fails. The retained retry must remember that state is already clean.
        quota_store.fail_put_number(4);
        let handle = spawn_quota_fetch_executor_with_store(
            Arc::new(provider.clone()),
            Arc::new(FixedViewFetchAdaptorFactory {
                view: quota_request_view(),
            }),
            FetchTranscriptStoreBackend::Memory(transcript_store.clone()),
            FetchQuotaStoreBackend::Memory(quota_store.clone()),
        )
        .await;
        let (first, first_input) = fetch_request_and_commitment(
            &signing_key,
            "echo",
            "run",
            br#"{"request":"cleanup-retry"}"#,
        );
        let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;

        let first_error = handle
            .run_ticket_handle(run_ticket_request(first_ticket, &signing_key))
            .await
            .unwrap_err();
        assert!(first_error.to_string().contains("post-write failure 2"));
        assert_eq!(provider.calls(), 0);
        assert!(!transcript_store.has_running(first_input).unwrap());
        assert_eq!(transcript_store.running_removals(), 1);
        assert_eq!(quota_store.puts(), 4);

        // A later admission rewrites Cancelling at put 5 and releases it at
        // put 6. Its own reserve/activation are puts 7 and 8; success proves the old
        // Dispatched entry was retired instead of silently leaked.
        let second = fetch_request(
            &signing_key,
            "echo",
            "run",
            br#"{"request":"after-cleanup-retry"}"#,
        );
        let second_ticket = handle.create_fetch_ticket(second).await.unwrap().response;
        let second_outcome = handle
            .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
            .await
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while provider.calls() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(provider.calls(), 1);
        assert_eq!(quota_store.puts(), 8);
        assert_eq!(
            transcript_store.running_removals(),
            1,
            "quota retry must not repeat an already-successful state rollback"
        );

        provider.release();
        timeout(Duration::from_secs(2), drain_outcome(second_outcome.events))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fetch_execution_drops_upstream_immediately_after_terminal() {
        let provider = TerminalThenPanicFetchProvider::default();
        let input_commitment = InputCommitment::from_digest(Digest::from_bytes([5; 32]));
        let call = crate::FetchCall::new(
            "echo",
            "run",
            hellas_rpc::JsonBytes::new(br#"{"hello":"world"}"#.to_vec()),
            input_commitment,
        );
        let request = PreparedFetchRequest::new(&call, call.body.clone());
        let (sender, _receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
        let signing_key = key();

        let result = run_fetch_provider(
            Arc::new(provider.clone()),
            request,
            Box::new(TestFetchProjector {
                terminal_seen: false,
            }),
            input_commitment,
            test_assurance(),
            &signing_key,
            sender,
        )
        .await;
        let Ok(run) = result else {
            panic!("terminal-only Fetch provider unexpectedly failed");
        };

        assert_eq!(provider.polls(), 1);
        assert_eq!(run.output_events.len(), 1);
    }

    #[tokio::test]
    async fn fetch_projection_rejects_event_buffered_after_terminal() {
        let signing_key = key();
        let input_commitment = InputCommitment::from_digest(Digest::from_bytes([6; 32]));
        let mut builder =
            FetchOutputTranscriptBuilder::new(input_commitment, test_assurance(), &signing_key);
        let mut terminal = None;
        let mut projection_budget = FetchProjectionBudget::default();
        let mut position = 0;
        let (sender, _receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);

        let result = process_projected_fetch(
            vec![
                ProjectedFetch::Terminal(vec![1]),
                ProjectedFetch::Event(vec![2]),
            ],
            &mut builder,
            &mut terminal,
            &mut projection_budget,
            &mut position,
            &sender,
        )
        .await;
        let Err(error) = result else {
            panic!("event buffered after terminal unexpectedly passed projection");
        };

        assert!(error.error.to_string().contains("event after terminal"));
        assert_eq!(projection_budget.events, 1);
    }

    #[tokio::test]
    async fn fetch_projection_preserves_one_permit_for_failure_terminal() {
        let signing_key = key();
        let input_commitment = InputCommitment::from_digest(Digest::from_bytes([8; 32]));
        let mut builder =
            FetchOutputTranscriptBuilder::new(input_commitment, test_assurance(), &signing_key);
        let mut terminal = None;
        let mut projection_budget = FetchProjectionBudget::default();
        let mut position = 0;
        let (sender, mut receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
        for _ in 0..PER_EXECUTION_CHANNEL_CAPACITY - 1 {
            sender
                .try_send(Ok(WorkEvent {
                    kind: Some(work_event::Kind::Chunk(WorkChunk { output_event: None })),
                }))
                .unwrap();
        }
        assert_eq!(sender.capacity(), 1);

        let error = process_projected_fetch(
            vec![ProjectedFetch::Event(b"never-signed".to_vec())],
            &mut builder,
            &mut terminal,
            &mut projection_budget,
            &mut position,
            &sender,
        )
        .await
        .unwrap_err();

        assert!(error.error.to_string().contains("did not drain"));
        assert_eq!(position, 0);
        assert_eq!(projection_budget.events, 0);
        assert_eq!(projection_budget.signed_payload_bytes, 0);
        send_fetch_failed(&sender, position, error.error.to_string());
        assert_eq!(sender.capacity(), 0);
        for _ in 0..PER_EXECUTION_CHANNEL_CAPACITY - 1 {
            assert!(matches!(
                receiver.recv().await.unwrap().unwrap().kind,
                Some(work_event::Kind::Chunk(_))
            ));
        }
        assert!(matches!(
            receiver.recv().await.unwrap().unwrap().kind,
            Some(work_event::Kind::Failed(WorkFailed { position: 0, .. }))
        ));
    }

    #[tokio::test]
    async fn retained_replay_waits_for_a_consumer_without_losing_events() {
        let signing_key = key();
        let input_commitment = InputCommitment::from_digest(Digest::from_bytes([10; 32]));
        let mut builder =
            FetchOutputTranscriptBuilder::new(input_commitment, test_assurance(), &signing_key);
        for _ in 0..PER_EXECUTION_CHANNEL_CAPACITY {
            builder.push_event(vec![1]).unwrap();
        }
        let terminal = hellas_rpc::fetch::encode_fetch_terminal_payload(
            &hellas_rpc::output::OutputEvent::Finished {
                stop_reason: hellas_rpc::output::StopReason::EndOfText,
                usage: None,
            },
        )
        .unwrap();
        let output_events = builder.finish(terminal).unwrap();
        let outcome = fetch_finished_outcome(
            ExecutionProvenance {
                commitment_id: [11; 32],
            },
            &output_events,
        )
        .await
        .unwrap();
        let mut receiver = outcome.events;

        timeout(Duration::from_secs(1), async {
            while receiver.len() < PER_EXECUTION_CHANNEL_CAPACITY {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(receiver.len(), PER_EXECUTION_CHANNEL_CAPACITY);
        for _ in 0..PER_EXECUTION_CHANNEL_CAPACITY {
            assert!(matches!(
                receiver.recv().await.unwrap().unwrap().kind,
                Some(work_event::Kind::Chunk(_))
            ));
        }
        assert!(matches!(
            receiver.recv().await.unwrap().unwrap().kind,
            Some(work_event::Kind::Finished(_))
        ));
        assert!(receiver.recv().await.is_none());
    }

    #[tokio::test]
    async fn retained_replay_larger_than_buffer_succeeds_for_a_draining_consumer() {
        let signing_key = key();
        let input_commitment = InputCommitment::from_digest(Digest::from_bytes([12; 32]));
        let mut builder =
            FetchOutputTranscriptBuilder::new(input_commitment, test_assurance(), &signing_key);
        let event_count = PER_EXECUTION_CHANNEL_CAPACITY * 2;
        for _ in 0..event_count {
            builder.push_event(vec![1]).unwrap();
        }
        let terminal = hellas_rpc::fetch::encode_fetch_terminal_payload(
            &hellas_rpc::output::OutputEvent::Finished {
                stop_reason: hellas_rpc::output::StopReason::EndOfText,
                usage: None,
            },
        )
        .unwrap();
        let output_events = builder.finish(terminal).unwrap();
        let outcome = fetch_finished_outcome(
            ExecutionProvenance {
                commitment_id: [13; 32],
            },
            &output_events,
        )
        .await
        .unwrap();
        let mut receiver = outcome.events;
        let mut chunks = 0;

        timeout(Duration::from_secs(1), async {
            loop {
                match receiver.recv().await.unwrap().unwrap().kind.unwrap() {
                    work_event::Kind::Chunk(_) => chunks += 1,
                    work_event::Kind::Finished(_) => break,
                    work_event::Kind::Failed(failed) => {
                        panic!("draining replay failed: {}", failed.error)
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(chunks, event_count);
    }

    #[test]
    fn fetch_projection_budget_caps_event_count_and_payload_bytes() {
        let mut event_budget = FetchProjectionBudget {
            events: MAX_FETCH_OUTPUT_EVENTS - 2,
            signed_payload_bytes: 0,
        };
        event_budget.record_event(0).unwrap();
        let event_error = event_budget.record_event(0).unwrap_err();
        assert!(event_error.to_string().contains("4095-event limit"));
        assert_eq!(event_budget.events, MAX_FETCH_OUTPUT_EVENTS - 1);
        event_budget.record_terminal(0).unwrap();
        assert_eq!(event_budget.events, MAX_FETCH_OUTPUT_EVENTS);

        let mut payload_budget = FetchProjectionBudget {
            events: 0,
            signed_payload_bytes: MAX_FETCH_OUTPUT_PAYLOAD_BYTES - 1,
        };
        payload_budget.record_event(1).unwrap();
        let payload_error = payload_budget.record_event(1).unwrap_err();
        assert!(
            payload_error
                .to_string()
                .contains("2097152-byte signed payload limit")
        );
        assert_eq!(
            payload_budget.signed_payload_bytes,
            MAX_FETCH_OUTPUT_PAYLOAD_BYTES
        );
    }

    #[tokio::test]
    async fn projected_payload_limit_is_reported_as_work_failed() {
        let signing_key = key();
        let input = br#"{"hello":"large"}"#;
        let provider = MockFetchProvider::new(test_environment());
        provider.insert(
            "echo",
            "run",
            input,
            [
                vec![b'x'; MAX_FETCH_OUTPUT_PAYLOAD_BYTES + 1],
                b"terminal:done".to_vec(),
            ],
        );
        let request = fetch_request(&signing_key, "echo", "run", input);
        let handle = Executor::spawn_with_fetch_routes(
            ExecutePolicy::Any,
            1,
            key(),
            test_genesis(),
            test_assurance(),
            test_routes(
                "echo",
                "run",
                Arc::new(provider),
                Arc::new(TestFetchAdaptorFactory),
            ),
        )
        .unwrap();
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let failed = run_failed(&handle, ticket, &signing_key).await;

        assert_eq!(failed.position, 0);
        assert!(failed.error.contains("2097152-byte signed payload limit"));
    }

    #[tokio::test]
    async fn fetch_quote_missing_route_does_not_poison_ticket_state() {
        let signing_key = key();
        let provider = MockFetchProvider::new(test_environment());
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_ticket_with_recovered_running_marker_reports_indeterminate() {
        use crate::fetch::{FetchRunningRecord, FetchTranscriptStore, FsFetchTranscriptStore};

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/hellas-fetch-actor-indeterminate")
            .join(uuid::Uuid::new_v4().simple().to_string());
        let signing_key = key();
        let events = build_input_events(
            "echo",
            "run",
            br#"{"hello":"crash"}"#,
            test_environment(),
            test_assurance(),
            &signing_key,
        )
        .unwrap();
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
            execute_policy: ExecutePolicy::Any,
            queue_capacity: 1,
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key: Arc::new(key()),
            provider_genesis: Arc::new(test_genesis()),
            assurance: test_assurance(),
            fetch_access_policy: FetchAccessPolicy::trusted_callers([signing_key.public_key()]),
            fetch_routes: test_routes(
                "echo",
                "run",
                Arc::new(MockFetchProvider::new(test_environment())),
                Arc::new(TestFetchAdaptorFactory),
            ),
            fetch_max_in_flight: 1,
            fetch_queue_capacity: 1,
            fetch_replay_max_in_flight: hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
            fetch_store: FetchTranscriptStoreBackend::fs(dir.join("fetch-transcripts")),
            #[cfg(feature = "evaluate")]
            artifact_store: ArtifactStoreConfig::memory(),
            #[cfg(feature = "evaluate")]
            content_store: ContentStore::new(),
            #[cfg(feature = "evaluate")]
            gpu_config: GpuConfig::default(),
        })
        .await
        .unwrap();

        let ticket = crate::state::quote_ticket(
            hellas_rpc::RequestCommitment::from_digest(input.digest()),
            &test_genesis(),
            test_assurance(),
        )
        .unwrap()
        .1;
        let err = handle
            .run_ticket_handle(run_ticket_request(ticket, &signing_key))
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
        let projector = FixedViewFetchAdaptorFactory {
            view: FetchRequestView {
                service: "codex".to_string(),
                method: "responses".to_string(),
                model: Some("denied-model".to_string()),
                max_output_units: Some(4),
            },
        };
        let handle = Executor::spawn_configured(ExecutorSpawnConfig {
            execute_policy: ExecutePolicy::Any,
            queue_capacity: 1,
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key: Arc::new(key()),
            provider_genesis: Arc::new(test_genesis()),
            assurance: test_assurance(),
            fetch_access_policy: policy,
            fetch_routes: test_routes(
                "codex",
                "responses",
                Arc::new(provider.clone()),
                Arc::new(projector),
            ),
            fetch_max_in_flight: 1,
            fetch_queue_capacity: 1,
            fetch_replay_max_in_flight: hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
            fetch_store: FetchTranscriptStoreBackend::memory(),
            #[cfg(feature = "evaluate")]
            artifact_store: ArtifactStoreConfig::memory(),
            #[cfg(feature = "evaluate")]
            content_store: ContentStore::new(),
            #[cfg(feature = "evaluate")]
            gpu_config: GpuConfig::default(),
        })
        .await
        .unwrap();
        let request = fetch_request(&signing_key, "codex", "responses", br#"{"model":"x"}"#);
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let err = handle
            .run_ticket_handle(run_ticket_request(ticket, &signing_key))
            .await
            .unwrap_err();

        assert!(matches!(err, ExecutorError::PolicyDenied(_)));
        assert_eq!(provider.calls(), 0);
    }

    #[tokio::test]
    async fn retained_capacity_refusal_never_starts_provider() {
        let signing_key = key();
        let provider = ReleasableFetchProvider::default();
        let handle = spawn_fetch_executor_with_bounds(
            Arc::new(provider.clone()),
            1,
            1,
            1,
            FetchTranscriptStoreBackend::memory_with_capacity(0),
        )
        .await;
        let request = fetch_request(&signing_key, "echo", "run", br#"{"n":1}"#);
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let error = handle
            .run_ticket_handle(run_ticket_request(ticket, &signing_key))
            .await
            .unwrap_err();

        assert!(matches!(&error, ExecutorError::ResourceExhausted(_)));
        assert!(
            error
                .to_string()
                .contains("retained Fetch transcript capacity of 0 is exhausted")
        );
        assert_eq!(provider.calls(), 0);
    }

    #[tokio::test]
    async fn queued_retained_capacity_refusal_fails_and_discards_ticket() {
        let signing_key = key();
        let provider = ReleasableFetchProvider::default();
        let handle = spawn_fetch_executor_with_bounds(
            Arc::new(provider.clone()),
            1,
            1,
            1,
            FetchTranscriptStoreBackend::memory_with_capacity(1),
        )
        .await;
        let first = fetch_request(&signing_key, "echo", "run", br#"{"n":1}"#);
        let second = fetch_request(&signing_key, "echo", "run", br#"{"n":2}"#);
        let first_ticket = handle.create_fetch_ticket(first).await.unwrap().response;
        let second_ticket = handle
            .create_fetch_ticket(second.clone())
            .await
            .unwrap()
            .response;
        let first_outcome = handle
            .run_ticket_handle(run_ticket_request(first_ticket, &signing_key))
            .await
            .unwrap();
        let second_outcome = handle
            .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
            .await
            .unwrap();

        provider.release();
        timeout(Duration::from_secs(2), drain_outcome(first_outcome.events))
            .await
            .unwrap();
        let failed = timeout(Duration::from_secs(2), async move {
            let mut events = second_outcome.events;
            loop {
                let event = events.recv().await.unwrap().unwrap();
                if let Some(work_event::Kind::Failed(failed)) = event.kind {
                    break failed;
                }
            }
        })
        .await
        .unwrap();

        assert!(
            failed
                .error
                .contains("retained Fetch transcript capacity of 1 is exhausted")
        );
        assert_eq!(provider.calls(), 1);
        // Dispatch refusal removed the dead Queued entry: the same signed
        // request can be quoted again, then fails synchronously at admission
        // rather than getting stuck as AlreadyQueued.
        let retried_ticket = handle.create_fetch_ticket(second).await.unwrap().response;
        let retried = handle
            .run_ticket_handle(run_ticket_request(retried_ticket, &signing_key))
            .await
            .unwrap_err();
        assert!(matches!(retried, ExecutorError::ResourceExhausted(_)));
        assert_eq!(provider.calls(), 1);
    }

    #[tokio::test]
    async fn replay_slot_lives_until_terminal_is_drained_or_receiver_is_dropped() {
        let signing_key = key();
        let input = br#"{"replay":"bounded"}"#;
        let provider = MockFetchProvider::new(test_environment());
        provider.insert("echo", "run", input, [b"terminal:done".to_vec()]);
        let transcript_store = MemoryFetchTranscriptStore::default();
        let handle = spawn_fetch_executor_with_bounds(
            Arc::new(provider.clone()),
            1,
            1,
            1,
            FetchTranscriptStoreBackend::Memory(transcript_store.clone()),
        )
        .await;
        let ticket = handle
            .create_fetch_ticket(fetch_request(&signing_key, "echo", "run", input))
            .await
            .unwrap()
            .response;
        run_one(&handle, ticket.clone(), &signing_key).await;

        let unauthorized_key =
            ProducerSigningKey::from_secret_bytes([8; 32]).expect("valid test key");
        let completed_loads = transcript_store.completed_loads();
        let replay_verifications = transcript_store.replay_verifications();
        let unauthorized = handle
            .run_ticket_handle(run_ticket_request(ticket.clone(), &unauthorized_key))
            .await
            .unwrap_err();
        assert!(
            matches!(unauthorized, ExecutorError::PolicyDenied(_)),
            "{unauthorized:?}"
        );
        assert_eq!(transcript_store.completed_loads(), completed_loads + 1);
        assert_eq!(
            transcript_store.replay_verifications(),
            replay_verifications,
            "a mismatched untrusted caller claim must reject before signature work"
        );

        let replay = handle
            .run_ticket_handle(run_ticket_request(ticket.clone(), &signing_key))
            .await
            .unwrap();
        assert_eq!(
            transcript_store.replay_verifications(),
            replay_verifications + 1,
            "a matching claim still requires complete transcript verification"
        );
        timeout(Duration::from_secs(1), async {
            while replay.events.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let completed_loads = transcript_store.completed_loads();
        let replay_verifications = transcript_store.replay_verifications();
        let refused = handle
            .run_ticket_handle(run_ticket_request(ticket.clone(), &signing_key))
            .await
            .unwrap_err();
        assert!(matches!(refused, ExecutorError::ResourceExhausted(_)));
        assert_eq!(transcript_store.completed_loads(), completed_loads);
        assert_eq!(
            transcript_store.replay_verifications(),
            replay_verifications
        );

        // Draining the already-buffered terminal releases the first slot.
        drain_outcome(replay.events).await;
        let drained_retry = timeout(Duration::from_secs(1), async {
            loop {
                match handle
                    .run_ticket_handle(run_ticket_request(ticket.clone(), &signing_key))
                    .await
                {
                    Ok(outcome) => break outcome,
                    Err(ExecutorError::ResourceExhausted(_)) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected replay error: {error}"),
                }
            }
        })
        .await
        .unwrap();
        drain_outcome(drained_retry.events).await;

        // Dropping an undrained receiver is the other release path.
        let dropped = timeout(Duration::from_secs(1), async {
            loop {
                match handle
                    .run_ticket_handle(run_ticket_request(ticket.clone(), &signing_key))
                    .await
                {
                    Ok(outcome) => break outcome,
                    Err(ExecutorError::ResourceExhausted(_)) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected replay error: {error}"),
                }
            }
        })
        .await
        .unwrap();
        drop(dropped.events);
        let after_drop = timeout(Duration::from_secs(1), async {
            loop {
                match handle
                    .run_ticket_handle(run_ticket_request(ticket.clone(), &signing_key))
                    .await
                {
                    Ok(outcome) => break outcome,
                    Err(ExecutorError::ResourceExhausted(_)) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected replay error: {error}"),
                }
            }
        })
        .await
        .unwrap();
        drain_outcome(after_drop.events).await;
        assert_eq!(provider.calls("echo", "run", input), 1);
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
            .run_ticket_handle(run_ticket_request(first_ticket, &signing_key))
            .await
            .unwrap();
        let error = handle
            .run_ticket_handle(run_ticket_request(second_ticket.clone(), &signing_key))
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutorError::QueueFull { capacity: 0 }));

        provider.release();
        let (_, first_finished) =
            timeout(Duration::from_secs(2), drain_outcome(first_outcome.events))
                .await
                .unwrap();
        assert!(first_finished.terminal_output_event.is_some());

        let (chunks, second_finished) = timeout(
            Duration::from_secs(2),
            run_one(&handle, second_ticket, &signing_key),
        )
        .await
        .unwrap();
        assert_eq!(chunks.len(), 1);
        assert!(second_finished.terminal_output_event.is_some());
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
            .run_ticket_handle(run_ticket_request(first_ticket, &signing_key))
            .await
            .unwrap();
        let second_outcome = handle
            .run_ticket_handle(run_ticket_request(second_ticket, &signing_key))
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

        assert!(first_finished.terminal_output_event.is_some());
        assert_eq!(second_chunks.len(), 1);
        assert!(second_finished.terminal_output_event.is_some());
        assert_eq!(provider.calls(), 2);
    }
}
