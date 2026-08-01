use crate::ExecutorError;
use crate::StateError;
use crate::chain::{acceptance_from_pb, receipt_response, voucher_from_pb};
use crate::executor::{
    ExecuteOutcome, ExecutorMessage, FetchCompletion, FetchProviderFailure, FetchProviderRun,
    PendingFetch,
};
use crate::fetch::{FetchStateError, FetchTranscript};
use crate::fetch_policy::{FetchAccessError, FetchRoute};
use crate::fetch_projection::{FetchProjector, ProjectedFetch};
use crate::fetch_provider::{FetchProvider, FetchProviderError, FetchProviderRequest};
use crate::state::{QuoteKind, new_execution_id, validate_job_terms};
use futures_util::StreamExt;
use hellas_kernel::SigVerifier as _;
use hellas_rpc::fetch::{FetchOutputTranscriptBuilder, decode_fetch_terminal_payload};
use hellas_rpc::pb::execute::{ReceiptRequest, ReceiptResponse, SettleRequest, SettleResponse};
use hellas_rpc::pb::execute::{
    RunTicketRequest, WorkChunk, WorkEvent, WorkFailed, WorkFinished, work_event,
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
    /// The staked job-admission gate.
    ///
    /// A staked provider requires every execution to carry a
    /// client-signed [`hellas_chain::staked::JobAcceptanceContext`]
    /// that names its bond, commits to exactly this ticket's request
    /// and price, verifies under the channel's client key, and passes
    /// [`hellas_chain::staked::Channel::admit`] at the latest finalized
    /// height — which also serializes jobs through resolution. An
    /// unstaked provider refuses acceptances outright rather than
    /// silently dropping a commitment it will never honor.
    async fn admit_staked_job(
        &mut self,
        request: &RunTicketRequest,
        verified_run: &VerifiedRunTicket,
    ) -> Result<(), ExecutorError> {
        let refuse = |message: String| Err(ExecutorError::InvalidQuoteRequest(message));
        let Some(staked) = self.staked.as_mut() else {
            if request.acceptance.is_some() {
                return refuse("provider does not run the staked flow".into());
            }
            return Ok(());
        };
        let Some(acceptance) = request.acceptance.as_ref() else {
            return refuse("staked provider requires a job acceptance".into());
        };
        let (context, client_signature) =
            acceptance_from_pb(acceptance).map_err(ExecutorError::InvalidQuoteRequest)?;
        if context.request != *verified_run.terms.request.as_bytes() {
            return refuse("acceptance does not commit to this request".into());
        }
        if context.environment != *verified_run.terms.provider_genesis.as_bytes() {
            return refuse("acceptance does not commit to this environment".into());
        }
        if context.price != verified_run.terms.amount {
            return refuse("acceptance price does not match the ticket terms".into());
        }
        let digest = context.digest();
        let verifier = hellas_kernel::Secp256k1Verifier::new();
        if !verifier.verify_sig(client_signature, staked.channel.client(), digest) {
            return refuse("acceptance client signature does not verify".into());
        }
        let height = staked
            .chain
            .finalized_height()
            .await
            .map_err(|err| ExecutorError::InvalidQuoteRequest(format!("chain view: {err}")))?;
        let Some(now) = height else {
            return refuse("no finalized block observed yet".into());
        };
        // A job the client abandoned past its committed deadline must
        // not hold the lock against the next one.
        self.release_abandoned_job(now).await;
        // Opportunistic redemption. `settle` succeeds only while
        // `now + close_margin < payment_timeout` and redemption is due
        // only at `>=`, so the two are exactly complementary — checking
        // at the settle site could never fire. The executor has no
        // height subscription, so an admission attempt is the one
        // height observation that can be late enough to matter. A
        // provider that goes idle past the margin will not bank until
        // something pokes it; a periodic watcher is the proper fix and
        // is not built yet.
        self.bank_frontier_if_due(now).await;
        let staked = self.staked.as_mut().expect("staked provider still present");
        staked.channel.admit(now, context).map_err(|reason| {
            ExecutorError::InvalidQuoteRequest(format!("job not admitted: {reason:?}"))
        })
    }

    /// Staked-flow receipt: signs the in-flight job's acceptance digest
    /// and a result context binding it to the provider's own recorded
    /// terminal transcript. Idempotent — the job stays in flight until
    /// settlement, so a lost response is simply re-requested.
    pub(super) async fn handle_receipt(
        &mut self,
        request: &ReceiptRequest,
    ) -> Result<ReceiptResponse, ExecutorError> {
        let refuse = |message: &str| ExecutorError::InvalidQuoteRequest(message.to_string());
        let Some(staked) = self.staked.as_ref() else {
            return Err(refuse("provider does not run the staked flow"));
        };
        let Some(active) = staked.channel.active().copied() else {
            return Err(refuse("no job awaiting a receipt"));
        };
        let digest = active.digest();
        if request.acceptance_digest.as_slice() != digest.as_bytes().as_slice() {
            return Err(refuse("receipt names a job other than the in-flight one"));
        }
        // Caller authentication. Without it, anyone who observed the
        // acceptance — a gateway proxying the run ticket, or any peer
        // that can reach the Execute ALPN — could harvest the
        // provider's fraud-evidence signatures.
        let signature = crate::chain::sig_from_pb("receipt client_signature", {
            request.client_signature.as_ref()
        })
        .map_err(ExecutorError::InvalidQuoteRequest)?;
        // Verified over a DOMAIN-SEPARATED receipt digest, not the
        // acceptance digest: the client's signature over the latter
        // already travels on the wire in the run ticket, so accepting
        // it here would authenticate any party that saw the ticket.
        if !hellas_kernel::Secp256k1Verifier::new().verify_sig(
            signature,
            staked.channel.client(),
            hellas_chain::staked::receipt_request_digest(digest),
        ) {
            return Err(refuse("receipt is not authorized by the channel's client"));
        }
        let transcript = self.terminal_commitment(active.request).await?;
        let signer = crate::kernel_signer(&self.provider.producer_key);
        Ok(receipt_response(&signer, digest, transcript))
    }

    /// Staked-flow settlement: accepts the client's frontier voucher
    /// for the in-flight job, releasing the serialization lock.
    ///
    /// The provider accepts payment only for work it has *terminally
    /// recorded*: settling before completion would clear the lock while
    /// the job still runs (breaking serialize-through-resolution) and
    /// leave the client paid but unable to obtain a receipt. Beyond
    /// that, `Channel::settle` re-validates the frontier advance, the
    /// canonical outputs, the maker authorization, and — against the
    /// finalized height — that the frontier can still be redeemed before
    /// the payment timeout.
    pub(super) async fn handle_settle(
        &mut self,
        request: &SettleRequest,
    ) -> Result<SettleResponse, ExecutorError> {
        let refuse = |message: String| ExecutorError::InvalidQuoteRequest(message);
        let Some(staked) = self.staked.as_ref() else {
            return Err(refuse("provider does not run the staked flow".into()));
        };
        let voucher = voucher_from_pb(request, &staked.channel)
            .map_err(ExecutorError::InvalidQuoteRequest)?;
        let Some(active_request) = staked.channel.active().map(|job| job.request) else {
            return Err(refuse("no job awaiting settlement".into()));
        };
        // Gate on the same completed-transcript check a receipt requires,
        // so `settled ⇒ the client could have obtained its receipt`.
        self.terminal_commitment(active_request).await?;
        let staked = self.staked.as_ref().expect("staked provider still present");
        let now = staked
            .chain
            .finalized_height()
            .await
            .map_err(|err| refuse(format!("chain view: {err}")))?
            .ok_or_else(|| refuse("no finalized block observed yet".into()))?;
        let staked = self.staked.as_mut().expect("staked provider still present");
        staked.channel.settle(now, voucher).map_err(|reason| {
            ExecutorError::InvalidQuoteRequest(format!("settlement refused: {reason:?}"))
        })?;
        Ok(SettleResponse {})
    }

    /// Staked maintenance for a newly finalized height: release a job
    /// abandoned past its deadline, then bank a frontier that is due.
    ///
    /// Driven by the height feed rather than by incoming requests: an
    /// idle provider is the one with the most to lose, since nothing
    /// else would ever wake it before the payment timeout.
    pub(super) async fn handle_staked_height(&mut self, height: hellas_kernel::BlockHeight) {
        if self.staked.is_none() {
            return;
        }
        self.release_abandoned_job(height).await;
        self.bank_frontier_if_due(height).await;
    }

    /// Submits the latest frontier as an on-chain `Mutual` close once
    /// the channel can no longer admit any job.
    ///
    /// Holding a voucher past that point is pure downside: the channel
    /// has no remaining useful life, and the client's timeout close
    /// refunds the FULL capacity — including everything the provider
    /// earned — so a provider that sits on its frontier can lose it to
    /// the refund. The trigger is derived from the committed margin
    /// (`Channel::redemption_due`), not a chosen constant.
    ///
    /// Best effort by design: this is the provider banking its own
    /// earnings, so a submission failure must not fail the client's
    /// settlement. It is logged and retried on the next due check.
    async fn bank_frontier_if_due(&mut self, now: hellas_kernel::BlockHeight) {
        let Some(staked) = self.staked.as_ref() else {
            return;
        };
        if !staked.channel.redemption_due(now) {
            return;
        }
        let signer = crate::kernel_signer(&self.provider.producer_key);
        let Some(close) = staked.channel.redeem(&signer) else {
            return;
        };
        if let Err(err) = staked
            .chain
            .submit(hellas_chain::domain::Transaction::Kernel(close))
            .await
        {
            warn!(
                chain_error = %err,
                "failed to submit frontier redemption; will retry when next due"
            );
        }
    }

    /// Releases the serialization lock for a job whose committed
    /// terminal deadline has passed without settlement, so one
    /// abandoned job cannot hold the pairing forever.
    ///
    /// Safe to do unilaterally: the deadline is in the acceptance both
    /// parties signed, so the client computes the same release height.
    ///
    /// Guarded on the job having TERMINALLY COMPLETED. A deadline can
    /// pass while the provider's own worker is still running — the
    /// deadline bounds the client's wait, not the execution — and
    /// releasing then would admit a second job while the first is still
    /// in flight, breaking serialize-through-resolution and leaving the
    /// finishing worker to resolve against a channel that has moved on.
    /// The only other way to hold the lock without a completed
    /// transcript is a dispatch or runtime failure, and
    /// `resolve_staked_failure` has already released those.
    async fn release_abandoned_job(&mut self, now: hellas_kernel::BlockHeight) {
        let Some(staked) = self.staked.as_ref() else {
            return;
        };
        let Some(job) = staked.channel.active().copied() else {
            return;
        };
        if now.get() <= job.terminal_deadline.get() {
            return;
        }
        if self.terminal_commitment(job.request).await.is_err() {
            // Still executing: the deadline lapsed but the work has not
            // resolved. Holding the lock is correct here.
            return;
        }
        let Some(staked) = self.staked.as_mut() else {
            return;
        };
        if let Some(released) = staked.channel.abandon(now) {
            warn!(
                sequence = released.sequence,
                deadline = released.terminal_deadline.get(),
                "released a completed job abandoned past its terminal deadline"
            );
        }
    }

    /// The terminal event commitment of the provider's own completed
    /// transcript for `request`, from whichever engine ran it.
    async fn terminal_commitment(&self, request: [u8; 32]) -> Result<[u8; 32], ExecutorError> {
        let refuse = |message: &str| ExecutorError::InvalidQuoteRequest(message.to_string());
        let input = InputCommitment::from_digest(Digest::from_bytes(request));
        let producer = self.provider.producer_key.public_key();
        match self.fetch_state.replay_completed(input, &producer) {
            Ok(transcript) => {
                let Some(terminal) = transcript.output_events().last() else {
                    return Err(refuse("empty fetch transcript"));
                };
                return Ok(*terminal.event_commitment().as_bytes());
            }
            Err(FetchStateError::NotFound | FetchStateError::NotCompleted) => {}
            Err(err) => return Err(fetch_execute_error(err)),
        }
        #[cfg(feature = "evaluate")]
        if let Some(engine) = self.evaluate.as_ref()
            && let Some(outcome) = engine
                .replay_completed(request, &producer, self.provider.assurance)
                .await?
        {
            let mut events = outcome.events;
            while let Some(event) = events.recv().await {
                let event =
                    event.map_err(|status| refuse(&format!("replayed transcript: {status}")))?;
                if let Some(work_event::Kind::Finished(finished)) = event.kind {
                    let Some(terminal) = finished.output_events.last() else {
                        break;
                    };
                    let envelope = hellas_rpc::stream::output_event_from_pb(terminal.clone())
                        .map_err(|err| refuse(&format!("replayed terminal event: {err}")))?;
                    return Ok(*envelope.event_commitment().as_bytes());
                }
            }
        }
        Err(refuse("no completed transcript for the in-flight job"))
    }

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
        if let Some(engine) = self.evaluate.as_ref()
            && let Some(outcome) = engine
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
            QuoteKind::Scheme(job) => {
                let evaluate = job
                    .clone_box()
                    .into_any()
                    .downcast::<crate::evaluate::EvaluateJob>()
                    .map_err(|_| {
                        ExecutorError::InvalidQuoteRequest("scheme job type mismatch".into())
                    })?;
                if evaluate.evaluate_request.assurance != verified_run.terms.assurance {
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
        self.admit_staked_job(&request, &verified_run).await?;
        // Admission consumed the serialization lock. Every dispatch path
        // that does NOT leave a job genuinely in flight must release it,
        // or one failed attempt wedges the pairing in `Busy` until
        // restart. The lock stays held only when this returns `Ok` with a
        // started/queued job; any error releases it below (the sequence
        // stays consumed, so a half-signed acceptance can never be
        // reused). Runtime failures after a successful start release it in
        // `handle_fetch_finished`.
        let dispatched: Result<ExecuteOutcome, ExecutorError> = async {
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
                        assurance: fetch_quote.assurance,
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
        .await;
        if dispatched.is_err() {
            self.resolve_staked_failure(request_commitment_id);
        }
        dispatched
    }

    /// Releases the staked serialization lock for a job that never
    /// reached (or fell out of) an in-flight state, keeping its sequence
    /// consumed. A no-op for unstaked providers or when a different job
    /// is active, so it is safe to call from any failure path.
    fn resolve_staked_failure(&mut self, request: [u8; 32]) {
        if let Some(staked) = self.staked.as_mut()
            && staked
                .channel
                .active()
                .is_some_and(|job| job.request == request)
        {
            staked.channel.rescind();
        }
    }

    async fn replay_fetch_execution(
        &self,
        input_commitment: InputCommitment,
        request_commitment_id: [u8; 32],
        verified_run: &VerifiedRunTicket,
    ) -> Result<Option<ExecuteOutcome>, ExecutorError> {
        let producer_key = self.provider.producer_key.public_key();
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
        if verified_input.assurance != verified_run.terms.assurance {
            return Err(ExecutorError::InvalidQuoteRequest(
                "fetch request assurance does not match ticket terms".into(),
            ));
        }
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
        spawn_fetch_provider(
            self.tx.clone(),
            Arc::clone(&self.provider.producer_key),
            pending,
        );
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
                    .cancel_reservation(quota_reservation.as_ref())
                {
                    warn!(
                        %execution_id,
                        quota_error = %err,
                        "failed to cancel fetch quota after provider failure"
                    );
                }
                let _ = self.fetch_state.fail(input_commitment, error.clone());
                self.metrics.record_execution_failed(&model_id, 0);
                send_fetch_failed(sender, failure.position, error).await;
                self.finish_fetch_slot();
                self.resolve_staked_failure(request_commitment_id);
                return;
            }
        };

        let (event, billable_units) = match fetch_finished_event(&run.output_events) {
            Ok(event) => event,
            Err(err) => {
                let error = err.to_string();
                let _ = self.fetch_state.fail(input_commitment, error.clone());
                let _ = self
                    .fetch_access_policy
                    .cancel_reservation(quota_reservation.as_ref());
                self.metrics.record_execution_failed(&model_id, 0);
                send_fetch_failed(sender, 0, error).await;
                self.finish_fetch_slot();
                self.resolve_staked_failure(request_commitment_id);
                return;
            }
        };
        if let Err(err) = self.fetch_state.complete_output(
            input_commitment,
            run.output_events,
            &self.provider.producer_key.public_key(),
        ) {
            let error = fetch_execute_error(err).to_string();
            let _ = self.fetch_state.fail(input_commitment, error.clone());
            self.metrics.record_execution_failed(&model_id, 0);
            send_fetch_failed(sender, 0, error).await;
            self.finish_fetch_slot();
            self.resolve_staked_failure(request_commitment_id);
            return;
        }
        if let Err(err) = self
            .fetch_access_policy
            .reconcile_reservation(quota_reservation.as_ref(), billable_units)
        {
            warn!(
                %execution_id,
                quota_error = %err,
                "failed to reconcile fetch quota after provider completion"
            );
        }

        self.metrics
            .record_execution_completed(&model_id, billable_units);
        let _ = sender.send(Ok(event)).await;

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
            assurance,
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
            assurance,
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
    assurance: hellas_rpc::Assurance,
    producer_key: &ProducerSigningKey,
    sender: mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
) -> Result<FetchProviderRun, FetchProviderFailure> {
    let mut builder = FetchOutputTranscriptBuilder::new(input_commitment, assurance, producer_key);
    let mut position = 0_u64;
    let mut terminal = None;
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
            &mut terminal,
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
        &mut terminal,
        &mut position,
        &sender,
    )
    .await?;
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
    Ok(FetchProviderRun { output_events })
}

async fn process_projected_fetch(
    projected: Vec<ProjectedFetch>,
    builder: &mut FetchOutputTranscriptBuilder<'_>,
    terminal: &mut Option<Vec<u8>>,
    position: &mut u64,
    sender: &mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
) -> Result<(), FetchProviderFailure> {
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
                if terminal.replace(payload).is_some() {
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
    )
    .await
}

async fn fetch_finished_outcome(
    provenance: ExecutionProvenance,
    output_events: &[OutputEventEnvelope],
) -> Result<ExecuteOutcome, ExecutorError> {
    let (event, _) = fetch_finished_event(output_events)?;
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
) -> Result<(WorkEvent, u64), ExecutorError> {
    let terminal = output_events
        .last()
        .ok_or_else(|| ExecutorError::InvalidQuoteRequest("empty fetch transcript".to_string()))?;
    let billable_units = decode_fetch_terminal_payload(terminal.payload())
        .map_err(|err| ExecutorError::InvalidQuoteRequest(err.to_string()))?
        .billable_units();
    let pb_output_events = output_events.iter().map(output_event_to_pb).collect();
    Ok((
        WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                output_events: pb_output_events,
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
    use crate::ExecutorError;
    use crate::{
        ArtifactStoreConfig, CallerAccess, Executor, ExecutorMetrics, ExecutorSpawnConfig,
        FetchAccessPolicy, FetchProjectionError, FetchProjectionSession, FetchProjector,
        FetchProjectorFactory, FetchProvider, FetchProviderFuture, FetchProviderRequest,
        FetchProviderStream, FetchRequestView, FetchRoute, FetchRouteGrant, FetchRoutePolicy,
        MockFetchProvider, ProjectedFetch,
    };
    use futures_util::stream;
    use hellas_rpc::Dtype;
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
            if bytes.strip_prefix(b"terminal:").is_some() {
                self.terminal_seen = true;
                let event = hellas_rpc::output::OutputEvent::Finished {
                    stop_reason: hellas_rpc::output::StopReason::EndOfText,
                    usage: None,
                };
                let payload = hellas_rpc::fetch::encode_fetch_terminal_payload(&event)
                    .map_err(|error| FetchProjectionError::failed(error.to_string()))?;
                Ok(vec![ProjectedFetch::Terminal(payload)])
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

    fn client_key() -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([8; 32]).expect("valid test key")
    }

    fn fixture_treasury() -> hellas_kernel::Key {
        crate::kernel_signer(
            &ProducerSigningKey::from_secret_bytes([9; 32]).expect("valid test key"),
        )
        .party_key()
    }

    fn fixture_bond_terms() -> hellas_kernel::Terms {
        use hellas_kernel::{
            BlockHeight, List, MAX_EDGE_OUTPUTS, Parties, Payout, StakeBondTerms, Terms,
        };
        let provider = crate::kernel_signer(&key()).party_key();
        let client = crate::kernel_signer(&client_key()).party_key();
        let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
        outputs[0] = Payout::new(provider, 2_000);
        Terms::stake_bond(StakeBondTerms {
            protocol: hellas_chain::staked::STAKE_BOND_PROTOCOL,
            parties: Parties::new(provider, client),
            timeout: BlockHeight::new(200),
            timeout_outputs: List::take(outputs, 1),
            treasury: fixture_treasury(),
            award: 1_500,
            stake: 2_000,
            max_job_price: 1_000,
            max_dispute_cost: 500,
            challenge_margin: 20,
        })
    }

    fn staked_channel_fixture() -> hellas_chain::staked::Channel {
        use hellas_kernel::{BlockHeight, EdgeId};
        let provider = crate::kernel_signer(&key()).party_key();
        let client = crate::kernel_signer(&client_key()).party_key();
        let payment =
            hellas_chain::staked::payment_terms(client, provider, BlockHeight::new(150), 5_000);
        hellas_chain::staked::Channel::new(
            EdgeId::from_bytes([1; 32]),
            fixture_bond_terms(),
            EdgeId::from_bytes([2; 32]),
            payment,
            5,
        )
        .expect("mirrored staked pairing")
    }

    async fn spawn_staked_executor(provider: Arc<dyn FetchProvider>) -> crate::ExecutorHandle {
        let chain = crate::FakeChainView::new();
        chain.set_height(10);
        spawn_staked_executor_with(provider, chain).await
    }

    /// Same, but with a caller-supplied chain view so a test can drive
    /// the observed height.
    async fn spawn_staked_executor_with(
        provider: Arc<dyn FetchProvider>,
        chain: crate::FakeChainView,
    ) -> crate::ExecutorHandle {
        spawn_staked_executor_feeding(provider, chain, crate::FakeHeightFeed::new()).await
    }

    async fn spawn_staked_executor_feeding(
        provider: Arc<dyn FetchProvider>,
        chain: crate::FakeChainView,
        heights: crate::FakeHeightFeed,
    ) -> crate::ExecutorHandle {
        Executor::spawn_configured(ExecutorSpawnConfig {
            execute_policy: ExecutePolicy::Eager,
            queue_capacity: 1,
            supported_dtypes: vec![Dtype::F32],
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key: Arc::new(key()),
            provider_genesis: Arc::new(test_genesis()),
            assurance: test_assurance(),
            fetch_access_policy: FetchAccessPolicy::trusted_callers([client_key().public_key()]),
            fetch_routes: test_routes("echo", "run", provider, Arc::new(TestFetchProjectorFactory)),
            fetch_max_in_flight: 1,
            fetch_queue_capacity: 1,
            artifact_store: ArtifactStoreConfig::Memory,
            staked: Some(crate::StakedProvider {
                channel: staked_channel_fixture(),
                chain: Arc::new(chain),
                heights: Arc::new(heights),
            }),
        })
        .await
        .unwrap()
    }

    /// A receipt request authorized by the channel's committed client.
    fn receipt_request(
        digest: hellas_kernel::PayloadHash,
    ) -> hellas_rpc::pb::execute::ReceiptRequest {
        hellas_rpc::pb::execute::ReceiptRequest {
            acceptance_digest: digest.as_bytes().to_vec(),
            client_signature: Some(crate::chain::sig_to_pb(
                crate::kernel_signer(&client_key())
                    .sign(hellas_chain::staked::receipt_request_digest(digest)),
            )),
        }
    }

    /// The client side of the staked handshake: run the same admission
    /// the provider will run on the caller's channel, sign the
    /// acceptance digest, and attach it.
    fn acceptance_for(
        channel: &mut hellas_chain::staked::Channel,
        ticket: hellas_rpc::pb::execute::Ticket,
        deadline: u64,
    ) -> (RunTicketRequest, hellas_chain::staked::JobAcceptanceContext) {
        let terms = ticket.terms.clone().expect("ticket terms");
        let request_commitment: [u8; 32] = ticket
            .request_commitment
            .clone()
            .try_into()
            .expect("32-byte request commitment");
        let environment: [u8; 32] = terms
            .provider_genesis
            .clone()
            .try_into()
            .expect("32-byte environment");
        let context = channel.job(
            request_commitment,
            environment,
            terms.amount,
            hellas_kernel::BlockHeight::new(deadline),
        );
        channel
            .admit(hellas_kernel::BlockHeight::new(10), context)
            .expect("client admits its own job");
        let signature = crate::kernel_signer(&client_key()).sign(context.digest());
        let mut request = run_ticket_request(ticket, &client_key());
        request.acceptance = Some(crate::acceptance_to_pb(&context, signature));
        (request, context)
    }

    #[tokio::test]
    async fn staked_executor_gates_receipts_and_settles_the_full_job_loop() {
        use hellas_chain::staked::{FraudArtifact, JobResultContext};

        let input = br#"{"hello":"staked"}"#;
        let second_input = br#"{"hello":"again"}"#;
        let provider = MockFetchProvider::new();
        for body in [input.as_slice(), second_input.as_slice()] {
            provider.insert(
                "echo",
                "run",
                body,
                [b"event:ok".to_vec(), b"terminal:done".to_vec()],
            );
        }
        let handle = spawn_staked_executor(Arc::new(provider)).await;
        let mut client_channel = staked_channel_fixture();
        let request = fetch_request(&client_key(), "echo", "run", input);
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        // No acceptance: the staked provider refuses outright.
        let bare = handle
            .run_ticket_handle(run_ticket_request(ticket.clone(), &client_key()))
            .await;
        assert!(matches!(
            bare,
            Err(ExecutorError::InvalidQuoteRequest(ref msg))
                if msg.contains("requires a job acceptance")
        ));

        // A price that does not match the ticket terms: refused before
        // any state changes.
        let (mut wrong_price, _) =
            acceptance_for(&mut staked_channel_fixture(), ticket.clone(), 60);
        wrong_price.acceptance.as_mut().unwrap().price -= 1;
        let refused = handle.run_ticket_handle(wrong_price).await;
        assert!(matches!(
            refused,
            Err(ExecutorError::InvalidQuoteRequest(ref msg))
                if msg.contains("price does not match")
        ));

        // An admissible client-signed acceptance runs to completion.
        let (admitted, first_job) = acceptance_for(&mut client_channel, ticket.clone(), 60);
        let outcome = handle.run_ticket_handle(admitted).await.unwrap();
        let (chunks, _finished) = drain_outcome(outcome.events).await;
        assert_eq!(chunks.len(), 1);

        // v1 serializes jobs through resolution: with the first job
        // unsettled, the next job is refused as Busy — even when it
        // carries the correct next sequence (2), so the refusal is the
        // lock and not a sequence mismatch. The client cannot build a
        // seq-2 acceptance on its own locked channel, so bump a spare
        // channel to sequence 1 (admit + rescind keeps it consumed).
        let request = fetch_request(&client_key(), "echo", "run", second_input);
        let second_ticket = handle.create_fetch_ticket(request).await.unwrap().response;
        let mut bumped = staked_channel_fixture();
        let throwaway = bumped.job([0; 32], [0; 32], 400, hellas_kernel::BlockHeight::new(50));
        bumped
            .admit(hellas_kernel::BlockHeight::new(10), throwaway)
            .unwrap();
        bumped.rescind();
        let (blocked, blocked_job) = acceptance_for(&mut bumped, second_ticket.clone(), 61);
        assert_eq!(
            blocked_job.sequence, 2,
            "the blocked job is the next sequence"
        );
        let busy = handle.run_ticket_handle(blocked).await;
        assert!(matches!(
            busy,
            Err(ExecutorError::InvalidQuoteRequest(ref msg)) if msg.contains("Busy")
        ));

        // The receipt completes a fraud artifact that binds to the
        // fixture bond under the kernel's pinned slash payouts.
        let digest = first_job.digest();
        let receipt = handle
            .receipt_handle(receipt_request(digest))
            .await
            .unwrap();
        let transcript: [u8; 32] = receipt.transcript.clone().try_into().unwrap();
        let artifact = FraudArtifact {
            acceptance: first_job,
            client_acceptance_sig: crate::kernel_signer(&client_key()).sign(digest),
            provider_acceptance_sig: crate::chain::sig_from_pb(
                "receipt acceptance sig",
                receipt.provider_acceptance_signature.as_ref(),
            )
            .unwrap(),
            result: JobResultContext {
                acceptance: digest,
                transcript,
            },
            provider_result_sig: crate::chain::sig_from_pb(
                "receipt result sig",
                receipt.provider_result_signature.as_ref(),
            )
            .unwrap(),
        };
        let bond = fixture_bond_terms();
        let mut slots = [hellas_kernel::Payout::default(); hellas_kernel::MAX_EDGE_OUTPUTS];
        slots[0] =
            hellas_kernel::Payout::new(crate::kernel_signer(&client_key()).party_key(), 1_500);
        slots[1] = hellas_kernel::Payout::new(fixture_treasury(), 500);
        let payouts = hellas_kernel::List::take(slots, 2);
        assert!(artifact.binds(&hellas_kernel::SealPublicInputs {
            edge_id: hellas_kernel::EdgeId::from_bytes([1; 32]),
            terms: &bond,
            payouts: &payouts,
        }));

        // Settlement with the client's frontier voucher releases the
        // serialization lock...
        let voucher = client_channel
            .issue(&crate::kernel_signer(&client_key()))
            .unwrap();
        let hellas_kernel::Auth::Native(authorization) = voucher.client_auth else {
            panic!("issued vouchers carry native maker authorization");
        };
        handle
            .settle_handle(hellas_rpc::pb::execute::SettleRequest {
                payment_edge: voucher.payment_edge.as_bytes().to_vec(),
                payment_terms: voucher.terms_hash.as_bytes().to_vec(),
                cumulative: voucher.cumulative,
                client_authorization: Some(crate::chain::sig_to_pb(authorization)),
            })
            .await
            .unwrap();

        // ...and the next job admits and runs.
        let (next, _) = acceptance_for(&mut client_channel, second_ticket, 61);
        let outcome = handle.run_ticket_handle(next).await.unwrap();
        let (chunks, _finished) = drain_outcome(outcome.events).await;
        assert_eq!(chunks.len(), 1);
    }

    /// The acceptance must commit to *this* ticket and be signed by the
    /// channel's committed client. Without these, a staked provider
    /// would run work bound to a different request, a different
    /// execution environment, or authorized by a stranger.
    ///
    /// Each binding previously had no negative test, so all four checks
    /// in `admit_staked_job` could have been deleted with the suite
    /// still green.
    #[tokio::test]
    async fn staked_admission_refuses_unbound_or_unauthorized_acceptances() {
        let input = br#"{"hello":"bindings"}"#;
        let provider = MockFetchProvider::new();
        provider.insert(
            "echo",
            "run",
            input,
            [b"event:ok".to_vec(), b"terminal:done".to_vec()],
        );
        let handle = spawn_staked_executor(Arc::new(provider)).await;
        let ticket = handle
            .create_fetch_ticket(fetch_request(&client_key(), "echo", "run", input))
            .await
            .unwrap()
            .response;

        // Bound to a different request commitment.
        let (mut wrong_request, _) =
            acceptance_for(&mut staked_channel_fixture(), ticket.clone(), 60);
        wrong_request.acceptance.as_mut().unwrap().request = vec![0xab; 32];
        assert!(matches!(
            handle.run_ticket_handle(wrong_request).await,
            Err(ExecutorError::InvalidQuoteRequest(ref msg))
                if msg.contains("does not commit to this request")
        ));

        // Bound to a different execution environment.
        let (mut wrong_env, _) = acceptance_for(&mut staked_channel_fixture(), ticket.clone(), 60);
        wrong_env.acceptance.as_mut().unwrap().environment = vec![0xcd; 32];
        assert!(matches!(
            handle.run_ticket_handle(wrong_env).await,
            Err(ExecutorError::InvalidQuoteRequest(ref msg))
                if msg.contains("does not commit to this environment")
        ));

        // Correctly bound, but signed by someone who is not the
        // channel's client — here the provider signing for itself.
        let (mut forged, context) = acceptance_for(&mut staked_channel_fixture(), ticket, 60);
        forged.acceptance = Some(crate::acceptance_to_pb(
            &context,
            crate::kernel_signer(&key()).sign(context.digest()),
        ));
        assert!(matches!(
            handle.run_ticket_handle(forged).await,
            Err(ExecutorError::InvalidQuoteRequest(ref msg))
                if msg.contains("client signature does not verify")
        ));
    }

    /// A provider must not accept payment, or issue fraud evidence, for
    /// work it has not terminally recorded.
    ///
    /// Settling early would clear the serialization lock while the job
    /// is still running — breaking serialize-through-resolution — and
    /// leave the client paid but unable to obtain a receipt, which is
    /// the evidence it needs if the result turns out to be wrong. The
    /// gate is `settled ⇒ the client could have obtained its receipt`.
    #[tokio::test]
    async fn settlement_and_receipt_are_refused_before_the_work_is_recorded() {
        let provider = ReleasableFetchProvider::default();
        let handle = spawn_staked_executor(Arc::new(provider.clone())).await;
        let mut client_channel = staked_channel_fixture();
        let ticket = handle
            .create_fetch_ticket(fetch_request(&client_key(), "echo", "run", br#"{"n":1}"#))
            .await
            .unwrap()
            .response;
        let (admitted, job) = acceptance_for(&mut client_channel, ticket, 60);
        let _outcome = handle
            .run_ticket_handle(admitted)
            .await
            .expect("the job admits and starts");
        // The provider is now blocked mid-run: the job is in flight and
        // nothing is terminally recorded.

        let receipt = handle.receipt_handle(receipt_request(job.digest())).await;
        assert!(
            matches!(
                receipt,
                Err(ExecutorError::InvalidQuoteRequest(ref msg))
                    if msg.contains("no completed transcript")
            ),
            "receipt before completion must be refused, got {receipt:?}",
        );

        // Even a perfectly valid voucher must not settle yet.
        let voucher = client_channel
            .issue(&crate::kernel_signer(&client_key()))
            .expect("client issues the frontier");
        let hellas_kernel::Auth::Native(authorization) = voucher.client_auth else {
            panic!("issued vouchers carry native maker authorization");
        };
        let settled = handle
            .settle_handle(hellas_rpc::pb::execute::SettleRequest {
                payment_edge: voucher.payment_edge.as_bytes().to_vec(),
                payment_terms: voucher.terms_hash.as_bytes().to_vec(),
                cumulative: voucher.cumulative,
                client_authorization: Some(crate::chain::sig_to_pb(authorization)),
            })
            .await;
        assert!(
            matches!(
                settled,
                Err(ExecutorError::InvalidQuoteRequest(ref msg))
                    if msg.contains("no completed transcript")
            ),
            "settlement before completion must be refused, got {settled:?}",
        );

        provider.release();
    }

    /// A receipt hands out the provider's signatures over a job's
    /// acceptance and result — the client's half of a fraud artifact.
    /// It must only ever answer for the job actually in flight.
    #[tokio::test]
    async fn receipt_refuses_a_digest_that_is_not_the_in_flight_job() {
        let input = br#"{"hello":"receipt"}"#;
        let provider = MockFetchProvider::new();
        provider.insert(
            "echo",
            "run",
            input,
            [b"event:ok".to_vec(), b"terminal:done".to_vec()],
        );
        let handle = spawn_staked_executor(Arc::new(provider)).await;
        let mut client_channel = staked_channel_fixture();
        let ticket = handle
            .create_fetch_ticket(fetch_request(&client_key(), "echo", "run", input))
            .await
            .unwrap()
            .response;
        let (admitted, _job) = acceptance_for(&mut client_channel, ticket, 60);
        let outcome = handle.run_ticket_handle(admitted).await.unwrap();
        let (_chunks, _finished) = drain_outcome(outcome.events).await;

        let foreign = handle
            .receipt_handle(hellas_rpc::pb::execute::ReceiptRequest {
                acceptance_digest: vec![0x5a; 32],
                client_signature: Some(crate::chain::sig_to_pb(
                    crate::kernel_signer(&client_key())
                        .sign(hellas_kernel::PayloadHash::from_bytes([0x5a; 32])),
                )),
            })
            .await;
        assert!(
            matches!(
                foreign,
                Err(ExecutorError::InvalidQuoteRequest(ref msg))
                    if msg.contains("names a job other than the in-flight one")
            ),
            "a foreign acceptance digest must be refused, got {foreign:?}",
        );
    }

    /// A receipt hands out the provider's fraud-evidence signatures, so
    /// it must answer only the channel's committed client — not any
    /// party that merely observed the acceptance on the wire (a
    /// proxying gateway, or any peer that can reach the Execute ALPN).
    #[tokio::test]
    async fn receipt_refuses_a_caller_that_is_not_the_channels_client() {
        let input = br#"{"hello":"auth"}"#;
        let provider = MockFetchProvider::new();
        provider.insert(
            "echo",
            "run",
            input,
            [b"event:ok".to_vec(), b"terminal:done".to_vec()],
        );
        let handle = spawn_staked_executor(Arc::new(provider)).await;
        let mut client_channel = staked_channel_fixture();
        let ticket = handle
            .create_fetch_ticket(fetch_request(&client_key(), "echo", "run", input))
            .await
            .unwrap()
            .response;
        let (admitted, job) = acceptance_for(&mut client_channel, ticket, 60);
        let outcome = handle.run_ticket_handle(admitted).await.unwrap();
        let (_chunks, _finished) = drain_outcome(outcome.events).await;
        let digest = job.digest();

        // THE REPLAY CASE. The client's signature over the acceptance
        // digest travels on the wire inside the run ticket, so any
        // party that saw the ticket holds it verbatim. It must not
        // authorize a receipt — otherwise the auth excludes nobody.
        let replayed = handle
            .receipt_handle(hellas_rpc::pb::execute::ReceiptRequest {
                acceptance_digest: digest.as_bytes().to_vec(),
                client_signature: Some(crate::chain::sig_to_pb(
                    crate::kernel_signer(&client_key()).sign(digest),
                )),
            })
            .await;
        assert!(
            matches!(
                replayed,
                Err(ExecutorError::InvalidQuoteRequest(ref msg))
                    if msg.contains("not authorized by the channel's client")
            ),
            "the admission signature must not authorize a receipt, got {replayed:?}",
        );

        // An observer who knows the digest but cannot sign as the
        // client — here the provider itself — is refused.
        let observer = handle
            .receipt_handle(hellas_rpc::pb::execute::ReceiptRequest {
                acceptance_digest: digest.as_bytes().to_vec(),
                client_signature: Some(crate::chain::sig_to_pb(
                    crate::kernel_signer(&key()).sign(digest),
                )),
            })
            .await;
        assert!(
            matches!(
                observer,
                Err(ExecutorError::InvalidQuoteRequest(ref msg))
                    if msg.contains("not authorized by the channel's client")
            ),
            "an unauthorized observer must not collect a receipt, got {observer:?}",
        );

        // The real client still gets its receipt.
        assert!(handle.receipt_handle(receipt_request(digest)).await.is_ok());
    }

    /// A client that takes delivery and then neither settles nor
    /// disputes must not hold the pairing forever. Once the committed
    /// terminal deadline passes, the provider releases the lock — a
    /// release the client computes identically, since the deadline is
    /// in the acceptance both parties signed.
    #[tokio::test]
    async fn an_abandoned_job_stops_holding_the_serialization_lock() {
        let input = br#"{"hello":"abandoned"}"#;
        let second_input = br#"{"hello":"next"}"#;
        let provider = MockFetchProvider::new();
        for body in [input.as_slice(), second_input.as_slice()] {
            provider.insert(
                "echo",
                "run",
                body,
                [b"event:ok".to_vec(), b"terminal:done".to_vec()],
            );
        }
        let chain = crate::FakeChainView::new();
        chain.set_height(10);
        let handle = spawn_staked_executor_with(Arc::new(provider), chain.clone()).await;
        let mut client_channel = staked_channel_fixture();

        let ticket = handle
            .create_fetch_ticket(fetch_request(&client_key(), "echo", "run", input))
            .await
            .unwrap()
            .response;
        let (admitted, _) = acceptance_for(&mut client_channel, ticket, 60);
        let outcome = handle.run_ticket_handle(admitted).await.unwrap();
        let (_chunks, _finished) = drain_outcome(outcome.events).await;
        // The client walks away: no settle, no dispute.

        // While the deadline stands, the lock holds.
        let request = fetch_request(&client_key(), "echo", "run", second_input);
        let next_ticket = handle.create_fetch_ticket(request).await.unwrap().response;
        let (blocked, _) = acceptance_for(&mut staked_channel_fixture(), next_ticket.clone(), 61);
        assert!(matches!(
            handle.run_ticket_handle(blocked).await,
            Err(ExecutorError::InvalidQuoteRequest(ref msg)) if msg.contains("Busy")
        ));

        // Past the deadline, the provider releases it and takes work again.
        chain.set_height(61);
        client_channel.abandon(hellas_kernel::BlockHeight::new(61));
        let (next, _) = acceptance_for(&mut client_channel, next_ticket, 100);
        let outcome = handle
            .run_ticket_handle(next)
            .await
            .expect("the next job admits once the abandoned one is released");
        let (chunks, _finished) = drain_outcome(outcome.events).await;
        assert_eq!(chunks.len(), 1);
    }

    /// Once the channel can no longer admit any job, the provider banks
    /// its frontier on-chain rather than holding a voucher the client's
    /// timeout refund would erase.
    #[tokio::test]
    async fn the_frontier_is_submitted_on_chain_once_redemption_is_due() {
        let input = br#"{"hello":"redeem"}"#;
        let provider = MockFetchProvider::new();
        provider.insert(
            "echo",
            "run",
            input,
            [b"event:ok".to_vec(), b"terminal:done".to_vec()],
        );
        let chain = crate::FakeChainView::new();
        // 143 + close_margin 5 = 148 < payment timeout 150: settlement
        // still fits, but no further job can be admitted.
        chain.set_height(143);
        let handle = spawn_staked_executor_with(Arc::new(provider), chain.clone()).await;
        let mut client_channel = staked_channel_fixture();
        let ticket = handle
            .create_fetch_ticket(fetch_request(&client_key(), "echo", "run", input))
            .await
            .unwrap()
            .response;
        let (admitted, _) = acceptance_for(&mut client_channel, ticket, 144);
        let outcome = handle.run_ticket_handle(admitted).await.unwrap();
        let (_chunks, _finished) = drain_outcome(outcome.events).await;
        assert!(
            chain.submitted().is_empty(),
            "nothing submitted before settle"
        );

        let voucher = client_channel
            .issue(&crate::kernel_signer(&client_key()))
            .expect("client issues the frontier");
        let hellas_kernel::Auth::Native(authorization) = voucher.client_auth else {
            panic!("issued vouchers carry native maker authorization");
        };
        handle
            .settle_handle(hellas_rpc::pb::execute::SettleRequest {
                payment_edge: voucher.payment_edge.as_bytes().to_vec(),
                payment_terms: voucher.terms_hash.as_bytes().to_vec(),
                cumulative: voucher.cumulative,
                client_authorization: Some(crate::chain::sig_to_pb(authorization)),
            })
            .await
            .expect("settlement lands");

        // At 143 redemption is not yet due (143 + 5 < 150), and settle
        // only ever succeeds while that holds — so nothing is banked
        // yet. The two conditions are complementary by construction.
        assert!(
            chain.submitted().is_empty(),
            "settling does not itself bank the frontier",
        );

        // Past the margin the channel can admit nothing more. The next
        // admission attempt is refused, and that height observation is
        // what triggers the provider to bank what it earned.
        chain.set_height(146);
        let late = fetch_request(&client_key(), "echo", "run", br#"{"n":"late"}"#);
        let late_ticket = handle.create_fetch_ticket(late).await.unwrap().response;
        // Deadline 144 is admissible when the client builds it, and
        // stale by the time the provider sees height 146.
        let (late_job, _) = acceptance_for(&mut staked_channel_fixture(), late_ticket, 144);
        assert!(
            handle.run_ticket_handle(late_job).await.is_err(),
            "no job is admissible past the redemption margin",
        );

        let submitted = chain.submitted();
        assert_eq!(submitted.len(), 1, "the frontier must be submitted once");
        assert!(
            matches!(&submitted[0], hellas_chain::domain::Transaction::Kernel(_)),
            "the redemption is a kernel close",
        );
    }

    /// An IDLE provider — one that receives no further requests —
    /// still banks its frontier, because chain progress alone wakes it.
    ///
    /// This is the case with real money on it: without a height-driven
    /// trigger the provider holds the voucher until the payment timeout
    /// and the client's close refunds the FULL capacity, erasing
    /// everything earned.
    #[tokio::test]
    async fn an_idle_provider_banks_its_frontier_when_the_chain_advances() {
        let input = br#"{"hello":"idle"}"#;
        let provider = MockFetchProvider::new();
        provider.insert(
            "echo",
            "run",
            input,
            [b"event:ok".to_vec(), b"terminal:done".to_vec()],
        );
        let chain = crate::FakeChainView::new();
        chain.set_height(143);
        let heights = crate::FakeHeightFeed::new();
        let handle =
            spawn_staked_executor_feeding(Arc::new(provider), chain.clone(), heights.clone()).await;
        let mut client_channel = staked_channel_fixture();

        let ticket = handle
            .create_fetch_ticket(fetch_request(&client_key(), "echo", "run", input))
            .await
            .unwrap()
            .response;
        let (admitted, _) = acceptance_for(&mut client_channel, ticket, 144);
        let outcome = handle.run_ticket_handle(admitted).await.unwrap();
        let (_chunks, _finished) = drain_outcome(outcome.events).await;
        let voucher = client_channel
            .issue(&crate::kernel_signer(&client_key()))
            .expect("client issues the frontier");
        let hellas_kernel::Auth::Native(authorization) = voucher.client_auth else {
            panic!("issued vouchers carry native maker authorization");
        };
        handle
            .settle_handle(hellas_rpc::pb::execute::SettleRequest {
                payment_edge: voucher.payment_edge.as_bytes().to_vec(),
                payment_terms: voucher.terms_hash.as_bytes().to_vec(),
                cumulative: voucher.cumulative,
                client_authorization: Some(crate::chain::sig_to_pb(authorization)),
            })
            .await
            .expect("settlement lands");
        assert!(chain.submitted().is_empty(), "not due yet at height 143");

        // No further requests arrive — only the chain moves.
        chain.set_height(146);
        heights.publish(146);

        for _ in 0..200 {
            if !chain.submitted().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            chain.submitted().len(),
            1,
            "chain progress alone must bank the frontier",
        );
    }

    #[tokio::test]
    async fn a_runtime_failure_does_not_wedge_the_pairing() {
        // The provider serves "run" but has no programmed response for
        // the first input, so that job admits and starts, then fails at
        // runtime — exercising the release on the async completion path.
        let bad = br#"{"hello":"unprogrammed"}"#;
        let good = br#"{"hello":"good"}"#;
        let provider = MockFetchProvider::new();
        provider.insert(
            "echo",
            "run",
            good,
            [b"event:ok".to_vec(), b"terminal:done".to_vec()],
        );
        let handle = spawn_staked_executor(Arc::new(provider)).await;
        let mut client_channel = staked_channel_fixture();

        let bad_ticket = handle
            .create_fetch_ticket(fetch_request(&client_key(), "echo", "run", bad))
            .await
            .unwrap()
            .response;
        let (admitted, _) = acceptance_for(&mut client_channel, bad_ticket, 60);
        let outcome = handle
            .run_ticket_handle(admitted)
            .await
            .expect("the job admits and starts");
        let mut events = outcome.events;
        let mut failed = false;
        while let Some(event) = events.recv().await {
            if let work_event::Kind::Failed(_) = event.unwrap().kind.unwrap() {
                failed = true;
            }
        }
        assert!(failed, "the unprogrammed provider run fails at runtime");
        // The client observes the failure and releases its own side too,
        // keeping both channels' sequences aligned (both consumed 1).
        client_channel.rescind();

        // The runtime failure released the provider's lock: the next
        // well-formed job admits and runs instead of hitting Busy
        // forever, at the next sequence (rescind kept 1 consumed).
        let good_ticket = handle
            .create_fetch_ticket(fetch_request(&client_key(), "echo", "run", good))
            .await
            .unwrap()
            .response;
        let (next, next_job) = acceptance_for(&mut client_channel, good_ticket, 61);
        assert_eq!(next_job.sequence, 2, "the failed job consumed sequence 1");
        let outcome = handle.run_ticket_handle(next).await.unwrap();
        let (chunks, _finished) = drain_outcome(outcome.events).await;
        assert_eq!(chunks.len(), 1);
    }

    #[tokio::test]
    async fn unstaked_executor_refuses_acceptances() {
        let input = br#"{"hello":"unstaked"}"#;
        let provider = MockFetchProvider::new();
        provider.insert(
            "echo",
            "run",
            input,
            [b"event:ok".to_vec(), b"terminal:done".to_vec()],
        );
        let handle = spawn_fetch_executor(Arc::new(provider), 1, 1).await;
        let request = fetch_request(&key(), "echo", "run", input);
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let channel = staked_channel_fixture();
        let context = channel.job([0; 32], [0; 32], 1, hellas_kernel::BlockHeight::new(60));
        let mut request = run_ticket_request(ticket, &key());
        request.acceptance = Some(crate::acceptance_to_pb(
            &context,
            crate::kernel_signer(&client_key()).sign(context.digest()),
        ));
        let refused = handle.run_ticket_handle(request).await;
        assert!(matches!(
            refused,
            Err(ExecutorError::InvalidQuoteRequest(ref msg))
                if msg.contains("does not run the staked flow")
        ));
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
        let events = build_input_events(
            service,
            method,
            body,
            test_environment(),
            test_assurance(),
            key,
        )
        .unwrap();
        FetchRequest {
            input: events.iter().map(input_event_to_pb).collect(),
        }
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
        projector_factory: Arc<dyn FetchProjectorFactory>,
    ) -> crate::FetchRouteRegistry {
        let mut registry = crate::FetchRouteRegistry::new();
        registry
            .register(
                FetchRoute::new(service, method),
                crate::FetchRouteEntry {
                    execution_environment: test_environment(),
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
            provider_genesis: Arc::new(test_genesis()),
            assurance: test_assurance(),
            fetch_access_policy: FetchAccessPolicy::trusted_callers([caller_key]),
            fetch_routes: test_routes("echo", "run", provider, Arc::new(TestFetchProjectorFactory)),
            fetch_max_in_flight,
            fetch_queue_capacity,
            artifact_store: ArtifactStoreConfig::Memory,
            staked: None,
        })
        .await
        .unwrap()
    }

    async fn run_failed(
        handle: &crate::ExecutorHandle,
        ticket: hellas_rpc::pb::execute::Ticket,
        key: &ProducerSigningKey,
    ) -> WorkFailed {
        let mut outcome = handle
            .run_ticket_handle(run_ticket_request(ticket, key))
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
            test_genesis(),
            test_assurance(),
            test_routes(
                "echo",
                "run",
                Arc::new(provider.clone()),
                Arc::new(TestFetchProjectorFactory),
            ),
        )
        .unwrap();
        let ticket = handle.create_fetch_ticket(request).await.unwrap().response;

        let (chunks, first) = run_one(&handle, ticket.clone(), &signing_key).await;
        let (replay_chunks, replayed) = run_one(&handle, ticket, &signing_key).await;

        assert_eq!(chunks.len(), 1);
        let chunk_event = chunks[0]
            .output_event
            .as_ref()
            .expect("fetch chunk should carry signed output event");
        assert_eq!(chunk_event.payload, b"event:ok");
        assert!(replay_chunks.is_empty());
        assert_eq!(first.output_events[0], *chunk_event);
        assert_eq!(
            decode_fetch_terminal_payload(&first.output_events[1].payload)
                .unwrap()
                .billable_units(),
            0
        );
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
            test_genesis(),
            test_assurance(),
            test_routes(
                "echo",
                "run",
                Arc::new(provider.clone()),
                Arc::new(TestFetchProjectorFactory),
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
            execute_policy: ExecutePolicy::Eager,
            queue_capacity: 1,
            supported_dtypes: vec![Dtype::F32],
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key: Arc::new(key()),
            provider_genesis: Arc::new(test_genesis()),
            assurance: test_assurance(),
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
            staked: None,
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
            artifact_store: ArtifactStoreConfig::Memory,
            staked: None,
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
        assert!(!first_finished.output_events.is_empty());

        let (chunks, second_finished) = timeout(
            Duration::from_secs(2),
            run_one(&handle, second_ticket, &signing_key),
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

        assert!(!first_finished.output_events.is_empty());
        assert_eq!(second_chunks.len(), 1);
        assert!(!second_finished.output_events.is_empty());
        assert_eq!(provider.calls(), 2);
    }
}
