//! The paid-work wire: how a client proposes one job and a provider
//! accepts or refuses it.
//!
//! # What crosses the wire
//!
//! Canonical private records, and nothing else. `AcceptWorkRequest`
//! carries the exact bytes of a [`PaidJobAuthorizationV1`] and a
//! [`PreparedPaidInputV1`], not a protobuf transcription of their
//! fields, because the two signatures on this exchange are over digests
//! of those bytes. A protobuf spelling beside them would be a second
//! definition of what both parties signed, agreeing with the first until
//! one of them gained a field.
//!
//! # The order
//!
//! Both endpoints obey the same rule, which is [`crate::work_store`]'s:
//! **the state that authorises a signature is fsynced before the
//! signature leaves the process.**
//!
//! The client reserves its nonce, builds and signs the authorization,
//! and journals the signature — all before the request is handed to a
//! transport. The provider journals the client's proposal, which is what
//! reserves its compute credit, then signs, then journals its own
//! signature, and only then answers. A crash anywhere in either sequence
//! costs a round trip and at most one burnt proposal nonce: the retry
//! finds the durable record, returns the retained bytes, and reserves no
//! credit twice.
//!
//! The one thing neither endpoint can promise is delivery. A provider
//! that crashes after its journal commits and before its reply reaches
//! the client has co-signed a job the client does not know is accepted;
//! the client's retry is what resolves that, and the acceptance deadline
//! is what bounds how long it may try.
//!
//! # Idempotence
//!
//! By `work_id`, which is the authorization's own digest. A retry of the
//! same proposal returns the retained co-signature without re-checking
//! deadlines — the answer was already given, and a deadline that passed
//! since cannot unsay it. A *different* proposal while one is in flight
//! is refused, never queued.
//!
//! # Running what was accepted
//!
//! [`run_accepted_work`] is the second half, and it obeys the same rule
//! in the one place it matters most: the running marker is fsynced
//! before the backend is called. It is not a wire exchange — there is no
//! Run RPC here — but it is the same journal, the same channel, and the
//! same `work_id`, so it lives beside the acceptance that authorised it.
//!
//! The property it exists for: **for one `work_id`, at most one call in
//! the lifetime of one journal ever invokes the backend.** Two durable
//! facts carry it, and neither alone does. The provider burns each
//! proposal nonce it sees, so one `work_id` opens at most one job, ever
//! — ending a job does not give its nonce back. And the journal takes a
//! running marker only from the accepted phase, so one job crosses into
//! running at most once; every later call reads that phase and answers
//! from it instead of invoking. Deleting the journal file forfeits both,
//! which is why the claim is scoped to one journal's life and not to one
//! `work_id`'s.
//!
//! A third durable fact is about the crash rather than the count. A
//! marker found on the disk by a process that did not write it makes the
//! state indeterminate, and that does not stop a second invocation — the
//! phase already does — it stops the *resolution*: a recovered process
//! may not sign a result for an invocation it cannot know it made.
//!
//! # Delivering the answer
//!
//! [`ProviderEndpoint::deliver`] and [`ClientEndpoint::receive`] are the
//! third exchange, and they obey the same rule at the one moment it is
//! irreversible: the release marker — which is what debits this client's
//! delivery credit — is fsynced before a byte of plaintext is returned.
//!
//! It is one unary call carrying the whole answer, and that is the
//! profile rather than a shortcut. Nothing is released before the
//! terminal result is durable and its price is reserved, so there is no
//! prefix to stream; what the client gets is the signed result and the
//! transcript the provider's own journal holds, and what it does with
//! them is rebuild one from the other before anything is stored.
//!
//! A lost response costs a round trip. The provider answers a second
//! call from the same spool and re-commits the same marker as a
//! redundant step, so one job's plaintext is debited once however many
//! times it is fetched.
//!
//! # What this phase does not carry
//!
//! Invoicing and certificate admission. Both need a producer that does
//! not exist yet, and a message with nothing on either end of it is not
//! a protocol. [`ClientEndpoint::verified`] is the step an invoice will
//! be asked for from; nothing here asks.

use std::sync::{Arc, Mutex, MutexGuard};

use hellas_kernel::{Secp256k1Signer, Secp256k1Verifier, Sig};
use hellas_wire::{StreamTransport, WireStatus};

use prost::Message as _;

use crate::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, DeliverResultRequest, DeliverResultResponse,
    WorkAccepted, WorkDelivered, WorkRefusalCode, WorkRefused, accept_work_response::Outcome,
    deliver_result_response::Outcome as DeliverOutcome,
};
use crate::protocol::Digest;
use crate::protocol::artifacts::PreparedPaidInputV1;
use crate::protocol::work::{
    JobDeadlines, PaidJobAuthorizationV1, PaidJobResultV1, PaidWorkError, PrivateRecord as _,
    check_authorization, check_prepared_input, encode_transcript, propose_authorization,
    result_digest, signing_hash, terminal_result, work_id,
};
use crate::protocol::work_setup::{ReadyChannel, WorkSetupError};
use crate::services::work::{WorkClientImpl, WorkHandler};
use crate::work_store::journal::MAX_RECORD_BYTES;
use crate::work_store::{
    ChannelRecord, ChannelState, ChannelStateError, ChannelStore, JobEnd, JobPhase, JobState, Role,
    WorkStoreError,
};
use crate::{EvaluateRequest, OutputEventEnvelope};

// ── Refusals ──────────────────────────────────────────────────────────

/// Why a provider did not accept a proposal.
///
/// Six answers, and the difference between them is what the caller may
/// do next: two are retryable unchanged, three are permanent for these
/// exact bytes, and one is permanent only while another job holds the
/// channel. A caller that cannot tell them apart either gives up on a
/// transient fault or retries an invalid proposal as a fresh paid job,
/// and the second of those is the expensive mistake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkRefusal {
    /// The provider cannot answer yet: it has not processed a finalized
    /// block it can admit work at, or the job it accepted has not
    /// finished. Retryable unchanged.
    NotReady,
    /// A deadline or the channel's admission horizon has passed.
    /// Permanent for these bytes; a fresh proposal may still be
    /// accepted.
    Expired,
    /// Not a well-formed proposal on this channel. Permanent, and never
    /// a reason to retry as a new paid job without changing it.
    Invalid,
    /// A different proposal already holds this key.
    Conflict,
    /// Well formed, and refused by the provider's own admission state:
    /// credit exhausted, an unallocated certificate gap, or a job
    /// already in flight.
    Declined,
    /// The provider could not make the state durable. Retryable, and
    /// nothing was released.
    Unavailable,
}

impl WorkRefusal {
    /// Returns the wire code for this refusal.
    #[must_use]
    pub const fn code(self) -> WorkRefusalCode {
        match self {
            Self::NotReady => WorkRefusalCode::NotReady,
            Self::Expired => WorkRefusalCode::Expired,
            Self::Invalid => WorkRefusalCode::Invalid,
            Self::Conflict => WorkRefusalCode::Conflict,
            Self::Declined => WorkRefusalCode::Declined,
            Self::Unavailable => WorkRefusalCode::Unavailable,
        }
    }

    /// Reads a refusal from its wire code.
    ///
    /// `WORK_REFUSAL_CODE_UNSPECIFIED` and every unassigned number
    /// return `None`: a refusal a peer cannot name is not a refusal this
    /// endpoint may act on, and proto3's open enums make the unassigned
    /// case reachable from any newer peer.
    #[must_use]
    pub const fn from_code(code: i32) -> Option<Self> {
        match code {
            c if c == WorkRefusalCode::NotReady as i32 => Some(Self::NotReady),
            c if c == WorkRefusalCode::Expired as i32 => Some(Self::Expired),
            c if c == WorkRefusalCode::Invalid as i32 => Some(Self::Invalid),
            c if c == WorkRefusalCode::Conflict as i32 => Some(Self::Conflict),
            c if c == WorkRefusalCode::Declined as i32 => Some(Self::Declined),
            c if c == WorkRefusalCode::Unavailable as i32 => Some(Self::Unavailable),
            _ => None,
        }
    }

    /// Whether retrying the identical request could succeed later.
    ///
    /// True only for the two faults that are about the provider's own
    /// progress. It says nothing about how long to wait, and nothing
    /// about whether the job's deadlines will still be met when the
    /// retry lands.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::NotReady | Self::Unavailable)
    }
}

impl core::fmt::Display for WorkRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotReady => "not ready",
            Self::Expired => "expired",
            Self::Invalid => "invalid",
            Self::Conflict => "conflict",
            Self::Declined => "declined",
            Self::Unavailable => "unavailable",
        })
    }
}

/// One refusal and the diagnostic text that goes with it.
///
/// The text is for an operator reading a log. Nothing decides on it, no
/// digest covers it, and no test asserts its wording.
struct Refusal {
    code: WorkRefusal,
    reason: String,
}

impl Refusal {
    fn new(code: WorkRefusal, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    fn invalid(reason: impl Into<String>) -> Self {
        Self::new(WorkRefusal::Invalid, reason)
    }
}

impl From<PaidWorkError> for Refusal {
    /// Only the acceptance deadline makes a record error a matter of
    /// timing. Everything else a record rule refuses is refused the same
    /// way at every height.
    fn from(error: PaidWorkError) -> Self {
        let code = match error {
            PaidWorkError::AcceptanceExpired { .. } => WorkRefusal::Expired,
            _ => WorkRefusal::Invalid,
        };
        Self::new(code, error.to_string())
    }
}

impl From<WorkSetupError> for Refusal {
    /// `check_signable` is the only producer on this path. `CursorBehind`
    /// is the provider's own lag. `HorizonPassed` and
    /// `TerminalUnreachable` are height-dependent and one-way: no later
    /// height makes either pass again. `OracleGraceTooShort` compares two
    /// carried deadlines to each other and to no height at all, so it is
    /// wrong rather than late — and its overflow sibling, which the same
    /// arithmetic raises, is wrong for the same reason.
    ///
    /// The rest belong to `check_ready`, which runs before an endpoint is
    /// built and never here. They are mapped so the match is total; no
    /// test reaches them, and none claims to.
    fn from(error: WorkSetupError) -> Self {
        let code = match error {
            WorkSetupError::CursorBehind { .. } => WorkRefusal::NotReady,
            WorkSetupError::HorizonPassed { .. } | WorkSetupError::TerminalUnreachable { .. } => {
                WorkRefusal::Expired
            }
            WorkSetupError::OracleGraceTooShort { .. } | WorkSetupError::Record(_) => {
                WorkRefusal::Invalid
            }
            _ => WorkRefusal::Invalid,
        };
        Self::new(code, error.to_string())
    }
}

impl From<WorkStoreError> for Refusal {
    /// A journal that will not take the record is the provider's own
    /// storage failing, and the proposal is untouched by it.
    fn from(error: WorkStoreError) -> Self {
        let code = match &error {
            WorkStoreError::Channel(channel) => channel_refusal(channel),
            WorkStoreError::Journal(_) | WorkStoreError::Setup(_) => WorkRefusal::Unavailable,
        };
        Self::new(code, error.to_string())
    }
}

/// Maps one channel-state refusal onto the wire's six answers.
///
/// Accepting a proposal reaches five of these through its two commits,
/// and each has a test: a nested record rule, a bad client signature, a
/// job already in flight, a nonce this channel has seen carrying other
/// bytes, and an unallocated certificate gap.
///
/// `OverCredit` is reachable but not from a test here. This profile
/// admits one job at a time, so the gate can only bite after earlier
/// jobs have been run and lost, which takes a journal rather than a
/// request. What it is on the wire — a decline, not a fault — is
/// decided here; that it bites at all is
/// `compute_credit_bounds_what_may_be_co_signed`'s, and that a channel
/// which has reached its limit still *opens* is
/// `a_journal_accepted_a_record_at_a_time_reopens_whole`'s.
///
/// The rest belong to steps this phase does not carry — a result, an
/// invoice, a cursor, a job whose ending is already on the disk — and
/// are mapped so the match is total, not because a proposal can produce
/// them.
const fn channel_refusal(error: &ChannelStateError) -> WorkRefusal {
    match error {
        ChannelStateError::Nonce { .. } | ChannelStateError::Conflict { .. } => {
            WorkRefusal::Conflict
        }
        ChannelStateError::WrongPhase { .. }
        | ChannelStateError::OverCredit { .. }
        | ChannelStateError::UnallocatedGap { .. }
        | ChannelStateError::LossRecorded
        | ChannelStateError::Indeterminate => WorkRefusal::Declined,
        ChannelStateError::NoCursor { .. } => WorkRefusal::NotReady,
        ChannelStateError::ReceiptLate { .. } => WorkRefusal::Expired,
        ChannelStateError::Record(_)
        | ChannelStateError::BadSignature { .. }
        | ChannelStateError::WrongRole { .. }
        | ChannelStateError::WrongChannel { .. }
        | ChannelStateError::CursorNotAdvancing { .. }
        | ChannelStateError::Malformed => WorkRefusal::Invalid,
    }
}

// ── Endpoint construction ─────────────────────────────────────────────

/// Why an endpoint could not be built over this channel, store, and key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    /// The journal is another channel's.
    #[error("the store's channel is not the one this readiness decided")]
    WrongChannel,
    /// The journal was opened at other funding than the readiness read
    /// found, so the two bound invoices differently.
    #[error("the store's settlement is not the one this readiness read")]
    WrongSettlement,
    /// The journal is the other role's.
    #[error("the store is the {found} journal, and this is the {expected} endpoint")]
    WrongRole {
        /// Role this endpoint is.
        expected: &'static str,
        /// Role the journal was opened as.
        found: &'static str,
    },
    /// The signer does not hold the settlement key this endpoint signs
    /// with.
    #[error("the signer is not the channel's {party} key")]
    WrongKey {
        /// Which party the endpoint signs as.
        party: &'static str,
    },
    /// A handler panicked while holding the endpoint.
    #[error("the endpoint lock is poisoned")]
    Poisoned,
}

const fn role_name(role: Role) -> &'static str {
    match role {
        Role::Client => "client",
        Role::Provider => "provider",
    }
}

/// Checks that a store, a readiness decision, and a signing key are
/// three views of the same half of the same channel.
///
/// All four disagreements are configuration mistakes rather than peer
/// behaviour, and every one of them would otherwise surface much later
/// as a signature nobody can verify or an invoice bounded by the wrong
/// capacity.
fn bind(
    ready: &ReadyChannel,
    store: &ChannelStore,
    signer: &Secp256k1Signer,
    role: Role,
) -> Result<(), EndpointError> {
    let state = store.state();
    if state.channel() != ready.channel() {
        return Err(EndpointError::WrongChannel);
    }
    if state.settlement() != ready.settlement() {
        return Err(EndpointError::WrongSettlement);
    }
    if state.role() != role {
        return Err(EndpointError::WrongRole {
            expected: role_name(role),
            found: role_name(state.role()),
        });
    }
    let party = match role {
        Role::Client => ready.channel().client_key(),
        Role::Provider => ready.channel().provider_key(),
    };
    if signer.party_key() != party {
        return Err(EndpointError::WrongKey {
            party: role_name(role),
        });
    }
    Ok(())
}

// ── The provider ──────────────────────────────────────────────────────

/// The provider half of the acceptance exchange.
///
/// It owns one channel's journal and answers proposals on that channel
/// alone. A proposal naming another channel is refused by
/// [`check_authorization`], never routed: routing many channels through
/// one endpoint is a later concern, and pretending to do it here would
/// mean an authorization whose `channel_id` selects its own validator.
#[derive(Debug)]
pub struct ProviderEndpoint {
    ready: ReadyChannel,
    store: ChannelStore,
    signer: Secp256k1Signer,
}

impl ProviderEndpoint {
    /// Builds the provider endpoint for one ready channel.
    ///
    /// # Errors
    ///
    /// [`EndpointError`] when the store, the readiness decision, and the
    /// key are not all the provider's view of the same channel.
    pub fn new(
        ready: ReadyChannel,
        store: ChannelStore,
        signer: Secp256k1Signer,
    ) -> Result<Self, EndpointError> {
        bind(&ready, &store, &signer, Role::Provider)?;
        Ok(Self {
            ready,
            store,
            signer,
        })
    }

    /// Returns what this endpoint durably knows.
    #[must_use]
    pub const fn state(&self) -> &ChannelState {
        self.store.state()
    }

    /// Answers one proposal.
    ///
    /// Infallible by construction: every outcome an endpoint can have is
    /// one of the six refusal codes or a co-signature, so there is one
    /// channel for answers and not two. Transport faults stay the
    /// transport's.
    ///
    /// On the accepting path the client's proposal is journaled — which
    /// is what reserves the compute credit — before the co-signature is
    /// produced, and the co-signature is journaled before this returns
    /// it. A crash before the first commit leaves nothing: the client
    /// retries into a fresh admission. A crash between the two leaves a
    /// half-signed job holding its credit, and the retry co-signs it if
    /// the deadlines still allow. A crash after the second commit and
    /// before the answer reaches the client leaves an accepted job, and
    /// the retry returns the retained signature.
    pub fn accept(&mut self, request: &AcceptWorkRequest) -> AcceptWorkResponse {
        match self.decide(request) {
            Ok(signature) => AcceptWorkResponse {
                outcome: Some(Outcome::Accepted(WorkAccepted {
                    provider_signature: signature.as_bytes().to_vec(),
                })),
            },
            Err(refusal) => AcceptWorkResponse {
                outcome: Some(Outcome::Refused(WorkRefused {
                    code: refusal.code.code() as i32,
                    reason: refusal.reason,
                })),
            },
        }
    }

    fn decide(&mut self, request: &AcceptWorkRequest) -> Result<Sig, Refusal> {
        let authorization = PaidJobAuthorizationV1::decode(&request.authorization)?;
        let client_signature = signature(&request.client_signature)
            .ok_or_else(|| Refusal::invalid("the client signature is not 64 bytes"))?;
        let work_id = work_id(self.ready.channel(), &authorization);

        // A question already answered is answered again, with the same
        // bytes and without re-deciding it. The deadlines are not
        // rechecked here on purpose: this co-signature is already
        // durable and already the client's, and a height that has passed
        // since cannot unsay it.
        if let Some(retained) = self.retained_signature(work_id) {
            return Ok(retained);
        }

        let Some((cursor_height, _)) = self.state().cursor() else {
            return Err(Refusal::new(
                WorkRefusal::NotReady,
                "no finalized block has been processed on this channel",
            ));
        };

        let policy = *self.ready.execution_policy();
        check_authorization(self.ready.channel(), &authorization, &policy, cursor_height)?;
        let bundle = PreparedPaidInputV1::decode(&request.prepared_input, MAX_RECORD_BYTES)
            .map_err(|error| Refusal::invalid(error.to_string()))?;
        check_prepared_input(self.ready.channel(), &authorization, &policy, &bundle)?;
        self.ready.check_signable(
            cursor_height,
            authorization.terminal_deadline,
            authorization.payment_deadline,
        )?;

        // The client's signature, its bundle, and the credit this job
        // costs, on the disk before a co-signature exists to leak.
        self.store.commit(
            ChannelRecord::JobProposed {
                authorization,
                client_signature,
                prepared_input: request.prepared_input.clone(),
            },
            &Secp256k1Verifier::new(),
        )?;

        let signature = self.signer.sign(signing_hash(work_id));
        self.store.commit(
            ChannelRecord::JobAccepted {
                provider_signature: signature,
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok(signature)
    }

    /// Returns this endpoint's co-signature over `work_id`, if it has
    /// already given one.
    fn retained_signature(&self, work_id: Digest) -> Option<Sig> {
        let job = self.state().job()?;
        (job.work_id() == work_id)
            .then(|| job.provider_signature())
            .flatten()
    }

    /// Decides whether the backend may be invoked for `work_id`, and
    /// makes that decision durable before it is returned.
    ///
    /// [`RunAdmission::Invoke`] is returned only when the job was
    /// accepted and not yet running, and only after the running marker
    /// is on the disk — so a crash between the marker and the answer
    /// costs the invocation, never a second one. Every other phase past
    /// acceptance answers with what it already is: a job this process is
    /// running, a job whose result is already signed, or a job whose
    /// marker was found by a process that did not write it. A job that
    /// was never co-signed is refused rather than answered.
    ///
    /// `ready` is a *fresh* readiness decision, and the freshness is the
    /// caller's to owe in exactly the sense [`ReadyChannel`] already
    /// documents: nothing on that type re-reads the chain, so a
    /// contest opened after it was built is invisible here. What is
    /// checked is that it is this endpoint's own channel, at this
    /// endpoint's own policy, that the channel still admits work at all,
    /// and that the margins the policy measured still fit before the
    /// terminal deadline — all at the height this endpoint has processed
    /// finalized blocks through, not at the height the readiness was
    /// decided at.
    ///
    /// The request it hands back is rebuilt from the bundle the journal
    /// holds, never from a quote. That bundle is the one the
    /// authorization both parties signed commits to: its digest is
    /// checked before it is stored and again on every replay
    /// (`ChannelState::apply_proposed`), so a bundle altered on disk
    /// fails when the journal is opened rather than producing a job
    /// nobody agreed to.
    ///
    /// # Errors
    ///
    /// [`RunError::NoSuchJob`] when no open job carries this
    /// `work_id`, [`RunError::NotAccepted`] before the co-signature
    /// exists, [`RunError::NoCursor`] before any finalized block has
    /// been processed, [`RunError::Endpoint`] when `ready` is not this
    /// endpoint's channel, [`RunError::Policy`] when it carries another
    /// execution policy, [`RunError::Setup`] when the deadlines can no
    /// longer be met, [`RunError::Record`] when the stored bundle does
    /// not parse, and [`RunError::Store`] when the marker cannot be
    /// made durable.
    pub fn begin_run(
        &mut self,
        work_id: Digest,
        ready: &ReadyChannel,
    ) -> Result<RunAdmission, RunError> {
        let job = self.state().job().ok_or(RunError::NoSuchJob)?;
        if job.work_id() != work_id {
            return Err(RunError::NoSuchJob);
        }
        // A signed result exists in exactly the three phases past it, so
        // this is the phase test as well as the answer.
        if let Some((result, signature)) = job.result() {
            return Ok(RunAdmission::Ready {
                result: *result,
                signature: *signature,
            });
        }
        match job.phase() {
            JobPhase::Running if self.state().is_indeterminate() => {
                return Ok(RunAdmission::Indeterminate);
            }
            JobPhase::Running => return Ok(RunAdmission::Running),
            JobPhase::Accepted => {}
            phase => return Err(RunError::NotAccepted { phase }),
        }

        bind(ready, &self.store, &self.signer, Role::Provider)?;
        if ready.execution_policy() != self.ready.execution_policy() {
            return Err(RunError::Policy);
        }
        let Some((cursor_height, _)) = self.state().cursor() else {
            return Err(RunError::NoCursor);
        };
        let authorization = *job.authorization();
        // The same arithmetic the co-signature was made under, asked
        // again at the height dispatch is happening at. It is the same
        // question both times — can the measured dispatch and delivery
        // margins still fit before the terminal deadline — so it is not
        // spelled a second way here.
        ready.check_signable(
            cursor_height,
            authorization.terminal_deadline,
            authorization.payment_deadline,
        )?;

        let bundle = PreparedPaidInputV1::decode(job.prepared_input(), MAX_RECORD_BYTES)
            .map_err(PaidWorkError::from)?;
        let request = bundle
            .parts()
            .map_err(PaidWorkError::from)?
            .evaluate_request;

        self.store
            .commit(ChannelRecord::JobRunning, &Secp256k1Verifier::new())?;
        Ok(RunAdmission::Invoke(request))
    }

    /// Signs the result of the transcript this job's invocation
    /// produced, and returns it only once it is on the disk.
    ///
    /// The transcript is the provider's own: [`terminal_result`] refuses
    /// events that are not one verified chain for this authorization's
    /// request under the channel's provider key, and the journal refuses
    /// the record unless the job is running, is not indeterminate, and
    /// the result names it. Nothing here accepts a commitment chosen by
    /// anyone else, because nothing here takes one.
    ///
    /// # Errors
    ///
    /// [`RunError::NoSuchJob`] when no open job carries this `work_id`,
    /// [`RunError::Transcript`] when the events are not this job's
    /// terminal transcript, [`RunError::Record`] when the transcript is
    /// larger than the signed policy's spool, and [`RunError::Store`]
    /// when the journal refuses the record — which is what it does for a
    /// job that is not running, or one left indeterminate by a crash.
    pub fn record_result(
        &mut self,
        work_id: Digest,
        transcript: &[OutputEventEnvelope],
    ) -> Result<(PaidJobResultV1, Sig), RunError> {
        let job = self.state().job().ok_or(RunError::NoSuchJob)?;
        if job.work_id() != work_id {
            return Err(RunError::NoSuchJob);
        }
        let authorization = *job.authorization();
        let channel = self.ready.channel();
        let result =
            terminal_result(channel, &authorization, transcript).map_err(RunError::Transcript)?;
        let spool = encode_transcript(transcript).map_err(RunError::Transcript)?;
        let spooled = u64::try_from(spool.len()).unwrap_or(u64::MAX);
        let limit = self.ready.execution_policy().max_spool_bytes;
        if spooled > limit {
            return Err(RunError::Record(PaidWorkError::OverEnvelope {
                field: "spooled transcript length",
                actual: spooled,
                limit,
            }));
        }
        let signature = self
            .signer
            .sign(signing_hash(result_digest(channel, &result)));
        self.store.commit(
            ChannelRecord::JobResult {
                result,
                provider_signature: signature,
                transcript: spool,
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok((result, signature))
    }

    /// Releases the answer for a job whose result is signed and durable.
    ///
    /// The order is the module's rule applied to plaintext: the release
    /// is journaled — which is what debits this client's delivery
    /// credit — before a byte of the answer is returned. A crash between
    /// the two costs a round trip and no credit: the retry finds the job
    /// already delivered, re-commits the same marker as a redundant
    /// step, and hands back the same bytes.
    ///
    /// That is the whole of the idempotence claim, and it is worth being
    /// exact about its key. The marker is per open job, not per
    /// `(work_id, result_digest)` pair, because a job has at most one
    /// result: the journal refuses a second one for the same job
    /// outright. So a replay carrying a different result is not a
    /// conflict resolved here — it is a request this endpoint has no
    /// second answer to give.
    ///
    /// The deadline is checked on every call, including replays. A
    /// release begun too late to arrive is refused even though the
    /// plaintext already left on the first attempt, because the client's
    /// own journal refuses a receipt past the same deadline: bytes it
    /// may not record are bytes it cannot pay for.
    ///
    /// # Errors
    ///
    /// [`DeliverError::NoSuchJob`] when no open job carries this
    /// `work_id`, [`DeliverError::NoResult`] before the result is
    /// signed, [`DeliverError::Endpoint`] when `ready` is not this
    /// endpoint's channel, [`DeliverError::Policy`] when it carries
    /// another execution policy, [`DeliverError::NoCursor`] before any
    /// finalized block has been processed, [`DeliverError::Setup`] when
    /// the delivery margin no longer fits, and [`DeliverError::Store`]
    /// when the release cannot be made durable — which is what happens
    /// when this client's delivery credit is exhausted.
    pub fn deliver(
        &mut self,
        work_id: Digest,
        ready: &ReadyChannel,
    ) -> Result<Delivery, DeliverError> {
        let job = self.state().job().ok_or(DeliverError::NoSuchJob)?;
        if job.work_id() != work_id {
            return Err(DeliverError::NoSuchJob);
        }
        let Some((result, signature)) = job.result() else {
            return Err(DeliverError::NoResult { phase: job.phase() });
        };
        let (result, signature) = (*result, *signature);
        let transcript = job.transcript().to_vec();
        let terminal_deadline = job.authorization().terminal_deadline;

        bind(ready, &self.store, &self.signer, Role::Provider)?;
        if ready.execution_policy() != self.ready.execution_policy() {
            return Err(DeliverError::Policy);
        }
        let Some((cursor_height, _)) = self.state().cursor() else {
            return Err(DeliverError::NoCursor);
        };
        ready.check_releasable(cursor_height, terminal_deadline)?;

        self.store
            .commit(ChannelRecord::PlaintextReleased, &Secp256k1Verifier::new())?;
        Ok(Delivery {
            result,
            signature,
            transcript,
        })
    }

    /// Ends the open job, releasing what it still holds.
    ///
    /// What ending costs is the journal's to decide from how far the job
    /// got and why it stopped; this only records the decision.
    ///
    /// # Errors
    ///
    /// [`RunError::NoSuchJob`] when no open job carries this `work_id`,
    /// and [`RunError::Store`] when the ending cannot be made durable.
    pub fn end_run(&mut self, work_id: Digest, reason: JobEnd) -> Result<(), RunError> {
        let job = self.state().job().ok_or(RunError::NoSuchJob)?;
        if job.work_id() != work_id {
            return Err(RunError::NoSuchJob);
        }
        self.store.commit(
            ChannelRecord::JobEnded { reason },
            &Secp256k1Verifier::new(),
        )?;
        Ok(())
    }
}

// ── Running an accepted job ───────────────────────────────────────────

/// Why the local execution backend produced no transcript.
///
/// Opaque on purpose. What the gate does about it — release the job and
/// charge the client nothing — is the same for every fault a backend can
/// have, so distinguishing them here would be a distinction nothing
/// reads.
#[derive(Clone, Debug, thiserror::Error)]
#[error("the execution backend failed: {0}")]
pub struct BackendFault(String);

impl BackendFault {
    /// Records one backend fault, by its operator-facing text.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// The one seam a paid job crosses on its way to real execution.
///
/// One method, and it takes the request this endpoint rebuilt from its
/// own journal rather than anything a peer sent. What comes back is the
/// complete signed transcript of that invocation — not a digest of one,
/// because a digest is exactly what a backend that ran nothing could
/// also return.
///
/// Implementors must invoke once per call. That is not a property this
/// trait can check, and it is not the one the gate rests on: the gate
/// calls this at most once per `work_id` whatever the implementor does.
pub trait PaidEvaluateBackend {
    /// Runs one prepared Evaluate request to its terminal.
    fn evaluate(
        &self,
        request: EvaluateRequest,
    ) -> impl core::future::Future<Output = Result<Vec<OutputEventEnvelope>, BackendFault>> + Send;
}

/// What [`ProviderEndpoint::begin_run`] found, and what may be done next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunAdmission {
    /// The marker is durable and the backend has not been called.
    /// Invoke exactly once, with this request.
    Invoke(EvaluateRequest),
    /// This process marked the job and has not recorded its result.
    Running,
    /// A signed result already exists.
    Ready {
        /// The result.
        result: PaidJobResultV1,
        /// The provider's signature over its digest.
        signature: Sig,
    },
    /// A marker was found by a process that did not write it. Whether
    /// the backend ran is not knowable here, and nothing resolves it
    /// automatically.
    Indeterminate,
}

/// What one run of an accepted job produced.
///
/// [`Self::Completed`] is returned by at most one call per `work_id`,
/// ever: it is the answer of the call that invoked the backend. It is
/// *at most* rather than exactly one because that call can still fault —
/// a backend that refuses, or a journal that will not take the result,
/// leaves a job whose `Completed` never comes.
///
/// Neither variant carries the transcript, and no caller needs one to:
/// the invocation's events are journaled beside the result, and
/// [`ProviderEndpoint::deliver`] is what serves them. Handing them back
/// here as well would put the answer in two places and make the second
/// one look authoritative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// This call invoked the backend and recorded its terminal.
    Completed {
        /// The result, now durable.
        result: PaidJobResultV1,
        /// The provider's signature over its digest.
        signature: Sig,
    },
    /// A signed result was already durable.
    Ready {
        /// The result.
        result: PaidJobResultV1,
        /// The provider's signature over its digest.
        signature: Sig,
    },
    /// The job is running in this process. Ask again.
    Running,
    /// A crash left the invocation unresolved.
    Indeterminate,
}

/// Why one run of an accepted job did not produce a result.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// No open job on this channel carries this `work_id`.
    #[error("no open job on this channel carries this work id")]
    NoSuchJob,
    /// The job has no provider co-signature, so nothing authorises
    /// running it.
    #[error("a {phase} job has not been accepted, and may not run")]
    NotAccepted {
        /// How far the job has got.
        phase: JobPhase,
    },
    /// No finalized block has been processed, so no deadline can be
    /// measured.
    #[error("no finalized block has been processed on this channel")]
    NoCursor,
    /// The readiness offered is not this endpoint's own channel.
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    /// The readiness offered carries another execution policy than the
    /// one this endpoint accepts work under.
    #[error("the readiness offered was decided under another execution policy")]
    Policy,
    /// The deadlines can no longer be met, or the endpoint is behind.
    #[error(transparent)]
    Setup(#[from] WorkSetupError),
    /// The stored bundle is not a readable prepared input.
    #[error(transparent)]
    Record(#[from] PaidWorkError),
    /// The events offered are not this job's terminal transcript.
    #[error(transparent)]
    Transcript(PaidWorkError),
    /// The backend produced no transcript.
    #[error(transparent)]
    Backend(BackendFault),
    /// The journal refused the step, or could not take it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
}

/// Runs one accepted job on a real backend, at most once, ever.
///
/// The order, and the whole of why it is this order: the running marker
/// is journaled while the endpoint lock is held, the lock is then
/// released, and only then is the backend called. Releasing the lock is
/// deliberate — a synchronous journal must not be held across an
/// invocation that takes minutes — and it is safe because the marker on
/// the disk, not the lock, is what excludes a second call. A concurrent
/// call finds the job running; a call after a restart finds it
/// indeterminate.
///
/// A backend fault, or a transcript that is not this job's, ends the job
/// as failed. That releases the compute the co-signature reserved and
/// charges this client nothing, because neither is the client's doing.
///
/// # Errors
///
/// [`RunError::Backend`] for a backend fault and [`RunError::Transcript`]
/// for events that are not this job's terminal transcript — in both
/// cases after the job has been ended. If *that* ending cannot be
/// journaled, the journal's error is returned in place of the fault:
/// a job left running by a store that will not take its ending is the
/// more urgent fact, and it is the one an operator must see. Whatever
/// [`ProviderEndpoint::begin_run`] and [`ProviderEndpoint::record_result`]
/// raise otherwise.
pub async fn run_accepted_work<B>(
    service: &WorkService,
    ready: &ReadyChannel,
    backend: &B,
    work_id: Digest,
) -> Result<RunOutcome, RunError>
where
    B: PaidEvaluateBackend + Sync,
{
    let admission = {
        let mut endpoint = service.endpoint()?;
        endpoint.begin_run(work_id, ready)?
    };
    let request = match admission {
        RunAdmission::Invoke(request) => request,
        RunAdmission::Running => return Ok(RunOutcome::Running),
        RunAdmission::Indeterminate => return Ok(RunOutcome::Indeterminate),
        RunAdmission::Ready { result, signature } => {
            return Ok(RunOutcome::Ready { result, signature });
        }
    };

    let transcript = match backend.evaluate(request).await {
        Ok(transcript) => transcript,
        Err(fault) => return Err(end_failed(service, work_id, RunError::Backend(fault))),
    };

    let recorded = {
        let mut endpoint = service.endpoint()?;
        endpoint.record_result(work_id, &transcript)
    };
    match recorded {
        Ok((result, signature)) => Ok(RunOutcome::Completed { result, signature }),
        Err(fault @ RunError::Transcript(_)) => Err(end_failed(service, work_id, fault)),
        Err(error) => Err(error),
    }
}

// ── Delivering the answer ─────────────────────────────────────────────

/// One whole delivery: the signed result and the transcript it
/// summarises.
///
/// The two travel together because neither is the answer alone. The
/// result is a pair of digests the provider stands behind; the
/// transcript is the signed events those digests are over, and the
/// tokens the client actually wanted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// The provider's signed result.
    pub result: PaidJobResultV1,
    /// The provider's signature over its digest.
    pub signature: Sig,
    /// The encoded transcript, as [`decode_transcript`] reads it.
    pub transcript: Vec<u8>,
}

/// Why one delivery did not happen.
#[derive(Debug, thiserror::Error)]
pub enum DeliverError {
    /// No open job on this channel carries this `work_id`.
    #[error("no open job on this channel carries this work id")]
    NoSuchJob,
    /// The job has no signed result, so there is nothing to deliver.
    #[error("a {phase} job has no result to deliver")]
    NoResult {
        /// How far the job has got.
        phase: JobPhase,
    },
    /// The readiness offered is not this endpoint's own channel.
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    /// The readiness offered carries another execution policy than the
    /// one this endpoint works under.
    #[error("the readiness offered was decided under another execution policy")]
    Policy,
    /// No finalized block has been processed, so no deadline can be
    /// measured.
    #[error("no finalized block has been processed on this channel")]
    NoCursor,
    /// The delivery margin no longer fits, or the endpoint is behind.
    #[error(transparent)]
    Setup(#[from] WorkSetupError),
    /// The response is larger than the frame both parties authorized.
    #[error("the delivered frame is {actual} bytes, over the authorized {limit}")]
    OverFrame {
        /// Bytes the encoded delivery occupies.
        actual: u64,
        /// Bytes the signed execution policy allows.
        limit: u64,
    },
    /// A private-record rule refused the delivered bytes.
    #[error(transparent)]
    Record(#[from] PaidWorkError),
    /// The journal refused the step, or could not take it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
    /// The provider refused to deliver.
    #[error("the provider refused as {refusal}: {reason}")]
    Refused {
        /// Which of the six answers came back.
        refusal: WorkRefusal,
        /// The provider's diagnostic text, unchecked and uncovered by
        /// any digest.
        reason: String,
    },
    /// The response was not one of the shapes the service defines.
    #[error("the provider's response has no readable {0}")]
    Malformed(&'static str),
    /// The call did not complete.
    #[error("the work call failed: {0}")]
    Transport(#[from] WireStatus),
}

impl From<DeliverError> for Refusal {
    /// What a provider says on the wire when it will not deliver.
    ///
    /// The distinction the client's orchestration turns on is
    /// retryable-or-not. A job that has been accepted and has not
    /// finished is `NotReady` — asking again is exactly the right thing
    /// and is how a client learns the answer exists — while a job this
    /// channel does not have is `Declined`, because no wait produces
    /// one. A passed deadline is permanent, a cursor that has not caught
    /// up is the provider's own lag, and a journal that will not take
    /// the release is the provider's storage.
    ///
    /// The client-only arms are mapped so the match is total; a provider
    /// never builds one, and no test claims it does.
    fn from(error: DeliverError) -> Self {
        let reason = error.to_string();
        let code = match error {
            DeliverError::NoSuchJob => WorkRefusal::Declined,
            DeliverError::NoResult { .. } | DeliverError::NoCursor => WorkRefusal::NotReady,
            DeliverError::Setup(setup) => return Refusal::from(setup),
            DeliverError::Store(store) => return Refusal::from(store),
            _ => WorkRefusal::Invalid,
        };
        Self::new(code, reason)
    }
}

/// Ends the job as failed, and returns `fault` if that ending was
/// recorded.
fn end_failed(service: &WorkService, work_id: Digest, fault: RunError) -> RunError {
    let mut endpoint = match service.endpoint() {
        Ok(endpoint) => endpoint,
        Err(error) => return RunError::Endpoint(error),
    };
    match endpoint.end_run(work_id, JobEnd::Failed) {
        Ok(()) => fault,
        Err(error) => error,
    }
}

/// The generated `Work` handler over one provider endpoint.
///
/// Cheap to clone and shared by every connection a node serves, because
/// one channel has one journal however many peers dial it.
///
/// The lock is the endpoint's, not the journal's: the journal already
/// refuses a second *process*, and this is what serialises the
/// concurrent calls of one. It is never held across an await, because
/// deciding a proposal — hashing, verifying, and two synchronous journal
/// appends — never awaits.
#[derive(Clone, Debug)]
pub struct WorkService(Arc<Mutex<ProviderEndpoint>>);

impl WorkService {
    /// Wraps one provider endpoint as a dispatchable service.
    #[must_use]
    pub fn new(endpoint: ProviderEndpoint) -> Self {
        Self(Arc::new(Mutex::new(endpoint)))
    }

    /// Borrows the endpoint.
    ///
    /// # Errors
    ///
    /// [`EndpointError::Poisoned`] after a handler panicked while
    /// holding it. The state is not recovered, because a panic mid-
    /// commit is a bug whose durable effect this type cannot know.
    pub fn endpoint(&self) -> Result<MutexGuard<'_, ProviderEndpoint>, EndpointError> {
        self.0.lock().map_err(|_| EndpointError::Poisoned)
    }

    /// Answers one proposal, or says the endpoint is unreachable.
    ///
    /// Synchronous, and that is the whole of why the lock above is a
    /// plain [`Mutex`]: nothing between taking it and dropping it can
    /// await.
    fn answer(&self, request: &AcceptWorkRequest) -> AcceptWorkResponse {
        match self.endpoint() {
            Ok(mut endpoint) => endpoint.accept(request),
            Err(error) => AcceptWorkResponse {
                outcome: Some(Outcome::Refused(WorkRefused {
                    code: WorkRefusalCode::Unavailable as i32,
                    reason: error.to_string(),
                })),
            },
        }
    }

    /// Releases one job's answer, or says why not.
    ///
    /// The readiness it releases against is this service's own, which is
    /// the endpoint's — the one the channel was configured with, at the
    /// height it was decided at. Its freshness is the operator's in
    /// exactly the sense [`ReadyChannel`] documents; what is measured
    /// against it is the height this endpoint has actually processed
    /// finalized blocks through.
    fn release(&self, request: &DeliverResultRequest) -> DeliverResultResponse {
        let outcome = match self.endpoint() {
            Ok(mut endpoint) => match work_id_bytes(&request.work_id) {
                Some(work_id) => {
                    let ready = endpoint.ready.clone();
                    endpoint.deliver(work_id, &ready).map_err(Refusal::from)
                }
                None => Err(Refusal::invalid("the work id is not 32 bytes")),
            },
            Err(error) => Err(Refusal::new(WorkRefusal::Unavailable, error.to_string())),
        };
        DeliverResultResponse {
            outcome: Some(match outcome {
                Ok(delivery) => DeliverOutcome::Delivered(WorkDelivered {
                    result: delivery.result.encode(),
                    provider_signature: delivery.signature.as_bytes().to_vec(),
                    transcript: delivery.transcript,
                }),
                Err(refusal) => DeliverOutcome::Refused(WorkRefused {
                    code: refusal.code.code() as i32,
                    reason: refusal.reason,
                }),
            }),
        }
    }
}

impl WorkHandler for WorkService {
    fn accept_work(
        &self,
        request: AcceptWorkRequest,
    ) -> impl core::future::Future<
        Output = Result<impl Into<crate::call::WithTrailer<AcceptWorkResponse>> + Send, WireStatus>,
    > + Send {
        core::future::ready(Ok(self.answer(&request)))
    }

    fn deliver_result(
        &self,
        request: DeliverResultRequest,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<crate::call::WithTrailer<DeliverResultResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        core::future::ready(Ok(self.release(&request)))
    }
}

/// Reads a `work_id` from exactly its 32 bytes.
fn work_id_bytes(bytes: &[u8]) -> Option<Digest> {
    <[u8; Digest::LEN]>::try_from(bytes)
        .ok()
        .map(Digest::from_bytes)
}

// ── The client ────────────────────────────────────────────────────────

/// What a client wants done, before it is an authorization.
///
/// The two things a proposal actually chooses. Everything else in the
/// authorization is derived from the channel, the policy, and this
/// bundle by [`propose_authorization`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobProposal {
    /// The inputs the job runs on.
    pub prepared_input: PreparedPaidInputV1,
    /// The three heights the job is bound by.
    pub deadlines: JobDeadlines,
}

/// Why a client could not complete one acceptance exchange.
#[derive(Debug, thiserror::Error)]
pub enum ProposeError {
    /// The provider refused.
    #[error("the provider refused as {refusal}: {reason}")]
    Refused {
        /// Which of the six answers came back.
        refusal: WorkRefusal,
        /// The provider's diagnostic text, unchecked and uncovered by
        /// any digest.
        reason: String,
    },
    /// The response was not one of the shapes the service defines.
    #[error("the provider's response has no readable {0}")]
    Malformed(&'static str),
    /// No finalized block has been processed, so no deadline can be
    /// measured and nothing may be signed.
    #[error("no finalized block has been processed on this channel")]
    NoCursor,
    /// An acceptance was applied with no proposal outstanding.
    #[error("there is no proposal for this acceptance to answer")]
    NoOpenJob,
    /// A job is already past proposal, so the channel has no room for
    /// another.
    #[error("a job is already {phase} on this channel")]
    JobInFlight {
        /// How far the job in flight has got.
        phase: JobPhase,
    },
    /// A proposal is outstanding and this one is not it.
    #[error("a different proposal is already outstanding on this channel")]
    Conflict,
    /// A private-record rule refused the proposal.
    #[error(transparent)]
    Record(#[from] PaidWorkError),
    /// A readiness rule refused the proposal.
    #[error(transparent)]
    Setup(#[from] WorkSetupError),
    /// The journal refused the step, or could not take it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
    /// The call did not complete.
    #[error("the work call failed: {0}")]
    Transport(#[from] WireStatus),
}

/// The client half of the acceptance exchange.
///
/// It owns one channel's journal and proposes on that channel alone.
#[derive(Debug)]
pub struct ClientEndpoint {
    ready: ReadyChannel,
    store: ChannelStore,
    signer: Secp256k1Signer,
}

impl ClientEndpoint {
    /// Builds the client endpoint for one ready channel.
    ///
    /// # Errors
    ///
    /// [`EndpointError`] when the store, the readiness decision, and the
    /// key are not all the client's view of the same channel.
    pub fn new(
        ready: ReadyChannel,
        store: ChannelStore,
        signer: Secp256k1Signer,
    ) -> Result<Self, EndpointError> {
        bind(&ready, &store, &signer, Role::Client)?;
        Ok(Self {
            ready,
            store,
            signer,
        })
    }

    /// Returns what this endpoint durably knows.
    #[must_use]
    pub const fn state(&self) -> &ChannelState {
        self.store.state()
    }

    /// Returns the request that proposes this job, making it durable
    /// first.
    ///
    /// The nonce is journaled before the authorization carrying it is
    /// built, and the signature is journaled before this returns it, so
    /// a request in the caller's hand is a request the journal already
    /// accounts for. A crash before the first commit leaves nothing; a
    /// crash between the two leaves a burnt nonce and no proposal, and
    /// the retry burns the next one.
    ///
    /// Called again while a proposal is outstanding it returns that
    /// proposal's retained bytes rather than a second one — the crash
    /// after journaling and before sending. `proposal` must rebuild to
    /// the retained authorization for that to happen: this is one job at
    /// a time, and a caller asking for a different job is told so rather
    /// than being handed the old one under a new name.
    ///
    /// # Errors
    ///
    /// [`ProposeError::NoCursor`] before any finalized block has been
    /// processed, [`ProposeError::JobInFlight`] once a job is past
    /// proposal, [`ProposeError::Conflict`] when a different proposal is
    /// outstanding, and the record, readiness, and journal errors the
    /// proposal itself raises.
    pub fn propose(&mut self, proposal: &JobProposal) -> Result<AcceptWorkRequest, ProposeError> {
        let Some((cursor_height, _)) = self.state().cursor() else {
            return Err(ProposeError::NoCursor);
        };
        let policy = *self.ready.execution_policy();

        if let Some(job) = self.state().job() {
            if job.phase() != JobPhase::HalfSigned {
                return Err(ProposeError::JobInFlight { phase: job.phase() });
            }
            let retained = *job.authorization();
            let rebuilt = propose_authorization(
                self.ready.channel(),
                &policy,
                &proposal.prepared_input,
                retained.proposal_nonce,
                proposal.deadlines,
            )?;
            if rebuilt != retained {
                return Err(ProposeError::Conflict);
            }
            return Ok(wire_request(
                &retained,
                job.client_signature(),
                job.prepared_input().to_vec(),
            ));
        }

        let nonce = self.state().next_proposal_nonce();
        let authorization = propose_authorization(
            self.ready.channel(),
            &policy,
            &proposal.prepared_input,
            nonce,
            proposal.deadlines,
        )?;
        // Refused before the nonce is spent, so a proposal the provider
        // would reject does not cost this channel a sequence number.
        check_authorization(self.ready.channel(), &authorization, &policy, cursor_height)?;
        check_prepared_input(
            self.ready.channel(),
            &authorization,
            &policy,
            &proposal.prepared_input,
        )?;
        self.ready.check_signable(
            cursor_height,
            authorization.terminal_deadline,
            authorization.payment_deadline,
        )?;
        let prepared_input = proposal
            .prepared_input
            .encode()
            .map_err(PaidWorkError::from)?;
        let work_id = work_id(self.ready.channel(), &authorization);

        self.store.commit(
            ChannelRecord::NonceReserved { nonce },
            &Secp256k1Verifier::new(),
        )?;
        let signature = self.signer.sign(signing_hash(work_id));
        self.store.commit(
            ChannelRecord::JobProposed {
                authorization,
                client_signature: signature,
                prepared_input: prepared_input.clone(),
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok(wire_request(&authorization, signature, prepared_input))
    }

    /// Applies one provider answer, and returns the accepted `work_id`.
    ///
    /// The co-signature is journaled before this returns, and the store
    /// is what verifies it against the provider key over the retained
    /// job's own digest. A crash before that commit leaves the proposal
    /// half-signed and the client's retry re-sends the retained request;
    /// the provider's answer to the retry is the same signature.
    ///
    /// # Errors
    ///
    /// [`ProposeError::Refused`] for a refusal, [`ProposeError::NoOpenJob`]
    /// with nothing outstanding, [`ProposeError::Malformed`] for a
    /// response this service does not define, and
    /// [`ProposeError::Store`] when the signature is not the provider's
    /// or the journal will not take it.
    pub fn accepted(&mut self, response: &AcceptWorkResponse) -> Result<Digest, ProposeError> {
        let signature = match response.outcome.as_ref() {
            Some(Outcome::Accepted(accepted)) => signature(&accepted.provider_signature)
                .ok_or(ProposeError::Malformed("provider signature"))?,
            Some(Outcome::Refused(refused)) => {
                return Err(ProposeError::Refused {
                    refusal: WorkRefusal::from_code(refused.code)
                        .ok_or(ProposeError::Malformed("refusal code"))?,
                    reason: refused.reason.clone(),
                });
            }
            None => return Err(ProposeError::Malformed("outcome")),
        };
        let work_id = self
            .state()
            .job()
            .map(JobState::work_id)
            .ok_or(ProposeError::NoOpenJob)?;
        self.store.commit(
            ChannelRecord::JobAccepted {
                provider_signature: signature,
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok(work_id)
    }
}

impl ClientEndpoint {
    /// Takes one delivered answer, and makes it durable before it is
    /// returned.
    ///
    /// What this establishes, and the order it establishes it in: the
    /// encoded delivery is inside the frame both parties signed a bound
    /// for; the result parses as this profile's record; and the store
    /// takes it, which is where the three rules that matter live —
    /// the transcript rebuilds exactly this result, the signature is
    /// the provider's over its digest, and the receipt is at or before
    /// the terminal deadline. None of those is spelled a second time
    /// here.
    ///
    /// What it does *not* establish is that the answer is right. That
    /// is the oracle's, it runs on the bytes this returns, and its
    /// verdict is a separate durable step.
    ///
    /// # Errors
    ///
    /// [`DeliverError::NoSuchJob`] when no open job carries this
    /// `work_id`, [`DeliverError::Endpoint`] when `ready` is not this
    /// endpoint's channel, [`DeliverError::Policy`] when it carries
    /// another execution policy, [`DeliverError::NoCursor`] before any
    /// finalized block has been processed, [`DeliverError::Setup`] when
    /// this endpoint has not caught up to that readiness,
    /// [`DeliverError::OverFrame`] above the signed frame bound,
    /// [`DeliverError::Malformed`] for a signature that is not 64
    /// bytes, [`DeliverError::Record`] when the result does not parse,
    /// and [`DeliverError::Store`] for every rule above.
    pub fn receive(
        &mut self,
        work_id: Digest,
        ready: &ReadyChannel,
        delivered: &WorkDelivered,
    ) -> Result<Delivery, DeliverError> {
        let job = self.state().job().ok_or(DeliverError::NoSuchJob)?;
        if job.work_id() != work_id {
            return Err(DeliverError::NoSuchJob);
        }

        bind(ready, &self.store, &self.signer, Role::Client)?;
        if ready.execution_policy() != self.ready.execution_policy() {
            return Err(DeliverError::Policy);
        }
        let Some((cursor_height, _)) = self.state().cursor() else {
            return Err(DeliverError::NoCursor);
        };
        ready.check_caught_up(cursor_height)?;

        // The bound is on the encoded message, which is what this
        // endpoint agreed to hold; the transport's own framing around
        // it is the transport's and is not measured here.
        let limit = u64::from(ready.execution_policy().max_encoded_result_frame);
        let actual = u64::try_from(delivered.encoded_len()).unwrap_or(u64::MAX);
        if actual > limit {
            return Err(DeliverError::OverFrame { actual, limit });
        }

        let result = PaidJobResultV1::decode(&delivered.result)?;
        let signature = signature(&delivered.provider_signature)
            .ok_or(DeliverError::Malformed("provider signature"))?;
        self.store.commit(
            ChannelRecord::JobResult {
                result,
                provider_signature: signature,
                transcript: delivered.transcript.clone(),
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok(Delivery {
            result,
            signature,
            transcript: delivered.transcript.clone(),
        })
    }

    /// Records that this client's own oracle reproduced the answer.
    ///
    /// It takes no verdict argument, and that is deliberate: a function
    /// that could be handed `false` would be a function some caller
    /// could hand `true`. The only way to record a verdict is to have
    /// one, and the caller that has one calls this.
    ///
    /// # Errors
    ///
    /// [`DeliverError::NoSuchJob`] when no open job carries this
    /// `work_id`, and [`DeliverError::Store`] when the job has no
    /// recorded result or the verdict cannot be made durable.
    pub fn verified(&mut self, work_id: Digest) -> Result<(), DeliverError> {
        let job = self.state().job().ok_or(DeliverError::NoSuchJob)?;
        if job.work_id() != work_id {
            return Err(DeliverError::NoSuchJob);
        }
        self.store
            .commit(ChannelRecord::ResultVerified, &Secp256k1Verifier::new())?;
        Ok(())
    }
}

/// Asks for one accepted job's answer over a live transport and makes it
/// durable.
///
/// Idempotent by the same rule as the exchange above: a lost response
/// costs a round trip, because the provider answers a second call from
/// its own spool and this endpoint's store takes the same result twice
/// as one.
///
/// # Errors
///
/// [`DeliverError::Transport`] when the call does not complete,
/// [`DeliverError::Refused`] for a refusal, [`DeliverError::Malformed`]
/// for a response this service does not define, and whatever
/// [`ClientEndpoint::receive`] raises.
pub async fn fetch_result<T>(
    transport: T,
    endpoint: &mut ClientEndpoint,
    ready: &ReadyChannel,
    work_id: Digest,
) -> Result<Delivery, DeliverError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let response = WorkClientImpl::new(transport)
        .deliver_result(DeliverResultRequest {
            work_id: work_id.as_bytes().to_vec(),
        })
        .await?;
    match response.outcome {
        Some(DeliverOutcome::Delivered(delivered)) => endpoint.receive(work_id, ready, &delivered),
        Some(DeliverOutcome::Refused(refused)) => Err(DeliverError::Refused {
            refusal: WorkRefusal::from_code(refused.code)
                .ok_or(DeliverError::Malformed("refusal code"))?,
            reason: refused.reason,
        }),
        None => Err(DeliverError::Malformed("outcome")),
    }
}

/// Proposes one job over a live transport and applies the answer.
///
/// The whole exchange, in the order the durability rule fixes: journal,
/// send, journal. Nothing between the two commits is retried here — a
/// transport fault leaves a durable half-signed proposal, and calling
/// this again with the same proposal re-sends the retained bytes.
///
/// # Errors
///
/// [`ProposeError::Transport`] when the call does not complete, and
/// whatever [`ClientEndpoint::propose`] or [`ClientEndpoint::accepted`]
/// raises.
pub async fn propose_work<T>(
    transport: T,
    endpoint: &mut ClientEndpoint,
    proposal: &JobProposal,
) -> Result<Digest, ProposeError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let request = endpoint.propose(proposal)?;
    let response = WorkClientImpl::new(transport).accept_work(request).await?;
    endpoint.accepted(&response)
}

// ── Wire shapes ───────────────────────────────────────────────────────

fn wire_request(
    authorization: &PaidJobAuthorizationV1,
    client_signature: Sig,
    prepared_input: Vec<u8>,
) -> AcceptWorkRequest {
    AcceptWorkRequest {
        authorization: authorization.encode(),
        client_signature: client_signature.as_bytes().to_vec(),
        prepared_input,
    }
}

/// Reads a compact secp256k1 signature from exactly its 64 bytes.
///
/// There is no key-kind discriminator to read: the channel's parties are
/// native secp256k1 keys fixed by the payment terms, so a signature of
/// any other shape is not a signature this channel could verify.
fn signature(bytes: &[u8]) -> Option<Sig> {
    <[u8; Sig::LENGTH]>::try_from(bytes)
        .ok()
        .map(Sig::from_bytes)
}
