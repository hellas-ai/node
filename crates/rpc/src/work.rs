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
//! # What this phase does not carry
//!
//! Dispatch, result delivery, invoicing, and certificate admission. Each
//! needs a producer that does not exist yet — an execution backend, a
//! retained transcript, a semantic oracle — and a message with nothing
//! on either end of it is not a protocol.

use std::sync::{Arc, Mutex, MutexGuard};

use hellas_kernel::{Secp256k1Signer, Secp256k1Verifier, Sig};
use hellas_wire::{StreamTransport, WireStatus};

use crate::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, WorkAccepted, WorkRefusalCode, WorkRefused,
    accept_work_response::Outcome,
};
use crate::protocol::Digest;
use crate::protocol::artifacts::PreparedPaidInputV1;
use crate::protocol::work::{
    JobDeadlines, PaidJobAuthorizationV1, PaidWorkError, PrivateRecord as _, check_authorization,
    check_prepared_input, propose_authorization, signing_hash, work_id,
};
use crate::protocol::work_setup::{ReadyChannel, WorkSetupError};
use crate::services::work::{WorkClientImpl, WorkHandler};
use crate::work_store::journal::MAX_RECORD_BYTES;
use crate::work_store::{
    ChannelRecord, ChannelState, ChannelStateError, ChannelStore, JobPhase, JobState, Role,
    WorkStoreError,
};

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
    /// The provider has not processed a finalized block it can admit
    /// work at. Retryable unchanged.
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
/// invoice, a cursor — and are mapped so the match is total, not because
/// a proposal can produce them.
const fn channel_refusal(error: &ChannelStateError) -> WorkRefusal {
    match error {
        ChannelStateError::Nonce { .. } | ChannelStateError::Conflict { .. } => {
            WorkRefusal::Conflict
        }
        ChannelStateError::WrongPhase { .. }
        | ChannelStateError::OverCredit { .. }
        | ChannelStateError::UnallocatedGap { .. }
        | ChannelStateError::Indeterminate => WorkRefusal::Declined,
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
