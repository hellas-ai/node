//! One channel's durable state: its one job, its credit, and the
//! certificates that pay for it.
//!
//! # Why this exists
//!
//! What says this channel's one job was paid for at most once is the
//! permanent terminal it rests at, together with the cumulative the
//! `CreditLedger` credited — and both are values in memory. A process
//! that lost them and started again would credit the same job at a
//! fresh cumulative, and nothing in the records themselves could tell
//! the difference. This module is where they live across a restart, and
//! it is what makes "paid once" a property of the endpoint rather than
//! of the process.
//!
//! # The order every rule here is about
//!
//! For each of the four signed artifacts — the client's authorization,
//! the provider's co-signature, the provider's result, and the client's
//! binding and certificate — the rule is the same: the record is fsynced
//! first, and only then does the signature leave the process.
//! [`ChannelStore::commit`] returns after `fsync`; a crash before it
//! returns loses a signature nobody has, and a crash after it returns is
//! recovered by re-sending retained bytes, never by signing again.
//!
//! Two credit checks have the same shape. The one job's price is
//! checked against the compute limit before the provider co-signs, not
//! when it dispatches, because a signature it cannot afford to honour
//! is already the loss. It is checked against the delivery limit before
//! the plaintext leaves, because afterwards there is nothing left to
//! decide.
//!
//! # A step is judged at its own height
//!
//! Several records are legal only up to a height — the co-signature,
//! the receipt, the payment. A replay therefore reads the journal the
//! way it was written: [`ChannelStore::open`] moves the cursor record
//! by record, so every historical step is re-checked against the
//! finalized height it was actually taken at. Judging an old step by a
//! later tip is how a file that was legal at every step becomes a file
//! that cannot be opened.
//!
//! # What a record is
//!
//! Twelve tags, and every one of them is a boundary something else
//! cannot be read off. Four carry a signed artifact — the
//! authorization, the co-signature, the result, and the certificate with
//! its binding inside the certified terminal — and for each of those
//! [`ChannelStore`] verifies the signature against the party the channel
//! names, over that record's own digest, on commit *and* on replay. A
//! journal that would not have been accepted a record at a time is not
//! accepted whole.
//!
//! The result carries one thing more, and it is the only record here
//! checked against something other than a key: the transcript it
//! summarises rides with it, and the result must be what
//! [`terminal_result`] rebuilds from those events. A signature says the
//! provider stands behind two digests; the rebuild says the digests are
//! that transcript's.
//!
//! Three — the running marker, the plaintext release, and the match —
//! are this endpoint's own statements about itself. Nothing signs them,
//! and nothing here pretends to check them against anything but the
//! state they move. The terminal is one record with five outcomes:
//! certified is the fourth signed artifact above, and the other four
//! are the ways the job stops without a payment. The last five — the
//! cursor and the four close records — are what this endpoint read
//! out of finalized blocks, plus the two answers it fixed on its own
//! disk before sending them: the start it opens a contest with, and
//! the response it gives one.
//!
//! None of it defends the file against someone who can write it; see
//! [`super::journal`].
//!
//! # What one job means here
//!
//! The profile admits one job at a time: at most one half-signed,
//! accepted, running, ready, or delivered-unpaid job exists in durable
//! state. That is why the job-scoped records carry no job identifier —
//! there is exactly one job they could be about — and why a payment
//! settles exactly the open job. A concurrent profile needs a job
//! identifier in every record; it is not this one.

use std::path::Path;

use hellas_kernel::{
    Decode, EarnedCertificate, Encode, Key, NetworkId, Party, PayloadHash, PaymentCloseStart, Sig,
    SigVerifier, StartId, WorkPaymentSettlement,
};
use hellas_xet::XetFileHasher;

use crate::protocol::Digest;
use crate::protocol::artifacts::PreparedPaidInputV1;
use crate::protocol::work::{
    CreditLedger, PaidChannel, PaidJobAuthorizationV1, PaidJobResultV1, PaidWorkError,
    PaymentBindingV1, PrivateRecord as _, decode_transcript, payment_binding_digest,
    prepared_input_digest, result_digest, signing_hash, terminal_result, work_id,
};
use crate::work_store::journal::{
    Journal, JournalError, JournalId, JournalKind, MAX_CHECKPOINT_BYTES, MAX_RECORD_BYTES, Role,
};
use crate::work_store::setup::SetupOrigin;
use crate::work_store::{
    Applied, WorkStoreError, cursor::Cursor, hex, put_bytes, put_option, put_u64, take_bool,
    take_bytes, take_option,
};

/// Domain of a channel journal's key.
const CHANNEL_KEY: &[u8] = b"hellas.work.channel-journal-key.v1";

/// Why a channel record is not one this state may hold.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChannelStateError {
    /// A private-record rule refused the record's own contents.
    #[error(transparent)]
    Record(#[from] PaidWorkError),
    /// A carried signature is not the named party's over this record's
    /// digest.
    #[error("the {slot} signature is not {party}'s over this record")]
    BadSignature {
        /// Which signature failed.
        slot: &'static str,
        /// Party whose key it was checked against.
        party: &'static str,
    },
    /// A step was recorded from a state that cannot take it.
    #[error("{step} cannot be recorded while the job is {phase}")]
    WrongPhase {
        /// Step that was attempted.
        step: &'static str,
        /// Phase the job is in, or `none`.
        phase: &'static str,
    },
    /// A step belongs to the other role.
    #[error("{step} is a {expected} step, and this journal is not one")]
    WrongRole {
        /// Step that was attempted.
        step: &'static str,
        /// Role that may take it.
        expected: &'static str,
    },
    /// A record named another channel, another job, or another entry
    /// than the one this state holds.
    #[error("the record's {field} is not this channel's")]
    WrongChannel {
        /// Which field disagreed.
        field: &'static str,
    },
    /// This channel's one job has already reached its permanent
    /// terminal, and this step would be a second job or a late reply to
    /// the finished one.
    ///
    /// The channel admits one job for its whole life. Once that job is
    /// certified, refuted, expired, failed, or indeterminate, its
    /// [`JobTerminal`] is on the disk forever: a fresh proposal has
    /// nothing to open, and a co-signature, result, or verdict that
    /// arrives now is answering a job that is over. This is that refusal.
    #[error("{step} is refused: this channel's one job is {outcome}")]
    Terminated {
        /// Step that was attempted.
        step: &'static str,
        /// The terminal the job already reached.
        outcome: &'static str,
    },
    /// A credit limit would have been exceeded.
    #[error("{ledger} credit: {used} lost plus {reserved} reserved plus {price} exceeds {limit}")]
    OverCredit {
        /// Which limit.
        ledger: &'static str,
        /// Unrecovered loss against this counterparty.
        used: u64,
        /// Reserved against the job in flight.
        reserved: u64,
        /// Price this job would add.
        price: u64,
        /// Limit the channel policy fixes.
        limit: u64,
    },
    /// A result arrived for an invocation this process did not make and
    /// cannot know the outcome of.
    #[error("the job's invocation is indeterminate after a restart; a result now would be a guess")]
    Indeterminate,
    /// A provider co-signature was applied after its authorization's
    /// acceptance deadline.
    #[error(
        "a job accepted at finalized height {height} is past the acceptance deadline {deadline}"
    )]
    AcceptanceLate {
        /// Finalized cursor consumed by the durable apply.
        height: u64,
        /// Deadline the authorization carries.
        deadline: u64,
    },
    /// Backend dispatch was durably applied after the terminal deadline.
    #[error(
        "a job dispatched at finalized height {height} is past the terminal deadline {deadline}"
    )]
    DispatchLate {
        /// Finalized cursor consumed by the durable apply.
        height: u64,
        /// Deadline the authorization carries.
        deadline: u64,
    },
    /// A result reached the client after the height it was owed by.
    ///
    /// Late plaintext earns nothing: the provider signed a terminal
    /// deadline, and a client that recorded a receipt past it would be
    /// building the evidence for a payment the same deadline refuses.
    #[error(
        "a result received at finalized height {height} is past the terminal deadline {deadline}"
    )]
    ReceiptLate {
        /// Finalized height the client had processed through.
        height: u64,
        /// Deadline the authorization carries.
        deadline: u64,
    },
    /// A client signed a payment after the height it owed it by.
    ///
    /// Past that height the provider may end this job as expired and
    /// charge its price to this client's loss ledger. A certificate
    /// signed afterwards is executable money whatever the journal
    /// later says, while nothing takes the loss back — so the client
    /// would have paid for one job twice.
    #[error(
        "a payment signed at finalized height {height} is past the payment deadline {deadline}"
    )]
    PaymentLate {
        /// Finalized height the client had processed through.
        height: u64,
        /// Deadline the authorization carries.
        deadline: u64,
    },
    /// The finalized cursor did not move on by exactly one block.
    ///
    /// A skipped height is a block this endpoint never read, and every
    /// close and every certificate it would have carried is a fact this
    /// journal would then be missing.
    #[error("cursor height {actual} is not the block after {held}")]
    CursorNotNext {
        /// Height already recorded.
        held: u64,
        /// Height the record carried.
        actual: u64,
    },
    /// The next block does not name the block the cursor holds as its
    /// parent.
    #[error("the block at height {height} is not a child of the cursor's block")]
    CursorNotContiguous {
        /// Height the record carried.
        height: u64,
    },
    /// A step needs a channel whose payment close has not begun.
    #[error("{step} is refused: this channel's payment close has begun")]
    Closing {
        /// Step that was attempted.
        step: &'static str,
    },
    /// The same step was recorded twice with different contents.
    #[error("{what} was already recorded with different contents")]
    Conflict {
        /// What repeated.
        what: &'static str,
    },
    /// A record's bytes were not canonical.
    #[error("channel record is not canonical")]
    Malformed,
}

/// How far one job has got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobPhase {
    /// The client's signature exists; the provider's does not.
    HalfSigned,
    /// Both signatures exist. Nothing has been invoked.
    Accepted,
    /// The backend may have been invoked. Provider-only.
    Running,
    /// A signed terminal result exists.
    Ready,
    /// The client's own re-execution reproduced the answer and it
    /// matched. Client-only.
    Matched,
    /// The plaintext has left the provider. Provider-only.
    Delivered,
}

impl core::fmt::Display for JobPhase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl JobPhase {
    const fn name(self) -> &'static str {
        match self {
            Self::HalfSigned => "half-signed",
            Self::Accepted => "accepted",
            Self::Running => "running",
            Self::Ready => "ready",
            Self::Matched => "matched",
            Self::Delivered => "delivered",
        }
    }

    /// Whether reaching this phase means plaintext left the provider.
    const fn delivered(self) -> bool {
        matches!(self, Self::Delivered)
    }

    const fn code(self) -> u8 {
        match self {
            Self::HalfSigned => 0,
            Self::Accepted => 1,
            Self::Running => 2,
            Self::Ready => 3,
            Self::Matched => 4,
            Self::Delivered => 5,
        }
    }

    const fn from_code(code: u8) -> Result<Self, ChannelStateError> {
        match code {
            0 => Ok(Self::HalfSigned),
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Running),
            3 => Ok(Self::Ready),
            4 => Ok(Self::Matched),
            5 => Ok(Self::Delivered),
            _ => Err(ChannelStateError::Malformed),
        }
    }

    /// Which role a job in this phase belongs to, when only one may hold
    /// it.
    const fn only_role(self) -> Option<Role> {
        match self {
            Self::Running | Self::Delivered => Some(Role::Provider),
            Self::Matched => Some(Role::Client),
            _ => None,
        }
    }

    /// Whether a signed result exists once a job has reached this phase.
    const fn has_result(self) -> bool {
        matches!(self, Self::Ready | Self::Matched | Self::Delivered)
    }
}

/// How this channel's one job ended, permanently.
///
/// The channel admits one job for its whole life, and this is where that
/// job comes to rest. One of these is written once, is never taken back,
/// and from then on the channel proposes no second job and answers no
/// late reply to the first. Only [`Self::Certified`] is a job that was
/// paid for; the other four are the ways a job stops without a payment,
/// and the provider bears whatever compute or delivery it already spent
/// on them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalOutcome {
    /// The client's certificate paid for the job. These are the exact
    /// bytes a recovered endpoint re-sends: the job is closed, so this is
    /// the only remaining copy of what was agreed.
    Certified {
        /// The scalar consensus will settle.
        certificate: EarnedCertificate,
        /// The private evidence of what it bought.
        binding: PaymentBindingV1,
        /// The client's signature over the binding's digest.
        binding_signature: Sig,
        /// The client's signature over the kernel's earned digest.
        certificate_signature: Sig,
    },
    /// The client's own re-execution did not reproduce the signed result.
    /// The job is over and unpayable; these two digests are what
    /// disagreed.
    Refuted {
        /// The digest the provider signed.
        result_digest: Digest,
        /// The digest the client's re-execution produced.
        reproduction_digest: Digest,
    },
    /// The job can no longer be paid for, at this finalized height:
    /// either a deadline passed with it unfinished or unpaid, or a close
    /// on the payment edge cut it off before one did — a contest or a
    /// settlement admits no payment after it, however much room the
    /// deadline still had.
    Expired {
        /// Deadline the authorization carried — the one that passed, or
        /// the payment deadline the cut-off job could no longer meet.
        deadline: u64,
        /// Finalized height the cursor held when the job expired.
        height: u64,
        /// That block's payload digest.
        payload: [u8; 32],
    },
    /// Execution or validation failed, with the backend's code.
    Failed {
        /// A code naming the failure.
        code: u32,
    },
    /// The process crashed between invocation and terminal persistence,
    /// and no local state can say what the invocation did. Recording this
    /// is an operator's decision, never an automatic one.
    Indeterminate,
}

impl TerminalOutcome {
    /// A one-word name for this terminal, for a refusal message.
    const fn name(&self) -> &'static str {
        match self {
            Self::Certified { .. } => "certified",
            Self::Refuted { .. } => "refuted",
            Self::Expired { .. } => "expired",
            Self::Failed { .. } => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// This channel's one job, named and resting at its permanent terminal.
///
/// One per channel, ever. It is what makes "one `work_id` opens at most
/// one job" a fact about this file: while it is absent a job may be
/// proposed, and once it is present nothing proposes another or replies
/// to the one it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobTerminal {
    /// The job that ended.
    pub work_id: Digest,
    /// The phase it had reached when it ended.
    pub phase: JobPhase,
    /// How it ended.
    pub outcome: TerminalOutcome,
}

mod outcome_code {
    pub(super) const CERTIFIED: u8 = 0;
    pub(super) const REFUTED: u8 = 1;
    pub(super) const EXPIRED: u8 = 2;
    pub(super) const FAILED: u8 = 3;
    pub(super) const INDETERMINATE: u8 = 4;
}

/// One durable step of a channel's life.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelRecord {
    /// Finalized blocks have been processed through this block.
    ///
    /// The parent rides with the payload because a cursor is only worth
    /// something if it is contiguous: a height alone would let a
    /// watcher skip from block 7 to block 20 and still report that it
    /// had processed everything through 20. What it would have skipped
    /// is every close and every deadline those thirteen blocks crossed.
    CursorAdvanced {
        /// Height processed through.
        height: u64,
        /// The payload digest that block names as its parent.
        parent: [u8; 32],
        /// That block's own payload digest.
        payload: [u8; 32],
    },
    /// The client's signed authorization, and the inputs it commits to.
    ///
    /// The prepared bundle rides here because the quote it came from is
    /// transient: a provider that accepted a job and then restarted must
    /// still be able to execute exactly the job it accepted, and an
    /// authorization carries only the digest of those inputs.
    JobProposed {
        /// The body both parties sign.
        authorization: PaidJobAuthorizationV1,
        /// The client's signature over its `work_id`.
        client_signature: Sig,
        /// The canonical prepared-input bundle the authorization's
        /// `prepared_input_digest` commits to.
        prepared_input: Vec<u8>,
    },
    /// The provider's co-signature over the same `work_id`.
    JobAccepted {
        /// The provider's signature.
        provider_signature: Sig,
    },
    /// The provider is about to invoke the backend.
    JobRunning,
    /// The provider's signed terminal result, and the signed events it
    /// summarises.
    ///
    /// The transcript rides here because the result is a pair of digests
    /// over it: a provider that kept only the digests could not deliver
    /// the answer it was paid for after a restart, and a client that
    /// kept only the digests could not run its own re-execution without
    /// asking the provider for the bytes again.
    JobResult {
        /// The result body.
        result: PaidJobResultV1,
        /// The provider's signature over its digest.
        provider_signature: Sig,
        /// The transcript the result was derived from.
        transcript: Vec<u8>,
    },
    /// The provider is about to release the plaintext.
    PlaintextReleased,
    /// The client's own re-execution reproduced this job's answer and it
    /// matched.
    ///
    /// Client-only, and it is the whole of what makes a delivered result
    /// payable. Nothing else on this journal distinguishes an answer that
    /// was reproduced from one that merely arrived signed, and without it
    /// a client that fetched a result its own re-execution refused could
    /// still sign a certificate for it. `hellas_client::work` writes this
    /// at exactly one place — immediately after the reproduction matched
    /// — and the payment rule below is what makes that one place the only
    /// way to reach a payment.
    ResultMatched,
    /// This channel's one job reaches its permanent terminal.
    ///
    /// It replaces both the old payment record and the old ending: a
    /// [`TerminalOutcome::Certified`] is the certificate and binding a
    /// payment admitted, and the other four are the ways a job stops
    /// without one. Written once, never taken back — the money (when
    /// there is money) and the close of the job reach the disk in the
    /// same `fsync` or neither does. The `work_id` and the phase the job
    /// had reached are read off the open job this record ends, not
    /// carried here: there is exactly one job they could be about.
    JobTerminated {
        /// How the job ended.
        outcome: TerminalOutcome,
    },
    /// This endpoint has signed a close start, and these are its exact
    /// bytes.
    ///
    /// Written before the signature leaves the process, like every
    /// other signature here — and it is the cutoff for as long as those
    /// bytes could still reach a block. While they could, the channel
    /// admits no new job and credits no new certificate, because a
    /// close that left out a certificate it was still admitting would
    /// be a close below what was earned. Once the window has passed
    /// with no contest on this disk, the signature can reach nothing
    /// and holds nothing shut; see [`ChannelState::is_closing`].
    ClosePrepared {
        /// The signed start, exactly as it will be submitted.
        ///
        /// Boxed because a start reveals the channel's complete terms
        /// and is the widest thing this enum carries by a long way; the
        /// other ten records would otherwise each be as large as it.
        start: Box<PaymentCloseStart>,
    },
    /// A close contest on this channel's payment edge was finalized.
    ///
    /// Two things the block says and nothing else can. The contest
    /// identifier cannot be derived from a retained signature: the
    /// kernel takes it from the start digest *and the height that
    /// accepted it*. And the opener cannot be recovered from the
    /// identifier, which is a hash — so an endpoint that dropped it
    /// could never afterwards say whether the contest that shut its
    /// channel was its own or the counterparty's, which is the whole of
    /// who owes for the job it cut off.
    CloseOpened {
        /// Contest a later response or close must name.
        start_id: StartId,
        /// Which party opened it.
        opener: Party,
        /// Height at which the response window shuts. The block that
        /// accepted the start fixed it, and recovery reads it here rather
        /// than from a second finalized snapshot: a provider that
        /// restarts with this record must know whether the window it may
        /// answer in is still open.
        response_deadline: u64,
        /// The cumulative amount the opener's own start claimed. A
        /// provider answers only a contest opened below what it already
        /// holds, so this is the floor its own certificate must strictly
        /// exceed for an answer to exist.
        claimed: u64,
    },
    /// This endpoint has fixed its answer to the contest on its payment
    /// edge, and this is the digest that answer's signature covers.
    ///
    /// Written before the response leaves the process, like every other
    /// signature here. What it says is that the answer is *chosen*, and
    /// that is all it says: it is fsynced before the submission it
    /// authorises, so a process that dies between the two leaves a
    /// journal holding an answer consensus has never seen. Read as
    /// "handed off" it would be a lie exactly then, which is why nothing
    /// in the duty rule consults it — see
    /// [`ChannelState::answerable_contest`], which decides what is owed
    /// from the contest and the certificate alone.
    ///
    /// The digest rather than the bytes, because the bytes are derived
    /// rather than kept: an answer is fixed by the contest it names and
    /// the certificate this journal already holds, and neither can change
    /// once a contest is open — the channel admits no work and credits no
    /// certificate from [`Self::CloseOpened`] onwards. So a resubmission
    /// re-derives the same answer, and this is what refuses a different
    /// one.
    CloseResponded {
        /// Contest this answer names.
        start_id: StartId,
        /// Digest the responder signed, over the answer's own body.
        response_digest: PayloadHash,
    },
    /// A close consuming this channel's payment edge was finalized.
    CloseSettled {
        /// Height of the block that carried it.
        height: u64,
        /// That block's payload digest.
        payload: [u8; 32],
        /// What the close paid the provider.
        provider_payout: u64,
    },
}

mod tag {
    pub(super) const CURSOR: u8 = 0;
    pub(super) const PROPOSED: u8 = 1;
    pub(super) const ACCEPTED: u8 = 2;
    pub(super) const RUNNING: u8 = 3;
    pub(super) const RESULT: u8 = 4;
    pub(super) const PLAINTEXT: u8 = 5;
    pub(super) const MATCHED: u8 = 6;
    pub(super) const TERMINATED: u8 = 7;
    pub(super) const CLOSE_PREPARED: u8 = 8;
    pub(super) const CLOSE_OPENED: u8 = 9;
    pub(super) const CLOSE_SETTLED: u8 = 10;
    pub(super) const CLOSE_RESPONDED: u8 = 11;
}

/// What one job can still add to a checkpoint after it is proposed.
///
/// The result the provider will sign, the signature over it, and the
/// certified terminal that pays for it — all fixed-width. The transcript
/// is deliberately not in here: it is the one variable-width thing a
/// proposal cannot know, and it is charged where it is known, at
/// [`ChannelRecord::JobResult`], which is still ahead of the provider's
/// own signature leaving the process.
const JOB_TAIL_BYTES: usize = PaidJobResultV1::ENCODED_SIZE
    + PaymentBindingV1::ENCODED_SIZE
    + EarnedCertificate::ENCODED_SIZE
    + 4 * Sig::LENGTH
    + 64;

impl ChannelRecord {
    /// What this step must leave room for in one checkpoint, when
    /// recording it is what lets a signature leave.
    ///
    /// `None` for the records that carry no signature and no
    /// variable-width body: a cursor advance, a running marker, a
    /// plaintext release, a match, and the two a finalized block
    /// dictates. Those cannot move the width of a checkpoint by anything
    /// this endpoint chooses.
    const fn checkpoint_tail(&self) -> Option<usize> {
        match self {
            Self::JobProposed { .. } => Some(JOB_TAIL_BYTES),
            Self::JobAccepted { .. }
            | Self::JobResult { .. }
            | Self::JobTerminated { .. }
            | Self::ClosePrepared { .. }
            | Self::CloseResponded { .. } => Some(0),
            _ => None,
        }
    }

    /// Whether this step takes on an obligation rather than discharging
    /// one.
    ///
    /// The proposal, and only the proposal. Everything after it follows
    /// a signature already exported — the co-signature the client is
    /// waiting on, the result it bought, the payment, the close, the
    /// answer, and every block the cursor must cross to know about
    /// them — and a journal that refused those would be one that stopped
    /// a duty it had already taken on.
    const fn is_new_work(&self) -> bool {
        matches!(self, Self::JobProposed { .. })
    }

    /// Returns this record's canonical bytes.
    ///
    /// Each nested body is its own canonical encoding — the private
    /// record's, or the kernel's — so the journal holds exactly the
    /// bytes whose digests the signatures beside them cover.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::CursorAdvanced {
                height,
                parent,
                payload,
            } => {
                out.push(tag::CURSOR);
                put_u64(&mut out, *height);
                out.extend_from_slice(parent);
                out.extend_from_slice(payload);
            }
            Self::JobProposed {
                authorization,
                client_signature,
                prepared_input,
            } => {
                out.push(tag::PROPOSED);
                out.extend_from_slice(&authorization.encode());
                out.extend_from_slice(client_signature.as_bytes());
                // Last field, and the whole of the rest: the journal
                // frame already carries this record's length, and a
                // second length here could disagree with it.
                out.extend_from_slice(prepared_input);
            }
            Self::JobAccepted { provider_signature } => {
                out.push(tag::ACCEPTED);
                out.extend_from_slice(provider_signature.as_bytes());
            }
            Self::JobRunning => out.push(tag::RUNNING),
            Self::JobResult {
                result,
                provider_signature,
                transcript,
            } => {
                out.push(tag::RESULT);
                out.extend_from_slice(&result.encode());
                out.extend_from_slice(provider_signature.as_bytes());
                // Last field, and the whole of the rest, for the reason
                // `JobProposed`'s bundle is: the journal frame already
                // carries this record's length.
                out.extend_from_slice(transcript);
            }
            Self::PlaintextReleased => out.push(tag::PLAINTEXT),
            Self::ResultMatched => out.push(tag::MATCHED),
            Self::JobTerminated { outcome } => {
                out.push(tag::TERMINATED);
                put_outcome(&mut out, outcome);
            }
            Self::ClosePrepared { start } => {
                out.push(tag::CLOSE_PREPARED);
                // Last field, and the whole of the rest, for the reason
                // `JobProposed`'s bundle is: a start is variable-width,
                // and the journal frame already carries this record's
                // length.
                out.extend_from_slice(&encode_kernel(start.as_ref()));
            }
            Self::CloseOpened {
                start_id,
                opener,
                response_deadline,
                claimed,
            } => {
                out.push(tag::CLOSE_OPENED);
                out.extend_from_slice(&start_id.to_bytes());
                out.push(party_code(*opener));
                put_u64(&mut out, *response_deadline);
                put_u64(&mut out, *claimed);
            }
            Self::CloseResponded {
                start_id,
                response_digest,
            } => {
                out.push(tag::CLOSE_RESPONDED);
                out.extend_from_slice(&start_id.to_bytes());
                out.extend_from_slice(response_digest.as_bytes());
            }
            Self::CloseSettled {
                height,
                payload,
                provider_payout,
            } => {
                out.push(tag::CLOSE_SETTLED);
                put_u64(&mut out, *height);
                out.extend_from_slice(payload);
                put_u64(&mut out, *provider_payout);
            }
        }
        out
    }

    /// Reads one record from exactly its canonical bytes.
    ///
    /// # Errors
    ///
    /// [`ChannelStateError::Malformed`] for an unknown tag, a nested
    /// body that does not decode, a truncated record, or a trailing
    /// byte.
    pub fn decode(bytes: &[u8]) -> Result<Self, ChannelStateError> {
        let mut cursor = Cursor::new(bytes);
        let record = match cursor.byte().ok_or(ChannelStateError::Malformed)? {
            tag::CURSOR => Self::CursorAdvanced {
                height: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                parent: cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
                payload: cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
            },
            tag::PROPOSED => Self::JobProposed {
                authorization: private_record(&mut cursor)?,
                client_signature: signature(&mut cursor)?,
                prepared_input: cursor.rest().to_vec(),
            },
            tag::ACCEPTED => Self::JobAccepted {
                provider_signature: signature(&mut cursor)?,
            },
            tag::RUNNING => Self::JobRunning,
            tag::RESULT => Self::JobResult {
                result: private_record(&mut cursor)?,
                provider_signature: signature(&mut cursor)?,
                transcript: cursor.rest().to_vec(),
            },
            tag::PLAINTEXT => Self::PlaintextReleased,
            tag::MATCHED => Self::ResultMatched,
            tag::TERMINATED => Self::JobTerminated {
                outcome: take_outcome(&mut cursor)?,
            },
            tag::CLOSE_PREPARED => Self::ClosePrepared {
                start: Box::new(decode_kernel(cursor.rest())?),
            },
            tag::CLOSE_OPENED => Self::CloseOpened {
                start_id: StartId::from_bytes(
                    cursor
                        .array::<{ StartId::LENGTH }>()
                        .ok_or(ChannelStateError::Malformed)?,
                ),
                opener: party(cursor.byte().ok_or(ChannelStateError::Malformed)?)?,
                response_deadline: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                claimed: cursor.u64().ok_or(ChannelStateError::Malformed)?,
            },
            tag::CLOSE_RESPONDED => Self::CloseResponded {
                start_id: StartId::from_bytes(
                    cursor
                        .array::<{ StartId::LENGTH }>()
                        .ok_or(ChannelStateError::Malformed)?,
                ),
                response_digest: PayloadHash::from_bytes(
                    cursor
                        .array::<{ PayloadHash::LENGTH }>()
                        .ok_or(ChannelStateError::Malformed)?,
                ),
            },
            tag::CLOSE_SETTLED => Self::CloseSettled {
                height: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                payload: cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
                provider_payout: cursor.u64().ok_or(ChannelStateError::Malformed)?,
            },
            _ => return Err(ChannelStateError::Malformed),
        };
        if cursor.is_empty() {
            Ok(record)
        } else {
            Err(ChannelStateError::Malformed)
        }
    }
}

/// Writes how a job ended.
///
/// One spelling, because a terminal is written twice: once as the record
/// that ends the job and once inside the checkpoint that carries the
/// ended job across a rotation. A second encoder for the second place
/// would be a second answer to what a certified job is.
fn put_outcome(out: &mut Vec<u8>, outcome: &TerminalOutcome) {
    match outcome {
        TerminalOutcome::Certified {
            certificate,
            binding,
            binding_signature,
            certificate_signature,
        } => {
            out.push(outcome_code::CERTIFIED);
            out.extend_from_slice(&encode_kernel(certificate));
            out.extend_from_slice(&binding.encode());
            out.extend_from_slice(binding_signature.as_bytes());
            out.extend_from_slice(certificate_signature.as_bytes());
        }
        TerminalOutcome::Refuted {
            result_digest,
            reproduction_digest,
        } => {
            out.push(outcome_code::REFUTED);
            out.extend_from_slice(result_digest.as_bytes());
            out.extend_from_slice(reproduction_digest.as_bytes());
        }
        TerminalOutcome::Expired {
            deadline,
            height,
            payload,
        } => {
            out.push(outcome_code::EXPIRED);
            put_u64(out, *deadline);
            put_u64(out, *height);
            out.extend_from_slice(payload);
        }
        TerminalOutcome::Failed { code } => {
            out.push(outcome_code::FAILED);
            out.extend_from_slice(&code.to_be_bytes());
        }
        TerminalOutcome::Indeterminate => out.push(outcome_code::INDETERMINATE),
    }
}

/// Reads back exactly what [`put_outcome`] wrote.
fn take_outcome(cursor: &mut Cursor<'_>) -> Result<TerminalOutcome, ChannelStateError> {
    Ok(match cursor.byte().ok_or(ChannelStateError::Malformed)? {
        outcome_code::CERTIFIED => TerminalOutcome::Certified {
            certificate: certificate(cursor)?,
            binding: private_record(cursor)?,
            binding_signature: signature(cursor)?,
            certificate_signature: signature(cursor)?,
        },
        outcome_code::REFUTED => TerminalOutcome::Refuted {
            result_digest: digest(cursor)?,
            reproduction_digest: digest(cursor)?,
        },
        outcome_code::EXPIRED => TerminalOutcome::Expired {
            deadline: cursor.u64().ok_or(ChannelStateError::Malformed)?,
            height: cursor.u64().ok_or(ChannelStateError::Malformed)?,
            payload: cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
        },
        outcome_code::FAILED => TerminalOutcome::Failed {
            code: u32::from_be_bytes(cursor.array::<4>().ok_or(ChannelStateError::Malformed)?),
        },
        outcome_code::INDETERMINATE => TerminalOutcome::Indeterminate,
        _ => return Err(ChannelStateError::Malformed),
    })
}

fn private_record<R: crate::protocol::work::PrivateRecord>(
    cursor: &mut Cursor<'_>,
) -> Result<R, ChannelStateError> {
    let bytes = cursor
        .take(R::ENCODED_SIZE)
        .ok_or(ChannelStateError::Malformed)?;
    Ok(R::decode(bytes)?)
}

/// The one byte a party is written as.
const fn party_code(party: Party) -> u8 {
    match party {
        Party::Maker => 0,
        Party::Taker => 1,
    }
}

fn party(code: u8) -> Result<Party, ChannelStateError> {
    match code {
        0 => Ok(Party::Maker),
        1 => Ok(Party::Taker),
        _ => Err(ChannelStateError::Malformed),
    }
}

const fn role_code(role: Role) -> u8 {
    match role {
        Role::Client => 1,
        Role::Provider => 2,
    }
}

const fn role_from_code(code: u8) -> Result<Role, ChannelStateError> {
    match code {
        1 => Ok(Role::Client),
        2 => Ok(Role::Provider),
        _ => Err(ChannelStateError::Malformed),
    }
}

fn signature(cursor: &mut Cursor<'_>) -> Result<Sig, ChannelStateError> {
    let bytes = cursor
        .array::<{ Sig::LENGTH }>()
        .ok_or(ChannelStateError::Malformed)?;
    Ok(Sig::from_bytes(bytes))
}

fn digest(cursor: &mut Cursor<'_>) -> Result<Digest, ChannelStateError> {
    Ok(Digest::from_bytes(
        cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
    ))
}

fn certificate(cursor: &mut Cursor<'_>) -> Result<EarnedCertificate, ChannelStateError> {
    let bytes = cursor
        .take(EarnedCertificate::ENCODED_SIZE)
        .ok_or(ChannelStateError::Malformed)?;
    let (certificate, consumed) =
        EarnedCertificate::decode(bytes).map_err(|_| ChannelStateError::Malformed)?;
    if consumed == bytes.len() {
        Ok(certificate)
    } else {
        Err(ChannelStateError::Malformed)
    }
}

/// Returns the kernel's own canonical encoding of a kernel value.
///
/// The journal holds these bytes and the wire carries them, and both
/// take them from here: the signature beside a certificate is over the
/// digest of this encoding, so a second speller of it would be a second
/// definition of what was signed.
pub(crate) fn encode_kernel<E: Encode>(value: &E) -> Vec<u8> {
    let mut buf = vec![0_u8; value.encoded_size()];
    let written = value.write_to(&mut buf);
    buf.truncate(written);
    buf
}

fn decode_kernel<D: Decode>(bytes: &[u8]) -> Result<D, ChannelStateError> {
    D::decode_exact(bytes).map_err(|_| ChannelStateError::Malformed)
}

/// The one job a channel may have in flight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobState {
    authorization: PaidJobAuthorizationV1,
    work_id: Digest,
    prepared_input: Vec<u8>,
    client_signature: Sig,
    provider_signature: Option<Sig>,
    phase: JobPhase,
    result: Option<(PaidJobResultV1, Sig)>,
    transcript: Vec<u8>,
}

impl JobState {
    /// Returns the authorization both parties sign.
    #[must_use]
    pub const fn authorization(&self) -> &PaidJobAuthorizationV1 {
        &self.authorization
    }

    /// Returns the job's `work_id`.
    #[must_use]
    pub const fn work_id(&self) -> Digest {
        self.work_id
    }

    /// Returns the prepared-input bundle this job executes from.
    ///
    /// Retained because the quote that carried it is transient. What
    /// makes it the right bundle is not that it was stored, but that it
    /// hashes to the digest inside the authorization both parties
    /// signed — which is checked before it is stored, and again on
    /// replay.
    #[must_use]
    pub fn prepared_input(&self) -> &[u8] {
        &self.prepared_input
    }

    /// Returns how far the job has got.
    #[must_use]
    pub const fn phase(&self) -> JobPhase {
        self.phase
    }

    /// Returns the client's signature over the `work_id`.
    #[must_use]
    pub const fn client_signature(&self) -> Sig {
        self.client_signature
    }

    /// Returns the provider's co-signature, once it exists.
    #[must_use]
    pub const fn provider_signature(&self) -> Option<Sig> {
        self.provider_signature
    }

    /// Returns the signed result, once it exists.
    #[must_use]
    pub const fn result(&self) -> Option<&(PaidJobResultV1, Sig)> {
        self.result.as_ref()
    }

    /// Returns the encoded transcript the result was derived from, or
    /// an empty slice before there is one.
    ///
    /// What makes these the right bytes is not that they were stored.
    /// The rule that pairs them with the result is applied when the
    /// record is committed and again when the journal is replayed —
    /// one function, run by both — so a journal that holds a transcript
    /// and a result that do not belong together is one that does not
    /// open.
    #[must_use]
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }
}

/// One credited payment, exactly as its terminal recorded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidCertificate {
    /// The job it paid for.
    ///
    /// Read off the [`JobTerminal`] this channel came to rest at. It is
    /// what lets a recovered endpoint answer "what did I pay for that
    /// work id" after the job itself has been closed by the payment.
    pub work_id: Digest,
    /// The scalar consensus will settle.
    pub certificate: EarnedCertificate,
    /// The private evidence of what it bought.
    pub binding: PaymentBindingV1,
    /// The client's signature over the binding's digest.
    pub binding_signature: Sig,
    /// The client's signature over the kernel's earned digest.
    pub certificate_signature: Sig,
}

/// What one endpoint durably knows about one channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelState {
    channel: PaidChannel,
    settlement: WorkPaymentSettlement,
    role: Role,
    ledger: CreditLedger,
    job: Option<JobState>,
    terminal: Option<JobTerminal>,
    cursor: (u64, [u8; 32]),
    indeterminate: bool,
    close_prepared: Option<PaymentCloseStart>,
    close_opened: Option<OpenContest>,
    close_responded: Option<RespondedContest>,
    close_settled: Option<CloseSettlement>,
}

/// A finalized close contest on this channel's payment edge, and
/// everything a recovering provider needs to answer it without a second
/// finalized snapshot.
///
/// The [`Self::start_id`] and [`Self::opener`] are what the watcher can
/// read nowhere but from the block that accepted the start. The
/// [`Self::response_deadline`] and [`Self::claimed`] ride with them
/// because an answer exists only while the window is open and only for a
/// contest opened below what this endpoint already holds, and a restart
/// that kept only the identifier could decide neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenContest {
    /// Contest a later response or close must name.
    pub start_id: StartId,
    /// Which party opened it.
    pub opener: Party,
    /// Height at which the response window shuts.
    pub response_deadline: u64,
    /// Cumulative amount the opener's own start claimed.
    pub claimed: u64,
}

/// The one answer this endpoint has chosen for the contest on its
/// payment edge.
///
/// Where [`OpenContest`] is what a block said, this is what this
/// endpoint decided about it: while a contest is open and this is
/// absent, no answer is fixed yet; once it is present, the answer is
/// fixed and no other may be given. What it does not say is that the
/// answer was sent, let alone received — it reaches the disk before the
/// submission it authorises, so a duty may be owed with this record
/// already written. The digest is the answer's own signed body, so a
/// resubmission that re-derives the answer can be checked against what
/// was already chosen rather than trusted to be the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RespondedContest {
    /// Contest the answer names.
    pub start_id: StartId,
    /// Digest the responder signed, over the answer's own body.
    pub response_digest: PayloadHash,
}

/// What a finalized close of this channel's payment edge paid, and
/// where it was.
///
/// Retained because a payout is a coin, and a coin can be spent. The
/// block that carried the close is the durable answer to "was this
/// channel settled"; a later lookup that finds no coin is not evidence
/// that it was not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseSettlement {
    /// Height of the block that carried the close.
    pub height: u64,
    /// That block's payload digest.
    pub payload: [u8; 32],
    /// What the close paid the provider.
    pub provider_payout: u64,
}

impl ChannelState {
    fn new(
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
        origin: SetupOrigin,
    ) -> Self {
        Self {
            channel,
            settlement,
            role,
            ledger: CreditLedger::new(),
            job: None,
            terminal: None,
            cursor: (origin.height, origin.payload),
            indeterminate: false,
            close_prepared: None,
            close_opened: None,
            close_responded: None,
            close_settled: None,
        }
    }

    /// Returns this state's canonical bytes: the whole of what a
    /// successor generation replays from.
    ///
    /// Not a summary, and the destructuring below is what keeps it from
    /// becoming one. Every field of this struct is named here and named
    /// again in [`Self::decode_checkpoint`]'s literal, so a field added
    /// to [`ChannelState`] and forgotten here does not compile: the
    /// pattern is refused for the field it does not mention, and the
    /// literal for the field it cannot fill. The same holds one level
    /// down, for [`JobState`] and for [`JobTerminal`].
    ///
    /// The channel and the settlement are written as what pins them
    /// rather than as a second copy of themselves: the channel id is a
    /// commitment to the network, both edges and both terms bodies, and
    /// the opener supplies the value. A checkpoint whose id or
    /// settlement is not the opener's is refused, so what the two hold
    /// is one channel and not two that happen to agree.
    #[must_use]
    pub fn checkpoint(&self) -> Vec<u8> {
        let Self {
            channel,
            settlement,
            role,
            ledger,
            job,
            terminal,
            cursor,
            indeterminate,
            close_prepared,
            close_opened,
            close_responded,
            close_settled,
        } = self;

        let mut out = Vec::new();
        out.extend_from_slice(channel.id().as_bytes());
        put_u64(&mut out, settlement.freeze_total());
        put_u64(&mut out, settlement.adjudicated_total());
        put_u64(&mut out, settlement.capacity());
        put_u64(&mut out, settlement.omission_bond());
        out.push(role_code(*role));
        put_u64(&mut out, ledger.credited_cumulative());
        put_option(&mut out, job.as_ref(), |out, job| {
            let JobState {
                authorization,
                work_id,
                prepared_input,
                client_signature,
                provider_signature,
                phase,
                result,
                transcript,
            } = job;
            out.extend_from_slice(&authorization.encode());
            out.extend_from_slice(work_id.as_bytes());
            out.extend_from_slice(client_signature.as_bytes());
            put_option(out, provider_signature.as_ref(), |out, signature| {
                out.extend_from_slice(signature.as_bytes());
            });
            out.push(phase.code());
            put_option(out, result.as_ref(), |out, (result, signature)| {
                out.extend_from_slice(&result.encode());
                out.extend_from_slice(signature.as_bytes());
            });
            put_bytes(out, prepared_input);
            put_bytes(out, transcript);
        });
        put_option(&mut out, terminal.as_ref(), |out, terminal| {
            let JobTerminal {
                work_id,
                phase,
                outcome,
            } = terminal;
            out.extend_from_slice(work_id.as_bytes());
            out.push(phase.code());
            put_outcome(out, outcome);
        });
        put_u64(&mut out, cursor.0);
        out.extend_from_slice(&cursor.1);
        out.push(u8::from(*indeterminate));
        put_option(&mut out, close_prepared.as_ref(), |out, start| {
            put_bytes(out, &encode_kernel(start));
        });
        put_option(&mut out, close_opened.as_ref(), |out, contest| {
            out.extend_from_slice(&contest.start_id.to_bytes());
            out.push(party_code(contest.opener));
            put_u64(out, contest.response_deadline);
            put_u64(out, contest.claimed);
        });
        put_option(&mut out, close_responded.as_ref(), |out, answer| {
            out.extend_from_slice(&answer.start_id.to_bytes());
            out.extend_from_slice(answer.response_digest.as_bytes());
        });
        put_option(&mut out, close_settled.as_ref(), |out, settlement| {
            put_u64(out, settlement.height);
            out.extend_from_slice(&settlement.payload);
            put_u64(out, settlement.provider_payout);
        });
        out
    }

    /// Reads a checkpoint back into the state it was written from.
    ///
    /// The channel and the settlement are the opener's, and the two
    /// values the checkpoint pins them by are checked against them
    /// first: a successor holding another channel's state is refused
    /// rather than adopted under this channel's keys.
    fn decode_checkpoint(
        bytes: &[u8],
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
    ) -> Result<Self, ChannelStateError> {
        let mut cursor = Cursor::new(bytes);
        if digest(&mut cursor)?.as_bytes() != channel.id().as_bytes() {
            return Err(ChannelStateError::WrongChannel {
                field: "checkpoint channel_id",
            });
        }
        for (field, held) in [
            ("freeze_total", settlement.freeze_total()),
            ("adjudicated_total", settlement.adjudicated_total()),
            ("capacity", settlement.capacity()),
            ("omission_bond", settlement.omission_bond()),
        ] {
            if cursor.u64().ok_or(ChannelStateError::Malformed)? != held {
                return Err(ChannelStateError::WrongChannel { field });
            }
        }
        if role_from_code(cursor.byte().ok_or(ChannelStateError::Malformed)?)? != role {
            return Err(ChannelStateError::WrongRole {
                step: "replaying a checkpoint",
                expected: match role {
                    Role::Client => "client",
                    Role::Provider => "provider",
                },
            });
        }
        let credited = cursor.u64().ok_or(ChannelStateError::Malformed)?;
        let state = Self {
            channel,
            settlement,
            role,
            ledger: CreditLedger::credited(credited),
            job: take_option(&mut cursor, ChannelStateError::Malformed, |cursor| {
                let authorization = private_record(cursor)?;
                let work_id = digest(cursor)?;
                let client_signature = signature(cursor)?;
                let provider_signature =
                    take_option(cursor, ChannelStateError::Malformed, signature)?;
                let phase =
                    JobPhase::from_code(cursor.byte().ok_or(ChannelStateError::Malformed)?)?;
                let result = take_option(cursor, ChannelStateError::Malformed, |cursor| {
                    Ok((private_record(cursor)?, signature(cursor)?))
                })?;
                Ok(JobState {
                    authorization,
                    work_id,
                    client_signature,
                    provider_signature,
                    phase,
                    result,
                    prepared_input: take_bytes(cursor, ChannelStateError::Malformed)?.to_vec(),
                    transcript: take_bytes(cursor, ChannelStateError::Malformed)?.to_vec(),
                })
            })?,
            terminal: take_option(&mut cursor, ChannelStateError::Malformed, |cursor| {
                Ok(JobTerminal {
                    work_id: digest(cursor)?,
                    phase: JobPhase::from_code(cursor.byte().ok_or(ChannelStateError::Malformed)?)?,
                    outcome: take_outcome(cursor)?,
                })
            })?,
            cursor: (
                cursor.u64().ok_or(ChannelStateError::Malformed)?,
                cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
            ),
            indeterminate: take_bool(&mut cursor, ChannelStateError::Malformed)?,
            close_prepared: take_option(&mut cursor, ChannelStateError::Malformed, |cursor| {
                decode_kernel(take_bytes(cursor, ChannelStateError::Malformed)?)
            })?,
            close_opened: take_option(&mut cursor, ChannelStateError::Malformed, |cursor| {
                Ok(OpenContest {
                    start_id: StartId::from_bytes(
                        cursor
                            .array::<{ StartId::LENGTH }>()
                            .ok_or(ChannelStateError::Malformed)?,
                    ),
                    opener: party(cursor.byte().ok_or(ChannelStateError::Malformed)?)?,
                    response_deadline: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                    claimed: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                })
            })?,
            close_responded: take_option(&mut cursor, ChannelStateError::Malformed, |cursor| {
                Ok(RespondedContest {
                    start_id: StartId::from_bytes(
                        cursor
                            .array::<{ StartId::LENGTH }>()
                            .ok_or(ChannelStateError::Malformed)?,
                    ),
                    response_digest: PayloadHash::from_bytes(
                        cursor
                            .array::<{ PayloadHash::LENGTH }>()
                            .ok_or(ChannelStateError::Malformed)?,
                    ),
                })
            })?,
            close_settled: take_option(&mut cursor, ChannelStateError::Malformed, |cursor| {
                Ok(CloseSettlement {
                    height: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                    payload: cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
                    provider_payout: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                })
            })?,
        };
        if cursor.is_empty() {
            Ok(state)
        } else {
            Err(ChannelStateError::Malformed)
        }
    }

    /// Reads a checkpoint and reruns every rule replay would have run to
    /// reach it.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::decode_checkpoint`] refuses about the bytes, and
    /// whatever [`Self::revalidate`] refuses about the state.
    fn from_checkpoint<V: SigVerifier>(
        bytes: &[u8],
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
        verifier: &V,
    ) -> Result<Self, ChannelStateError> {
        let state = Self::decode_checkpoint(bytes, channel, settlement, role)?;
        state.revalidate(verifier)?;
        Ok(state)
    }

    /// Refuses a checkpoint whose stored fields are not the ones its own
    /// contents produce.
    ///
    /// Every signature this journal ever verified is verified again,
    /// against the party the channel names and over the same digest —
    /// the client's authorization, the provider's co-signature, the
    /// provider's result, and the client's binding and certificate. The
    /// result is rebuilt from the transcript beside it by
    /// [`terminal_result`], exactly as a record replay rebuilds it. The
    /// inputs are hashed against the digest the authorization commits
    /// to. The retained close start is checked against this channel and
    /// this role, and the fixed answer is re-derived from the contest
    /// and the certificate that determine it.
    ///
    /// What cannot be rerun is the height each of those steps was legal
    /// at: a checkpoint is the state a replay reached, not the blocks it
    /// crossed, and judging an old step by the cursor the checkpoint
    /// carries would refuse a journal that was legal at every step. That
    /// is the one thing this does not claim, and it is the reason the
    /// deadline rules stay where they are — on the records, at the
    /// heights they were taken.
    fn revalidate<V: SigVerifier>(&self, verifier: &V) -> Result<(), ChannelStateError> {
        // The one number consensus sees, against the one terminal that
        // could have moved it. A ledger the terminal does not produce is
        // a channel that would credit a second payment.
        if self.ledger.credited_cumulative() != self.max_executable_certificate() {
            return Err(ChannelStateError::WrongChannel {
                field: "credited cumulative against the terminal",
            });
        }
        if let Some(job) = &self.job {
            if job.work_id != work_id(&self.channel, &job.authorization) {
                return Err(ChannelStateError::WrongChannel { field: "work_id" });
            }
            self.check_authorization(&job.authorization, &job.prepared_input)?;
            if job.phase.only_role().is_some_and(|role| role != self.role)
                || job.provider_signature.is_some() != (job.phase != JobPhase::HalfSigned)
                || job.result.is_some() != job.phase.has_result()
            {
                return Err(ChannelStateError::WrongPhase {
                    step: "replaying a checkpoint",
                    phase: job.phase.name(),
                });
            }
            if !verifier.verify_sig(
                job.client_signature,
                self.client_key(),
                signing_hash(job.work_id),
            ) {
                return Err(ChannelStateError::BadSignature {
                    slot: "authorization",
                    party: "the client",
                });
            }
            if let Some(provider_signature) = job.provider_signature
                && !verifier.verify_sig(
                    provider_signature,
                    self.provider_key(),
                    signing_hash(job.work_id),
                )
            {
                return Err(ChannelStateError::BadSignature {
                    slot: "authorization",
                    party: "the provider",
                });
            }
            if let Some((result, provider_signature)) = &job.result {
                let events = decode_transcript(&job.transcript, MAX_RECORD_BYTES)?;
                if terminal_result(&self.channel, &job.authorization, &events)? != *result {
                    return Err(ChannelStateError::WrongChannel {
                        field: "result against its transcript",
                    });
                }
                if !verifier.verify_sig(
                    *provider_signature,
                    self.provider_key(),
                    signing_hash(result_digest(&self.channel, result)),
                ) {
                    return Err(ChannelStateError::BadSignature {
                        slot: "result",
                        party: "the provider",
                    });
                }
            }
        }
        if let Some(terminal) = &self.terminal {
            if self.job.is_some() {
                return Err(ChannelStateError::Terminated {
                    step: "replaying a checkpoint with a job still open",
                    outcome: terminal.outcome.name(),
                });
            }
            if let TerminalOutcome::Certified {
                certificate,
                binding,
                binding_signature,
                certificate_signature,
            } = &terminal.outcome
            {
                for (slot, signature, hash) in [
                    (
                        "binding",
                        *binding_signature,
                        signing_hash(payment_binding_digest(&self.channel, binding)),
                    ),
                    (
                        "certificate",
                        *certificate_signature,
                        certificate.digest(self.network()),
                    ),
                ] {
                    if !verifier.verify_sig(signature, self.client_key(), hash) {
                        return Err(ChannelStateError::BadSignature {
                            slot,
                            party: "the client",
                        });
                    }
                }
            }
        }
        if let Some(start) = &self.close_prepared {
            self.check_close_start(start)?;
        }
        if let Some(answer) = self.close_responded {
            let Some(contest) = self
                .close_opened
                .filter(|contest| contest.start_id == answer.start_id)
            else {
                return Err(ChannelStateError::WrongChannel {
                    field: "close response start_id",
                });
            };
            let Some((certificate, _)) = self.executable_certificate() else {
                return Err(ChannelStateError::WrongPhase {
                    step: "replaying a fixed contest answer",
                    phase: "owed no answer",
                });
            };
            if answer.response_digest
                != crate::work_close::response_body_digest(
                    &self.channel,
                    contest.start_id,
                    &certificate,
                )
            {
                return Err(ChannelStateError::WrongChannel {
                    field: "close response digest",
                });
            }
        }
        Ok(())
    }

    /// Returns the channel every record here is bound to.
    #[must_use]
    pub const fn channel(&self) -> &PaidChannel {
        &self.channel
    }

    /// Returns what this endpoint has credited.
    #[must_use]
    pub const fn ledger(&self) -> &CreditLedger {
        &self.ledger
    }

    /// Returns which half of the channel this journal is.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns what the funded payment edge can settle.
    ///
    /// Fixed when the store was opened, from the finalized read that
    /// established the channel is live. An endpoint built over a
    /// readiness decision taken at other funding would bound its
    /// payments by a different number than this one.
    #[must_use]
    pub const fn settlement(&self) -> WorkPaymentSettlement {
        self.settlement
    }

    /// Returns the job in flight, if there is one.
    #[must_use]
    pub const fn job(&self) -> Option<&JobState> {
        self.job.as_ref()
    }

    /// Returns this channel's one permanent terminal, once its job has
    /// reached one.
    ///
    /// Present means the job is over for good: no second proposal opens,
    /// and no late reply to the first is taken.
    #[must_use]
    pub const fn terminal(&self) -> Option<&JobTerminal> {
        self.terminal.as_ref()
    }

    /// Returns the certificate this channel's job was paid with, if it
    /// was paid.
    ///
    /// What a recovered endpoint re-sends. The job it paid for is closed
    /// by its own terminal, so these bytes are the only remaining copy of
    /// what was agreed, and offering them again is idempotent rather than
    /// a second payment.
    #[must_use]
    pub fn last_payment(&self) -> Option<PaidCertificate> {
        let terminal = self.terminal.as_ref()?;
        let TerminalOutcome::Certified {
            certificate,
            binding,
            binding_signature,
            certificate_signature,
        } = &terminal.outcome
        else {
            return None;
        };
        Some(PaidCertificate {
            work_id: terminal.work_id,
            certificate: *certificate,
            binding: *binding,
            binding_signature: *binding_signature,
            certificate_signature: *certificate_signature,
        })
    }

    /// Returns whether the job in flight was left running by a process
    /// that did not come back.
    ///
    /// True means exactly one thing: the backend may or may not have
    /// been invoked, and nothing local can say which. No automatic step
    /// resolves it, and a [`ChannelRecord::JobResult`] is refused while
    /// it holds.
    #[must_use]
    pub const fn is_indeterminate(&self) -> bool {
        self.indeterminate
    }

    /// Returns the largest cumulative the paid certificate names.
    ///
    /// The most this channel has been shown it earned. A certificate the
    /// client signed is one it cannot repudiate, so a close that named
    /// less than this would be a close below what was already earned.
    /// Nothing here builds a close, and nothing here enforces that; this
    /// is the value such a builder must start from.
    ///
    /// Read off the one paid terminal. This channel admits one job, so
    /// there is at most one certificate, and it is the largest by being
    /// the only one.
    #[must_use]
    pub fn max_executable_certificate(&self) -> u64 {
        self.last_payment()
            .map_or(0, |payment| payment.certificate.earned_cumulative())
    }

    /// Returns the finalized block this endpoint has processed through.
    ///
    /// Contiguous by construction, and contiguous all the way back to
    /// the block that opened the channel: the store is anchored at that
    /// origin when it is opened, and every record since named the block
    /// before it as its parent. That is what makes it usable as a clock
    /// — a height reached by skipping is a height at which this
    /// endpoint does not know what happened, and there is no height
    /// here that was reached by skipping.
    ///
    /// There is no "before the first block" case, and that is the whole
    /// point of the origin: an endpoint whose clock could be absent is
    /// an endpoint every deadline rule passes for.
    #[must_use]
    pub const fn cursor(&self) -> (u64, [u8; 32]) {
        self.cursor
    }

    /// Returns the close start this endpoint signed and retains.
    ///
    /// What a resubmission sends, and only while
    /// [`Self::includable_close_start`] still offers it: the record
    /// itself is never taken back — nothing on this journal is — but a
    /// signature whose window has passed is history rather than a
    /// pending close.
    #[must_use]
    pub const fn close_prepared(&self) -> Option<&PaymentCloseStart> {
        self.close_prepared.as_ref()
    }

    /// Returns the retained close start while `height` is still inside
    /// the window it could be included in.
    ///
    /// The one predicate that decides both halves of a resubmission: it
    /// is why an endpoint offers the retained bytes again instead of
    /// signing, and it is why the journal refuses to replace them. A
    /// second spelling of it would let the two disagree about which
    /// start this channel is closing with.
    #[must_use]
    pub fn includable_close_start(&self, height: u64) -> Option<&PaymentCloseStart> {
        self.close_prepared
            .as_ref()
            .filter(|start| height <= start.valid_through_height())
    }

    /// Returns the finalized contest on this channel's payment edge,
    /// and the party that opened it.
    #[must_use]
    pub const fn close_opened(&self) -> Option<(StartId, Party)> {
        match self.close_opened {
            Some(contest) => Some((contest.start_id, contest.opener)),
            None => None,
        }
    }

    /// Returns the finalized contest in full, including the window and
    /// the amount an answer must strictly exceed.
    ///
    /// Where [`Self::close_opened`] answers "is there a contest, and
    /// whose", this answers "may this endpoint still answer it, and with
    /// what floor" — the two facts a restart services the response from.
    #[must_use]
    pub const fn open_contest(&self) -> Option<OpenContest> {
        self.close_opened
    }

    /// Returns the answer this endpoint has already fixed for the
    /// contest on this edge, if it has fixed one.
    ///
    /// Present says the answer is chosen, not that anyone has it: the
    /// record is on the disk before the submission it authorises, so a
    /// crash in between leaves this present and consensus empty. What it
    /// is for is refusing a *different* answer to the same contest —
    /// [`Self::answerable_contest`] is what says whether one is still
    /// owed.
    #[must_use]
    pub const fn close_responded(&self) -> Option<RespondedContest> {
        self.close_responded
    }

    /// Returns the contest this endpoint owes an answer to, with the
    /// certificate that answers it.
    ///
    /// Five conditions, and every one of them is frozen the moment the
    /// contest is journaled — which is why an endpoint that fails them
    /// gains nothing by waiting, and must not stop reading blocks over
    /// an answer it will never be able to give:
    ///
    /// - this journal is the provider's, because only a certificate's
    ///   beneficiary may spend it;
    /// - the edge has not already settled;
    /// - the opener is the client, since a contest this endpoint opened
    ///   is one it already put its own evidence into;
    /// - the cursor is strictly inside the response window, the kernel's
    ///   own rule for a late answer;
    /// - and the certificate on this disk strictly exceeds what the
    ///   contest claims, or the one answer the window admits would buy
    ///   nothing.
    ///
    /// The certificate rides along because the answer is not a choice:
    /// these two values determine it, so every caller that derives the
    /// answer derives the same one.
    #[must_use]
    pub fn answerable_contest(&self) -> Option<(OpenContest, (EarnedCertificate, Sig))> {
        if self.role != Role::Provider || self.close_settled.is_some() {
            return None;
        }
        let contest = self.close_opened?;
        if contest.opener != Party::Maker || self.cursor.0 >= contest.response_deadline {
            return None;
        }
        let certificate = self
            .executable_certificate()
            .filter(|(certificate, _)| certificate.earned_cumulative() > contest.claimed)?;
        Some((contest, certificate))
    }

    /// Returns the finalized close of this channel's payment edge.
    #[must_use]
    pub const fn close_settled(&self) -> Option<CloseSettlement> {
        self.close_settled
    }

    /// Returns the largest certificate held, with the client signature
    /// that makes it spendable.
    ///
    /// The pair rather than the amount, because a close carries both:
    /// [`Self::max_executable_certificate`] answers "how much", and this
    /// answers "with what".
    #[must_use]
    pub fn executable_certificate(&self) -> Option<(EarnedCertificate, Sig)> {
        self.last_payment()
            .map(|payment| (payment.certificate, payment.certificate_signature))
    }

    /// Whether this channel is closing now.
    ///
    /// True while a close start of this endpoint's could still be
    /// included, and from the moment a contest is finalized on this
    /// edge or the edge is gone. It is the cutoff: while it holds, no
    /// job is admitted and no certificate is credited, because a close
    /// cannot carry what it did not know about.
    ///
    /// A start that can no longer be included is not a closing channel,
    /// and that is [`Self::includable_close_start`]'s judgement rather
    /// than a second one. The cursor is contiguous, so every block in
    /// that start's window was read: had it opened a contest,
    /// [`Self::close_opened`] would say so. It did not, it never will,
    /// and a channel shut for good by a signature that reached no block
    /// is a channel whose certificate can never be spent — the endpoint
    /// would have to close it to be paid, and closing is the thing it
    /// could no longer do.
    #[must_use]
    pub fn is_closing(&self) -> bool {
        self.close_opened.is_some()
            || self.close_settled.is_some()
            || self.includable_close_start(self.cursor.0).is_some()
    }

    fn refuse_if_closing(&self, step: &'static str) -> Result<(), ChannelStateError> {
        if self.is_closing() {
            return Err(ChannelStateError::Closing { step });
        }
        Ok(())
    }

    const fn client_key(&self) -> Key {
        self.channel.client_key()
    }

    const fn provider_key(&self) -> Key {
        self.channel.provider_key()
    }

    const fn network(&self) -> NetworkId {
        self.channel.network()
    }

    fn require_role(&self, step: &'static str, role: Role) -> Result<(), ChannelStateError> {
        if self.role == role {
            Ok(())
        } else {
            Err(ChannelStateError::WrongRole {
                step,
                expected: match role {
                    Role::Client => "client",
                    Role::Provider => "provider",
                },
            })
        }
    }

    fn open_job(&self, step: &'static str) -> Result<JobState, ChannelStateError> {
        if let Some(job) = &self.job {
            return Ok(job.clone());
        }
        // A late reply to a finished job is refused as terminated rather
        // than as a phase error: the job is not merely absent, it is over
        // for good, and no step reopens it.
        if let Some(terminal) = &self.terminal {
            return Err(ChannelStateError::Terminated {
                step,
                outcome: terminal.outcome.name(),
            });
        }
        Err(ChannelStateError::WrongPhase {
            step,
            phase: "none",
        })
    }

    fn refuse_if_terminated(&self, step: &'static str) -> Result<(), ChannelStateError> {
        match &self.terminal {
            Some(terminal) => Err(ChannelStateError::Terminated {
                step,
                outcome: terminal.outcome.name(),
            }),
            None => Ok(()),
        }
    }

    /// Applies one record, or says why it may not be applied.
    ///
    /// Every rule this endpoint has is here, and replay runs it too, so
    /// a journal that could not have been written a record at a time is
    /// not read back whole.
    fn apply<V: SigVerifier>(
        &mut self,
        record: &ChannelRecord,
        verifier: &V,
    ) -> Result<Applied, ChannelStateError> {
        match record {
            ChannelRecord::CursorAdvanced {
                height,
                parent,
                payload,
            } => self.apply_cursor(*height, parent, payload),
            ChannelRecord::JobProposed {
                authorization,
                client_signature,
                prepared_input,
            } => self.apply_proposed(authorization, *client_signature, prepared_input, verifier),
            ChannelRecord::JobAccepted { provider_signature } => {
                self.apply_accepted(*provider_signature, verifier)
            }
            ChannelRecord::JobRunning => self.apply_running(),
            ChannelRecord::JobResult {
                result,
                provider_signature,
                transcript,
            } => self.apply_result(result, *provider_signature, transcript, verifier),
            ChannelRecord::PlaintextReleased => self.apply_plaintext(),
            ChannelRecord::ResultMatched => self.apply_matched(),
            ChannelRecord::JobTerminated { outcome } => self.apply_terminated(outcome, verifier),
            ChannelRecord::ClosePrepared { start } => self.apply_close_prepared(start),
            ChannelRecord::CloseOpened {
                start_id,
                opener,
                response_deadline,
                claimed,
            } => self.apply_close_opened(OpenContest {
                start_id: *start_id,
                opener: *opener,
                response_deadline: *response_deadline,
                claimed: *claimed,
            }),
            ChannelRecord::CloseResponded {
                start_id,
                response_digest,
            } => self.apply_close_responded(RespondedContest {
                start_id: *start_id,
                response_digest: *response_digest,
            }),
            ChannelRecord::CloseSettled {
                height,
                payload,
                provider_payout,
            } => self.apply_close_settled(CloseSettlement {
                height: *height,
                payload: *payload,
                provider_payout: *provider_payout,
            }),
        }
    }

    /// Moves the cursor on by exactly one contiguous block.
    ///
    /// The rule itself is [`Self::reading`], which is asked twice about
    /// every block: once by the watcher before it records anything the
    /// block *means*, and once here when the cursor itself is written.
    /// One function, so the two askings cannot disagree about which
    /// block this journal may read next.
    fn apply_cursor(
        &mut self,
        height: u64,
        parent: &[u8; 32],
        payload: &[u8; 32],
    ) -> Result<Applied, ChannelStateError> {
        match self.reading(height, parent, payload)? {
            Applied::Redundant => Ok(Applied::Redundant),
            Applied::Changed => {
                self.cursor = (height, *payload);
                Ok(Applied::Changed)
            }
        }
    }

    /// Whether this journal may read `height`, and whether reading it
    /// moves the cursor.
    ///
    /// Two rules, and they are the whole of what a cursor means here.
    /// The height must be the next one, so nothing is skipped; and the
    /// block must name the held block as its parent, so the chain that
    /// was read is one chain. A watcher that fetched heights alone
    /// would accept a block from a history this endpoint never saw.
    ///
    /// The block already held is [`Applied::Redundant`] rather than a
    /// refusal: a watcher that died after recording what a block meant
    /// and before recording that it read it re-reads that same block,
    /// and every record it re-offers is the retry it is.
    ///
    /// # Errors
    ///
    /// [`ChannelStateError::CursorNotNext`] for any other height and
    /// [`ChannelStateError::CursorNotContiguous`] for the next height
    /// on another chain.
    pub(crate) fn reading(
        &self,
        height: u64,
        parent: &[u8; 32],
        payload: &[u8; 32],
    ) -> Result<Applied, ChannelStateError> {
        let (held_height, held_payload) = self.cursor;
        if (height, *payload) == (held_height, held_payload) {
            return Ok(Applied::Redundant);
        }
        if height != held_height.saturating_add(1) {
            return Err(ChannelStateError::CursorNotNext {
                held: held_height,
                actual: height,
            });
        }
        if *parent != held_payload {
            return Err(ChannelStateError::CursorNotContiguous { height });
        }
        Ok(Applied::Changed)
    }

    /// Retains this endpoint's own signed close start, and shuts the
    /// channel.
    ///
    /// A start already held is returned as the retry it is. A
    /// *different* start replaces it only when the cursor has passed
    /// the last height the held one could have been included at — and
    /// that is not an approximation of the three facts §12 asks a
    /// snapshot for, it is those facts. The cursor is contiguous, so
    /// every block up to it was read: had any contest opened on this
    /// edge, [`ChannelRecord::CloseOpened`] would be on this disk, and
    /// had the edge been closed, [`ChannelRecord::CloseSettled`] would
    /// be. Both refuse below. What remains — the held signature can no
    /// longer be included anywhere — is exactly what the cursor says.
    fn apply_close_prepared(
        &mut self,
        start: &PaymentCloseStart,
    ) -> Result<Applied, ChannelStateError> {
        if self.close_prepared.as_ref() == Some(start) {
            return Ok(Applied::Redundant);
        }
        if self.close_opened.is_some() || self.close_settled.is_some() {
            return Err(ChannelStateError::Closing {
                step: "signing a close start",
            });
        }
        if let Some(job) = &self.job {
            return Err(ChannelStateError::WrongPhase {
                step: "signing a close start",
                phase: job.phase.name(),
            });
        }
        // The start is about this channel, and it is this endpoint's to
        // sign. Only the beneficiary of a certificate can be the
        // provider, so a journal signing in the other role would be
        // building a close for the other party.
        self.check_close_start(start)?;
        let (cursor_height, _) = self.cursor;
        if self.includable_close_start(cursor_height).is_some() {
            return Err(ChannelStateError::Conflict {
                what: "a close start that can still be included",
            });
        }
        self.close_prepared = Some(start.clone());
        Ok(Applied::Changed)
    }

    /// Records the contest a finalized start opened, and who opened it.
    ///
    /// Refused once the edge is gone, and that is the rule that makes
    /// the watcher's ordering visible: a block carrying a start and the
    /// close that ends it is one history read in the validator's order
    /// and another read backwards, and only one of them is a history
    /// this journal takes.
    ///
    /// Refused too while a job is open, and that is the cutoff itself.
    /// Nothing after this record credits a certificate, so a job still
    /// in flight is a job that can no longer be paid for, and leaving
    /// it open would leave an endpoint holding a result it may still
    /// release for a payment that can never arrive. The watcher ends it
    /// first — see `work_close::observe` — and this refusal is what
    /// makes that the only order a journal can be written or replayed
    /// in.
    fn apply_close_opened(&mut self, contest: OpenContest) -> Result<Applied, ChannelStateError> {
        if self.close_opened == Some(contest) {
            return Ok(Applied::Redundant);
        }
        if self.close_settled.is_some() {
            return Err(ChannelStateError::Closing {
                step: "opening a close contest",
            });
        }
        if self.close_opened.is_some() {
            return Err(ChannelStateError::Conflict {
                what: "this edge's close contest",
            });
        }
        self.refuse_open_job("opening a close contest")?;
        self.close_opened = Some(contest);
        Ok(Applied::Changed)
    }

    /// Records the one answer this endpoint gives the open contest.
    ///
    /// The answer is checked, not taken on trust, and against the two
    /// things that fix it: [`Self::answerable_contest`] must still owe
    /// one — provider role, client opener, open window, a superior
    /// certificate — and the digest must be the one those two derive.
    /// An arbitrary digest accepted here would be worse than useless:
    /// it would say this contest is answered while the answer that
    /// actually spends the certificate is still unsent, and the journal
    /// would then refuse that answer as a disagreement.
    ///
    /// The same answer again is the retry it is: an endpoint that died
    /// between this write and the submission it authorises re-derives
    /// the answer from the contest and the certificate — both of which
    /// are frozen by [`Self::apply_close_opened`], which shuts the
    /// channel to new work — and offers exactly these bytes again. A
    /// *different* answer to the same contest is refused, because the
    /// window admits one and a second would be this endpoint disagreeing
    /// with itself about what it already sent.
    fn apply_close_responded(
        &mut self,
        answer: RespondedContest,
    ) -> Result<Applied, ChannelStateError> {
        if self.close_responded == Some(answer) {
            return Ok(Applied::Redundant);
        }
        if self.close_responded.is_some() {
            return Err(ChannelStateError::Conflict {
                what: "this contest's answer",
            });
        }
        self.require_role("answering a close contest", Role::Provider)?;
        if self.close_settled.is_some() {
            return Err(ChannelStateError::Closing {
                step: "answering a close contest",
            });
        }
        let Some((contest, certificate)) = self.answerable_contest() else {
            return Err(ChannelStateError::WrongPhase {
                step: "answering a close contest",
                phase: "owed no answer",
            });
        };
        if contest.start_id != answer.start_id {
            return Err(ChannelStateError::WrongChannel {
                field: "close response start_id",
            });
        }
        if answer.response_digest
            != crate::work_close::response_body_digest(
                &self.channel,
                answer.start_id,
                &certificate.0,
            )
        {
            return Err(ChannelStateError::WrongChannel {
                field: "close response digest",
            });
        }
        self.close_responded = Some(answer);
        Ok(Applied::Changed)
    }

    /// Records the close that consumed this edge.
    ///
    /// It refuses an open job for the reason above, and it is a
    /// separate arrival rather than a consequence of one: a cooperative
    /// freeze consumes the edge with no contest in front of it, so this
    /// is reachable without [`Self::apply_close_opened`] ever running.
    fn apply_close_settled(
        &mut self,
        settlement: CloseSettlement,
    ) -> Result<Applied, ChannelStateError> {
        if self.close_settled == Some(settlement) {
            return Ok(Applied::Redundant);
        }
        if self.close_settled.is_some() {
            return Err(ChannelStateError::Conflict {
                what: "this edge's close",
            });
        }
        self.refuse_open_job("closing the payment edge")?;
        self.close_settled = Some(settlement);
        Ok(Applied::Changed)
    }

    fn refuse_open_job(&self, step: &'static str) -> Result<(), ChannelStateError> {
        match &self.job {
            Some(job) => Err(ChannelStateError::WrongPhase {
                step,
                phase: job.phase.name(),
            }),
            None => Ok(()),
        }
    }

    /// Checks one authorization and its inputs against the channel this
    /// journal is.
    ///
    /// One spelling, asked when the proposal arrives and again when a
    /// checkpoint carrying the open job is opened. The rest of the
    /// authorization's rules — the policy digest, the deadlines, the
    /// price against the finalized height — are `check_authorization`'s,
    /// and a second spelling of them here would be a second chance to
    /// spell them differently.
    fn check_authorization(
        &self,
        authorization: &PaidJobAuthorizationV1,
        prepared_input: &[u8],
    ) -> Result<(), ChannelStateError> {
        let terms = self.channel.payment_terms();
        for (field, holds) in [
            (
                "channel_id",
                authorization.channel_id.as_bytes() == self.channel.id().as_bytes(),
            ),
            (
                "payment_edge",
                authorization.payment_edge == self.channel.payment_edge(),
            ),
            (
                "payment_terms_hash",
                authorization.payment_terms_hash == self.channel.payment_terms_hash(),
            ),
            ("bond_edge", authorization.bond_edge == terms.bond_edge),
            (
                "bond_terms_hash",
                authorization.bond_terms_hash == terms.bond_terms_hash(),
            ),
            // The sole authorization a channel ever admits is its first,
            // and its nonce is one. There is no sequence to advance: the
            // permanent terminal above is what stops a second job, so the
            // nonce is a fixed marker rather than a high-water mark.
            ("proposal_nonce", authorization.proposal_nonce == 1),
        ] {
            if !holds {
                return Err(ChannelStateError::WrongChannel { field });
            }
        }

        // The inputs this job will be executed from, against the digest
        // the authorization both parties sign commits to. A bundle that
        // does not hash to it is a job neither party agreed to run.
        let bundle = PreparedPaidInputV1::decode(prepared_input, MAX_RECORD_BYTES)
            .map_err(PaidWorkError::from)?;
        if prepared_input_digest(&self.channel, &bundle)?.as_bytes()
            != authorization.prepared_input_digest.as_bytes()
        {
            return Err(ChannelStateError::Record(PaidWorkError::Mismatch {
                field: "prepared_input_digest",
            }));
        }
        Ok(())
    }

    /// Checks one retained close start against the channel and role it
    /// was signed for.
    ///
    /// One spelling, asked when the start is signed and again when a
    /// checkpoint carrying it is opened. It does not ask whether the
    /// start may still be *included* — that is the cursor's judgement
    /// and it moves — only whether it is this endpoint's start for this
    /// channel over the certificate this journal holds.
    fn check_close_start(&self, start: &PaymentCloseStart) -> Result<(), ChannelStateError> {
        for (field, holds) in [
            (
                "close start payment_edge",
                start.payment_edge() == self.channel.payment_edge(),
            ),
            (
                "close start payment_terms_hash",
                start.terms().hash() == self.channel.payment_terms_hash(),
            ),
            (
                "close start opener_role",
                start.opener_role()
                    == match self.role {
                        Role::Client => Party::Maker,
                        Role::Provider => Party::Taker,
                    },
            ),
            (
                "close start certificate",
                start.certificate().copied() == self.executable_certificate(),
            ),
        ] {
            if !holds {
                return Err(ChannelStateError::WrongChannel { field });
            }
        }
        Ok(())
    }

    fn apply_proposed<V: SigVerifier>(
        &mut self,
        authorization: &PaidJobAuthorizationV1,
        client_signature: Sig,
        prepared_input: &[u8],
        verifier: &V,
    ) -> Result<Applied, ChannelStateError> {
        let work_id = work_id(&self.channel, authorization);
        if let Some(job) = &self.job {
            if job.authorization == *authorization
                && job.client_signature == client_signature
                && job.prepared_input == prepared_input
            {
                return Ok(Applied::Redundant);
            }
            return Err(ChannelStateError::WrongPhase {
                step: "proposing a job",
                phase: job.phase.name(),
            });
        }
        // This channel admits one job for its whole life. Once that job
        // has reached its terminal, a fresh proposal has nothing to open.
        self.refuse_if_terminated("proposing a job")?;
        // A closing channel takes no new work. The close is built from
        // what is held now, so a job admitted after it would be a job
        // whose payment no close could carry.
        self.refuse_if_closing("proposing a job")?;

        self.check_authorization(authorization, prepared_input)?;
        if !verifier.verify_sig(client_signature, self.client_key(), signing_hash(work_id)) {
            return Err(ChannelStateError::BadSignature {
                slot: "authorization",
                party: "the client",
            });
        }

        // Compute credit is the provider's exposure and only the
        // provider's: the client is the party that would default on it.
        // The provider checks the one job's price against its limit
        // before it co-signs; there is no cross-job total to accumulate,
        // because there is no second job.
        if self.role == Role::Provider {
            self.check_compute_limit(authorization.price)?;
        }

        self.job = Some(JobState {
            authorization: *authorization,
            work_id,
            prepared_input: prepared_input.to_vec(),
            client_signature,
            provider_signature: None,
            phase: JobPhase::HalfSigned,
            result: None,
            transcript: Vec::new(),
        });
        Ok(Applied::Changed)
    }

    fn apply_accepted<V: SigVerifier>(
        &mut self,
        provider_signature: Sig,
        verifier: &V,
    ) -> Result<Applied, ChannelStateError> {
        let mut job = self.open_job("co-signing a job")?;
        if job.provider_signature == Some(provider_signature) {
            return Ok(Applied::Redundant);
        }
        if job.phase != JobPhase::HalfSigned {
            return Err(ChannelStateError::WrongPhase {
                step: "co-signing a job",
                phase: job.phase.name(),
            });
        }
        let (height, _) = self.cursor;
        if height > job.authorization.acceptance_deadline {
            return Err(ChannelStateError::AcceptanceLate {
                height,
                deadline: job.authorization.acceptance_deadline,
            });
        }
        if !verifier.verify_sig(
            provider_signature,
            self.provider_key(),
            signing_hash(job.work_id),
        ) {
            return Err(ChannelStateError::BadSignature {
                slot: "authorization",
                party: "the provider",
            });
        }
        job.provider_signature = Some(provider_signature);
        job.phase = JobPhase::Accepted;
        self.job = Some(job);
        Ok(Applied::Changed)
    }

    fn apply_running(&mut self) -> Result<Applied, ChannelStateError> {
        self.require_role("a running marker", Role::Provider)?;
        let mut job = self.open_job("a running marker")?;
        match job.phase {
            JobPhase::Running => return Ok(Applied::Redundant),
            JobPhase::Accepted => {}
            phase => {
                return Err(ChannelStateError::WrongPhase {
                    step: "a running marker",
                    phase: phase.name(),
                });
            }
        }
        let (height, _) = self.cursor;
        if height > job.authorization.terminal_deadline {
            return Err(ChannelStateError::DispatchLate {
                height,
                deadline: job.authorization.terminal_deadline,
            });
        }
        job.phase = JobPhase::Running;
        self.job = Some(job);
        Ok(Applied::Changed)
    }

    /// Records the provider's signed result and the transcript it
    /// summarises.
    ///
    /// The rule that makes this more than a signature check is the
    /// reproduction below: [`terminal_result`] is handed the stored
    /// events and this job's own authorization, and what it builds must
    /// be the result byte for byte. That establishes, on commit and on
    /// every replay, that the events are one verified signed chain for
    /// the request both parties authorized, under the key this channel
    /// calls the provider, and that both digests in the result are that
    /// chain's own.
    ///
    /// It subsumes a separate `result.work_id == job.work_id` check,
    /// which is why there is not one: the work id is a field of what is
    /// rebuilt, so a result naming another job cannot equal it.
    fn apply_result<V: SigVerifier>(
        &mut self,
        result: &PaidJobResultV1,
        provider_signature: Sig,
        transcript: &[u8],
        verifier: &V,
    ) -> Result<Applied, ChannelStateError> {
        let mut job = self.open_job("recording a result")?;
        if let Some((held, signature)) = &job.result {
            if held == result && *signature == provider_signature && job.transcript == transcript {
                return Ok(Applied::Redundant);
            }
            return Err(ChannelStateError::Conflict {
                what: "this job's result",
            });
        }
        // A running marker proves only that the backend may have been
        // invoked. If this process did not make that invocation, no
        // result it could produce now is evidence about it.
        if self.indeterminate {
            return Err(ChannelStateError::Indeterminate);
        }
        // The provider may only record a result for an invocation it
        // marked; the client never sees that marker, and records the
        // result it was sent against the job it accepted.
        let expected = match self.role {
            Role::Provider => JobPhase::Running,
            Role::Client => JobPhase::Accepted,
        };
        if job.phase != expected {
            return Err(ChannelStateError::WrongPhase {
                step: "recording a result",
                phase: job.phase.name(),
            });
        }

        // A result is owed by a height, and both roles are bounded by
        // it. The height is this journal's own cursor, so what it
        // measures is when this endpoint had *processed* a block, not
        // when a peer said one existed; how fresh that cursor is stays
        // the caller's, in the sense `ReadyChannel` already documents.
        //
        // The provider is bounded here for the reason the client is,
        // read from the other side: a result recorded past the terminal
        // deadline is one the client's own journal will refuse a
        // receipt for, so it can never be paid for — and recording it
        // anyway would make it a result the ending ledger charges this
        // client for. Late compute is the provider's own loss, and this
        // is where that is decided.
        let (height, _) = self.cursor;
        if height > job.authorization.terminal_deadline {
            return Err(ChannelStateError::ReceiptLate {
                height,
                deadline: job.authorization.terminal_deadline,
            });
        }

        let events = decode_transcript(transcript, MAX_RECORD_BYTES)?;
        if terminal_result(&self.channel, &job.authorization, &events)? != *result {
            return Err(ChannelStateError::WrongChannel {
                field: "result against its transcript",
            });
        }
        if !verifier.verify_sig(
            provider_signature,
            self.provider_key(),
            signing_hash(result_digest(&self.channel, result)),
        ) {
            return Err(ChannelStateError::BadSignature {
                slot: "result",
                party: "the provider",
            });
        }
        job.result = Some((*result, provider_signature));
        job.transcript = transcript.to_vec();
        job.phase = JobPhase::Ready;
        self.job = Some(job);
        Ok(Applied::Changed)
    }

    /// Records that this client's own re-execution reproduced the answer
    /// and it matched.
    ///
    /// It checks that there is a delivered result to have an opinion
    /// about and that this journal is a client's. What it cannot check is
    /// the reproduction itself: the engine is the caller's, and this
    /// records a decision rather than making one. That is why matching is
    /// a step of its own rather than a flag on the result — a receipt is
    /// timely or late whatever a re-execution later says, and the two are
    /// decided at different heights.
    fn apply_matched(&mut self) -> Result<Applied, ChannelStateError> {
        self.require_role("recording a reproduction match", Role::Client)?;
        let mut job = self.open_job("recording a reproduction match")?;
        match job.phase {
            JobPhase::Matched => return Ok(Applied::Redundant),
            JobPhase::Ready => {}
            phase => {
                return Err(ChannelStateError::WrongPhase {
                    step: "recording a reproduction match",
                    phase: phase.name(),
                });
            }
        }
        job.phase = JobPhase::Matched;
        self.job = Some(job);
        Ok(Applied::Changed)
    }

    fn apply_plaintext(&mut self) -> Result<Applied, ChannelStateError> {
        self.require_role("releasing plaintext", Role::Provider)?;
        let mut job = self.open_job("releasing plaintext")?;
        if job.phase.delivered() {
            return Ok(Applied::Redundant);
        }
        if job.phase != JobPhase::Ready {
            return Err(ChannelStateError::WrongPhase {
                step: "releasing plaintext",
                phase: job.phase.name(),
            });
        }
        self.check_delivery_limit(job.authorization.price)?;
        job.phase = JobPhase::Delivered;
        self.job = Some(job);
        Ok(Applied::Changed)
    }

    /// Brings this channel's one job to rest at its permanent terminal.
    ///
    /// One function for all five outcomes, because they are one decision:
    /// this channel's job ends once, and the record that ends it is the
    /// only thing that ever fills the terminal. [`TerminalOutcome::Certified`]
    /// is the join with consensus — the certificate is money, the binding
    /// is what the money bought — and the other four are the ways a job
    /// stops without one.
    fn apply_terminated<V: SigVerifier>(
        &mut self,
        outcome: &TerminalOutcome,
        verifier: &V,
    ) -> Result<Applied, ChannelStateError> {
        // The terminal already written, offered again. This is the crash
        // between writing it and acting on it: the job is closed, and
        // re-committing the same outcome must be the retry it is rather
        // than a second job's terminal or a step a closed job cannot
        // take. Answered before the open-job rule below for that reason.
        if let Some(held) = &self.terminal {
            if held.outcome == *outcome {
                return Ok(Applied::Redundant);
            }
            return Err(ChannelStateError::Terminated {
                step: "terminating the job",
                outcome: held.outcome.name(),
            });
        }
        let job = self.open_job("terminating the job")?;
        match outcome {
            TerminalOutcome::Certified {
                certificate,
                binding,
                binding_signature,
                certificate_signature,
            } => self.terminate_certified(
                &job,
                certificate,
                binding,
                *binding_signature,
                *certificate_signature,
                verifier,
            ),
            TerminalOutcome::Refuted {
                result_digest: named,
                reproduction_digest,
            } => {
                self.require_role("refuting a result", Role::Client)?;
                if job.phase != JobPhase::Ready {
                    return Err(ChannelStateError::WrongPhase {
                        step: "refuting a result",
                        phase: job.phase.name(),
                    });
                }
                let Some((result, _)) = &job.result else {
                    return Err(ChannelStateError::WrongPhase {
                        step: "refuting a result",
                        phase: job.phase.name(),
                    });
                };
                // The refuted digest is this job's own signed result's,
                // not a number the record chose: a refutation is a
                // statement about the result the delivery recorded.
                if named.as_bytes() != result_digest(&self.channel, result).as_bytes() {
                    return Err(ChannelStateError::WrongChannel {
                        field: "refuted result_digest",
                    });
                }
                self.rest_at(JobTerminal {
                    work_id: job.work_id,
                    phase: job.phase,
                    outcome: TerminalOutcome::Refuted {
                        result_digest: *named,
                        reproduction_digest: *reproduction_digest,
                    },
                });
                Ok(Applied::Changed)
            }
            TerminalOutcome::Expired { .. }
            | TerminalOutcome::Failed { .. }
            | TerminalOutcome::Indeterminate => {
                self.rest_at(JobTerminal {
                    work_id: job.work_id,
                    phase: job.phase,
                    outcome: outcome.clone(),
                });
                Ok(Applied::Changed)
            }
        }
    }

    /// Credits one client payment and rests the job at a certified
    /// terminal.
    fn terminate_certified<V: SigVerifier>(
        &mut self,
        job: &JobState,
        certificate: &EarnedCertificate,
        binding: &PaymentBindingV1,
        binding_signature: Sig,
        certificate_signature: Sig,
        verifier: &V,
    ) -> Result<Applied, ChannelStateError> {
        // A provider credits what it has delivered. A client has no
        // delivery marker of its own; what it has is that its own
        // re-execution matched, and a result that merely arrived is not
        // one an honest client signs a certificate for.
        let expected = match self.role {
            Role::Provider => JobPhase::Delivered,
            Role::Client => JobPhase::Matched,
        };
        if job.phase != expected {
            return Err(ChannelStateError::WrongPhase {
                step: "crediting a payment",
                phase: job.phase.name(),
            });
        }
        let Some((result, _)) = job.result else {
            // Unreachable: both phases above are phases a result was
            // recorded to reach. It is a refusal rather than an `expect`
            // because nothing here panics on stored state.
            return Err(ChannelStateError::WrongPhase {
                step: "crediting a payment",
                phase: job.phase.name(),
            });
        };

        // A client pays by the height it signed to pay by, and this is
        // the last step where refusing costs it nothing. Past that height
        // the provider may end the job as expired and bear its cost
        // itself; a certificate signed afterwards is money the provider
        // can still close on. The provider is not bounded here: what
        // stops it crediting a late payment is that the job's terminal
        // is the only step left, and whichever terminal reaches the disk
        // first is the one that happened.
        if self.role == Role::Client {
            let (height, _) = self.cursor;
            if height > job.authorization.payment_deadline {
                return Err(ChannelStateError::PaymentLate {
                    height,
                    deadline: job.authorization.payment_deadline,
                });
            }
        }
        for (slot, signature, hash) in [
            (
                "binding",
                binding_signature,
                signing_hash(payment_binding_digest(&self.channel, binding)),
            ),
            (
                "certificate",
                certificate_signature,
                certificate.digest(self.network()),
            ),
        ] {
            if !verifier.verify_sig(signature, self.client_key(), hash) {
                return Err(ChannelStateError::BadSignature {
                    slot,
                    party: "the client",
                });
            }
        }

        // The rule that joins the private evidence to the one number
        // consensus sees. It runs here, on commit and on replay both,
        // over the job this journal itself recorded.
        self.ledger.credit_payment(
            &self.channel,
            &job.authorization,
            &result,
            binding,
            certificate,
            self.settlement,
        )?;

        self.rest_at(JobTerminal {
            work_id: job.work_id,
            phase: job.phase,
            outcome: TerminalOutcome::Certified {
                certificate: *certificate,
                binding: *binding,
                binding_signature,
                certificate_signature,
            },
        });
        Ok(Applied::Changed)
    }

    /// Installs this channel's one permanent terminal and closes the job.
    fn rest_at(&mut self, terminal: JobTerminal) {
        self.terminal = Some(terminal);
        self.job = None;
        self.indeterminate = false;
    }

    /// Checks the one job's price against the compute limit.
    ///
    /// There is no cross-job total to accumulate: the channel admits one
    /// job, so a price that fits the limit is the whole of what fits.
    fn check_compute_limit(&self, price: u64) -> Result<(), ChannelStateError> {
        let limit = self.channel.channel_policy().compute_credit_limit;
        if price > limit {
            return Err(ChannelStateError::OverCredit {
                ledger: "compute",
                used: 0,
                reserved: 0,
                price,
                limit,
            });
        }
        Ok(())
    }

    /// Checks the one job's price against the delivery limit.
    fn check_delivery_limit(&self, price: u64) -> Result<(), ChannelStateError> {
        let limit = self.channel.channel_policy().delivery_credit_limit;
        if price > limit {
            return Err(ChannelStateError::OverCredit {
                ledger: "delivery",
                used: 0,
                reserved: 0,
                price,
                limit,
            });
        }
        Ok(())
    }
}

/// The durable channel journal: the state above and the file it is
/// replayed from.
#[derive(Debug)]
pub struct ChannelStore {
    journal: Journal,
    state: ChannelState,
    torn_tail: bool,
}

impl ChannelStore {
    /// Opens one channel's journal, replaying and re-checking every
    /// record it holds.
    ///
    /// `settlement` is what the funded payment edge can settle, taken
    /// from the finalized read that established the channel is live. It
    /// is a channel constant: a payment edge's value is fixed when it is
    /// opened, and every payment this store admits is bounded by it.
    ///
    /// `origin` is where the channel begins: the finalized block that
    /// carried its payment Open, which the setup handshake recorded.
    /// The cursor starts there rather than at nothing, and that is the
    /// whole of why it is required. A store that began with no cursor
    /// would have its watcher anchor at whatever height it first
    /// caught up to — skipping every block between the channel opening
    /// and that catch-up, and with them every close and every payment
    /// those blocks carried. The origin's payment edge must be this
    /// channel's, so the height cannot be another channel's.
    ///
    /// A job left in its running phase by the process that did not come
    /// back makes the state indeterminate. Opening does not resolve it,
    /// does not invoke anything, and refuses a result for it.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Journal`] when a file is held, corrupt, or
    /// another journal, and [`WorkStoreError::Channel`] when the origin
    /// is another channel's or a replayed record does not obey the
    /// transition rules.
    pub fn open<V: SigVerifier>(
        root: &Path,
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
        origin: SetupOrigin,
        verifier: &V,
    ) -> Result<Self, WorkStoreError> {
        if origin.payment_edge != channel.payment_edge() {
            return Err(ChannelStateError::WrongChannel {
                field: "setup origin payment_edge",
            }
            .into());
        }
        let key = channel_key(&channel).into_bytes();
        let (journal, replay) = Journal::open_latest(
            root,
            &format!("channel-{}", hex(&key)),
            JournalId {
                kind: JournalKind::Channel,
                role,
                key,
                generation: 0,
            },
        )?;
        let mut state = match &replay.checkpoint {
            Some(bytes) => {
                ChannelState::from_checkpoint(bytes, channel, settlement, role, verifier)?
            }
            None => ChannelState::new(channel, settlement, role, origin),
        };
        for bytes in &replay.records {
            let record = ChannelRecord::decode(bytes)?;
            state.apply(&record, verifier)?;
        }
        state.indeterminate = state
            .job
            .as_ref()
            .is_some_and(|job| job.phase == JobPhase::Running);
        let store = Self {
            journal,
            state,
            torn_tail: replay.truncated_tail,
        };
        Ok(store)
    }

    /// Returns whether opening removed an interrupted write.
    ///
    /// True says the last thing this endpoint tried to record did not
    /// finish reaching the disk, and the state above is the state
    /// before it. Nothing was acknowledged, so nothing here is wrong —
    /// but a clean shutdown does not produce it, and an operator who
    /// sees it has been told the truth about a crash.
    #[must_use]
    pub const fn recovered_torn_tail(&self) -> bool {
        self.torn_tail
    }

    /// Returns what this endpoint durably knows.
    #[must_use]
    pub const fn state(&self) -> &ChannelState {
        &self.state
    }

    /// Journals one step, and returns only once it is on the disk.
    ///
    /// The rule this exists to enforce: call it *before* the bytes it
    /// records leave the process, and before the side effect it
    /// authorises happens. A record the state already holds is not
    /// written twice, so retrying after a crash between the write and
    /// the release costs nothing and changes nothing.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Channel`] when the step is not one this state
    /// may take — checked before anything is written — and
    /// [`WorkStoreError::Journal`] when an append or its sync fails.
    pub fn commit<V: SigVerifier>(
        &mut self,
        record: ChannelRecord,
        verifier: &V,
    ) -> Result<&ChannelState, WorkStoreError> {
        // Applied to a copy first: a record the rules refuse must leave
        // neither the file nor the state touched.
        let mut next = self.state.clone();
        if next.apply(&record, verifier)? == Applied::Changed {
            // The signature this record carries leaves after this
            // returns, so the state that authorises it has to be one a
            // rotation can still carry. The sole job is charged the
            // fixed tail it can still add — the result it will be
            // answered with and the terminal that pays for it — because
            // by then there is no refusal left that costs nothing.
            if let Some(tail) = record.checkpoint_tail() {
                let len = next.checkpoint().len().saturating_add(tail);
                if len > MAX_CHECKPOINT_BYTES {
                    return Err(JournalError::CheckpointTooLarge { len }.into());
                }
            }
            self.rotate_if_full(record.is_new_work())?;
            self.journal.append(&record.encode())?;
            self.state = next;
        }
        Ok(&self.state)
    }

    /// Moves the journal on to its next generation, carrying this state
    /// as its first frame.
    ///
    /// What [`Self::commit`] does for itself at the soft limit, and what
    /// an operator may ask for at any time. It is the step that makes a
    /// close duty outlive the file it is written in: the successor's
    /// first frame is everything the predecessor said, so the
    /// predecessor's bytes go and none of its facts do.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Journal`] when the checkpoint does not fit one
    /// frame or an install step fails.
    pub fn rotate(&mut self) -> Result<(), WorkStoreError> {
        self.journal.rotate(&self.state.checkpoint())?;
        Ok(())
    }

    /// Rotates at the soft limit, and decides who may go on without it.
    ///
    /// New work stops when a rotation cannot complete, because admitting
    /// it would be promising a duty this journal has no room to finish.
    /// A duty already exported does not stop: the reserve above the soft
    /// limit is exactly the room the cursor advances, the close and the
    /// answer finish in, and it is [`Journal::append`] that refuses when
    /// even that is gone.
    fn rotate_if_full(&mut self, new_work: bool) -> Result<(), WorkStoreError> {
        if !self.journal.at_soft_limit() {
            return Ok(());
        }
        match self.journal.rotate(&self.state.checkpoint()) {
            Ok(()) => Ok(()),
            Err(error) if new_work => Err(error.into()),
            Err(_) => Ok(()),
        }
    }

    /// Returns how many records the channel journal holds.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.journal.len()
    }

    /// Returns whether the channel journal holds no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.journal.is_empty()
    }
}

/// Returns the key a channel journal is named and bound by.
///
/// The channel id, which already binds the network, both edges, and
/// both terms bodies. A journal opened for a channel whose terms,
/// edges, or network differ by one byte is a journal with another key,
/// and the header check refuses it.
fn channel_key(channel: &PaidChannel) -> Digest {
    let mut hasher = XetFileHasher::new();
    hasher.update(CHANNEL_KEY);
    hasher.update(channel.id().as_bytes());
    hasher.finalize()
}
