//! One channel's durable state: its one job, its credit, and the
//! certificates that pay for it.
//!
//! # Why this exists
//!
//! `CreditLedger` is what says a job is paid for at most once, and it is
//! a value in memory. A process that lost it and started again would
//! credit the same job at a fresh cumulative, and nothing in the records
//! themselves could tell the difference. This module is where that value
//! lives across a restart, and it is what makes "paid once" a property
//! of the endpoint rather than of the process.
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
//! Two ledger movements have the same shape. Compute credit is reserved
//! before the provider co-signs, not when it dispatches, because a
//! signature it cannot afford to honour is already the loss. Delivery
//! credit is reserved before the plaintext leaves, because afterwards
//! there is nothing left to decide.
//!
//! # Credit is a decision with a time
//!
//! Both reservations read what this counterparty has already lost, and
//! that number only grows. A replay therefore reads the journal the way
//! it was written: [`ChannelStore::open`] starts owed nothing and adds
//! each ending's loss as it reaches the record that ends it, so every
//! historical reservation is re-checked against what was lost *before*
//! it. Judging an old reservation by a later total is how a file that
//! was legal at every step becomes a file that cannot be opened.
//!
//! What that re-check can see is what this journal itself records. The
//! loss ledger is keyed by counterparty, not by channel, so the totals
//! it holds when the file is opened may include channels this journal
//! has never heard of; those are installed once, at the end, because
//! they bound the *next* job rather than the ones already recorded.
//!
//! # What a record is
//!
//! Twelve tags, and every one of them is a boundary something else
//! cannot be read off. Four carry a signed artifact — the
//! authorization, the co-signature, the result, and the certificate with
//! its binding — and for each of those [`ChannelStore`] verifies the
//! signature against the party the channel names, over that record's own
//! digest, on commit *and* on replay. A journal that would not have been
//! accepted a record at a time is not accepted whole.
//!
//! The result carries one thing more, and it is the only record here
//! checked against something other than a key: the transcript it
//! summarises rides with it, and the result must be what
//! [`terminal_result`] rebuilds from those events. A signature says the
//! provider stands behind two digests; the rebuild says the digests are
//! that transcript's.
//!
//! Four — the running marker, the plaintext release, the oracle
//! verdict, and the job ending — are this endpoint's own statements
//! about itself. Nothing
//! signs them, and nothing here pretends to check them against anything
//! but the state they move. The last four — the cursor and the three
//! close records — are what this endpoint read out of finalized blocks,
//! plus the one close signature it wrote ahead of sending.
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use hellas_kernel::{
    Decode, EarnedCertificate, Encode, Key, NetworkId, Party, PaymentCloseStart, Sig, SigVerifier,
    StartId, WorkPaymentSettlement,
};
use hellas_xet::XetFileHasher;

use crate::protocol::Digest;
use crate::protocol::artifacts::PreparedPaidInputV1;
use crate::protocol::work::{
    CreditLedger, PaidChannel, PaidJobAuthorizationV1, PaidJobResultV1, PaidWorkError,
    PaymentBindingV1, PrivateRecord as _, decode_transcript, payment_binding_digest,
    prepared_input_digest, result_digest, signing_hash, terminal_result, work_id,
};
use crate::work_store::journal::{Journal, JournalId, JournalKind, MAX_RECORD_BYTES, Role};
use crate::work_store::{Applied, WorkStoreError, cursor::Cursor, hex, put_u64};

/// Domain of a channel journal's key.
const CHANNEL_KEY: &[u8] = b"hellas.work.channel-journal-key.v1";
/// Domain of a counterparty-loss journal's key.
const LOSS_KEY: &[u8] = b"hellas.work.counterparty-loss-key.v1";

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
    /// The proposal nonce was one this channel has already spent.
    ///
    /// A client's nonces are its own and only ever advance, so the rule
    /// is a high-water mark rather than a set: a proposal at or below
    /// what this journal has already recorded is a proposal it has
    /// already answered, whatever bytes it carries now. That is what
    /// makes "one `work_id` opens at most one job, ever" a fact about
    /// this file rather than about a process.
    #[error("proposal nonce {actual} is not at least the expected {expected}")]
    Nonce {
        /// Smallest nonce the transition admits.
        expected: u64,
        /// Nonce the record carried.
        actual: u64,
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
    /// A step needs a finalized height and none has been processed.
    #[error("{step} needs a finalized block, and none has been processed")]
    NoCursor {
        /// Step that was attempted.
        step: &'static str,
    },
    /// A result reached the client after the height it was owed by.
    ///
    /// Late plaintext earns nothing: the provider signed a terminal
    /// deadline, and a client that recorded a receipt past it would be
    /// building the evidence for an invoice the same deadline refuses.
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
    /// This job's loss is already on the disk, so the ending it belongs
    /// to is the only step left for it.
    #[error("this job's loss is already recorded; only its ending may be committed now")]
    LossRecorded,
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
    /// The client's oracle reproduced the answer. Client-only.
    Verified,
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
            Self::Verified => "verified",
            Self::Delivered => "delivered",
        }
    }

    /// Whether reaching this phase means a signed result exists.
    ///
    /// Deliberately not "compute was spent", which the running phase
    /// also means. A client owes for compute it could have been paid
    /// for — which is compute that produced a result the client could
    /// have taken — and a job that stopped while running produced
    /// nothing for anyone.
    const fn result_recorded(self) -> bool {
        matches!(self, Self::Ready | Self::Verified | Self::Delivered)
    }

    /// Whether reaching this phase means plaintext left the provider.
    const fn delivered(self) -> bool {
        matches!(self, Self::Delivered)
    }
}

/// Why one job stopped without being paid.
///
/// It decides who bears the cost, which is why it is journaled and why
/// [`ChannelState::loss_of`] reads it. Only [`Self::Expired`] can charge
/// this counterparty, and only for a job that got far enough to have
/// produced something the client could have paid for. The other two name
/// the provider's own side going wrong, and the provider bears those:
/// otherwise a provider could exhaust a client's identity-wide credit by
/// accepting jobs and failing them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JobEnd {
    /// A deadline passed with the job unfinished or unpaid.
    #[error("expired")]
    Expired,
    /// Execution or validation failed.
    #[error("failed")]
    Failed,
    /// The process crashed between invocation and terminal
    /// persistence. Recording this is an operator's decision, never an
    /// automatic one.
    #[error("indeterminate")]
    Indeterminate,
}

mod end_code {
    pub(super) const EXPIRED: u8 = 0;
    pub(super) const FAILED: u8 = 1;
    pub(super) const INDETERMINATE: u8 = 2;
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
    /// kept only the digests could not re-run its oracle without asking
    /// the provider for the bytes again.
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
    /// The client's oracle reproduced this job's answer.
    ///
    /// Client-only, and kept past this profile's simplification for one
    /// reason: it is the whole of what makes a delivered result payable.
    /// Nothing else on this journal distinguishes an answer that was
    /// checked from one that merely arrived signed, and without it a
    /// client that fetched a result its own oracle refused could still
    /// sign a certificate for it. `hellas_client::work` writes this at
    /// exactly one place — immediately after `oracle::verify` returns —
    /// and the payment rule below is what makes that one place the only
    /// way to reach a payment.
    ResultVerified,
    /// The client's certificate and the binding that says what it paid
    /// for.
    ///
    /// One record for both, because neither is evidence without the
    /// other: a certificate alone is a number, and a binding alone names
    /// a certificate that need not exist. It is also the record that
    /// retires this job's compute and delivery credit, so the money and
    /// the release reach the disk in the same `fsync` or neither does.
    CertificateAdmitted {
        /// The scalar consensus will settle.
        certificate: EarnedCertificate,
        /// The private evidence of what it bought.
        binding: PaymentBindingV1,
        /// The client's signature over the binding's digest.
        binding_signature: Sig,
        /// The client's signature over the kernel's earned digest.
        certificate_signature: Sig,
    },
    /// The open job stopped without payment.
    JobEnded {
        /// Why.
        reason: JobEnd,
    },
    /// This endpoint has signed a close start, and these are its exact
    /// bytes.
    ///
    /// Written before the signature leaves the process, like every
    /// other signature here — and it is also the cutoff: from this
    /// record on the channel admits no new job and credits no new
    /// certificate, because a close that left out a certificate it was
    /// still admitting would be a close below what was earned.
    ClosePrepared {
        /// The signed start, exactly as it will be submitted.
        ///
        /// Boxed because a start reveals the channel's complete terms
        /// and is the widest thing this enum carries by a long way; the
        /// other eleven records would otherwise each be as large as it.
        start: Box<PaymentCloseStart>,
    },
    /// A close contest on this channel's payment edge was finalized.
    ///
    /// The contest identifier is the whole of what this adds, and it is
    /// the one thing about a close that cannot be derived from a
    /// retained signature: the kernel derives it from the start digest
    /// *and the height that accepted it*, so only the block tells an
    /// endpoint which contest its start became.
    CloseOpened {
        /// Contest a later response or close must name.
        start_id: StartId,
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
    pub(super) const VERIFIED: u8 = 6;
    pub(super) const ADMITTED: u8 = 7;
    pub(super) const ENDED: u8 = 8;
    pub(super) const CLOSE_PREPARED: u8 = 9;
    pub(super) const CLOSE_OPENED: u8 = 10;
    pub(super) const CLOSE_SETTLED: u8 = 11;
}

impl ChannelRecord {
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
            Self::ResultVerified => out.push(tag::VERIFIED),
            Self::CertificateAdmitted {
                certificate,
                binding,
                binding_signature,
                certificate_signature,
            } => {
                out.push(tag::ADMITTED);
                out.extend_from_slice(&encode_kernel(certificate));
                out.extend_from_slice(&binding.encode());
                out.extend_from_slice(binding_signature.as_bytes());
                out.extend_from_slice(certificate_signature.as_bytes());
            }
            Self::JobEnded { reason } => {
                out.push(tag::ENDED);
                out.push(match reason {
                    JobEnd::Expired => end_code::EXPIRED,
                    JobEnd::Failed => end_code::FAILED,
                    JobEnd::Indeterminate => end_code::INDETERMINATE,
                });
            }
            Self::ClosePrepared { start } => {
                out.push(tag::CLOSE_PREPARED);
                // Last field, and the whole of the rest, for the reason
                // `JobProposed`'s bundle is: a start is variable-width,
                // and the journal frame already carries this record's
                // length.
                out.extend_from_slice(&encode_kernel(start.as_ref()));
            }
            Self::CloseOpened { start_id } => {
                out.push(tag::CLOSE_OPENED);
                out.extend_from_slice(&start_id.to_bytes());
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

    /// Whether this record carries the open job forward.
    ///
    /// The six steps between a proposal and its payment. Not the
    /// ending, which is what stops it; not the proposal, which is what
    /// there would be no open job without; and not the cursor or the
    /// close records, which say nothing about a job.
    const fn advances_the_open_job(&self) -> bool {
        matches!(
            self,
            Self::JobAccepted { .. }
                | Self::JobRunning
                | Self::JobResult { .. }
                | Self::PlaintextReleased
                | Self::ResultVerified
                | Self::CertificateAdmitted { .. }
        )
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
            tag::VERIFIED => Self::ResultVerified,
            tag::ADMITTED => Self::CertificateAdmitted {
                certificate: certificate(&mut cursor)?,
                binding: private_record(&mut cursor)?,
                binding_signature: signature(&mut cursor)?,
                certificate_signature: signature(&mut cursor)?,
            },
            tag::ENDED => Self::JobEnded {
                reason: match cursor.byte().ok_or(ChannelStateError::Malformed)? {
                    end_code::EXPIRED => JobEnd::Expired,
                    end_code::FAILED => JobEnd::Failed,
                    end_code::INDETERMINATE => JobEnd::Indeterminate,
                    _ => return Err(ChannelStateError::Malformed),
                },
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

fn private_record<R: crate::protocol::work::PrivateRecord>(
    cursor: &mut Cursor<'_>,
) -> Result<R, ChannelStateError> {
    let bytes = cursor
        .take(R::ENCODED_SIZE)
        .ok_or(ChannelStateError::Malformed)?;
    Ok(R::decode(bytes)?)
}

fn signature(cursor: &mut Cursor<'_>) -> Result<Sig, ChannelStateError> {
    let bytes = cursor
        .array::<{ Sig::LENGTH }>()
        .ok_or(ChannelStateError::Malformed)?;
    Ok(Sig::from_bytes(bytes))
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

/// One credited payment, exactly as it was recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidCertificate {
    /// The job it paid for.
    ///
    /// Not a field of the record: it is read off the job this journal
    /// was crediting when the record was applied, which is the same job
    /// on commit and on replay. It is what lets a recovered endpoint
    /// answer "what did I pay for that work id" after the job itself
    /// has been closed by the payment.
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

impl PaidCertificate {
    /// Whether this retained payment is exactly these recorded bytes.
    ///
    /// The four fields a [`ChannelRecord::CertificateAdmitted`] carries,
    /// and deliberately not [`Self::work_id`], which it does not carry:
    /// a re-sent payment is the same payment when its bytes are the same
    /// bytes, and the job those bytes closed is not offered again.
    fn is_recorded_as(
        &self,
        certificate: &EarnedCertificate,
        binding: &PaymentBindingV1,
        binding_signature: Sig,
        certificate_signature: Sig,
    ) -> bool {
        self.certificate == *certificate
            && self.binding == *binding
            && self.binding_signature == binding_signature
            && self.certificate_signature == certificate_signature
    }
}

/// Unrecovered value one counterparty owes, in the two currencies v4
/// bounds it in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LossTotals {
    /// Compute spent on jobs that were never paid for.
    pub compute: u64,
    /// Plaintext value delivered on jobs that were never paid for.
    pub delivery: u64,
}

impl LossTotals {
    /// Returns these totals with one more job's loss counted.
    ///
    /// # Errors
    ///
    /// [`PaidWorkError::Overflow`] if either currency would wrap. The
    /// totals move in one step, so a sum that cannot be taken leaves
    /// neither currency moved.
    fn plus(self, compute: u64, delivery: u64) -> Result<Self, PaidWorkError> {
        Ok(Self {
            compute: self
                .compute
                .checked_add(compute)
                .ok_or(PaidWorkError::Overflow {
                    field: "compute loss",
                })?,
            delivery: self
                .delivery
                .checked_add(delivery)
                .ok_or(PaidWorkError::Overflow {
                    field: "delivery loss",
                })?,
        })
    }
}

/// What one endpoint durably knows about one channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelState {
    channel: PaidChannel,
    settlement: WorkPaymentSettlement,
    role: Role,
    loss: LossTotals,
    ledger: CreditLedger,
    next_proposal_nonce: u64,
    job: Option<JobState>,
    last_payment: Option<PaidCertificate>,
    compute_outstanding: u64,
    delivery_outstanding: u64,
    cursor: Option<(u64, [u8; 32])>,
    indeterminate: bool,
    close_prepared: Option<PaymentCloseStart>,
    close_opened: Option<StartId>,
    close_settled: Option<CloseSettlement>,
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
        loss: LossTotals,
    ) -> Self {
        Self {
            channel,
            settlement,
            role,
            loss,
            ledger: CreditLedger::new(),
            // A client's own nonces start at one and only advance, so
            // this is the first one it may spend. It is not a claim
            // about every authorization: a provider takes the nonce the
            // client's signature carries, whatever number that is, and
            // what it enforces is that it never takes that one or any
            // smaller one again.
            next_proposal_nonce: 1,
            job: None,
            last_payment: None,
            compute_outstanding: 0,
            delivery_outstanding: 0,
            cursor: None,
            indeterminate: false,
            close_prepared: None,
            close_opened: None,
            close_settled: None,
        }
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
    /// invoices by a different number than this one.
    #[must_use]
    pub const fn settlement(&self) -> WorkPaymentSettlement {
        self.settlement
    }

    /// Returns the next proposal nonce this client may consume.
    #[must_use]
    pub const fn next_proposal_nonce(&self) -> u64 {
        self.next_proposal_nonce
    }

    /// Returns the job in flight, if there is one.
    #[must_use]
    pub const fn job(&self) -> Option<&JobState> {
        self.job.as_ref()
    }

    /// Returns the last certificate this channel credited, with the
    /// allocation and the two signatures it was credited against.
    ///
    /// What a recovered endpoint re-sends. The job it paid for is
    /// closed, so these bytes are the only remaining copy of what was
    /// agreed, and offering them again is idempotent rather than a
    /// second payment.
    #[must_use]
    pub const fn last_payment(&self) -> Option<&PaidCertificate> {
        self.last_payment.as_ref()
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

    /// Returns the largest cumulative any held certificate names.
    ///
    /// The most this channel has been shown it earned. A certificate the
    /// client signed is one it cannot repudiate, so a close that named
    /// less than this would be a close below what was already earned.
    /// Nothing here builds a close, and nothing here enforces that; this
    /// is the value such a builder must start from.
    ///
    /// Read off the last admitted payment rather than tracked beside it.
    /// Every certificate this journal holds arrived as a payment, and a
    /// payment's cumulative is the credited total plus a price that
    /// cannot be zero — so payments are strictly increasing and the last
    /// one is the largest. A second field for "the biggest so far" would
    /// be a second answer to a question that already has one.
    #[must_use]
    pub fn max_executable_certificate(&self) -> u64 {
        self.last_payment
            .as_ref()
            .map_or(0, |payment| payment.certificate.earned_cumulative())
    }

    /// Returns the compute reserved against the job in flight.
    #[must_use]
    pub const fn compute_outstanding(&self) -> u64 {
        self.compute_outstanding
    }

    /// Returns the plaintext value delivered and not yet paid for.
    #[must_use]
    pub const fn delivery_outstanding(&self) -> u64 {
        self.delivery_outstanding
    }

    /// Returns this counterparty's unrecovered loss, as the shared
    /// identity-keyed ledger holds it.
    #[must_use]
    pub const fn loss(&self) -> LossTotals {
        self.loss
    }

    /// Returns the finalized block this endpoint has processed through.
    ///
    /// Contiguous by construction: every block from the first one this
    /// journal recorded to this one was read, in order, each naming the
    /// last as its parent. That is what makes it usable as a clock — a
    /// height reached by skipping is a height at which this endpoint
    /// does not know what happened.
    #[must_use]
    pub const fn cursor(&self) -> Option<(u64, [u8; 32])> {
        self.cursor
    }

    /// Returns the close start this endpoint signed and retains.
    ///
    /// What a resubmission sends. It stays here until a finalized block
    /// shows a contest opened, or until the cursor has passed the last
    /// height the signature could have been included at.
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

    /// Returns the finalized contest on this channel's payment edge.
    #[must_use]
    pub const fn close_opened(&self) -> Option<StartId> {
        self.close_opened
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
        self.last_payment
            .as_ref()
            .map(|payment| (payment.certificate, payment.certificate_signature))
    }

    /// Whether this channel has begun closing.
    ///
    /// True from the moment a close start of this endpoint's is on the
    /// disk, or a contest is finalized on this edge, or the edge is
    /// gone. It is the cutoff: past it no job is admitted and no
    /// certificate is credited, because a close cannot carry what it
    /// did not know about.
    #[must_use]
    pub const fn is_closing(&self) -> bool {
        self.close_prepared.is_some() || self.close_opened.is_some() || self.close_settled.is_some()
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
        self.job.clone().ok_or(ChannelStateError::WrongPhase {
            step,
            phase: "none",
        })
    }

    /// Applies one record, or says why it may not be applied.
    ///
    /// Every rule this endpoint has is here, and replay runs it too, so
    /// a journal that could not have been written a record at a time is
    /// not read back whole. The two credit rules read [`Self::loss`],
    /// which is a moving number rather than a fact about the record —
    /// so a replay must move it as it goes, and [`ChannelStore::open`]
    /// is where that is done.
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
            ChannelRecord::ResultVerified => self.apply_verified(),
            ChannelRecord::CertificateAdmitted {
                certificate,
                binding,
                binding_signature,
                certificate_signature,
            } => self.apply_admitted(
                certificate,
                binding,
                *binding_signature,
                *certificate_signature,
                verifier,
            ),
            ChannelRecord::JobEnded { reason } => self.apply_ended(*reason),
            ChannelRecord::ClosePrepared { start } => self.apply_close_prepared(start),
            ChannelRecord::CloseOpened { start_id } => self.apply_close_opened(*start_id),
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
    /// Two rules, and they are the whole of what a cursor means here.
    /// The height must be the next one, so nothing is skipped; and the
    /// block must name the held block as its parent, so the chain that
    /// was read is one chain. A watcher that fetched heights alone
    /// would accept a block from a history this endpoint never saw.
    ///
    /// The first record has neither to check against. It anchors the
    /// scan, and its parent is checked against nothing — an endpoint
    /// that starts watching at height 900 has read no block before 900
    /// and this makes no claim that it has.
    fn apply_cursor(
        &mut self,
        height: u64,
        parent: &[u8; 32],
        payload: &[u8; 32],
    ) -> Result<Applied, ChannelStateError> {
        if self.cursor == Some((height, *payload)) {
            return Ok(Applied::Redundant);
        }
        if let Some((held_height, held_payload)) = self.cursor {
            if height != held_height.saturating_add(1) {
                return Err(ChannelStateError::CursorNotNext {
                    held: held_height,
                    actual: height,
                });
            }
            if *parent != held_payload {
                return Err(ChannelStateError::CursorNotContiguous { height });
            }
        }
        self.cursor = Some((height, *payload));
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
        let Some((cursor_height, _)) = self.cursor else {
            return Err(ChannelStateError::NoCursor {
                step: "signing a close start",
            });
        };
        if self.includable_close_start(cursor_height).is_some() {
            return Err(ChannelStateError::Conflict {
                what: "a close start that can still be included",
            });
        }
        self.close_prepared = Some(start.clone());
        Ok(Applied::Changed)
    }

    /// Records the contest a finalized start opened.
    ///
    /// Refused once the edge is gone, and that is the rule that makes
    /// the watcher's ordering visible: a block carrying a start and the
    /// close that ends it is one history read in the validator's order
    /// and another read backwards, and only one of them is a history
    /// this journal takes.
    fn apply_close_opened(&mut self, start_id: StartId) -> Result<Applied, ChannelStateError> {
        if self.close_opened == Some(start_id) {
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
        self.close_opened = Some(start_id);
        Ok(Applied::Changed)
    }

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
        self.close_settled = Some(settlement);
        Ok(Applied::Changed)
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
        // A closing channel takes no new work. The close is built from
        // what is held now, so a job admitted after it would be a job
        // whose payment no close could carry.
        self.refuse_if_closing("proposing a job")?;

        // The channel this endpoint is, against the channel the
        // authorization names. The rest of the authorization's rules —
        // the policy digest, the deadlines, the price against the
        // finalized height — are `check_authorization`'s, and a second
        // spelling of them here would be a second chance to spell them
        // differently.
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

        if !verifier.verify_sig(client_signature, self.client_key(), signing_hash(work_id)) {
            return Err(ChannelStateError::BadSignature {
                slot: "authorization",
                party: "the client",
            });
        }

        // The nonce, burnt here and nowhere else, by both roles under
        // one rule: a proposal must carry a nonce this journal has not
        // reached, and recording it moves the mark past it. Ending a job
        // releases its credit and its capacity, and never its nonce, so
        // one `work_id` opens at most one job in this journal's life.
        //
        // A high-water mark rather than a set of spent numbers. The two
        // differ only for a client that proposes out of order, which its
        // own half of this rule already stops it doing — and the mark is
        // one integer that survives a restart for free, while a set is a
        // thing that grows for as long as the channel lives.
        let nonce = authorization.proposal_nonce;
        if nonce < self.next_proposal_nonce {
            return Err(ChannelStateError::Nonce {
                expected: self.next_proposal_nonce,
                actual: nonce,
            });
        }
        self.next_proposal_nonce = nonce.checked_add(1).ok_or(PaidWorkError::Overflow {
            field: "proposal nonce",
        })?;
        // Compute credit is the provider's exposure and only the
        // provider's: the client is the party that would default on it.
        if self.role == Role::Provider {
            self.reserve_compute(authorization.price)?;
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

        // A client records what was delivered to it, and delivery has a
        // deadline. The height is this journal's own cursor, so what it
        // measures is when this endpoint had *processed* a block, not
        // when a peer said one existed; how fresh that cursor is stays
        // the caller's, in the sense `ReadyChannel` already documents.
        // A provider is not bounded here: its own release gate is what
        // stops late plaintext, and journaling a result it computed but
        // may not release is honest evidence rather than a step.
        if self.role == Role::Client {
            let Some((height, _)) = self.cursor else {
                return Err(ChannelStateError::NoCursor {
                    step: "recording a delivered result",
                });
            };
            if height > job.authorization.terminal_deadline {
                return Err(ChannelStateError::ReceiptLate {
                    height,
                    deadline: job.authorization.terminal_deadline,
                });
            }
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

    /// Records that this client's oracle reproduced the answer.
    ///
    /// It checks that there is a delivered result to have an opinion
    /// about and that this journal is a client's. What it cannot check
    /// is the verdict itself: the oracle is the caller's, and this
    /// records a decision rather than making one. That is why the
    /// verdict is a step of its own rather than a flag on the result —
    /// a receipt is timely or late whatever an oracle later says, and
    /// the two are decided at different heights.
    fn apply_verified(&mut self) -> Result<Applied, ChannelStateError> {
        self.require_role("recording an oracle verdict", Role::Client)?;
        let mut job = self.open_job("recording an oracle verdict")?;
        match job.phase {
            JobPhase::Verified => return Ok(Applied::Redundant),
            JobPhase::Ready => {}
            phase => {
                return Err(ChannelStateError::WrongPhase {
                    step: "recording an oracle verdict",
                    phase: phase.name(),
                });
            }
        }
        job.phase = JobPhase::Verified;
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
        self.reserve_delivery(job.authorization.price)?;
        job.phase = JobPhase::Delivered;
        self.job = Some(job);
        Ok(Applied::Changed)
    }

    /// Credits one client payment, closing the job it pays for.
    ///
    /// The whole of the economic state machine's join with consensus,
    /// and it is one function because the two things it joins are one
    /// decision: the certificate is money, the binding is what the money
    /// bought, and an endpoint that took one without the other would
    /// hold a number it could not account for.
    fn apply_admitted<V: SigVerifier>(
        &mut self,
        certificate: &EarnedCertificate,
        binding: &PaymentBindingV1,
        binding_signature: Sig,
        certificate_signature: Sig,
        verifier: &V,
    ) -> Result<Applied, ChannelStateError> {
        // The retained payment, offered again. This is the crash
        // between writing the certificate and sending it: the job it
        // paid for is closed, and re-sending the retained bytes must
        // not look like a second payment — nor like a step a closed job
        // cannot take, which is why this is answered before the rules
        // below rather than among them.
        if self.last_payment.as_ref().is_some_and(|held| {
            held.is_recorded_as(
                certificate,
                binding,
                binding_signature,
                certificate_signature,
            )
        }) {
            return Ok(Applied::Redundant);
        }
        // No cutoff check here, and none is needed: a payment credits
        // the open job, and a close start is refused while there is
        // one. The two are excluded by the same fact, and a second
        // spelling of it would be a second chance to spell it
        // differently.
        let job = self.open_job("crediting a payment")?;
        // A provider credits what it has delivered. A client has no
        // delivery marker of its own; what it has is the verdict its own
        // oracle reached, and a result that merely arrived is not one an
        // honest client signs a certificate for.
        let expected = match self.role {
            Role::Provider => JobPhase::Delivered,
            Role::Client => JobPhase::Verified,
        };
        if job.phase != expected {
            return Err(ChannelStateError::WrongPhase {
                step: "crediting a payment",
                phase: job.phase.name(),
            });
        }
        let Some((result, _)) = job.result else {
            // Unreachable: both phases above are phases a result was
            // recorded to reach. It is a refusal rather than an
            // `expect` because nothing here panics on stored state. No
            // test isolates it, and none claims to.
            return Err(ChannelStateError::WrongPhase {
                step: "crediting a payment",
                phase: job.phase.name(),
            });
        };

        // A client pays by the height it signed to pay by, and this is
        // the last step where refusing costs it nothing. Past that
        // height the provider may end the job as expired and charge its
        // price to this client's identity-wide loss ledger; a
        // certificate signed afterwards is money the provider can still
        // close on, so the job would be paid for twice. The provider is
        // not bounded here: what stops it crediting a late payment is
        // that ending the job is the only step left for a job whose
        // loss is already on the disk (`ChannelStore::commit`), and
        // whichever of the two reaches that file first is the one that
        // happened.
        if self.role == Role::Client {
            // Unreachable through a client's own journal: a client
            // cannot hold a result without having recorded a receipt, a
            // receipt needs a cursor, and a cursor never goes back. It
            // is a refusal rather than an assumed height because this
            // rule must not pass for want of a number. No test isolates
            // it, and none claims to.
            let Some((height, _)) = self.cursor else {
                return Err(ChannelStateError::NoCursor {
                    step: "signing a payment",
                });
            };
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

        // The one rule that says a job is paid for at most once. It runs
        // here, on commit and on replay both, over the job this journal
        // itself recorded — not over anything the record could have
        // named for itself.
        self.ledger.credit_payment(
            &self.channel,
            &job.authorization,
            &result,
            binding,
            certificate,
            self.settlement,
        )?;

        let price = job.authorization.price;
        self.compute_outstanding = self.compute_outstanding.saturating_sub(price);
        if job.phase.delivered() {
            self.delivery_outstanding = self.delivery_outstanding.saturating_sub(price);
        }
        self.last_payment = Some(PaidCertificate {
            work_id: job.work_id,
            certificate: *certificate,
            binding: *binding,
            binding_signature,
            certificate_signature,
        });
        self.job = None;
        self.indeterminate = false;
        Ok(Applied::Changed)
    }

    /// Ends the open job, releasing everything it still holds.
    ///
    /// Both reservations come off here, whatever the ending was. What
    /// the ending *cost* is [`Self::loss_of`]'s, is written to the
    /// counterparty ledger before this, and is already installed in
    /// [`Self::loss`] by the time this runs — so the release below never
    /// gives back something the ledger has just taken.
    fn apply_ended(&mut self, reason: JobEnd) -> Result<Applied, ChannelStateError> {
        let _ = reason;
        let job = self.open_job("ending a job")?;
        let price = job.authorization.price;
        self.compute_outstanding = self.compute_outstanding.saturating_sub(price);
        if job.phase.delivered() {
            self.delivery_outstanding = self.delivery_outstanding.saturating_sub(price);
        }
        self.job = None;
        self.indeterminate = false;
        Ok(Applied::Changed)
    }

    /// Returns what ending the open job for `reason` costs this
    /// counterparty permanently, if anything.
    ///
    /// Two questions, and both must answer yes. *Whose fault* — only an
    /// expiry is the client's, because only an expiry is this client
    /// staying silent through a deadline it signed. A failure and an
    /// indeterminate marker are the provider's own side going wrong, and
    /// charging them here would let a provider drain a client's credit
    /// across every channel it has, by accepting work and failing it.
    /// Then *how far it got* — compute is owed for a result that exists
    /// and was not paid for, delivery for plaintext that left. A job
    /// that expired while still running produced nothing the client
    /// could have paid for, so it costs the client nothing.
    ///
    /// This is the ledger's whole opinion about cause. It is not a claim
    /// that an expiry was the client's fault in any richer sense: the
    /// journal does not know why a deadline passed, only that one did
    /// with a signed result unpaid.
    fn loss_of(&self, reason: JobEnd) -> Option<(Digest, u64, u64)> {
        let job = self.job.as_ref()?;
        if self.role != Role::Provider {
            return None;
        }
        let JobEnd::Expired = reason else {
            return None;
        };
        let price = job.authorization.price;
        let compute = if job.phase.result_recorded() {
            price
        } else {
            0
        };
        let delivery = if job.phase.delivered() { price } else { 0 };
        if compute == 0 && delivery == 0 {
            return None;
        }
        Some((job.work_id, compute, delivery))
    }

    fn reserve_compute(&mut self, price: u64) -> Result<(), ChannelStateError> {
        let limit = self.channel.channel_policy().compute_credit_limit;
        let reserved = self.compute_outstanding;
        let used = self.loss.compute;
        let total = used
            .checked_add(reserved)
            .and_then(|sum| sum.checked_add(price))
            .ok_or(PaidWorkError::Overflow {
                field: "compute credit",
            })?;
        if total > limit {
            return Err(ChannelStateError::OverCredit {
                ledger: "compute",
                used,
                reserved,
                price,
                limit,
            });
        }
        self.compute_outstanding = total.saturating_sub(used);
        Ok(())
    }

    fn reserve_delivery(&mut self, price: u64) -> Result<(), ChannelStateError> {
        let limit = self.channel.channel_policy().delivery_credit_limit;
        let reserved = self.delivery_outstanding;
        let used = self.loss.delivery;
        let total = used
            .checked_add(reserved)
            .and_then(|sum| sum.checked_add(price))
            .ok_or(PaidWorkError::Overflow {
                field: "delivery credit",
            })?;
        if total > limit {
            return Err(ChannelStateError::OverCredit {
                ledger: "delivery",
                used,
                reserved,
                price,
                limit,
            });
        }
        self.delivery_outstanding = total.saturating_sub(used);
        Ok(())
    }
}

/// One counterparty's unrecovered loss, keyed by identity rather than by
/// channel.
///
/// Separate from the channel journal on purpose, and this is the whole
/// reason it is a second file: a fresh payment edge for the same client
/// inherits it. Closing a channel, rotating it, or deleting its journal
/// does not give a defaulting client its credit back.
#[derive(Debug)]
pub struct CounterpartyLoss {
    journal: Journal,
    entries: BTreeMap<[u8; 32], (u64, u64)>,
    totals: LossTotals,
}

impl CounterpartyLoss {
    /// Opens the loss ledger for one client key on one network.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Journal`] when the file is held, corrupt, or
    /// another journal, and [`WorkStoreError::Channel`] when a replayed
    /// record contradicts an earlier one.
    pub fn open(
        root: &Path,
        network: NetworkId,
        client: Key,
        role: Role,
    ) -> Result<Self, WorkStoreError> {
        let key = loss_key(network, client).into_bytes();
        let (journal, replay) = Journal::open(
            root.join(format!("counterparty-{}.journal", hex(&key))),
            JournalId {
                kind: JournalKind::CounterpartyLoss,
                role,
                key,
            },
        )?;
        let mut ledger = Self {
            journal,
            entries: BTreeMap::new(),
            totals: LossTotals::default(),
        };
        for bytes in &replay.records {
            let (work_id, compute, delivery) = decode_loss(bytes)?;
            ledger.apply(work_id, compute, delivery)?;
        }
        Ok(ledger)
    }

    /// Returns what this counterparty owes and has not paid.
    #[must_use]
    pub const fn totals(&self) -> LossTotals {
        self.totals
    }

    /// Returns whether this job's loss is already on the disk.
    ///
    /// Which is to say: whether ending it was already decided durably.
    /// Nothing here ever takes an entry back, so this answer only ever
    /// goes from false to true.
    #[must_use]
    pub fn holds(&self, work_id: Digest) -> bool {
        self.entries.contains_key(&work_id.into_bytes())
    }

    /// Records one job's unrecovered loss, and returns once it is on
    /// the disk.
    ///
    /// Idempotent by `work_id`: the same job's loss recorded twice is
    /// counted once, which is what lets the channel journal re-commit
    /// an interrupted job ending without paying for it twice.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Channel`] when the same job is recorded with
    /// different amounts, and [`WorkStoreError::Journal`] when the
    /// append or its sync fails.
    pub fn record(
        &mut self,
        work_id: Digest,
        compute: u64,
        delivery: u64,
    ) -> Result<(), WorkStoreError> {
        let key = work_id.into_bytes();
        match self.entries.get(&key) {
            Some(held) if *held == (compute, delivery) => return Ok(()),
            Some(_) => {
                return Err(ChannelStateError::Conflict {
                    what: "this job's loss",
                }
                .into());
            }
            None => {}
        }
        self.journal
            .append(&encode_loss(work_id, compute, delivery))?;
        self.apply(key, compute, delivery)?;
        Ok(())
    }

    fn apply(
        &mut self,
        work_id: [u8; 32],
        compute: u64,
        delivery: u64,
    ) -> Result<(), ChannelStateError> {
        match self.entries.get(&work_id) {
            Some(held) if *held == (compute, delivery) => return Ok(()),
            Some(_) => {
                return Err(ChannelStateError::Conflict {
                    what: "this job's loss",
                });
            }
            None => {}
        }
        self.totals = self.totals.plus(compute, delivery)?;
        self.entries.insert(work_id, (compute, delivery));
        Ok(())
    }
}

fn encode_loss(work_id: Digest, compute: u64, delivery: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(work_id.as_bytes());
    put_u64(&mut out, compute);
    put_u64(&mut out, delivery);
    out
}

fn decode_loss(bytes: &[u8]) -> Result<([u8; 32], u64, u64), ChannelStateError> {
    let mut cursor = Cursor::new(bytes);
    let work_id = cursor.array::<32>().ok_or(ChannelStateError::Malformed)?;
    let compute = cursor.u64().ok_or(ChannelStateError::Malformed)?;
    let delivery = cursor.u64().ok_or(ChannelStateError::Malformed)?;
    if cursor.is_empty() {
        Ok((work_id, compute, delivery))
    } else {
        Err(ChannelStateError::Malformed)
    }
}

/// The durable channel journal: the state above, the file it is
/// replayed from, and the counterparty ledger its credit rules read.
#[derive(Debug)]
pub struct ChannelStore {
    journal: Journal,
    loss: CounterpartyLoss,
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
    /// opened, and every invoice this store admits is bounded by it.
    ///
    /// A job left in its running phase by the process that did not come
    /// back makes the state indeterminate. Opening does not resolve it,
    /// does not invoke anything, and refuses a result for it.
    ///
    /// Loss is replayed with the records rather than in front of them:
    /// each historical reservation is re-checked against what this
    /// journal shows was lost before it, and the counterparty's whole
    /// total — every channel it has had — is what the state carries
    /// afterwards. A journal this endpoint wrote a record at a time is
    /// therefore never refused by a credit rule — each reservation is
    /// re-checked against a total no larger than the one it was taken
    /// under — while a journal whose own records show a reservation the
    /// limit did not allow still is.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Journal`] when a file is held, corrupt, or
    /// another journal, and [`WorkStoreError::Channel`] when a replayed
    /// record does not obey the transition rules.
    pub fn open<V: SigVerifier>(
        root: &Path,
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
        verifier: &V,
    ) -> Result<Self, WorkStoreError> {
        let loss = CounterpartyLoss::open(root, channel.network(), channel.client_key(), role)?;
        let key = channel_key(&channel).into_bytes();
        let (journal, replay) = Journal::open(
            root.join(format!("channel-{}.journal", hex(&key))),
            JournalId {
                kind: JournalKind::Channel,
                role,
                key,
            },
        )?;
        // Replay starts owed nothing and learns what it is owed as it
        // reads, because that is the order the file was written in. A
        // credit rule reads [`ChannelState::loss`], and a rule re-run
        // over a total that only existed later is a rule asking a
        // different question than the one that was answered.
        let mut state = ChannelState::new(channel, settlement, role, LossTotals::default());
        let mut counted = BTreeSet::new();
        for bytes in &replay.records {
            let record = ChannelRecord::decode(bytes)?;
            // Read before the record is applied: applying it is what
            // closes the job whose loss this is. Counted by `work_id`,
            // exactly as the ledger being reconstructed counts it, so
            // what one job cost is added once however it is recorded.
            let ending = match record {
                ChannelRecord::JobEnded { reason } => state.loss_of(reason),
                _ => None,
            };
            state.apply(&record, verifier)?;
            if let Some((work_id, compute, delivery)) = ending
                && counted.insert(work_id.into_bytes())
            {
                state.loss = state
                    .loss
                    .plus(compute, delivery)
                    .map_err(ChannelStateError::from)?;
            }
        }
        // What the *next* job is checked against is the whole of what
        // this client owes now — including the channels this journal
        // knows nothing about, which is the reason the loss ledger is
        // keyed by identity and not by channel.
        state.loss = loss.totals();
        state.indeterminate = state
            .job
            .as_ref()
            .is_some_and(|job| job.phase == JobPhase::Running);
        Ok(Self {
            journal,
            loss,
            state,
            torn_tail: replay.truncated_tail,
        })
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

    /// Returns this counterparty's unrecovered loss.
    #[must_use]
    pub const fn loss(&self) -> LossTotals {
        self.loss.totals()
    }

    /// Journals one step, and returns only once it is on the disk.
    ///
    /// The rule this exists to enforce: call it *before* the bytes it
    /// records leave the process, and before the side effect it
    /// authorises happens. A record the state already holds is not
    /// written twice, so retrying after a crash between the write and
    /// the release costs nothing and changes nothing.
    ///
    /// Ending a job writes two files. The counterparty's loss goes
    /// first, so a crash between them leaves the loss counted and the
    /// job still open — which over-counts what the client owes until
    /// the ending is re-committed, and never under-counts it.
    ///
    /// Re-committing that ending is then the *only* step this store
    /// will take for that job. A journal alone cannot see it: the job
    /// reads as open, so a late payment would credit it while its price
    /// stayed in a ledger that has no way to give it back, and the
    /// client would have both paid and been charged. The loss file is
    /// consulted here rather than on replay, because once the ending is
    /// recorded the phase rules say the same thing from the journal
    /// itself — and a replay that judged old records by a file which
    /// outlived them is the defect this store had once already.
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
        let loss = match record {
            ChannelRecord::JobEnded { reason } => next.loss_of(reason),
            _ => None,
        };
        // Read before the record is applied, because a payment is one
        // of the steps that would close the job this asks about.
        let decided = self
            .state
            .job
            .as_ref()
            .is_some_and(|job| self.loss.holds(job.work_id));
        if next.apply(&record, verifier)? == Applied::Changed {
            // Gated on `Changed`, so a record this state already holds
            // is still the free retry it was: the refusal is for a job
            // being carried forward, never for one being repeated.
            if decided && record.advances_the_open_job() {
                return Err(ChannelStateError::LossRecorded.into());
            }
            if let Some((work_id, compute, delivery)) = loss {
                self.loss.record(work_id, compute, delivery)?;
                // Installed on the live state as well as on the one
                // about to replace it: if the append below fails, the
                // loss is already durable, and a state that had not
                // counted it would admit work this client's credit no
                // longer covers.
                self.state.loss = self.loss.totals();
                next.loss = self.loss.totals();
            }
            self.journal.append(&record.encode())?;
            self.state = next;
        }
        Ok(&self.state)
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

/// Returns the key a counterparty-loss journal is named and bound by.
fn loss_key(network: NetworkId, client: Key) -> Digest {
    let mut hasher = XetFileHasher::new();
    hasher.update(LOSS_KEY);
    hasher.update(network.as_str().as_bytes());
    hasher.update(&client.to_bytes());
    hasher.finalize()
}
