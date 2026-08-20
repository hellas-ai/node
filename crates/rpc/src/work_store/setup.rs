//! The two-Open handshake as durable state, and the one decision that
//! recovers it.
//!
//! # What is durable, and in which order
//!
//! `work_bundle` carries the handshake; it says so itself that "a
//! bundle is a value" and that the journal beneath it is this module's.
//! Here is that journal. Its rule is one sentence: **a revision is
//! fsynced before the signature it carries is exported.** Each revision
//! contains the signature its author has just made, so writing the
//! revision first means no signature ever leaves a process that has not
//! already written it down. A crash after the write and before the
//! export loses nothing: recovery re-exports the retained bytes, and
//! the signer is never asked to produce the same bytes twice.
//!
//! # Recovery is one function
//!
//! [`SetupState::decide`] is the whole of §6's five-way state machine,
//! and it is also what decides the *first* bond submission. That is
//! deliberate: the preflight — every coin funding the client's already
//! authorized payment Open is still live — is a premise of the
//! submit-bond branch, so an endpoint cannot lock stake without it, and
//! cannot skip it on a resubmission by taking a different code path.
//!
//! # What it cannot establish
//!
//! That the objects it is shown came from one coherent read. Whoever
//! fills in [`ObservedSetup`] owes that, exactly as with
//! `work_setup::ObservedChannel`. What this module does enforce is that
//! the coins and the edges are judged together, in one decision, from
//! one supplied height.

use std::collections::BTreeSet;
use std::path::Path;

use hellas_kernel::{CoinId, Edge, EdgeId, LeaseSlots, NetworkId, SigVerifier, Tx};
use hellas_xet::XetFileHasher;

use crate::protocol::Digest;
use crate::protocol::work_bundle::{SetupBundleError, WorkChannelSetupBundleV1};
use crate::work_store::journal::{Journal, JournalId, JournalKind, Role};
use crate::work_store::{Applied, WorkStoreError, cursor::Cursor, put_u64};

/// Domain of the setup journal's key.
const SETUP_KEY: &[u8] = b"hellas.work.setup-journal-key.v1";

/// Why a setup record is not one this journal may hold.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupStateError {
    /// The bundle did not decode, or is not the next revision of the
    /// one held.
    #[error(transparent)]
    Bundle(#[from] SetupBundleError),
    /// The bundle is over another network, or another bond, than this
    /// journal is keyed to.
    #[error("the bundle's {field} is not the one this journal is keyed to")]
    WrongChannel {
        /// Which field disagreed.
        field: &'static str,
    },
    /// A step was recorded from a stage that cannot take it.
    #[error("{step} cannot be recorded at revision {revision:?}")]
    WrongStage {
        /// Step that was attempted.
        step: &'static str,
        /// Revision the journal holds, if any.
        revision: Option<u8>,
    },
    /// Setup has already ended, one way or the other.
    #[error("setup has already ended: {0}")]
    Ended(SetupEnd),
    /// A record naming an edge the retained bundle does not produce.
    #[error("the record names payment edge {named:?}, not the retained {retained:?}")]
    WrongPaymentEdge {
        /// Edge the record named.
        named: EdgeId,
        /// Edge the retained bundle derives.
        retained: Option<EdgeId>,
    },
    /// Only a provider holds both transactions and submits them.
    #[error("{step} is a provider step, and this journal is a client's")]
    WrongRole {
        /// Step that was attempted.
        step: &'static str,
    },
    /// A record's bytes were not canonical.
    #[error("setup record is not canonical")]
    Malformed,
}

/// How setup ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupEnd {
    /// Both edges and the lease are live. This is the only end that
    /// produces a channel.
    #[error("complete")]
    Complete,
    /// Setup stopped without spending the provider's stake, and without
    /// anything to reconcile.
    #[error("aborted: {0}")]
    Aborted(SetupAbort),
    /// Setup stopped in a state no automatic step can leave.
    #[error("faulted: {0}")]
    Faulted(SetupFault),
}

/// Why setup stopped cleanly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupAbort {
    /// The retained bond Open can no longer be included: its own
    /// timeout is at or before the finalized height. Its funding is
    /// unspent and stays that way.
    #[error("the retained bond open expired before it was included")]
    BondOpenExpired,
    /// A coin funding the client's payment Open was spent before the
    /// bond was posted, so the channel it would insure cannot be
    /// funded.
    #[error("a coin funding the payment open was spent before the bond was posted")]
    PaymentFundingSpent,
}

/// Why setup cannot continue without reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupFault {
    /// The bond is absent and a coin that funded it is gone: something
    /// else spent the provider's stake input.
    #[error("the bond is absent and a coin funding it has been spent")]
    BondFundingSpent,
    /// The bond's lease slots hold something that is not a readable
    /// lease.
    #[error("the bond's lease slots are not a readable lease")]
    LeaseMalformed,
    /// The bond is leased to another payment edge.
    #[error("the bond is leased to another payment channel")]
    LeasedElsewhere,
    /// A live object contradicts another: a payment edge without its
    /// bond, a lease without its payment edge, or a payment edge with
    /// no lease at all.
    #[error("the finalized objects contradict each other")]
    UnexplainedState,
}

/// What one restart, or one first submission, should do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupDecision {
    /// Both edges and this channel's lease are live: record completion.
    Complete,
    /// Nothing to do here: the other party has not produced the next
    /// revision, or the transaction this endpoint is waiting on is not
    /// its own to send.
    AwaitingCounterparty,
    /// Submit the retained bond Open. This is both the first
    /// submission and every resubmission, and reaching it means the
    /// payment-funding preflight passed at the height decided from.
    SubmitBond,
    /// Submit the retained payment Open over the live unleased bond.
    SubmitPayment,
    /// Take the unleased bond's immediate Timeout back.
    TimeoutBond,
    /// Stop, with the provider's coins unspent.
    Abort(SetupAbort),
    /// Stop, and reconcile by hand.
    Fault(SetupFault),
}

/// One finalized read the setup decision is made from.
///
/// A struct rather than five arguments, for the same reason
/// `work_setup::ObservedChannel` is: two of its fields are
/// `Option<&Edge>` and would otherwise be silently swappable. Coherence
/// is the caller's: every field must come from one database snapshot at
/// `height`, and `live_funding` in particular must be read at that same
/// snapshot, because a coin read later than the edges is a preflight
/// that answers about a different state than the one it is protecting.
#[derive(Clone, Copy, Debug)]
pub struct ObservedSetup<'a> {
    /// Finalized height every field below was read at.
    pub height: u64,
    /// The bond edge, or its absence.
    pub bond: Option<&'a Edge>,
    /// The payment edge, or its absence.
    pub payment: Option<&'a Edge>,
    /// What the bond's lease slots held.
    pub lease: LeaseSlots,
    /// Every coin of the two Opens' funding that is still live at that
    /// snapshot. A coin absent from this set is a coin that is gone.
    pub live_funding: &'a BTreeSet<CoinId>,
}

/// One durable step of the handshake.
///
/// Deliberately small. The two submission markers carry no transaction
/// bytes because the retained bundle already is both transactions —
/// a second copy could only ever be a different one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupRecord {
    /// One revision of the handshake, written before the signature it
    /// carries is exported.
    Bundle {
        /// The revision's exact canonical bytes.
        bundle: Vec<u8>,
    },
    /// The retained bond Open is about to be broadcast.
    BondSubmitted,
    /// The retained payment Open is about to be broadcast.
    PaymentSubmitted,
    /// Both edges and the lease are finalized, at this block.
    Complete {
        /// The payment edge the retained bundle derives.
        payment_edge: EdgeId,
        /// Height of the block carrying the accepted payment Open.
        origin_height: u64,
        /// Payload digest of that block.
        origin_payload: [u8; 32],
        /// Payload digest of that block's parent, which is the watcher
        /// cursor immediately before the channel existed.
        origin_parent: [u8; 32],
    },
    /// Setup ended without a channel.
    Ended {
        /// Why.
        outcome: SetupEnd,
    },
}

mod tag {
    pub(super) const BUNDLE: u8 = 0;
    pub(super) const BOND_SUBMITTED: u8 = 1;
    pub(super) const PAYMENT_SUBMITTED: u8 = 2;
    pub(super) const COMPLETE: u8 = 3;
    pub(super) const ENDED: u8 = 4;
}

mod end_code {
    pub(super) const COMPLETE: u8 = 0;
    pub(super) const ABORT_BOND_EXPIRED: u8 = 1;
    pub(super) const ABORT_PAYMENT_FUNDING_SPENT: u8 = 2;
    pub(super) const FAULT_BOND_FUNDING_SPENT: u8 = 3;
    pub(super) const FAULT_LEASE_MALFORMED: u8 = 4;
    pub(super) const FAULT_LEASED_ELSEWHERE: u8 = 5;
    pub(super) const FAULT_UNEXPLAINED: u8 = 6;
}

const fn end_to_code(end: SetupEnd) -> u8 {
    match end {
        SetupEnd::Complete => end_code::COMPLETE,
        SetupEnd::Aborted(SetupAbort::BondOpenExpired) => end_code::ABORT_BOND_EXPIRED,
        SetupEnd::Aborted(SetupAbort::PaymentFundingSpent) => end_code::ABORT_PAYMENT_FUNDING_SPENT,
        SetupEnd::Faulted(SetupFault::BondFundingSpent) => end_code::FAULT_BOND_FUNDING_SPENT,
        SetupEnd::Faulted(SetupFault::LeaseMalformed) => end_code::FAULT_LEASE_MALFORMED,
        SetupEnd::Faulted(SetupFault::LeasedElsewhere) => end_code::FAULT_LEASED_ELSEWHERE,
        SetupEnd::Faulted(SetupFault::UnexplainedState) => end_code::FAULT_UNEXPLAINED,
    }
}

const fn end_from_code(code: u8) -> Option<SetupEnd> {
    Some(match code {
        end_code::COMPLETE => SetupEnd::Complete,
        end_code::ABORT_BOND_EXPIRED => SetupEnd::Aborted(SetupAbort::BondOpenExpired),
        end_code::ABORT_PAYMENT_FUNDING_SPENT => SetupEnd::Aborted(SetupAbort::PaymentFundingSpent),
        end_code::FAULT_BOND_FUNDING_SPENT => SetupEnd::Faulted(SetupFault::BondFundingSpent),
        end_code::FAULT_LEASE_MALFORMED => SetupEnd::Faulted(SetupFault::LeaseMalformed),
        end_code::FAULT_LEASED_ELSEWHERE => SetupEnd::Faulted(SetupFault::LeasedElsewhere),
        end_code::FAULT_UNEXPLAINED => SetupEnd::Faulted(SetupFault::UnexplainedState),
        _ => return None,
    })
}

impl SetupRecord {
    /// Returns this record's canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Bundle { bundle } => {
                out.push(tag::BUNDLE);
                // Last field, and the whole of the rest: the journal
                // frame already carries this record's length, and a
                // second length here could disagree with it.
                out.extend_from_slice(bundle);
            }
            Self::BondSubmitted => out.push(tag::BOND_SUBMITTED),
            Self::PaymentSubmitted => out.push(tag::PAYMENT_SUBMITTED),
            Self::Complete {
                payment_edge,
                origin_height,
                origin_payload,
                origin_parent,
            } => {
                out.push(tag::COMPLETE);
                out.extend_from_slice(&payment_edge.to_bytes());
                put_u64(&mut out, *origin_height);
                out.extend_from_slice(origin_payload);
                out.extend_from_slice(origin_parent);
            }
            Self::Ended { outcome } => {
                out.push(tag::ENDED);
                out.push(end_to_code(*outcome));
            }
        }
        out
    }

    /// Reads one record from exactly its canonical bytes.
    ///
    /// # Errors
    ///
    /// [`SetupStateError::Malformed`] for an unknown tag, a truncated
    /// body, or a trailing byte.
    pub fn decode(bytes: &[u8]) -> Result<Self, SetupStateError> {
        let mut cursor = Cursor::new(bytes);
        let record = match cursor.byte().ok_or(SetupStateError::Malformed)? {
            tag::BUNDLE => Self::Bundle {
                bundle: cursor.rest().to_vec(),
            },
            tag::BOND_SUBMITTED => Self::BondSubmitted,
            tag::PAYMENT_SUBMITTED => Self::PaymentSubmitted,
            tag::COMPLETE => Self::Complete {
                payment_edge: EdgeId::from_bytes(
                    cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
                ),
                origin_height: cursor.u64().ok_or(SetupStateError::Malformed)?,
                origin_payload: cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
                origin_parent: cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
            },
            tag::ENDED => Self::Ended {
                outcome: end_from_code(cursor.byte().ok_or(SetupStateError::Malformed)?)
                    .ok_or(SetupStateError::Malformed)?,
            },
            _ => return Err(SetupStateError::Malformed),
        };
        if cursor.is_empty() {
            Ok(record)
        } else {
            Err(SetupStateError::Malformed)
        }
    }
}

/// Where the channel this journal opens is finalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupOrigin {
    /// The payment edge the handshake produced.
    pub payment_edge: EdgeId,
    /// Height of the block carrying the accepted payment Open.
    pub height: u64,
    /// Payload digest of that block.
    pub payload: [u8; 32],
    /// Payload digest of its parent: the watcher's starting cursor.
    pub parent: [u8; 32],
}

/// Everything the handshake has durably reached.
#[derive(Clone, Debug)]
pub struct SetupState {
    network: NetworkId,
    bond_edge: EdgeId,
    role: Role,
    bundle: Option<WorkChannelSetupBundleV1>,
    bundle_bytes: Vec<u8>,
    bond_submitted: bool,
    payment_submitted: bool,
    origin: Option<SetupOrigin>,
    end: Option<SetupEnd>,
}

impl SetupState {
    fn new(network: NetworkId, bond_edge: EdgeId, role: Role) -> Self {
        Self {
            network,
            bond_edge,
            role,
            bundle: None,
            bundle_bytes: Vec::new(),
            bond_submitted: false,
            payment_submitted: false,
            origin: None,
            end: None,
        }
    }

    /// Returns the revision this endpoint has durably retained.
    #[must_use]
    pub fn revision(&self) -> Option<u8> {
        self.bundle.as_ref().map(WorkChannelSetupBundleV1::revision)
    }

    /// Returns the exact bytes of the retained revision.
    ///
    /// The bytes that were handed in, kept verbatim rather than
    /// re-encoded from the decoded value: a recovered endpoint
    /// re-exports the artifact it exported before, and "the encoding of
    /// what those bytes decode to" would be that artifact only as long
    /// as the codec is a fixed point. This does not need it to be.
    #[must_use]
    pub fn bundle_bytes(&self) -> Option<&[u8]> {
        self.bundle.as_ref().map(|_| self.bundle_bytes.as_slice())
    }

    /// Returns the bond edge this journal is keyed to.
    #[must_use]
    pub const fn bond_edge(&self) -> EdgeId {
        self.bond_edge
    }

    /// Returns the payment edge, once the client's revision has named
    /// its funding and terms.
    #[must_use]
    pub fn payment_edge(&self) -> Option<EdgeId> {
        self.bundle
            .as_ref()
            .and_then(WorkChannelSetupBundleV1::payment_edge)
    }

    /// Returns whether the bond Open has been journaled as submitted.
    #[must_use]
    pub const fn bond_submitted(&self) -> bool {
        self.bond_submitted
    }

    /// Returns whether the payment Open has been journaled as
    /// submitted.
    #[must_use]
    pub const fn payment_submitted(&self) -> bool {
        self.payment_submitted
    }

    /// Returns where the channel was finalized, once setup completed.
    #[must_use]
    pub const fn origin(&self) -> Option<SetupOrigin> {
        self.origin
    }

    /// Returns how setup ended, if it has.
    #[must_use]
    pub const fn end(&self) -> Option<SetupEnd> {
        self.end
    }

    /// Returns the coins the two retained Opens spend.
    ///
    /// This is what a caller reads liveness for before calling
    /// [`Self::decide`]. It is derived from the retained transactions,
    /// so a caller cannot check a coin set the signed bytes do not
    /// actually name.
    #[must_use]
    pub fn funding_coins(&self) -> BTreeSet<CoinId> {
        let mut coins = BTreeSet::new();
        for tx in [self.bond_open(), self.payment_open()]
            .into_iter()
            .flatten()
        {
            if let Tx::Open { funding, .. } = tx {
                coins.extend(funding.maker().iter().copied());
                coins.extend(funding.taker().iter().copied());
            }
        }
        coins
    }

    /// Returns the executable bond Open, once both parties have signed
    /// it.
    #[must_use]
    pub fn bond_open(&self) -> Option<Tx> {
        self.bundle
            .as_ref()
            .and_then(WorkChannelSetupBundleV1::bond_open)
    }

    /// Returns the executable payment Open, once both parties have
    /// signed it.
    #[must_use]
    pub fn payment_open(&self) -> Option<Tx> {
        self.bundle
            .as_ref()
            .and_then(WorkChannelSetupBundleV1::payment_open)
    }

    /// Returns the height at and after which the retained bond Open can
    /// no longer be included, and the channel admits no work.
    ///
    /// One value, not two: the tag-4 timeout is the bond's own expiry
    /// and, through the tag-2 body that derives its admission horizon
    /// from it, the channel's.
    #[must_use]
    pub fn horizon(&self) -> Option<u64> {
        let Some(Tx::Open { terms, .. }) = self.bond_open() else {
            return None;
        };
        Some(terms.timeout().get())
    }

    /// Decides what this endpoint should do next, from one finalized
    /// read.
    ///
    /// This is §6's recovery machine and the first submission both. The
    /// branch that submits the bond has the payment-funding preflight
    /// as a premise, so stake cannot be locked while a coin funding the
    /// client's already-signed payment Open is gone — on the first
    /// attempt or on the tenth.
    ///
    /// It never proposes a step whose subject is absent: no Timeout of
    /// an edge that does not exist, no resubmission of an Open whose
    /// own timeout has passed, and no reconstruction of a transaction
    /// from anything but the retained bytes.
    #[must_use]
    pub fn decide(&self, observed: &ObservedSetup<'_>) -> SetupDecision {
        if let Some(end) = self.end {
            return match end {
                SetupEnd::Complete => SetupDecision::Complete,
                SetupEnd::Aborted(abort) => SetupDecision::Abort(abort),
                SetupEnd::Faulted(fault) => SetupDecision::Fault(fault),
            };
        }
        let Some(payment_edge) = self.payment_edge() else {
            // Revision 1: no payment leg exists yet, so nothing on
            // chain can be about this channel.
            return SetupDecision::AwaitingCounterparty;
        };

        let leased_here = match observed.lease {
            LeaseSlots::Present(lease) => {
                if lease.payment_edge() == payment_edge && lease.bond_edge() == self.bond_edge {
                    Leased::Here
                } else {
                    Leased::Elsewhere
                }
            }
            LeaseSlots::Absent => Leased::Absent,
            LeaseSlots::Faulty(_) => Leased::Faulty,
        };

        match (observed.bond.is_some(), observed.payment.is_some()) {
            (true, true) => match leased_here {
                Leased::Here => SetupDecision::Complete,
                Leased::Elsewhere => SetupDecision::Fault(SetupFault::LeasedElsewhere),
                Leased::Faulty => SetupDecision::Fault(SetupFault::LeaseMalformed),
                // A live payment edge exists only because a payment
                // Open took this bond's lease. An absent slot beside it
                // is not an unleased channel, it is a state the kernel
                // does not produce.
                Leased::Absent => SetupDecision::Fault(SetupFault::UnexplainedState),
            },
            (true, false) => match leased_here {
                Leased::Absent => self.decide_unleased_bond(observed),
                Leased::Elsewhere => SetupDecision::Fault(SetupFault::LeasedElsewhere),
                Leased::Faulty => SetupDecision::Fault(SetupFault::LeaseMalformed),
                Leased::Here => SetupDecision::Fault(SetupFault::UnexplainedState),
            },
            // A payment edge whose bond is gone is not a channel and
            // not a state this handshake produces.
            (false, true) => SetupDecision::Fault(SetupFault::UnexplainedState),
            (false, false) => self.decide_absent_bond(observed),
        }
    }

    /// The bond is live and unleased: post the payment, or take the
    /// stake back.
    fn decide_unleased_bond(&self, observed: &ObservedSetup<'_>) -> SetupDecision {
        let Some(payment) = self.payment_open() else {
            // The client holds no countersigned payment Open, so it has
            // nothing to submit and nothing to time out; the provider
            // is the party that acts here.
            return SetupDecision::AwaitingCounterparty;
        };
        if self.role != Role::Provider {
            return SetupDecision::AwaitingCounterparty;
        }
        let horizon = self.horizon().unwrap_or(0);
        if !funding_live(&payment, observed.live_funding) || observed.height >= horizon {
            // Either the capacity funding is gone or the channel would
            // be born past its own horizon. The unleased bond has an
            // immediate Timeout, so the stake comes back now rather
            // than at the horizon.
            return SetupDecision::TimeoutBond;
        }
        SetupDecision::SubmitPayment
    }

    /// Neither edge exists: submit, abort, or reconcile.
    fn decide_absent_bond(&self, observed: &ObservedSetup<'_>) -> SetupDecision {
        let (Some(bond), Some(payment)) = (self.bond_open(), self.payment_open()) else {
            return SetupDecision::AwaitingCounterparty;
        };
        if self.role != Role::Provider {
            return SetupDecision::AwaitingCounterparty;
        }
        if !funding_live(&bond, observed.live_funding) {
            // The stake input is gone and no bond exists to explain it.
            // Nothing here can tell a duplicate submission from a theft,
            // so this stops rather than guessing.
            return SetupDecision::Fault(SetupFault::BondFundingSpent);
        }
        let horizon = self.horizon().unwrap_or(0);
        if observed.height >= horizon {
            return SetupDecision::Abort(SetupAbort::BondOpenExpired);
        }
        // The preflight. It is here, in the premise of the only branch
        // that locks stake, rather than in a caller that could forget
        // it on the second attempt.
        if !funding_live(&payment, observed.live_funding) {
            return SetupDecision::Abort(SetupAbort::PaymentFundingSpent);
        }
        SetupDecision::SubmitBond
    }

    /// Applies one record, or says why it may not be applied.
    fn apply(&mut self, record: &SetupRecord) -> Result<Applied, SetupStateError> {
        if let Some(end) = self.end {
            // Completion is idempotent, so a retried completion is not
            // an error; anything else after an end is.
            if matches!(
                (end, record),
                (SetupEnd::Complete, SetupRecord::Complete { .. })
            ) {
                return Ok(Applied::Redundant);
            }
            if matches!(record, SetupRecord::Ended { outcome } if *outcome == end) {
                return Ok(Applied::Redundant);
            }
            return Err(SetupStateError::Ended(end));
        }
        match record {
            SetupRecord::Bundle { bundle } => self.apply_bundle(bundle),
            SetupRecord::BondSubmitted => {
                self.require_provider("bond submission")?;
                self.require_executable("bond submission")?;
                if self.bond_submitted {
                    return Ok(Applied::Redundant);
                }
                self.bond_submitted = true;
                Ok(Applied::Changed)
            }
            SetupRecord::PaymentSubmitted => {
                self.require_provider("payment submission")?;
                self.require_executable("payment submission")?;
                if !self.bond_submitted {
                    return Err(SetupStateError::WrongStage {
                        step: "payment submission before the bond was submitted",
                        revision: self.revision(),
                    });
                }
                if self.payment_submitted {
                    return Ok(Applied::Redundant);
                }
                self.payment_submitted = true;
                Ok(Applied::Changed)
            }
            SetupRecord::Complete {
                payment_edge,
                origin_height,
                origin_payload,
                origin_parent,
            } => {
                let retained = self.payment_edge();
                if retained != Some(*payment_edge) {
                    return Err(SetupStateError::WrongPaymentEdge {
                        named: *payment_edge,
                        retained,
                    });
                }
                self.origin = Some(SetupOrigin {
                    payment_edge: *payment_edge,
                    height: *origin_height,
                    payload: *origin_payload,
                    parent: *origin_parent,
                });
                self.end = Some(SetupEnd::Complete);
                Ok(Applied::Changed)
            }
            SetupRecord::Ended { outcome } => {
                if *outcome == SetupEnd::Complete {
                    // Completion carries the channel's origin, and a
                    // bare end byte does not. Recording it this way
                    // would leave a watcher with no cursor.
                    return Err(SetupStateError::Malformed);
                }
                self.end = Some(*outcome);
                Ok(Applied::Changed)
            }
        }
    }

    fn apply_bundle(&mut self, bytes: &[u8]) -> Result<Applied, SetupStateError> {
        let bundle = WorkChannelSetupBundleV1::decode(bytes)?;
        if bundle.network() != self.network {
            return Err(SetupStateError::WrongChannel { field: "network" });
        }
        if bundle.bond_edge() != self.bond_edge {
            return Err(SetupStateError::WrongChannel { field: "bond edge" });
        }
        match &self.bundle {
            None => {
                if bundle.revision() != 1 {
                    return Err(SetupStateError::WrongStage {
                        step: "importing a revision that skips the proposal",
                        revision: None,
                    });
                }
            }
            Some(held) if held == &bundle => return Ok(Applied::Redundant),
            Some(held) => bundle.check_extends(held)?,
        }
        self.bundle = Some(bundle);
        self.bundle_bytes = bytes.to_vec();
        Ok(Applied::Changed)
    }

    fn require_provider(&self, step: &'static str) -> Result<(), SetupStateError> {
        if self.role == Role::Provider {
            Ok(())
        } else {
            Err(SetupStateError::WrongRole { step })
        }
    }

    fn require_executable(&self, step: &'static str) -> Result<(), SetupStateError> {
        if self.bond_open().is_some() && self.payment_open().is_some() {
            Ok(())
        } else {
            Err(SetupStateError::WrongStage {
                step,
                revision: self.revision(),
            })
        }
    }
}

/// Whether the bond's lease is this channel's, another's, or neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leased {
    Here,
    Elsewhere,
    Absent,
    Faulty,
}

fn funding_live(tx: &Tx, live: &BTreeSet<CoinId>) -> bool {
    let Tx::Open { funding, .. } = tx else {
        return false;
    };
    funding
        .maker()
        .iter()
        .chain(funding.taker().iter())
        .all(|coin| live.contains(coin))
}

/// The durable setup journal: the state above, plus the file it is
/// replayed from.
#[derive(Debug)]
pub struct SetupStore {
    journal: Journal,
    state: SetupState,
    torn_tail: bool,
}

impl SetupStore {
    /// Opens the setup journal for one bond, replaying and re-checking
    /// every record it holds.
    ///
    /// Replay runs the same transition rules as [`Self::commit`], with
    /// the same signature verification, so a journal that would not be
    /// accepted a record at a time is not accepted whole.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Journal`] when the file is held, corrupt, or
    /// some other journal, and [`WorkStoreError::Setup`] when a
    /// replayed record does not obey the transition rules.
    pub fn open<V: SigVerifier>(
        root: &Path,
        network: NetworkId,
        bond_edge: EdgeId,
        role: Role,
        verifier: &V,
    ) -> Result<Self, WorkStoreError> {
        let key = setup_key(network, bond_edge);
        let id = JournalId {
            kind: JournalKind::Setup,
            role,
            key: key.into_bytes(),
        };
        let path = root.join(format!("setup-{}.journal", hex(&key.into_bytes())));
        let (journal, replay) = Journal::open(path, id)?;
        let mut state = SetupState::new(network, bond_edge, role);
        for bytes in &replay.records {
            let record = SetupRecord::decode(bytes)?;
            check_signatures(&record, verifier)?;
            state.apply(&record)?;
        }
        Ok(Self {
            journal,
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

    /// Returns what the handshake has durably reached.
    #[must_use]
    pub const fn state(&self) -> &SetupState {
        &self.state
    }

    /// Journals one step, and returns only once it is on the disk.
    ///
    /// The rule this exists to enforce: call it *before* exporting the
    /// revision's signature, and before broadcasting a transaction. A
    /// record the state already holds is not written twice, so a retry
    /// after a crash between the write and the release is free.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Setup`] when the step is not one this state
    /// may take — which is checked before anything is written — and
    /// [`WorkStoreError::Journal`] when the append or its sync fails.
    pub fn commit<V: SigVerifier>(
        &mut self,
        record: SetupRecord,
        verifier: &V,
    ) -> Result<&SetupState, WorkStoreError> {
        check_signatures(&record, verifier)?;
        // Applied to a copy first: a record that the rules refuse must
        // leave neither the file nor the state touched.
        let mut next = self.state.clone();
        if next.apply(&record)? == Applied::Changed {
            self.journal.append(&record.encode())?;
            self.state = next;
        }
        Ok(&self.state)
    }

    /// Returns how many records the journal holds.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.journal.len()
    }

    /// Returns whether the journal holds no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.journal.is_empty()
    }
}

/// Verifies every signature a bundle record carries.
///
/// Run on commit and on replay, so the journal cannot hold a revision
/// whose signatures were never checked — including the one a recovered
/// endpoint is about to re-export.
fn check_signatures<V: SigVerifier>(
    record: &SetupRecord,
    verifier: &V,
) -> Result<(), SetupStateError> {
    let SetupRecord::Bundle { bundle } = record else {
        return Ok(());
    };
    let decoded = WorkChannelSetupBundleV1::decode(bundle)?;
    decoded.check(verifier)?;
    Ok(())
}

/// Returns the key a setup journal is named and bound by.
#[must_use]
pub fn setup_key(network: NetworkId, bond_edge: EdgeId) -> Digest {
    let mut hasher = XetFileHasher::new();
    hasher.update(SETUP_KEY);
    hasher.update(network.as_str().as_bytes());
    hasher.update(&bond_edge.to_bytes());
    hasher.finalize()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
