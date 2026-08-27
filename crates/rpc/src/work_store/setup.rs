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
use std::fs;
use std::path::{Path, PathBuf};

use hellas_kernel::{CoinId, Decode, Edge, EdgeId, Encode, LeaseSlots, NetworkId, SigVerifier, Tx};
use hellas_xet::XetFileHasher;

use crate::protocol::Digest;
use crate::protocol::work_bundle::{SetupBundleError, WorkChannelSetupBundleV1};
use crate::protocol::work_setup::{CloseDescriptor, WorkSetupError};
use crate::work_store::journal::{Journal, JournalError, JournalId, JournalKind, Role};
use crate::work_store::{Applied, WorkStoreError, cursor::Cursor, hex, put_u64};

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
    /// An armed descriptor is not for the bundle stored beside it.
    #[error("the armed close descriptor does not describe its setup bundle")]
    DescriptorMismatch,
    /// The persisted or proposed close descriptor failed its structural
    /// policy checks.
    #[error(transparent)]
    Descriptor(#[from] WorkSetupError),
    /// An abort or fault cannot discard an Open that may still finalize.
    #[error("setup cannot end while a submitted Open is unresolved")]
    SubmittedOpenUnresolved,
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
    /// The provider's own finalized bond Timeout consumed the stake and
    /// returned it. Contiguous history holds the bond Open and the Close
    /// that spent it, so the absent bond and spent funding are this
    /// endpoint's own reclaim rather than a theft: there is no channel and
    /// nothing to reconcile.
    #[error("the provider's own bond timeout reclaimed the stake")]
    BondReclaimed,
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
    /// A payment Open finalized, so close recovery must be mounted even
    /// though the admission bond or payment edge is no longer live.
    CloseOnly,
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

/// The immutable finalized observation floor retained before an executable
/// authorization can leave an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupScan {
    /// Finalized height already observed when the setup was armed.
    pub height: u64,
    /// Payload digest at `height`; the first history block must name it as
    /// parent.
    pub payload: [u8; 32],
}

/// One finalized header and the accepted kernel transactions in it which
/// touch this setup's named edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupHistoryBlock {
    pub height: u64,
    pub parent: [u8; 32],
    pub payload: [u8; 32],
    pub txs: Vec<Tx>,
}

/// One bounded atomic setup-history transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupHistoryBatch {
    /// Between one and 256 contiguous finalized blocks.
    pub blocks: Vec<SetupHistoryBlock>,
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
    /// The immutable observation floor, written once before revision 1 (the
    /// provider) or revision 2 (the client) can be exported.
    ScanArmed {
        /// Finalized height already observed.
        height: u64,
        /// Payload digest at `height`.
        payload: [u8; 32],
    },
    /// An executable revision and everything close-only recovery needs,
    /// fsynced together before that revision is returned to the peer.
    ArmedBundle {
        /// The revision's exact canonical bytes.
        bundle: Vec<u8>,
        /// The admitted descriptor recovered without operator configuration.
        close_descriptor: Box<CloseDescriptor>,
    },
    /// A bounded contiguous finalized-history transition.
    SetupHistoryBatch(SetupHistoryBatch),
    /// The provider is about to submit the deterministic bond Timeout.
    BondTimeoutSubmitted,
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
    pub(super) const SCAN_ARMED: u8 = 5;
    pub(super) const ARMED_BUNDLE: u8 = 6;
    pub(super) const SETUP_HISTORY_BATCH: u8 = 7;
    pub(super) const BOND_TIMEOUT_SUBMITTED: u8 = 8;
}

mod end_code {
    pub(super) const COMPLETE: u8 = 0;
    pub(super) const ABORT_BOND_EXPIRED: u8 = 1;
    pub(super) const ABORT_PAYMENT_FUNDING_SPENT: u8 = 2;
    pub(super) const FAULT_BOND_FUNDING_SPENT: u8 = 3;
    pub(super) const FAULT_LEASE_MALFORMED: u8 = 4;
    pub(super) const FAULT_LEASED_ELSEWHERE: u8 = 5;
    pub(super) const FAULT_UNEXPLAINED: u8 = 6;
    pub(super) const ABORT_BOND_RECLAIMED: u8 = 7;
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
        SetupEnd::Aborted(SetupAbort::BondReclaimed) => end_code::ABORT_BOND_RECLAIMED,
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
        end_code::ABORT_BOND_RECLAIMED => SetupEnd::Aborted(SetupAbort::BondReclaimed),
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
            Self::ScanArmed { height, payload } => {
                out.push(tag::SCAN_ARMED);
                put_u64(&mut out, *height);
                out.extend_from_slice(payload);
            }
            Self::ArmedBundle {
                bundle,
                close_descriptor,
            } => {
                out.push(tag::ARMED_BUNDLE);
                put_u64(&mut out, u64::try_from(bundle.len()).unwrap_or(u64::MAX));
                out.extend_from_slice(bundle);
                out.extend_from_slice(&close_descriptor.encode());
            }
            Self::SetupHistoryBatch(batch) => {
                out.push(tag::SETUP_HISTORY_BATCH);
                out.extend_from_slice(&(batch.blocks.len() as u16).to_be_bytes());
                for block in &batch.blocks {
                    put_u64(&mut out, block.height);
                    out.extend_from_slice(&block.parent);
                    out.extend_from_slice(&block.payload);
                    out.extend_from_slice(&(block.txs.len() as u16).to_be_bytes());
                    for tx in &block.txs {
                        let mut bytes = vec![0_u8; Tx::MAX_ENCODED_SIZE];
                        let written = tx.write_to(&mut bytes);
                        out.extend_from_slice(&(written as u32).to_be_bytes());
                        out.extend_from_slice(&bytes[..written]);
                    }
                }
            }
            Self::BondTimeoutSubmitted => out.push(tag::BOND_TIMEOUT_SUBMITTED),
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
            tag::SCAN_ARMED => Self::ScanArmed {
                height: cursor.u64().ok_or(SetupStateError::Malformed)?,
                payload: cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
            },
            tag::ARMED_BUNDLE => {
                let bundle_len = usize::try_from(cursor.u64().ok_or(SetupStateError::Malformed)?)
                    .map_err(|_| SetupStateError::Malformed)?;
                let bundle = cursor
                    .take(bundle_len)
                    .ok_or(SetupStateError::Malformed)?
                    .to_vec();
                let close_descriptor = CloseDescriptor::decode(cursor.rest())
                    .map_err(|_| SetupStateError::Malformed)?;
                Self::ArmedBundle {
                    bundle,
                    close_descriptor: Box::new(close_descriptor),
                }
            }
            tag::SETUP_HISTORY_BATCH => {
                let count = usize::from(u16::from_be_bytes(
                    cursor.array::<2>().ok_or(SetupStateError::Malformed)?,
                ));
                let mut blocks = Vec::with_capacity(count);
                for _ in 0..count {
                    let height = cursor.u64().ok_or(SetupStateError::Malformed)?;
                    let parent = cursor.array::<32>().ok_or(SetupStateError::Malformed)?;
                    let payload = cursor.array::<32>().ok_or(SetupStateError::Malformed)?;
                    let tx_count = usize::from(u16::from_be_bytes(
                        cursor.array::<2>().ok_or(SetupStateError::Malformed)?,
                    ));
                    let mut txs = Vec::with_capacity(tx_count);
                    for _ in 0..tx_count {
                        let len = usize::try_from(u32::from_be_bytes(
                            cursor.array::<4>().ok_or(SetupStateError::Malformed)?,
                        ))
                        .map_err(|_| SetupStateError::Malformed)?;
                        let bytes = cursor.take(len).ok_or(SetupStateError::Malformed)?;
                        let (tx, consumed) =
                            Tx::decode(bytes).map_err(|_| SetupStateError::Malformed)?;
                        if consumed != len {
                            return Err(SetupStateError::Malformed);
                        }
                        txs.push(tx);
                    }
                    blocks.push(SetupHistoryBlock {
                        height,
                        parent,
                        payload,
                        txs,
                    });
                }
                Self::SetupHistoryBatch(SetupHistoryBatch { blocks })
            }
            tag::BOND_TIMEOUT_SUBMITTED => Self::BondTimeoutSubmitted,
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
    scan_armed: Option<SetupScan>,
    close_descriptor: Option<CloseDescriptor>,
    unresolved_bond_open: bool,
    unresolved_payment_open: bool,
    history_cursor: Option<SetupScan>,
    history: Vec<SetupHistoryBlock>,
    bond_finalized: bool,
    payment_finalized: bool,
    bond_closed: bool,
    payment_closed: bool,
    bond_timeout_submitted: bool,
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
            scan_armed: None,
            close_descriptor: None,
            unresolved_bond_open: false,
            unresolved_payment_open: false,
            history_cursor: None,
            history: Vec::new(),
            bond_finalized: false,
            payment_finalized: false,
            bond_closed: false,
            payment_closed: false,
            bond_timeout_submitted: false,
            origin: None,
            end: None,
        }
    }

    /// Returns the revision this endpoint has durably retained.
    #[must_use]
    pub fn revision(&self) -> Option<u8> {
        self.bundle.as_ref().map(WorkChannelSetupBundleV1::revision)
    }

    /// Returns the retained revision itself.
    ///
    /// Beside [`Self::bundle_bytes`] rather than instead of it, and the
    /// two are for different things. An endpoint that is *re-exporting*
    /// what it already exported wants the bytes, verbatim. An endpoint
    /// that is about to add its own signature wants the value, because
    /// re-decoding bytes this journal has already decoded and checked
    /// would be a second parse whose failure would have no meaning.
    #[must_use]
    pub const fn bundle(&self) -> Option<&WorkChannelSetupBundleV1> {
        self.bundle.as_ref()
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

    /// Returns the immutable observation floor once this endpoint is armed.
    #[must_use]
    pub const fn scan_armed(&self) -> Option<SetupScan> {
        self.scan_armed
    }

    /// Returns the close-only descriptor retained beside this role's
    /// executable setup revision.
    #[must_use]
    pub const fn close_descriptor(&self) -> Option<&CloseDescriptor> {
        self.close_descriptor.as_ref()
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
        self.unresolved_bond_open
    }

    /// Returns whether the payment Open has been journaled as
    /// submitted.
    #[must_use]
    pub const fn payment_submitted(&self) -> bool {
        self.unresolved_payment_open
    }

    /// Returns the last contiguous finalized setup header held.
    #[must_use]
    pub const fn history_cursor(&self) -> Option<SetupScan> {
        self.history_cursor
    }

    /// Returns retained relevant history for mounting a channel watcher.
    #[must_use]
    pub fn history(&self) -> &[SetupHistoryBlock] {
        &self.history
    }

    /// Returns whether finalized history proves that a once-funded payment
    /// channel can no longer be admitted as a live leased channel but still
    /// needs its close history mounted.
    #[must_use]
    pub const fn close_only_recovery(&self) -> bool {
        self.origin.is_some() && (self.bond_closed || self.payment_closed)
    }

    /// Returns whether any submitted Open remains unresolved.
    #[must_use]
    pub const fn submitted_open_unresolved(&self) -> bool {
        self.unresolved_bond_open || self.unresolved_payment_open
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
            // A leased bond may be permissionlessly timed out at its
            // horizon while the payment edge survives. Admission is over,
            // but the payment edge still carries a close duty.
            (false, true) => SetupDecision::CloseOnly,
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
            if self.bond_closed {
                // The bond finalized and contiguous history holds the
                // Close that spent it. For a provider that is the only
                // party to record bond Close evidence, that Close is its
                // own Timeout: the stake input is gone because the stake
                // came back, and the reclaim is clean rather than a fault.
                return SetupDecision::Abort(SetupAbort::BondReclaimed);
            }
            if self.bond_timeout_submitted {
                // This endpoint submitted the deterministic Timeout that
                // is spending the stake. History has not yet caught the
                // finalized Close, so its own reclaim in flight must not
                // be journaled as a theft: it waits for the Close.
                return SetupDecision::AwaitingCounterparty;
            }
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
            SetupRecord::ScanArmed { height, payload } => {
                let scan = SetupScan {
                    height: *height,
                    payload: *payload,
                };
                if self.scan_armed == Some(scan) {
                    return Ok(Applied::Redundant);
                }
                if self.scan_armed.is_some() {
                    return Err(SetupStateError::WrongStage {
                        step: "arming a second scan floor",
                        revision: self.revision(),
                    });
                }
                let stage_is_right = match self.role {
                    Role::Provider => self.revision().is_none(),
                    Role::Client => self.revision() == Some(1),
                };
                if !stage_is_right {
                    return Err(SetupStateError::WrongStage {
                        step: "arming the history scan",
                        revision: self.revision(),
                    });
                }
                self.scan_armed = Some(scan);
                self.history_cursor = Some(scan);
                Ok(Applied::Changed)
            }
            SetupRecord::ArmedBundle {
                bundle,
                close_descriptor,
            } => self.apply_armed_bundle(bundle, close_descriptor),
            SetupRecord::SetupHistoryBatch(batch) => self.apply_history_batch(batch),
            SetupRecord::BondTimeoutSubmitted => {
                self.require_provider("bond Timeout submission")?;
                self.require_executable("bond Timeout submission")?;
                if self.bond_timeout_submitted {
                    return Ok(Applied::Redundant);
                }
                self.bond_timeout_submitted = true;
                Ok(Applied::Changed)
            }
            SetupRecord::BondSubmitted => {
                self.require_provider("bond submission")?;
                self.require_executable("bond submission")?;
                if self.unresolved_bond_open {
                    return Ok(Applied::Redundant);
                }
                self.unresolved_bond_open = true;
                Ok(Applied::Changed)
            }
            SetupRecord::PaymentSubmitted => {
                self.require_provider("payment submission")?;
                self.require_executable("payment submission")?;
                if !self.bond_finalized && !self.unresolved_bond_open {
                    return Err(SetupStateError::WrongStage {
                        step: "payment submission before the bond was submitted",
                        revision: self.revision(),
                    });
                }
                if self.unresolved_payment_open {
                    return Ok(Applied::Redundant);
                }
                self.unresolved_payment_open = true;
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
                if self.submitted_open_unresolved() {
                    return Err(SetupStateError::SubmittedOpenUnresolved);
                }
                self.end = Some(*outcome);
                Ok(Applied::Changed)
            }
        }
    }

    fn apply_bundle(&mut self, bytes: &[u8]) -> Result<Applied, SetupStateError> {
        let bundle = WorkChannelSetupBundleV1::decode(bytes)?;
        if self.bundle.as_ref() == Some(&bundle) {
            return Ok(Applied::Redundant);
        }
        if bundle.network() != self.network {
            return Err(SetupStateError::WrongChannel { field: "network" });
        }
        if bundle.bond_edge() != self.bond_edge {
            return Err(SetupStateError::WrongChannel { field: "bond edge" });
        }
        if let Some(held) = &self.bundle {
            bundle.check_extends(held)?;
        }
        if matches!(
            (self.role, bundle.revision()),
            (Role::Client, 2) | (Role::Provider, 3)
        ) {
            return Err(SetupStateError::WrongStage {
                step: "recording an executable revision without its close descriptor",
                revision: self.revision(),
            });
        }
        if self.role == Role::Provider && bundle.revision() == 1 && self.scan_armed.is_none() {
            return Err(SetupStateError::WrongStage {
                step: "recording revision 1 before arming its scan floor",
                revision: self.revision(),
            });
        }
        self.apply_decoded_bundle(bytes, bundle)
    }

    fn apply_armed_bundle(
        &mut self,
        bytes: &[u8],
        close_descriptor: &CloseDescriptor,
    ) -> Result<Applied, SetupStateError> {
        let bundle = WorkChannelSetupBundleV1::decode(bytes)?;
        let expected_revision = match self.role {
            Role::Client => 2,
            Role::Provider => 3,
        };
        if bundle.revision() != expected_revision || self.scan_armed.is_none() {
            return Err(SetupStateError::WrongStage {
                step: "arming an executable setup bundle",
                revision: self.revision(),
            });
        }
        if self.bundle.as_ref() == Some(&bundle) {
            if self.close_descriptor.as_ref() == Some(close_descriptor) {
                return Ok(Applied::Redundant);
            }
            return Err(SetupStateError::DescriptorMismatch);
        }
        let Some(payment_edge) = bundle.payment_edge() else {
            return Err(SetupStateError::DescriptorMismatch);
        };
        if close_descriptor.channel().network() != bundle.network()
            || close_descriptor.channel().payment_edge() != payment_edge
            || bundle.payment_terms() != Some(close_descriptor.channel().payment_terms())
            || close_descriptor.bond_edge() != bundle.bond_edge()
        {
            return Err(SetupStateError::DescriptorMismatch);
        }
        let applied = self.apply_decoded_bundle(bytes, bundle)?;
        debug_assert_eq!(applied, Applied::Changed);
        self.close_descriptor = Some(close_descriptor.clone());
        Ok(Applied::Changed)
    }

    fn apply_decoded_bundle(
        &mut self,
        bytes: &[u8],
        bundle: WorkChannelSetupBundleV1,
    ) -> Result<Applied, SetupStateError> {
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

    fn apply_history_batch(
        &mut self,
        batch: &SetupHistoryBatch,
    ) -> Result<Applied, SetupStateError> {
        if batch.blocks.is_empty() || batch.blocks.len() > 256 {
            return Err(SetupStateError::Malformed);
        }
        let Some(mut held) = self.history_cursor else {
            return Err(SetupStateError::WrongStage {
                step: "recording history before arming its scan floor",
                revision: self.revision(),
            });
        };
        if batch
            .blocks
            .last()
            .is_some_and(|last| last.height <= held.height)
        {
            return Ok(Applied::Redundant);
        }
        let payment_edge = self.payment_edge().ok_or(SetupStateError::WrongStage {
            step: "recording history before the payment edge is named",
            revision: self.revision(),
        })?;
        for block in &batch.blocks {
            if block.height != held.height.saturating_add(1) || block.parent != held.payload {
                return Err(SetupStateError::Malformed);
            }
            for tx in &block.txs {
                // Named before the filter below, so a client batch
                // carrying the one transaction the filter drops is
                // refused as the role error it is rather than as
                // malformed bytes.
                if self.role == Role::Client
                    && matches!(tx, Tx::Close { input, .. } if *input == self.bond_edge)
                {
                    return Err(SetupStateError::WrongRole {
                        step: "recording bond Close evidence",
                    });
                }
                if !touches_setup(tx, self.role, self.bond_edge, payment_edge) {
                    return Err(SetupStateError::Malformed);
                }
                match tx {
                    Tx::Open { funding, terms, .. } => {
                        let edge = Tx::edge_id_of(funding, terms);
                        if edge == self.bond_edge {
                            self.bond_finalized = true;
                            self.bond_closed = false;
                            self.unresolved_bond_open = false;
                        } else if edge == payment_edge {
                            self.payment_finalized = true;
                            self.payment_closed = false;
                            self.unresolved_payment_open = false;
                            if self.origin.is_none() {
                                self.origin = Some(SetupOrigin {
                                    payment_edge,
                                    height: block.height,
                                    payload: block.payload,
                                    parent: block.parent,
                                });
                            }
                        }
                    }
                    Tx::Close { input, .. } if *input == self.bond_edge => {
                        self.bond_closed = true;
                    }
                    Tx::Close { input, .. } if *input == payment_edge => {
                        self.payment_closed = true;
                    }
                    _ => {}
                }
            }
            held = SetupScan {
                height: block.height,
                payload: block.payload,
            };
        }
        self.history_cursor = Some(held);
        if self.unresolved_bond_open && held.height > self.open_horizon(true).unwrap_or(u64::MAX) {
            self.unresolved_bond_open = false;
        }
        if self.unresolved_payment_open
            && held.height > self.open_horizon(false).unwrap_or(u64::MAX)
        {
            self.unresolved_payment_open = false;
        }
        self.history.extend(batch.blocks.iter().cloned());
        Ok(Applied::Changed)
    }

    fn open_horizon(&self, bond: bool) -> Option<u64> {
        let tx = if bond {
            self.bond_open()
        } else {
            self.payment_open()
        }?;
        let Tx::Open { terms, .. } = tx else {
            return None;
        };
        Some(terms.timeout().get())
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

/// Whether this transaction belongs in `role`'s history of this setup.
///
/// Role-aware in one place, and it is the bond's Close: §7 gives bond
/// Timeout and bond Close evidence to the provider alone, and either
/// role may record payment history. A bond Timeout is permissionless, so
/// a client's contiguous history *will* cross one — and a batch is
/// applied whole, so a client that carried that Close would have every
/// batch containing it refused and its cursor stuck below the block it
/// landed in, for good. The header stays and the transaction does not:
/// contiguity is what the cursor is, and the Close is evidence the
/// client is not the one to record.
pub(crate) fn touches_setup(tx: &Tx, role: Role, bond_edge: EdgeId, payment_edge: EdgeId) -> bool {
    match tx {
        Tx::Open { funding, terms, .. } => {
            let edge = Tx::edge_id_of(funding, terms);
            edge == bond_edge || edge == payment_edge
        }
        Tx::Close { input, .. } => {
            *input == payment_edge || (*input == bond_edge && role == Role::Provider)
        }
        Tx::Move { action } => match action {
            hellas_kernel::Move::StartPaymentClose(start) => start.payment_edge() == payment_edge,
            hellas_kernel::Move::RespondPaymentClose(response) => {
                response.payment_edge() == payment_edge
            }
        },
    }
}

/// The durable setup journal: the state above, plus the file it is
/// replayed from.
#[derive(Debug)]
pub struct SetupStore {
    root: PathBuf,
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
            root: root.to_path_buf(),
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

    /// Returns the root under which recovered channel journals are mounted.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns which endpoint owns this setup journal.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.state.role
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
    let bundle = match record {
        SetupRecord::Bundle { bundle } | SetupRecord::ArmedBundle { bundle, .. } => bundle,
        _ => return Ok(()),
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

/// One setup journal found under a root, named by what is inside it.
///
/// The two values [`SetupStore::open`] is keyed by, and nothing else: a
/// path is not carried, because the store derives its own from the key
/// and a second copy could only ever disagree with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveredSetup {
    /// The bond this journal's handshake stakes.
    pub bond_edge: EdgeId,
    /// Which endpoint wrote it.
    pub role: Role,
}

/// A setup journal under the root that names no setup this node can
/// open.
#[derive(Debug)]
pub struct UnidentifiedSetup {
    /// The file, so an operator is told which one to go and look at.
    pub path: PathBuf,
    /// What stopped it being named.
    pub reason: SetupDiscoveryError,
}

/// Why one setup journal could not be named from what is in it.
#[derive(Debug, thiserror::Error)]
pub enum SetupDiscoveryError {
    /// The file is not a journal this binary can read.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// A record in it is not a setup record.
    #[error(transparent)]
    Record(#[from] SetupStateError),
    /// It is a journal of another kind, or under another key than its
    /// name carries.
    #[error("the file is not the setup journal its own name makes it")]
    NotThisSetup,
    /// It holds no revision, so the bond is not in it to recover. A
    /// handshake that armed its history floor and crashed before its
    /// first revision leaves exactly this.
    #[error("the journal holds no setup revision, so the bond it is keyed to is not in it")]
    NoRevision,
    /// Its revision names a bond, and this file is not the journal that
    /// bond and this network key to.
    #[error("the journal is not keyed to the configured network and the bond its revision names")]
    WrongKey,
}

/// What the setup journals under one root are about.
#[derive(Debug, Default)]
pub struct SetupDiscovery {
    /// Every journal whose bond and role were recovered from it, in the
    /// order its file name sorts.
    pub setups: Vec<DiscoveredSetup>,
    /// Every setup journal that could not be named, and why. Named
    /// rather than dropped: a file this node cannot open is a channel it
    /// may still owe a close, and a discovery that silently skipped it
    /// would be a node that quietly stopped answering.
    pub unidentified: Vec<UnidentifiedSetup>,
}

/// Enumerates the setup journals under `root`, recovering what each one
/// is about from the file itself.
///
/// [`SetupStore::open`] is keyed by a bond edge and a role, and a
/// restarting node is told neither: its configuration carries this root
/// and no more. Both are on the disk. The role is in the journal's own
/// header, and the bond edge is in the first revision it retained —
/// every later revision fixes the bond leg, so the first one is the
/// whole answer. What ties them to *this* file is the key: a journal is
/// named and bound by `setup_key(network, bond_edge)`, so a revision
/// whose bond does not reproduce the name is a revision that does not
/// belong to it, and is refused rather than believed.
///
/// Only `setup-<key>.journal` files are considered. A channel journal
/// beside them is another store's, and a file that is not either is not
/// this module's business.
///
/// # Errors
///
/// [`WorkStoreError::Journal`] when the root itself cannot be
/// enumerated. A root that does not exist yet is not one of those: a
/// node that has never opened a journal owns none, which is an answer.
/// Nor is one unreadable journal — that is reported by name in
/// [`SetupDiscovery::unidentified`], because the journals beside it are
/// still this node's to open.
pub fn discover_setups(root: &Path, network: NetworkId) -> Result<SetupDiscovery, WorkStoreError> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SetupDiscovery::default());
        }
        Err(error) => return Err(JournalError::Io(error).into()),
    };
    // Sorted, because `read_dir` hands them over in whatever order the
    // filesystem holds them: a caller that mounted them in that order
    // would mount them differently on two machines holding the same
    // journals.
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry.map_err(JournalError::Io)?.path();
        if setup_file_key(&path).is_some() {
            paths.push(path);
        }
    }
    paths.sort();

    let mut discovery = SetupDiscovery::default();
    for path in paths {
        match identify_setup(&path, network) {
            Ok(setup) => discovery.setups.push(setup),
            Err(reason) => discovery
                .unidentified
                .push(UnidentifiedSetup { path, reason }),
        }
    }
    Ok(discovery)
}

/// Returns the key a setup journal's file name carries, if it is one.
fn setup_file_key(path: &Path) -> Option<[u8; 32]> {
    let name = path.file_name()?.to_str()?;
    let named = name.strip_prefix("setup-")?.strip_suffix(".journal")?;
    if named.len() != 64 {
        return None;
    }
    let mut key = [0_u8; 32];
    for (slot, pair) in key.iter_mut().zip(named.as_bytes().chunks_exact(2)) {
        let Ok(pair) = std::str::from_utf8(pair) else {
            return None;
        };
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    // Written back rather than trusted: the parse above accepts a sign
    // and mixed case, and neither is a name this store ever wrote.
    (hex(&key) == named).then_some(key)
}

/// Recovers what one setup journal is about, or says why it cannot.
fn identify_setup(path: &Path, network: NetworkId) -> Result<DiscoveredSetup, SetupDiscoveryError> {
    let Some(named) = setup_file_key(path) else {
        return Err(SetupDiscoveryError::NotThisSetup);
    };
    let (id, replay) = Journal::inspect(path)?;
    if id.kind != JournalKind::Setup || id.key != named {
        return Err(SetupDiscoveryError::NotThisSetup);
    }
    for bytes in &replay.records {
        let (SetupRecord::Bundle { bundle } | SetupRecord::ArmedBundle { bundle, .. }) =
            SetupRecord::decode(bytes)?
        else {
            continue;
        };
        let decoded = WorkChannelSetupBundleV1::decode(&bundle).map_err(SetupStateError::from)?;
        let bond_edge = decoded.bond_edge();
        if setup_key(network, bond_edge).into_bytes() != id.key {
            return Err(SetupDiscoveryError::WrongKey);
        }
        return Ok(DiscoveredSetup {
            bond_edge,
            role: id.role,
        });
    }
    Err(SetupDiscoveryError::NoRevision)
}
