//! Kernel error vocabulary.

use crate::primitive::{CoinId, EdgeId};

/// Public kernel result type.
pub type KernelResult<T, E = ApplyError> = core::result::Result<T, E>;

/// Error returned when an ordered operation batch fails.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct BatchError {
    index: usize,
    source: ApplyError,
}

impl BatchError {
    pub(crate) const fn new(index: usize, source: ApplyError) -> Self {
        Self { index, source }
    }

    /// Returns the index of the failed operation.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }

    /// Returns the operation error.
    #[must_use]
    pub const fn source(self) -> ApplyError {
        self.source
    }
}

/// Reason an insert into a [`crate::Batch`] failed.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InsertError {
    /// The target slot is already occupied.
    Exists,

    /// The store cannot accept the requested identifier.
    Unavailable,
}

/// Error returned when a [`crate::Tx`] cannot be applied.
///
/// Most variants describe ordinary user-input rejections — bad funding,
/// unknown ids, mismatched payouts. The [`Self::CoinChanged`],
/// [`Self::EdgeChanged`], and fold-phase [`Self::MissingCoin`] /
/// [`Self::MissingEdge`] paths instead signal a [`crate::Batch`] contract
/// violation: the kernel reads a slot during validation, then the same
/// slot returns different bytes (or nothing) during fold without any
/// intervening kernel write. The kernel surfaces these as recoverable
/// errors rather than panicking so a misbehaving store can be rolled
/// back, but seeing them in production means the store implementation
/// is broken, not the operation payload.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ApplyError {
    /// A required coin does not exist. During validation this is an
    /// ordinary rejection (the user named a coin id that is not live);
    /// during fold it is a [`crate::Batch`] contract violation (the slot
    /// disappeared between validation and fold without a kernel write).
    MissingCoin {
        /// Missing coin id.
        id: CoinId,
    },

    /// A coin changed between validation and fold. Indicates a
    /// [`crate::Batch`] contract violation — the kernel does not write to
    /// a slot between reading it and folding the corresponding effect,
    /// so any divergence is the store's fault.
    CoinChanged {
        /// Changed coin id.
        id: CoinId,
    },

    /// A required edge does not exist. Same dual interpretation as
    /// [`Self::MissingCoin`]: validation = user error, fold = store bug.
    MissingEdge {
        /// Missing edge id.
        id: EdgeId,
    },

    /// An edge changed between validation and fold. Same interpretation
    /// as [`Self::CoinChanged`]: a [`crate::Batch`] contract violation.
    EdgeChanged {
        /// Changed edge id.
        id: EdgeId,
    },

    /// An output id is already occupied.
    OutputExists {
        /// Occupied output coin id.
        id: CoinId,
    },

    /// An output edge id is already occupied.
    EdgeExists {
        /// Occupied output edge id.
        id: EdgeId,
    },

    /// An operation attempts to consume the same input twice.
    DuplicateInput {
        /// Duplicated input coin id.
        id: CoinId,
    },

    /// The requested funding cannot open an edge.
    InvalidOpen {
        /// Edge requested for open.
        output: EdgeId,
        /// Specific reason the open was rejected.
        reason: InvalidOpenReason,
    },

    /// An edge cannot close into the requested payouts.
    InvalidClose {
        /// Edge requested for close.
        input: EdgeId,
        /// Specific reason the close was rejected.
        reason: InvalidCloseReason,
    },

    /// A close proof is unsupported or does not match the edge being closed.
    InvalidProof {
        /// Edge requested for close.
        input: EdgeId,
        /// Specific reason the proof was rejected.
        reason: InvalidProofReason,
    },

    /// The backing store rejected a coin insertion.
    CoinInsertRejected {
        /// Coin id that could not be inserted.
        id: CoinId,
        /// Reason the store rejected the insertion.
        reason: InsertError,
    },

    /// The backing store rejected an edge insertion.
    EdgeInsertRejected {
        /// Edge id that could not be inserted.
        id: EdgeId,
        /// Reason the store rejected the insertion.
        reason: InsertError,
    },
}

/// Specific reason an [`ApplyError::InvalidOpen`] was raised.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InvalidOpenReason {
    /// `context.fee(open.cost())` overflowed.
    FeeOverflow,
    /// `context.fee(open.reserve_cost())` overflowed.
    ReserveOverflow,
    /// Sum of funding coin values overflowed `u64`.
    FundingOverflow,
    /// Sum of funding coin values is less than open fee + locked reserve.
    FundingInsufficient,
    /// A funding coin's owner does not match its party's settlement key.
    /// The maker funding list must contain coins owned by
    /// `terms.parties().maker()`; the taker funding list, by
    /// `terms.parties().taker()`.
    FundingUnauthorized,
    /// One of the open signatures was rejected by the configured
    /// `SigVerifier`. Both maker and taker must sign the canonical open
    /// hash for the produced edge.
    BadSignature,
}

/// Specific reason an [`ApplyError::InvalidClose`] was raised.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InvalidCloseReason {
    /// `context.fee(close.cost())` overflowed.
    FeeOverflow,
    /// Sum of payout values overflowed `u64`.
    PayoutOverflow,
    /// Locked reserve does not cover the current priced close cost. Under v1
    /// fee semantics this is the deliberate stale-edge collection signal.
    ReserveTooSmall,
    /// Sum of payout values does not equal the edge's principal.
    ValueMismatch,
}

/// Specific reason an [`ApplyError::InvalidProof`] was raised.
///
/// `BadSignature` and `BadSeal` come from the wired
/// [`crate::SigVerifier`] / [`crate::SealVerifier`]; `TermsMismatch`,
/// `TimeoutNotReached`, and `PayoutMismatch` come from the kernel's
/// inline Timeout/Violation structural checks.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InvalidProofReason {
    /// The proof's terms commitment does not match the edge's `TermsHash`.
    TermsMismatch,
    /// A signature on the close payload was rejected.
    BadSignature,
    /// A dispute seal was rejected.
    BadSeal,
    /// A `Proof::Timeout` was submitted before the committed timeout height.
    TimeoutNotReached,
    /// A `Proof::Timeout` carries payouts that do not equal
    /// `Terms::timeout_outputs`.
    PayoutMismatch,
}
