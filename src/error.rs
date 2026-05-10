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

/// Reason an insert into a [`crate::Tx`] failed.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InsertError {
    /// The target slot is already occupied.
    Exists,

    /// The store cannot accept the requested identifier.
    Unavailable,
}

/// Error returned when a [`crate::Op`] cannot be applied.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ApplyError {
    /// A required coin does not exist.
    MissingCoin {
        /// Missing coin id.
        id: CoinId,
    },

    /// A coin changed between validation and fold.
    CoinChanged {
        /// Changed coin id.
        id: CoinId,
    },

    /// A required edge does not exist.
    MissingEdge {
        /// Missing edge id.
        id: EdgeId,
    },

    /// An edge changed between validation and fold.
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

    /// An operation attempts to create the same output twice.
    DuplicateOutput {
        /// Duplicated output coin id.
        id: CoinId,
    },

    /// The requested funding cannot open an edge.
    InvalidOpen {
        /// Edge requested for open.
        output: EdgeId,
        /// Specific reason the open was rejected.
        reason: InvalidOpenReason,
    },

    /// An edge cannot resolve into the requested payouts.
    InvalidResolve {
        /// Edge requested for resolve.
        input: EdgeId,
        /// Specific reason the resolve was rejected.
        reason: InvalidResolveReason,
    },

    /// A resolve proof is unsupported or does not match the edge being resolved.
    InvalidProof {
        /// Edge requested for resolve.
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
    /// Constructing the bounded funding list exceeded its capacity. Defensive
    /// path; reachable only from a misbehaving caller.
    BoundsExceeded,
}

/// Specific reason an [`ApplyError::InvalidResolve`] was raised.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InvalidResolveReason {
    /// `context.fee(resolve.cost())` overflowed.
    FeeOverflow,
    /// Sum of payout values overflowed `u64`.
    PayoutOverflow,
    /// Locked reserve does not cover the current priced resolve cost. Under v1
    /// fee semantics this is the deliberate stale-edge collection signal.
    ReserveTooSmall,
    /// Sum of payout values does not equal the edge's principal.
    ValueMismatch,
    /// Constructing the bounded payout list exceeded its capacity. Defensive
    /// path; reachable only from a misbehaving caller.
    BoundsExceeded,
}

/// Specific reason an [`ApplyError::InvalidProof`] was raised.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InvalidProofReason {
    /// `Proof::Basic` was supplied in a build that does not accept it.
    BasicNotAccepted,
    /// The proof's terms commitment does not match the edge's `TermsHash`.
    TermsMismatch,
    /// An agreement signature was rejected by the verifier.
    BadSignature,
    /// A dispute seal was rejected by the verifier.
    BadSeal,
    /// `Proof::Timeout` was submitted before the committed timeout height.
    TimeoutNotReached,
    /// `Proof::Timeout` payouts do not equal `Terms::timeout_outputs`.
    PayoutMismatch,
}
