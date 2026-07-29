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
    /// Sum of funding coin values is less than open fee + lifetime fee +
    /// locked reserve.
    FundingInsufficient,
    /// The committed timeout height is not strictly after the open block.
    TimeoutNotFuture,
    /// `context.fees().lifetime() * paid_lifetime_blocks` overflowed.
    LifetimeFeeOverflow,
    /// Sum of deterministic payouts committed by the open terms overflowed.
    TermsPayoutOverflow,
    /// Deterministic timeout payouts committed by the open terms do not equal
    /// edge principal plus timeout reserve surplus under the open-time close
    /// fee schedule.
    TermsValueMismatch,
    /// A funding coin's owner does not match its party's settlement key.
    /// The maker funding list must contain coins owned by
    /// `terms.parties().maker()`; the taker funding list, by
    /// `terms.parties().taker()`.
    FundingUnauthorized,
    /// One of the open signatures was rejected by the configured
    /// `SigVerifier`. Both maker and taker must sign the canonical open
    /// hash for the produced edge.
    BadSignature,
    /// Stake-bond terms commit a stake that does not equal the net value
    /// the open actually locks.
    StakeMismatch,
    /// Stake-bond terms commit an award of zero or above the stake.
    AwardOutOfRange,
    /// Stake-bond terms commit an award below `max_job_price +
    /// max_dispute_cost`, so a slash could not make the client whole.
    AwardBelowFloor,
    /// `max_job_price + max_dispute_cost` overflowed while checking the
    /// award floor.
    AwardFloorOverflow,
}

/// Specific reason an [`ApplyError::InvalidClose`] was raised.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InvalidCloseReason {
    /// Sum of payout values overflowed `u64`.
    PayoutOverflow,
    /// The edge's open-time reserve does not cover this close path's
    /// open-time committed fee. Edges opened by this kernel reserve the
    /// worst-case close path, so this indicates corrupted preloaded state or
    /// an incompatible future cost rule rather than current fee repricing.
    ReserveTooSmall,
    /// Sum of payout values does not equal principal plus reserve surplus for
    /// the selected close path.
    ValueMismatch,
    /// The close kind is not in the edge's committed [`crate::CloseKindSet`].
    /// Raised before any witness check — e.g. a `Mutual` close of a stake
    /// bond is rejected even with both parties' valid signatures.
    KindForbidden,
}

/// Specific reason an [`ApplyError::InvalidProof`] was raised.
///
/// `BadSignature` and `BadSeal` come from the wired
/// [`crate::SigVerifier`] / [`crate::SealVerifier`]; `TermsMismatch`,
/// `ProofExpired`, `TimeoutNotReached`, and `PayoutMismatch` come from the
/// kernel's inline lifetime and Timeout/Violation structural checks.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InvalidProofReason {
    /// The proof's terms commitment does not match the edge's `TermsHash`.
    TermsMismatch,
    /// A signature on the close payload was rejected.
    BadSignature,
    /// A dispute seal was rejected.
    BadSeal,
    /// A pre-expiry close proof (`Mutual` or `Violation`) was submitted at or
    /// after the committed timeout height.
    ProofExpired,
    /// A `Proof::Timeout` was submitted before the committed timeout height.
    TimeoutNotReached,
    /// A `Proof::Timeout` carries payouts that do not equal
    /// `Terms::timeout_outputs`.
    PayoutMismatch,
}
