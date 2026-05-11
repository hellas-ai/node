//! Block context and deterministic resource pricing.
//!
//! Abstract counterpart: the `height` state var in `models/l1.qnt` (read
//! by the `proofOk` Timeout guard in `models/verifier.qnt`). The
//! `heightMonotonic` assumption in `models/deps/assumptions.qnt` is what
//! lets the kernel trust [`BlockHeight`] without re-checking every apply.
//!
//! # Deliberately absent
//!
//! - **Wall-clock timestamp.** A BFT-safe block timestamp is its own
//!   subtle problem (median-of-validators? leader-asserts-then-bounded?
//!   tolerated drift?), and adding one to [`Context`] commits the kernel
//!   to one set of safety arguments before consensus integration has
//!   pinned them down. [`BlockHeight`] is sufficient for every current
//!   proof shape; revisit only when a settlement semantic genuinely
//!   needs wall-clock time, not block-relative time.
//! - **Validator set.** The kernel never checks "is this signer in the
//!   active set?" — that knowledge lives in whichever
//!   [`crate::SigVerifier`] / [`crate::SealVerifier`] implementations
//!   the chain wires in. A future dispute mode that wants validator-
//!   quorum-signed seals expresses that policy inside the verifier
//!   impls; [`Context`] stays oblivious.

use crate::consts::HASH_LENGTH;

/// Hash of the previous finalized block.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct BlockHash([u8; Self::LENGTH]);

impl BlockHash {
    /// Encoded length of a block hash.
    pub const LENGTH: usize = HASH_LENGTH;

    /// Creates a block hash from canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical byte representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }

    /// Borrows the canonical byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Deterministic resource units consumed by one operation.
///
/// Three dimensions:
///
///   - `base`: fixed per-op overhead (always 1 for kernel ops; 0 for the
///     proof contribution alone).
///   - `slots`: each touched store slot. The kernel reads each slot for an
///     existence check and writes it for the insert/remove that follows, so
///     reads and writes always match — they are folded into one dimension.
///   - `proofs`: signature/seal verifications.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Cost {
    base: u64,
    slots: u64,
    proofs: u64,
}

impl Cost {
    /// Zero resource cost.
    pub const ZERO: Self = Self {
        base: 0,
        slots: 0,
        proofs: 0,
    };

    /// Creates a resource cost.
    #[must_use]
    pub const fn new(base: u64, slots: u64, proofs: u64) -> Self {
        Self {
            base,
            slots,
            proofs,
        }
    }

    /// Returns the fixed operation unit count.
    #[must_use]
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Returns the touched-slot unit count.
    #[must_use]
    pub const fn slots(self) -> u64 {
        self.slots
    }

    /// Returns the proof-verification unit count.
    #[must_use]
    pub const fn proofs(self) -> u64 {
        self.proofs
    }

    /// Adds two resource costs, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            base: self.base.checked_add(other.base)?,
            slots: self.slots.checked_add(other.slots)?,
            proofs: self.proofs.checked_add(other.proofs)?,
        })
    }

    /// Returns true if every cost dimension is within `budget`.
    #[must_use]
    pub const fn fits(self, budget: Self) -> bool {
        self.base <= budget.base && self.slots <= budget.slots && self.proofs <= budget.proofs
    }
}

/// Deterministic fee schedule for kernel operation costs.
///
/// One price per [`Cost`] dimension.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Fees {
    base: u64,
    slot: u64,
    proof: u64,
}

impl Fees {
    /// Zero-fee schedule for tests and local models.
    pub const ZERO: Self = Self {
        base: 0,
        slot: 0,
        proof: 0,
    };

    /// Creates a fee schedule.
    #[must_use]
    pub const fn new(base: u64, slot: u64, proof: u64) -> Self {
        Self { base, slot, proof }
    }

    /// Returns the price per fixed operation unit.
    #[must_use]
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Returns the price per touched-slot unit.
    #[must_use]
    pub const fn slot(self) -> u64 {
        self.slot
    }

    /// Returns the price per proof-verification unit.
    #[must_use]
    pub const fn proof(self) -> u64 {
        self.proof
    }

    /// Calculates the fee for `cost`.
    #[must_use]
    pub fn charge(self, cost: Cost) -> Option<u64> {
        let base = self.base.checked_mul(cost.base())?;
        let slots = self.slot.checked_mul(cost.slots())?;
        let proofs = self.proof.checked_mul(cost.proofs())?;
        base.checked_add(slots)?.checked_add(proofs)
    }
}

/// Monotonic finalized block height.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockHeight(u64);

impl BlockHeight {
    /// Creates a block height.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the integer block height.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Explicit context for applying one ordered kernel operation.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Context {
    block_height: BlockHeight,
    previous_hash: BlockHash,
    fees: Fees,
}

impl Context {
    /// Creates an operation context.
    #[must_use]
    pub const fn new(block_height: BlockHeight, previous_hash: BlockHash) -> Self {
        Self::with_fees(block_height, previous_hash, Fees::ZERO)
    }

    /// Creates an operation context with an explicit fee schedule.
    #[must_use]
    pub const fn with_fees(
        block_height: BlockHeight,
        previous_hash: BlockHash,
        fees: Fees,
    ) -> Self {
        Self {
            block_height,
            previous_hash,
            fees,
        }
    }

    /// Returns the finalized block height for this operation.
    #[must_use]
    pub const fn block_height(self) -> BlockHeight {
        self.block_height
    }

    /// Returns the previous finalized block hash.
    #[must_use]
    pub const fn previous_hash(self) -> BlockHash {
        self.previous_hash
    }

    /// Returns the fee schedule active for this operation.
    #[must_use]
    pub const fn fees(self) -> Fees {
        self.fees
    }

    /// Calculates the fee for `cost` under the active schedule.
    #[must_use]
    pub fn fee(self, cost: Cost) -> Option<u64> {
        self.fees.charge(cost)
    }
}
