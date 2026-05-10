//! Block context and deterministic resource pricing.

const HASH_LENGTH: usize = 32;

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
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Cost {
    base: u64,
    reads: u64,
    writes: u64,
    proofs: u64,
}

impl Cost {
    /// Zero resource cost.
    pub const ZERO: Self = Self {
        base: 0,
        reads: 0,
        writes: 0,
        proofs: 0,
    };

    /// Creates a resource cost.
    #[must_use]
    pub const fn new(base: u64, reads: u64, writes: u64, proofs: u64) -> Self {
        Self {
            base,
            reads,
            writes,
            proofs,
        }
    }

    /// Returns the fixed operation unit count.
    #[must_use]
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Returns the state-read unit count.
    #[must_use]
    pub const fn reads(self) -> u64 {
        self.reads
    }

    /// Returns the state-write unit count.
    #[must_use]
    pub const fn writes(self) -> u64 {
        self.writes
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
            reads: self.reads.checked_add(other.reads)?,
            writes: self.writes.checked_add(other.writes)?,
            proofs: self.proofs.checked_add(other.proofs)?,
        })
    }
}

/// Deterministic fee schedule for kernel operation costs.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Fees {
    base: u64,
    read: u64,
    write: u64,
    proof: u64,
}

impl Fees {
    /// Zero-fee schedule for tests and local models.
    pub const ZERO: Self = Self {
        base: 0,
        read: 0,
        write: 0,
        proof: 0,
    };

    /// Creates a fee schedule.
    #[must_use]
    pub const fn new(base: u64, read: u64, write: u64, proof: u64) -> Self {
        Self {
            base,
            read,
            write,
            proof,
        }
    }

    /// Returns the price per fixed operation unit.
    #[must_use]
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Returns the price per state-read unit.
    #[must_use]
    pub const fn read(self) -> u64 {
        self.read
    }

    /// Returns the price per state-write unit.
    #[must_use]
    pub const fn write(self) -> u64 {
        self.write
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
        let reads = self.read.checked_mul(cost.reads())?;
        let writes = self.write.checked_mul(cost.writes())?;
        let proofs = self.proof.checked_mul(cost.proofs())?;
        base.checked_add(reads)?
            .checked_add(writes)?
            .checked_add(proofs)
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
