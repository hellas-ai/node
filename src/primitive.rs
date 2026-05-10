//! Byte-level primitives: settlement keys, object identifiers, protocol tags.
//!
//! No direct abstract counterpart — the model addresses objects by tagged
//! identifiers (`MakerCoin`, `Edge1`, …) declared in `models/types.qnt`.
//! These byte newtypes are the kernel's concrete realization of those
//! abstract tags; structural invariants come from how they are used in
//! [`crate::object`] and [`crate::op`].

use core::fmt;

const ID_LENGTH: usize = 32;
const HASH_LENGTH: usize = 32;
const KEY_LENGTH: usize = 33;
const SIG_LENGTH: usize = 64;

/// Settlement public key controlling owner-only objects.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Key([u8; Self::LENGTH]);

impl Key {
    /// Encoded length of a compressed secp256k1 settlement key.
    pub const LENGTH: usize = KEY_LENGTH;

    /// Creates a settlement key from canonical bytes.
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

/// Stable identifier for a coin object.
///
/// Coin ids are derived as `H(coin_tag ‖ ...)`. Their byte representation
/// cannot collide with that of an [`EdgeId`] under this domain separation.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoinId([u8; Self::LENGTH]);

impl CoinId {
    /// Encoded length of a coin identifier.
    pub const LENGTH: usize = ID_LENGTH;

    pub(crate) const ZERO: Self = Self([0; Self::LENGTH]);

    /// Creates a coin id from canonical bytes.
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

    /// Creates a coin id from a finished canonical digest.
    pub(crate) fn from_digest(digest: Digest) -> Self {
        Self(digest.finish())
    }

    /// Derives the canonical id for one resolve payout coin.
    pub(crate) fn payout(edge: EdgeId, index: usize, owner: Key) -> Self {
        let mut digest = Digest::new(crate::domain::COIN_PAYOUT);

        digest.bytes(edge.as_bytes());
        digest.usize(index);
        digest.bytes(owner.as_bytes());

        Self::from_digest(digest)
    }
}

/// Stable identifier for an edge object.
///
/// Edge ids are derived as `H(edge_tag ‖ ...)`. Their byte representation
/// cannot collide with that of a [`CoinId`] under this domain separation.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EdgeId([u8; Self::LENGTH]);

impl EdgeId {
    /// Encoded length of an edge identifier.
    pub const LENGTH: usize = ID_LENGTH;

    pub(crate) const ZERO: Self = Self([0; Self::LENGTH]);

    /// Creates an edge id from canonical bytes.
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

    /// Creates an edge id from a finished canonical digest.
    pub(crate) fn from_digest(digest: Digest) -> Self {
        Self(digest.finish())
    }
}

/// Commitment to the open terms of an edge.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TermsHash([u8; Self::LENGTH]);

impl TermsHash {
    /// Encoded length of a terms commitment.
    pub const LENGTH: usize = HASH_LENGTH;

    /// Creates a terms commitment from canonical bytes.
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

/// Commitment to one concrete resolve payload.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResolveHash([u8; Self::LENGTH]);

impl ResolveHash {
    /// Encoded length of a resolve commitment.
    pub const LENGTH: usize = HASH_LENGTH;

    /// Creates a resolve commitment from canonical bytes.
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

    /// Creates a resolve commitment from a finished canonical digest.
    pub(crate) fn from_digest(digest: Digest) -> Self {
        Self(digest.finish())
    }
}

/// Compact settlement signature bytes.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sig([u8; Self::LENGTH]);

impl Sig {
    /// Encoded length of a compact settlement signature.
    pub const LENGTH: usize = SIG_LENGTH;

    /// Creates a settlement signature from canonical bytes.
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

    /// Creates a deterministic signature placeholder for modelling.
    ///
    /// This is forgeable and not a cryptographic signature. Whether the kernel
    /// accepts this shape is decided by the [`crate::Verifier`] passed at
    /// apply time.
    #[must_use]
    pub fn placeholder(key: Key, hash: ResolveHash) -> Self {
        let mut out = [0_u8; Self::LENGTH];
        let first = Self::half(key, hash, 0);
        let second = Self::half(key, hash, 1);

        out[..ResolveHash::LENGTH].copy_from_slice(&first);
        out[ResolveHash::LENGTH..].copy_from_slice(&second);

        Self(out)
    }

    fn half(key: Key, hash: ResolveHash, index: u8) -> [u8; ResolveHash::LENGTH] {
        let mut digest = Digest::new(crate::domain::SIG_PLACEHOLDER);

        digest.u8(index);
        digest.bytes(key.as_bytes());
        digest.bytes(hash.as_bytes());

        digest.finish()
    }
}

/// Compact chain-version-local protocol code.
///
/// This is deliberately one byte in v1: protocol tags are scarce, governed hot
/// path identifiers. Widening it changes terms commitments and requires a chain
/// version boundary.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolCode(u8);

impl ProtocolCode {
    /// Creates a protocol code.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the integer protocol code.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Positional party in a v1 bilateral edge.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Party {
    /// Party whose open intent or offer is being filled.
    Maker,

    /// Party that fills the maker's open intent or offer.
    Taker,
}

impl Party {
    /// Returns the canonical one-byte party tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Maker => 0,
            Self::Taker => 1,
        }
    }

    /// Decodes a canonical one-byte party tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Maker),
            1 => Some(Self::Taker),
            _ => None,
        }
    }
}

/// Incremental BLAKE3-256 digest builder for canonical kernel commitments.
#[allow(clippy::redundant_pub_crate)]
pub(crate) struct Digest {
    hasher: blake3::Hasher,
}

impl Digest {
    /// Starts a digest with a domain separator.
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        Self { hasher }
    }

    /// Absorbs canonical bytes.
    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    /// Absorbs one unsigned byte.
    pub(crate) fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    /// Absorbs one unsigned 64-bit integer.
    pub(crate) fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    /// Absorbs one bounded in-memory length.
    pub(crate) fn usize(&mut self, value: usize) {
        self.u64(u64::try_from(value).unwrap_or(u64::MAX));
    }

    /// Finishes the digest.
    pub(crate) fn finish(self) -> [u8; HASH_LENGTH] {
        *self.hasher.finalize().as_bytes()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Digest { .. }")
    }
}
