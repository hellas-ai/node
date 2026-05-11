//! Byte-level primitives: settlement keys, object identifiers, protocol tags.
//!
//! No direct abstract counterpart — the model addresses objects by tagged
//! identifiers (`MakerCoin`, `Edge1`, …) declared in `models/types.qnt`.
//! These byte newtypes are the kernel's concrete realization of those
//! abstract tags; structural invariants come from how they are used in
//! [`crate::object`] and [`crate::op`].
//!
//! # Hash newtype discipline
//!
//! Two categories of 32-byte newtypes live here:
//!
//! - **Object identifiers** ([`CoinId`], [`EdgeId`]). These routinely
//!   enter the kernel from observed bytes — genesis allocations, MMR
//!   reads, RPC payloads. Both implement [`Encode`] + [`Decode`] (where
//!   applicable) and have a public `from_bytes` constructor. The
//!   integrity story is at the *derivation site*: the kernel's
//!   `CoinId::genesis`/`CoinId::payout`/`Open::id` helpers are the
//!   canonical ways to produce *fresh* ids.
//! - **Cryptographic commitments** ([`TermsHash`], [`ResolveHash`]).
//!   These are pure derived outputs of `Terms::hash()` /
//!   `Resolve::payload_hash`. They implement [`Encode`] only — you can
//!   serialize a commitment you hold, you cannot deserialize one in
//!   isolation. The `pub(crate) from_bytes` constructor is reserved for
//!   the kernel's own round-trip decoders on object types containing
//!   one of these commitments as a field.

use core::fmt;

use crate::canonical::{Decode, DecodeError, Encode, Writer};

const ID_LENGTH: usize = 32;
const HASH_LENGTH: usize = 32;
const KEY_LENGTH: usize = 33;
const SIG_LENGTH: usize = 64;

/// Settlement public key controlling owner-only objects.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Key([u8; Self::LENGTH]);

impl Default for Key {
    fn default() -> Self {
        Self([0; Self::LENGTH])
    }
}

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

impl Encode for Key {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.0);
    }
}

impl Decode for Key {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        decode_fixed::<{ Self::LENGTH }>(buf).map(|(bytes, n)| (Self(bytes), n))
    }
}

/// Stable identifier for a coin object.
///
/// Coin ids are derived as `H(coin_tag ‖ ...)`. Their byte representation
/// cannot collide with that of an [`EdgeId`] under this domain separation.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoinId([u8; Self::LENGTH]);

impl CoinId {
    /// Encoded length of a coin identifier.
    pub const LENGTH: usize = ID_LENGTH;

    pub(crate) const ZERO: Self = Self([0; Self::LENGTH]);

    /// Reconstructs a coin id from canonical bytes.
    ///
    /// `CoinId` is an *object identifier* — it routinely enters the
    /// kernel from observed bytes (genesis allocation, MMR reads, RPC
    /// payloads). Public `from_bytes` is therefore legitimate; the
    /// integrity discipline that applies here is the kernel's
    /// canonical derivation helpers ([`Self::genesis`],
    /// [`Self::payout`]) for producing fresh ids.
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

    /// Derives the canonical id for a genesis coin allocation.
    ///
    /// Genesis coins are produced at chain bootstrap; the kernel commits
    /// to a deterministic id derived from the allocation index. Callers
    /// (e.g. consensus configuration) supply indices and the kernel
    /// returns the canonical ids.
    #[must_use]
    pub fn genesis(index: u32) -> Self {
        Self(crate::canonical::hash(crate::domain::COIN_GENESIS, &index))
    }

    /// Derives the canonical id for one resolve payout coin.
    pub(crate) fn payout(edge: EdgeId, index: usize, owner: Key) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(crate::domain::COIN_PAYOUT);
        edge.encode_to(&mut hasher);
        index.encode_to(&mut hasher);
        owner.encode_to(&mut hasher);
        Self(*hasher.finalize().as_bytes())
    }
}

impl Encode for CoinId {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.0);
    }
}

// CoinId deliberately does *not* implement `Decode`. Construction is
// canonical-derivation-only.

/// Stable identifier for an edge object.
///
/// Edge ids are derived as `H(edge_tag ‖ ...)`. Their byte representation
/// cannot collide with that of a [`CoinId`] under this domain separation.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EdgeId([u8; Self::LENGTH]);

impl EdgeId {
    /// Encoded length of an edge identifier.
    pub const LENGTH: usize = ID_LENGTH;

    /// Reconstructs an edge id from canonical bytes.
    ///
    /// `EdgeId` is an *object identifier* — it routinely enters the
    /// kernel from observed bytes (MMR reads, RPC payloads). Public
    /// `from_bytes` is legitimate; the integrity discipline is at the
    /// kernel's canonical derivation site (`Open::id`).
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

impl Encode for EdgeId {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.0);
    }
}

// EdgeId deliberately does *not* implement `Decode`. Construction is
// canonical-derivation-only.

/// Commitment to the open terms of an edge.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TermsHash([u8; Self::LENGTH]);

impl TermsHash {
    /// Encoded length of a terms commitment.
    pub const LENGTH: usize = HASH_LENGTH;

    /// Reconstructs a terms commitment from canonical bytes.
    ///
    /// `pub(crate)` by design: see [`CoinId::from_bytes`].
    pub(crate) const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
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

impl Encode for TermsHash {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.0);
    }
}

// TermsHash deliberately does *not* implement `Decode`.

/// Commitment to one concrete resolve payload.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResolveHash([u8; Self::LENGTH]);

impl ResolveHash {
    /// Encoded length of a resolve commitment.
    pub const LENGTH: usize = HASH_LENGTH;

    /// Reconstructs a resolve commitment from canonical bytes.
    ///
    /// `pub(crate)` by design: see [`CoinId::from_bytes`].
    pub(crate) const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
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

impl Encode for ResolveHash {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.0);
    }
}

// ResolveHash deliberately does *not* implement `Decode`.

/// Compact settlement signature bytes.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sig([u8; Self::LENGTH]);

impl Default for Sig {
    fn default() -> Self {
        Self([0; Self::LENGTH])
    }
}

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
        let mut hasher = blake3::Hasher::new();
        hasher.update(crate::domain::SIG_PLACEHOLDER);
        index.encode_to(&mut hasher);
        key.encode_to(&mut hasher);
        hash.encode_to(&mut hasher);
        *hasher.finalize().as_bytes()
    }
}

impl Encode for Sig {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.0);
    }
}

impl Decode for Sig {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        decode_fixed::<{ Self::LENGTH }>(buf).map(|(bytes, n)| (Self(bytes), n))
    }
}

/// Compact chain-version-local protocol code.
///
/// This is deliberately one byte in v1: protocol tags are scarce, governed hot
/// path identifiers. Widening it changes terms commitments and requires a chain
/// version boundary.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

impl Encode for ProtocolCode {
    const MAX_ENCODED_SIZE: usize = 1;
    fn encoded_size(&self) -> usize {
        1
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.0.encode_to(writer);
    }
}

impl Decode for ProtocolCode {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (byte, n) = u8::decode(buf)?;
        Ok((Self(byte), n))
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

/// Reads `N` canonical bytes from `buf`. Helper for fixed-shape byte
/// newtype `Decode` impls.
fn decode_fixed<const N: usize>(buf: &[u8]) -> Result<([u8; N], usize), DecodeError> {
    if buf.len() < N {
        return Err(DecodeError::InsufficientBytes {
            needed: N,
            got: buf.len(),
        });
    }
    let mut bytes = [0_u8; N];
    bytes.copy_from_slice(&buf[..N]);
    Ok((bytes, N))
}

#[allow(dead_code)]
impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
