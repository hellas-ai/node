//! Close witnesses.
//!
//! A [`Proof`] is the kernel-visible *shape* of why an edge should
//! close. Each variant maps to exactly one validation kind: `Mutual` →
//! [`crate::SigVerifier`] (one [`Auth`] witness per party), `Timeout` →
//! kernel inline structural check, `Violation` → [`crate::SealVerifier`].
//!
//! Abstract counterpart: `models/types.qnt::Proof` (witness ADT) and
//! `models/verifier.qnt` (`proofOk`, `payoutsBound`). The Quint module
//! treats these as pure predicates over opaque verifiers; the kernel
//! defers the same checks by routing each variant to the matching
//! verifier impl (or to its own inline check for Timeout).

#[cfg(any(test, feature = "placeholders"))]
use crate::primitive::{PayloadHash, ProtocolCode};
use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    consts::SEAL_LENGTH,
    context::Cost,
    terms::Terms,
    tx::Auth,
};
#[cfg(any(test, feature = "placeholders"))]
use hellas_xet::SingleChunkHasher;

const MUTUAL_TAG: u8 = 0;
const TIMEOUT_TAG: u8 = 1;
const VIOLATION_TAG: u8 = 2;

/// Universal close witness kind.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum CloseKind {
    /// Cooperative close agreed by both parties.
    Mutual,

    /// Timeout close under the committed terms.
    Timeout,

    /// Correctness violation resolved by a protocol-specific seal.
    Violation,
}

impl CloseKind {
    /// Returns the canonical one-byte close witness tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Mutual => 0,
            Self::Timeout => 1,
            Self::Violation => 2,
        }
    }

    pub(crate) const fn proofs(self) -> u64 {
        match self {
            Self::Timeout | Self::Violation => 1,
            Self::Mutual => 2,
        }
    }

    const fn bit(self) -> u8 {
        1 << self.tag()
    }
}

/// Committed set of close kinds an edge admits.
///
/// Derived from the open terms (each [`crate::Terms`] shape fixes its
/// set structurally) and persisted on the [`crate::Edge`], so every
/// close — including `Mutual`, which reveals no terms body — is checked
/// against the committed policy. `Timeout` is a member of every set the
/// kernel constructs: an edge must always have a unilateral,
/// non-cryptographic exit, or funds could be locked forever.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct CloseKindSet(u8);

impl CloseKindSet {
    const ALL_BITS: u8 =
        CloseKind::Mutual.bit() | CloseKind::Timeout.bit() | CloseKind::Violation.bit();

    /// The empty set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Every close kind.
    #[must_use]
    pub const fn all() -> Self {
        Self(Self::ALL_BITS)
    }

    /// Returns this set with `kind` added.
    #[must_use]
    pub const fn with(self, kind: CloseKind) -> Self {
        Self(self.0 | kind.bit())
    }

    /// Returns true when `kind` is a member of this set.
    #[must_use]
    pub const fn contains(self, kind: CloseKind) -> bool {
        self.0 & kind.bit() != 0
    }
}

impl Encode for CloseKindSet {
    const MAX_ENCODED_SIZE: usize = u8::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.0.encode_to(writer);
    }
}

impl Decode for CloseKindSet {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = 0;
        let bits = decode_field::<u8>(buf, &mut consumed)?;
        // Reject unknown bits, and reject any set without Timeout: the
        // kernel never constructs one (an edge must keep a unilateral
        // exit), so a persisted no-exit set is corrupt state, not data.
        if bits & !Self::ALL_BITS != 0 || bits & CloseKind::Timeout.bit() == 0 {
            return Err(DecodeError::InvalidTag { tag: bits });
        }
        Ok((Self(bits), consumed))
    }
}

/// Compact mode-specific proof result for a violation outcome.
///
/// Opaque to the kernel. The seal's bytes encode whatever artifact the
/// protocol-specific dispute game produces — a TEE attestation, a ZK
/// proof commitment, a fraud-game commitment — and the wired
/// [`crate::SealVerifier`] alone decides whether it is admissible.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Seal([u8; Self::LENGTH]);

impl Seal {
    /// Encoded length of a compact dispute seal.
    pub const LENGTH: usize = SEAL_LENGTH;

    /// Creates a dispute seal from its fixed-width payload bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-width payload bytes, without the codec envelope.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }

    /// Borrows the fixed-width payload bytes, without the codec envelope.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// Creates a deterministic dispute seal placeholder for modelling.
    ///
    /// This is forgeable and not a cryptographic proof. Whether the kernel
    /// accepts this shape is decided by the [`crate::SealVerifier`] passed
    /// at apply time. Gated behind the `placeholders` feature so production
    /// builds cannot construct one.
    #[cfg(any(test, feature = "placeholders"))]
    #[must_use]
    pub fn placeholder(protocol: ProtocolCode, kind: CloseKind, hash: PayloadHash) -> Self {
        let mut hasher = SingleChunkHasher::new();
        hasher.update(crate::consts::SEAL_PLACEHOLDER);
        protocol.encode_to(&mut hasher);
        kind.tag().encode_to(&mut hasher);
        hash.encode_to(&mut hasher);
        Self(hasher.finalize().into_bytes())
    }
}

impl Encode for Seal {
    const MAX_ENCODED_SIZE: usize =
        ENVELOPE_SIZE + <[u8; Self::LENGTH] as Encode>::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::SEAL);
        self.0.encode_to(writer);
    }
}

impl Decode for Seal {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::SEAL)?;
        let bytes = decode_field(buf, &mut consumed)?;
        Ok((Self::from_bytes(bytes), consumed))
    }
}

/// Bounded close witness.
///
/// Each variant maps to one validator: `Mutual` is checked by
/// [`crate::SigVerifier`], `Timeout` is checked structurally inside the
/// kernel, `Violation` is checked by [`crate::SealVerifier`].
#[allow(
    clippy::large_enum_variant,
    reason = "Mutual auth is stored inline so the no-alloc kernel can verify WebAuthn bytes directly"
)]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum Proof {
    /// Cooperative close authorized by both edge parties. The authorized
    /// payload is `Tx::payload_hash(edge_id, Mutual, edge.terms(),
    /// payouts)`; the terms commitment is read from the edge itself, so
    /// no terms reveal is needed here.
    Mutual {
        /// Maker authorization.
        maker: Auth,
        /// Taker authorization.
        taker: Auth,
    },

    /// Timeout close under committed terms.
    Timeout {
        /// Concrete terms revealed to check the timeout.
        terms: Terms,
    },

    /// Correctness violation witness resolved by a mode-specific seal.
    Violation {
        /// Concrete terms revealed to select the mode verifier.
        terms: Terms,
        /// Compact mode-specific verifier result.
        seal: Seal,
    },
}

impl Proof {
    /// Creates a cooperative close witness.
    #[must_use]
    pub const fn mutual(maker: Auth, taker: Auth) -> Self {
        Self::Mutual { maker, taker }
    }

    /// Creates a timeout close witness.
    #[must_use]
    pub const fn timeout(terms: Terms) -> Self {
        Self::Timeout { terms }
    }

    /// Creates a correctness-violation close witness.
    #[must_use]
    pub const fn violation(terms: Terms, seal: Seal) -> Self {
        Self::Violation { terms, seal }
    }

    /// Returns the close witness kind.
    #[must_use]
    pub const fn kind(&self) -> CloseKind {
        match self {
            Self::Mutual { .. } => CloseKind::Mutual,
            Self::Timeout { .. } => CloseKind::Timeout,
            Self::Violation { .. } => CloseKind::Violation,
        }
    }

    /// Returns the deterministic resource cost of checking this proof.
    #[must_use]
    pub const fn cost(&self) -> Cost {
        Cost::new(0, 0, self.kind().proofs())
    }
}

impl Encode for Proof {
    const MAX_ENCODED_SIZE: usize = {
        let mutual = 2 * Auth::MAX_ENCODED_SIZE;
        let timeout = Terms::MAX_ENCODED_SIZE;
        let violation = Terms::MAX_ENCODED_SIZE + Seal::MAX_ENCODED_SIZE;
        let max_terms = if timeout > violation {
            timeout
        } else {
            violation
        };
        let max_body = if mutual > max_terms {
            mutual
        } else {
            max_terms
        };
        ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + max_body
    };

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE
            + u8::MAX_ENCODED_SIZE
            + match self {
                Self::Mutual { maker, taker } => maker.encoded_size() + taker.encoded_size(),
                Self::Timeout { terms } => terms.encoded_size(),
                Self::Violation { terms, seal } => terms.encoded_size() + seal.encoded_size(),
            }
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::PROOF);
        match self {
            Self::Mutual { maker, taker } => {
                MUTUAL_TAG.encode_to(writer);
                maker.encode_to(writer);
                taker.encode_to(writer);
            }
            Self::Timeout { terms } => {
                TIMEOUT_TAG.encode_to(writer);
                terms.encode_to(writer);
            }
            Self::Violation { terms, seal } => {
                VIOLATION_TAG.encode_to(writer);
                terms.encode_to(writer);
                seal.encode_to(writer);
            }
        }
    }
}

impl Decode for Proof {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::PROOF)?;
        let variant = decode_field::<u8>(buf, &mut consumed)?;
        match variant {
            MUTUAL_TAG => {
                let maker = decode_field(buf, &mut consumed)?;
                let taker = decode_field(buf, &mut consumed)?;
                Ok((Self::mutual(maker, taker), consumed))
            }
            TIMEOUT_TAG => {
                let terms = decode_field(buf, &mut consumed)?;
                Ok((Self::timeout(terms), consumed))
            }
            VIOLATION_TAG => {
                let terms = decode_field(buf, &mut consumed)?;
                let seal = decode_field(buf, &mut consumed)?;
                Ok((Self::violation(terms, seal), consumed))
            }
            tag => Err(DecodeError::InvalidTag { tag }),
        }
    }
}
