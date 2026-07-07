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
use crate::{
    canonical::Encode,
    primitive::{PayloadHash, ProtocolCode},
};
use crate::{consts::SEAL_LENGTH, context::Cost, terms::Terms, tx::Auth};

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

    /// Creates a dispute seal from canonical bytes.
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

    /// Creates a deterministic dispute seal placeholder for modelling.
    ///
    /// This is forgeable and not a cryptographic proof. Whether the kernel
    /// accepts this shape is decided by the [`crate::SealVerifier`] passed
    /// at apply time. Gated behind the `placeholders` feature so production
    /// builds cannot construct one.
    #[cfg(any(test, feature = "placeholders"))]
    #[must_use]
    pub fn placeholder(protocol: ProtocolCode, kind: CloseKind, hash: PayloadHash) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(crate::consts::SEAL_PLACEHOLDER);
        protocol.encode_to(&mut hasher);
        kind.tag().encode_to(&mut hasher);
        hash.encode_to(&mut hasher);
        Self(*hasher.finalize().as_bytes())
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
