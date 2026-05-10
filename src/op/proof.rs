use super::{Resolve, SEAL_LENGTH};
use crate::{
    context::{Context, Cost},
    object::{Edge, Parties},
    primitive::{Digest, ProtocolCode, ResolveHash, Sig, TermsHash},
    terms::Terms,
    verifier::Verifier,
};

/// Universal resolve witness kind.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ResolveKind {
    /// Degenerate modelling witness.
    Basic,

    /// Cooperative resolve agreed by both parties.
    Agreement,

    /// Timeout resolve under the committed terms.
    Timeout,

    /// Correctness dispute resolved for the claimant.
    ClaimantWins,

    /// Correctness dispute resolved for the challenger.
    ChallengerWins,
}

impl ResolveKind {
    /// Returns the canonical one-byte resolve witness tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Basic => 0,
            Self::Agreement => 1,
            Self::Timeout => 2,
            Self::ClaimantWins => 3,
            Self::ChallengerWins => 4,
        }
    }

    pub(super) const fn proofs(self) -> u64 {
        match self {
            Self::Basic | Self::Timeout => 1,
            Self::Agreement | Self::ClaimantWins | Self::ChallengerWins => 2,
        }
    }
}

/// Cooperative resolve witness signed by both edge parties.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Agreement {
    maker: Sig,
    taker: Sig,
}

impl Agreement {
    /// Creates a cooperative agreement witness.
    #[must_use]
    pub const fn new(maker: Sig, taker: Sig) -> Self {
        Self { maker, taker }
    }

    /// Returns the maker signature.
    #[must_use]
    pub const fn maker(self) -> Sig {
        self.maker
    }

    /// Returns the taker signature.
    #[must_use]
    pub const fn taker(self) -> Sig {
        self.taker
    }

    fn accepts<V: Verifier + ?Sized>(
        self,
        verifier: &V,
        parties: Parties,
        hash: ResolveHash,
    ) -> bool {
        verifier.verify_sig(self.maker, parties.maker(), hash)
            && verifier.verify_sig(self.taker, parties.taker(), hash)
    }
}

/// Compact mode-specific proof result for a dispute outcome.
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
    /// accepts this shape is decided by the [`crate::Verifier`] passed at
    /// apply time.
    #[must_use]
    pub fn placeholder(protocol: ProtocolCode, kind: ResolveKind, hash: ResolveHash) -> Self {
        let mut digest = Digest::new(crate::domain::SEAL_PLACEHOLDER);

        digest.u8(protocol.get());
        digest.u8(kind.tag());
        digest.bytes(hash.as_bytes());

        Self(digest.finish())
    }
}

/// Bounded proof carried by an edge resolve.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Proof {
    /// Degenerate modelling witness.
    Basic {
        /// Terms commitment this proof opens under.
        terms: TermsHash,
    },

    /// Cooperative agreement witness signed by both parties.
    Agreement {
        /// Terms commitment this proof opens under.
        terms: TermsHash,
        /// Agreement signatures.
        agreement: Agreement,
    },

    /// Timeout witness under committed terms.
    Timeout {
        /// Concrete terms revealed to check the timeout.
        terms: Terms,
    },

    /// Correctness witness resolving for the claimant.
    ClaimantWins {
        /// Concrete terms revealed to select the mode verifier.
        terms: Terms,
        /// Compact mode-specific verifier result.
        seal: Seal,
    },

    /// Correctness witness resolving for the challenger.
    ChallengerWins {
        /// Concrete terms revealed to select the mode verifier.
        terms: Terms,
        /// Compact mode-specific verifier result.
        seal: Seal,
    },
}

impl Proof {
    /// Creates a basic resolve proof.
    #[must_use]
    pub const fn basic(terms: TermsHash) -> Self {
        Self::Basic { terms }
    }

    /// Creates a cooperative agreement resolve witness.
    #[must_use]
    pub const fn agreement(terms: TermsHash, agreement: Agreement) -> Self {
        Self::Agreement { terms, agreement }
    }

    /// Creates a timeout resolve witness.
    #[must_use]
    pub const fn timeout(terms: Terms) -> Self {
        Self::Timeout { terms }
    }

    /// Creates a claimant-wins resolve witness.
    #[must_use]
    pub const fn claimant_wins(terms: Terms, seal: Seal) -> Self {
        Self::ClaimantWins { terms, seal }
    }

    /// Creates a challenger-wins resolve witness.
    #[must_use]
    pub const fn challenger_wins(terms: Terms, seal: Seal) -> Self {
        Self::ChallengerWins { terms, seal }
    }

    /// Returns the resolve witness kind.
    #[must_use]
    pub const fn kind(self) -> ResolveKind {
        match self {
            Self::Basic { .. } => ResolveKind::Basic,
            Self::Agreement { .. } => ResolveKind::Agreement,
            Self::Timeout { .. } => ResolveKind::Timeout,
            Self::ClaimantWins { .. } => ResolveKind::ClaimantWins,
            Self::ChallengerWins { .. } => ResolveKind::ChallengerWins,
        }
    }

    /// Returns the terms commitment this proof opens under.
    #[must_use]
    pub fn terms(self) -> TermsHash {
        match self {
            Self::Basic { terms } | Self::Agreement { terms, .. } => terms,
            Self::Timeout { terms }
            | Self::ClaimantWins { terms, .. }
            | Self::ChallengerWins { terms, .. } => terms.hash(),
        }
    }

    /// Returns the deterministic resource cost of checking this proof.
    #[must_use]
    pub const fn cost(self) -> Cost {
        Cost::new(0, 0, 0, self.kind().proofs())
    }

    pub(super) fn accepts<V: Verifier + ?Sized>(
        self,
        context: Context,
        verifier: &V,
        resolve: &Resolve,
        edge: Edge,
    ) -> bool {
        match self {
            Self::Basic { terms } => {
                #[cfg(feature = "fake-crypto")]
                {
                    terms == edge.terms()
                }

                #[cfg(not(feature = "fake-crypto"))]
                {
                    let _ = terms;
                    false
                }
            }
            Self::Agreement { terms, agreement } => {
                terms == edge.terms()
                    && agreement.accepts(
                        verifier,
                        edge.parties(),
                        resolve.hash(ResolveKind::Agreement),
                    )
            }
            Self::Timeout { terms } => {
                terms.hash() == edge.terms()
                    && context.block_height() >= terms.timeout()
                    && *resolve.outputs() == terms.timeout_outputs()
            }
            Self::ClaimantWins { terms, seal } => {
                let kind = ResolveKind::ClaimantWins;
                terms.hash() == edge.terms()
                    && verifier.verify_seal(seal, terms.protocol(), kind, resolve.hash(kind))
            }
            Self::ChallengerWins { terms, seal } => {
                let kind = ResolveKind::ChallengerWins;
                terms.hash() == edge.terms()
                    && verifier.verify_seal(seal, terms.protocol(), kind, resolve.hash(kind))
            }
        }
    }
}
