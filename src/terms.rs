//! Concrete edge terms and their deterministic commitment.
//!
//! No direct abstract counterpart — the L1 model treats terms as opaque
//! constants (`TimeoutHeight`, `MakerPayout`, `TakerPayout` in
//! `models/types.qnt`). The Rust kernel commits to a structured [`Terms`]
//! body and binds it via [`TermsHash`] so resolves can carry only the
//! commitment, not the full payload.
//!
//! [`Terms`] computes its [`TermsHash`] at construction and stores it
//! alongside the body. Callers that need the hash get a field load; no
//! type that contains a `Terms` ever needs to cache `terms_hash`
//! separately.

use crate::{
    canonical::{Encode, Writer},
    context::BlockHeight,
    list::List,
    object::Parties,
    tx::{MAX_EDGE_OUTPUTS, Payout},
    primitive::{ProtocolCode, TermsHash},
};

/// Concrete open terms committed by an edge.
///
/// `Terms` is the *body* + a precomputed [`TermsHash`] that binds it.
/// The two cannot drift because the only constructor computes the hash
/// once and stores it, and the body is immutable thereafter.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Terms {
    body: TermsBody,
    hash: TermsHash,
}

/// Body of a [`Terms`] commitment. Variants enumerate the supported
/// protocol-mode shapes; the wrapping [`Terms`] adds the canonical
/// commitment over the body.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
enum TermsBody {
    /// Degenerate bilateral terms used until protocol-specific terms land.
    Basic {
        protocol: ProtocolCode,
        parties: Parties,
        timeout: BlockHeight,
        timeout_outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    },
}

impl Terms {
    /// Creates basic terms.
    #[must_use]
    pub fn basic(
        protocol: ProtocolCode,
        parties: Parties,
        timeout: BlockHeight,
        timeout_outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> Self {
        let body = TermsBody::Basic {
            protocol,
            parties,
            timeout,
            timeout_outputs,
        };
        let hash = body.compute_hash();
        Self { body, hash }
    }

    /// Returns the canonical BLAKE3 commitment for these terms.
    ///
    /// Computed once at construction; this is a field load.
    #[must_use]
    pub const fn hash(&self) -> TermsHash {
        self.hash
    }

    /// Returns the chain-version-local protocol code.
    #[must_use]
    pub const fn protocol(&self) -> ProtocolCode {
        match &self.body {
            TermsBody::Basic { protocol, .. } => *protocol,
        }
    }

    /// Returns the committed parties.
    #[must_use]
    pub const fn parties(&self) -> Parties {
        match &self.body {
            TermsBody::Basic { parties, .. } => *parties,
        }
    }

    /// Returns the earliest valid timeout height.
    #[must_use]
    pub const fn timeout(&self) -> BlockHeight {
        match &self.body {
            TermsBody::Basic { timeout, .. } => *timeout,
        }
    }

    /// Returns the deterministic timeout payout shape.
    #[must_use]
    pub const fn timeout_outputs(&self) -> &List<Payout, MAX_EDGE_OUTPUTS> {
        match &self.body {
            TermsBody::Basic {
                timeout_outputs, ..
            } => timeout_outputs,
        }
    }
}

impl TermsBody {
    fn compute_hash(&self) -> TermsHash {
        TermsHash::from_bytes(crate::canonical::hash(crate::domain::TERMS_BASIC, self))
    }
}

impl Encode for TermsBody {
    // Max size: 1 (protocol) + 33 + 33 (parties) + 8 (timeout) + List<Payout, MAX>
    const MAX_ENCODED_SIZE: usize =
        1 + 33 + 33 + 8 + <List<Payout, MAX_EDGE_OUTPUTS> as Encode>::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        match self {
            Self::Basic {
                protocol,
                parties,
                timeout,
                timeout_outputs,
            } => {
                protocol.encoded_size()
                    + parties.maker().encoded_size()
                    + parties.taker().encoded_size()
                    + timeout.get().encoded_size()
                    + timeout_outputs.encoded_size()
            }
        }
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        match self {
            Self::Basic {
                protocol,
                parties,
                timeout,
                timeout_outputs,
            } => {
                protocol.encode_to(writer);
                parties.maker().encode_to(writer);
                parties.taker().encode_to(writer);
                timeout.get().encode_to(writer);
                timeout_outputs.encode_to(writer);
            }
        }
    }
}
