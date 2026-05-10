//! Concrete edge terms and their deterministic commitment.

use crate::{
    context::BlockHeight,
    list::List,
    object::Parties,
    op::{MAX_EDGE_OUTPUTS, Payout},
    primitive::{Digest, ProtocolCode, TermsHash},
};

/// Concrete open terms committed by an edge.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Terms {
    /// Degenerate bilateral terms used until protocol-specific terms land.
    Basic {
        /// Chain-version-local protocol code.
        protocol: ProtocolCode,
        /// Positional settlement parties.
        parties: Parties,
        /// Earliest block height at which a timeout resolve is valid.
        timeout: BlockHeight,
        /// Deterministic payout shape accepted by timeout resolve.
        timeout_outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    },
}

impl Terms {
    /// Creates basic terms.
    #[must_use]
    pub const fn basic(
        protocol: ProtocolCode,
        parties: Parties,
        timeout: BlockHeight,
        timeout_outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> Self {
        Self::Basic {
            protocol,
            parties,
            timeout,
            timeout_outputs,
        }
    }

    /// Returns the chain-version-local protocol code.
    #[must_use]
    pub const fn protocol(self) -> ProtocolCode {
        match self {
            Self::Basic { protocol, .. } => protocol,
        }
    }

    /// Returns the committed parties.
    #[must_use]
    pub const fn parties(self) -> Parties {
        match self {
            Self::Basic { parties, .. } => parties,
        }
    }

    /// Returns the earliest valid timeout height.
    #[must_use]
    pub const fn timeout(self) -> BlockHeight {
        match self {
            Self::Basic { timeout, .. } => timeout,
        }
    }

    /// Returns the deterministic timeout payout shape.
    #[must_use]
    pub const fn timeout_outputs(self) -> List<Payout, MAX_EDGE_OUTPUTS> {
        match self {
            Self::Basic {
                timeout_outputs, ..
            } => timeout_outputs,
        }
    }

    /// Returns the canonical BLAKE3 commitment for these terms.
    #[must_use]
    pub fn hash(self) -> TermsHash {
        let mut digest = Digest::new(crate::domain::TERMS_BASIC);
        let parties = self.parties();
        let maker = parties.maker().to_bytes();
        let taker = parties.taker().to_bytes();
        let outputs = self.timeout_outputs();

        digest.u8(self.protocol().get());
        digest.bytes(&maker);
        digest.bytes(&taker);
        digest.u64(self.timeout().get());
        digest.usize(outputs.len());
        for output in outputs.iter() {
            digest.bytes(output.owner().as_bytes());
            digest.u64(output.value());
        }

        TermsHash::from_bytes(digest.finish())
    }
}
