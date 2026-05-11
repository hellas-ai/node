//! Coin payout requested by an edge close.
//!
//! Abstract counterpart: the per-position payout entries in
//! `models/l1.qnt::closeEdge`. The kernel materializes one owner-only
//! coin per `Payout`, with a canonical id derived from the consumed edge
//! and the position of the payout in the close.

use crate::{
    canonical::{Decode, DecodeError, Encode, Writer},
    object::Coin,
    primitive::{CoinId, EdgeId, Key},
};

/// Coin payout requested by an edge close.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct Payout {
    owner: Key,
    value: u64,
}

impl Encode for Payout {
    const MAX_ENCODED_SIZE: usize = Key::LENGTH + 8;
    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.owner.encode_to(writer);
        self.value.encode_to(writer);
    }
}

impl Decode for Payout {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (owner, n) = Key::decode(buf)?;
        let (value, m) = u64::decode(&buf[n..])?;
        Ok((Self { owner, value }, n + m))
    }
}

impl Payout {
    /// Creates a close payout.
    #[must_use]
    pub const fn new(owner: Key, value: u64) -> Self {
        Self { owner, value }
    }

    /// Returns the output coin owner.
    #[must_use]
    pub const fn owner(self) -> Key {
        self.owner
    }

    /// Returns the output coin value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Derives the canonical output coin id for this payout position.
    #[must_use]
    pub fn id(self, edge: EdgeId, index: usize) -> CoinId {
        CoinId::payout(edge, index, self.owner)
    }

    pub(super) fn coin(self, edge: EdgeId, index: usize) -> (CoinId, Coin) {
        (self.id(edge, index), Coin::issue(self.owner, self.value))
    }
}
