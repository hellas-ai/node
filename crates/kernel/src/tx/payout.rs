//! Coin payout requested by an edge close.
//!
//! Abstract counterpart: the per-position payout entries in
//! `models/l1.qnt::closeEdge`. The kernel materializes one owner-only
//! coin per `Payout`, with a canonical id derived from the consumed edge
//! and the position of the payout in the close.

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
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
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE + Key::MAX_ENCODED_SIZE + u64::MAX_ENCODED_SIZE;
    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::PAYOUT);
        self.owner.encode_to(writer);
        self.value.encode_to(writer);
    }
}

impl Decode for Payout {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::PAYOUT)?;
        let owner = decode_field(buf, &mut consumed)?;
        let value = decode_field(buf, &mut consumed)?;
        Ok((Self { owner, value }, consumed))
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
