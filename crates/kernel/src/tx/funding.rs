//! Bilateral funding consumed by an edge open.
//!
//! Abstract counterpart: the funding inputs in `models/l1.qnt::openEdge`.
//! `Funding` carries one bounded per-party list of coin ids; the kernel
//! consumes those coins and locks their summed value into the produced
//! edge.

use super::{MAX_PARTY_INPUTS, PartyCoins};
use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    list::List,
    primitive::CoinId,
};

/// Funding consumed by an edge open.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Funding {
    maker: PartyCoins,
    taker: PartyCoins,
}

impl Funding {
    /// Creates bilateral edge funding.
    #[must_use]
    pub const fn new(
        maker: List<CoinId, MAX_PARTY_INPUTS>,
        taker: List<CoinId, MAX_PARTY_INPUTS>,
    ) -> Self {
        Self { maker, taker }
    }

    /// Returns the maker funding inputs.
    #[must_use]
    pub const fn maker(&self) -> &List<CoinId, MAX_PARTY_INPUTS> {
        &self.maker
    }

    /// Returns the taker funding inputs.
    #[must_use]
    pub const fn taker(&self) -> &List<CoinId, MAX_PARTY_INPUTS> {
        &self.taker
    }

    pub(super) const fn len(&self) -> usize {
        self.maker.len() + self.taker.len()
    }

    pub(super) const fn maker_len(&self) -> usize {
        self.maker.len()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = CoinId> + '_ {
        self.maker.iter().chain(self.taker.iter()).copied()
    }
}

impl Encode for Funding {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE + 2 * <PartyCoins as Encode>::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE + self.maker.encoded_size() + self.taker.encoded_size()
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::FUNDING);
        self.maker.encode_to(writer);
        self.taker.encode_to(writer);
    }
}

impl Decode for Funding {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::FUNDING)?;
        let maker = decode_field(buf, &mut consumed)?;
        let taker = decode_field(buf, &mut consumed)?;
        Ok((Self::new(maker, taker), consumed))
    }
}
