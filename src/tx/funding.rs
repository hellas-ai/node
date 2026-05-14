//! Bilateral funding consumed by an edge open.
//!
//! Abstract counterpart: the funding inputs in `models/l1.qnt::openEdge`.
//! `Funding` carries one bounded per-party list of coin ids; the kernel
//! consumes those coins and locks their summed value into the produced
//! edge.

use super::{MAX_PARTY_INPUTS, PartyCoins};
use crate::{list::List, primitive::CoinId};

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
