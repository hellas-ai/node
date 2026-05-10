//! On-chain object payloads: coins, edges, and initial coin seeds.

use crate::{
    error::{InsertError, KernelResult},
    list::List,
    primitive::{CoinId, Key, TermsHash},
    store::Tx,
};

/// Owner-only UTXO object.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Coin {
    owner: Key,
    value: u64,
}

impl Coin {
    const fn new(owner: Key, value: u64) -> Self {
        Self { owner, value }
    }

    /// Issues a coin from raw operation payload.
    pub(super) const fn issue(owner: Key, value: u64) -> Self {
        Self::new(owner, value)
    }

    pub(super) const fn zero() -> Self {
        Self::new(Key::from_bytes([0; Key::LENGTH]), 0)
    }

    /// Returns the owner settlement key.
    #[must_use]
    pub const fn owner(self) -> Key {
        self.owner
    }

    /// Returns the coin value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }
}

/// Positional settlement keys committed by an edge.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Parties {
    maker: Key,
    taker: Key,
}

impl Parties {
    /// Creates the positional parties for a bilateral edge.
    #[must_use]
    pub const fn new(maker: Key, taker: Key) -> Self {
        Self { maker, taker }
    }

    /// Returns the maker settlement key.
    #[must_use]
    pub const fn maker(self) -> Key {
        self.maker
    }

    /// Returns the taker settlement key.
    #[must_use]
    pub const fn taker(self) -> Key {
        self.taker
    }
}

/// Locked channel object governed by open terms.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Edge {
    value: u64,
    reserve: u64,
    parties: Parties,
    terms: TermsHash,
}

impl Edge {
    const fn new(value: u64, reserve: u64, parties: Parties, terms: TermsHash) -> Self {
        Self {
            value,
            reserve,
            parties,
            terms,
        }
    }

    pub(super) fn open<const N: usize>(
        coins: &List<(CoinId, Coin), N>,
        parties: Parties,
        terms: TermsHash,
        open_fee: u64,
        reserve: u64,
    ) -> Option<Self> {
        let value = Self::total(coins)?
            .checked_sub(open_fee)?
            .checked_sub(reserve)?;
        Some(Self::new(value, reserve, parties, terms))
    }

    pub(super) fn resolves<const N: usize>(
        self,
        coins: &List<(CoinId, Coin), N>,
        fee: u64,
    ) -> bool {
        fee <= self.reserve && Self::total(coins) == Some(self.value)
    }

    fn total<const N: usize>(coins: &List<(CoinId, Coin), N>) -> Option<u64> {
        let mut total = 0_u64;
        for (_, coin) in coins.iter() {
            total = total.checked_add(coin.value())?;
        }

        Some(total)
    }

    /// Returns the value locked by this edge.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Returns the prepaid reserve consumed when this edge resolves.
    #[must_use]
    pub const fn reserve(self) -> u64 {
        self.reserve
    }

    /// Returns the positional parties committed by this edge.
    #[must_use]
    pub const fn parties(self) -> Parties {
        self.parties
    }

    /// Returns the commitment to the terms that opened this edge.
    #[must_use]
    pub const fn terms(self) -> TermsHash {
        self.terms
    }
}

/// Initial coin seed.
///
/// `Genesis` values populate a [`crate::Store`] before it is wrapped in a
/// [`crate::State`]. Every other [`Coin`] and every [`Edge`] originates from a
/// [`crate::Op`] applied against existing state.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Genesis {
    id: CoinId,
    coin: Coin,
}

impl Genesis {
    /// Creates an initial coin seed.
    #[must_use]
    pub const fn coin(id: CoinId, owner: Key, value: u64) -> Self {
        Self {
            id,
            coin: Coin::new(owner, value),
        }
    }

    pub(super) fn insert<T: Tx>(&self, tx: &mut T) -> KernelResult<(), InsertError> {
        tx.insert_coin(self.id, self.coin)
    }
}
