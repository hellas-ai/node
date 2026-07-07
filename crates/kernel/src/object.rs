//! On-chain object payloads: coins, edges, and initial coin seeds.
//!
//! Abstract counterpart: `models/types.qnt` (the closed-universe `Coin` /
//! `Edge` ADTs and their canonical wiring) plus the conservation, shape,
//! and binding rules in `models/rules/invariants.qnt`. Genesis seeding
//! mirrors the assumed `genesisFunded` predicate in
//! `models/deps/assumptions.qnt`.

use crate::{
    context::{BlockHeight, Cost, Fees},
    error::{InsertError, InvalidCloseReason, InvalidOpenReason, KernelResult},
    list::List,
    primitive::{CoinId, Key, TermsHash},
    store::Batch,
};

/// Owner-only UTXO object.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Coin {
    owner: Key,
    value: u64,
}

impl Coin {
    pub(super) const ZERO: Self = Self::new(Key::from_bytes([0; Key::LENGTH]), 0);

    const fn new(owner: Key, value: u64) -> Self {
        Self { owner, value }
    }

    /// Issues a coin from raw operation payload.
    pub(super) const fn issue(owner: Key, value: u64) -> Self {
        Self::new(owner, value)
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
    close_fees: Fees,
    timeout: BlockHeight,
    parties: Parties,
    terms: TermsHash,
}

impl Edge {
    const fn new(
        value: u64,
        reserve: u64,
        close_fees: Fees,
        timeout: BlockHeight,
        parties: Parties,
        terms: TermsHash,
    ) -> Self {
        Self {
            value,
            reserve,
            close_fees,
            timeout,
            parties,
            terms,
        }
    }

    pub(super) fn open<const N: usize>(
        coins: &List<(CoinId, Coin), N>,
        parties: Parties,
        terms: TermsHash,
        debits: (u64, u64, u64, Fees),
        timeout: BlockHeight,
    ) -> Result<Self, InvalidOpenReason> {
        let (open_fee, lifetime_fee, reserve, close_fees) = debits;
        let total = Self::total(coins).ok_or(InvalidOpenReason::FundingOverflow)?;
        let value = total
            .checked_sub(open_fee)
            .and_then(|after_open_fee| after_open_fee.checked_sub(lifetime_fee))
            .and_then(|after_fee| after_fee.checked_sub(reserve))
            .ok_or(InvalidOpenReason::FundingInsufficient)?;
        Ok(Self::new(
            value, reserve, close_fees, timeout, parties, terms,
        ))
    }

    /// Validates a close against the edge's locked principal and reserve.
    ///
    /// Payouts must sum to the principal locked at open plus the part of the
    /// open-time close reserve not consumed by this close kind. The committed
    /// close fee is priced by the fee schedule stored on the edge at open time,
    /// so current block fees cannot make an already-open edge unclosable.
    pub(super) fn closes<const N: usize>(
        self,
        coins: &List<(CoinId, Coin), N>,
        close_cost: Cost,
    ) -> Result<(), InvalidCloseReason> {
        let expected = self
            .close_value(close_cost)
            .ok_or(InvalidCloseReason::ReserveTooSmall)?;
        match Self::total(coins) {
            None => Err(InvalidCloseReason::PayoutOverflow),
            Some(total) if total != expected => Err(InvalidCloseReason::ValueMismatch),
            Some(_) => Ok(()),
        }
    }

    pub(super) fn close_value(self, close_cost: Cost) -> Option<u64> {
        let fee = self.close_fees.charge(close_cost)?;
        let surplus = self.reserve.checked_sub(fee)?;
        self.value.checked_add(surplus)
    }

    fn total<const N: usize>(coins: &List<(CoinId, Coin), N>) -> Option<u64> {
        coins.checked_sum(|(_, coin)| coin.value())
    }

    /// Returns the value locked by this edge.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Returns the close reserve locked when this edge opened.
    #[must_use]
    pub const fn reserve(self) -> u64 {
        self.reserve
    }

    /// Returns the fee schedule committed for future close execution.
    #[must_use]
    pub const fn close_fees(self) -> Fees {
        self.close_fees
    }

    /// Returns the block height at which timeout fallback becomes available.
    #[must_use]
    pub const fn timeout(self) -> BlockHeight {
        self.timeout
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
/// [`crate::Tx`] applied against existing state.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Genesis {
    id: CoinId,
    coin: Coin,
}

impl Genesis {
    /// Creates an initial coin seed.
    ///
    /// The id is trusted chain configuration. Prefer ids derived via
    /// [`CoinId::genesis`]: a hand-picked id that collides with a future
    /// payout id (`H(payout ‖ edge ‖ index ‖ owner)`) would permanently
    /// block that close path with [`crate::ApplyError::OutputExists`].
    #[must_use]
    pub const fn coin(id: CoinId, owner: Key, value: u64) -> Self {
        Self {
            id,
            coin: Coin::new(owner, value),
        }
    }

    pub(super) fn insert<B: Batch>(&self, batch: &mut B) -> KernelResult<(), InsertError> {
        batch.insert_coin(self.id, self.coin)
    }
}
