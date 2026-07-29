//! On-chain object payloads: coins, edges, and initial coin seeds.
//!
//! Abstract counterpart: `models/types.qnt` (the closed-universe `Coin` /
//! `Edge` ADTs and their canonical wiring) plus the conservation, shape,
//! and binding rules in `models/rules/invariants.qnt`. Genesis seeding
//! mirrors the assumed `genesisFunded` predicate in
//! `models/deps/assumptions.qnt`.

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    context::{BlockHeight, Cost, Fees},
    error::{InsertError, InvalidCloseReason, InvalidOpenReason, KernelResult},
    list::List,
    primitive::{CoinId, Key, TermsHash},
    store::Batch,
    tx::{CloseKind, CloseKindSet},
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

    /// Issues a coin from a trusted host state transition.
    ///
    /// This is an issuance path, not a persistence reconstitution path:
    /// stored coins must still be reconstructed through [`Decode`].
    #[must_use]
    pub const fn issue(owner: Key, value: u64) -> Self {
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

impl Encode for Coin {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE + Key::MAX_ENCODED_SIZE + u64::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::COIN);
        self.owner.encode_to(writer);
        self.value.encode_to(writer);
    }
}

impl Decode for Coin {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::COIN)?;
        let owner = decode_field(buf, &mut consumed)?;
        let value = decode_field(buf, &mut consumed)?;
        Ok((Self::new(owner, value), consumed))
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

impl Encode for Parties {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE + 2 * Key::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::PARTIES);
        self.maker.encode_to(writer);
        self.taker.encode_to(writer);
    }
}

impl Decode for Parties {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::PARTIES)?;
        let maker = decode_field(buf, &mut consumed)?;
        let taker = decode_field(buf, &mut consumed)?;
        Ok((Self::new(maker, taker), consumed))
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
    allowed: CloseKindSet,
}

impl Edge {
    const fn new(
        value: u64,
        reserve: u64,
        close_fees: Fees,
        timeout: BlockHeight,
        parties: Parties,
        terms: TermsHash,
        allowed: CloseKindSet,
    ) -> Self {
        Self {
            value,
            reserve,
            close_fees,
            timeout,
            parties,
            terms,
            allowed,
        }
    }

    pub(super) fn open<const N: usize>(
        coins: &List<(CoinId, Coin), N>,
        parties: Parties,
        terms: TermsHash,
        debits: (u64, u64, u64, Fees),
        timeout: BlockHeight,
        allowed: CloseKindSet,
    ) -> Result<Self, InvalidOpenReason> {
        let (open_fee, lifetime_fee, reserve, close_fees) = debits;
        let total = Self::total(coins).ok_or(InvalidOpenReason::FundingOverflow)?;
        let value = total
            .checked_sub(open_fee)
            .and_then(|after_open_fee| after_open_fee.checked_sub(lifetime_fee))
            .and_then(|after_fee| after_fee.checked_sub(reserve))
            .ok_or(InvalidOpenReason::FundingInsufficient)?;
        Ok(Self::new(
            value, reserve, close_fees, timeout, parties, terms, allowed,
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

    /// Returns the close kinds committed by the opening terms.
    #[must_use]
    pub const fn allowed_closes(self) -> CloseKindSet {
        self.allowed
    }

    /// Returns true when the opening terms admit this close kind.
    #[must_use]
    pub const fn allows(self, kind: CloseKind) -> bool {
        self.allowed.contains(kind)
    }
}

impl Encode for Edge {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE
        + 2 * u64::MAX_ENCODED_SIZE
        + Fees::MAX_ENCODED_SIZE
        + BlockHeight::MAX_ENCODED_SIZE
        + Parties::MAX_ENCODED_SIZE
        + TermsHash::MAX_ENCODED_SIZE
        + CloseKindSet::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::EDGE);
        self.value.encode_to(writer);
        self.reserve.encode_to(writer);
        self.close_fees.encode_to(writer);
        self.timeout.encode_to(writer);
        self.parties.encode_to(writer);
        self.terms.encode_to(writer);
        self.allowed.encode_to(writer);
    }
}

impl Decode for Edge {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::EDGE)?;
        let value = decode_field(buf, &mut consumed)?;
        let reserve = decode_field(buf, &mut consumed)?;
        let close_fees = decode_field(buf, &mut consumed)?;
        let timeout = decode_field(buf, &mut consumed)?;
        let parties = decode_field(buf, &mut consumed)?;
        let terms = decode_field(buf, &mut consumed)?;
        let allowed = decode_field(buf, &mut consumed)?;
        Ok((
            Self::new(value, reserve, close_fees, timeout, parties, terms, allowed),
            consumed,
        ))
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

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "codec tests intentionally inspect exact bytes and fail loudly"
)]
mod tests {
    use super::*;

    fn assert_canonical_round_trip<T>(value: T, buf: &mut [u8])
    where
        T: Copy + core::fmt::Debug + Decode + Encode + PartialEq,
    {
        let written = value.write_to(buf);
        assert_eq!(written, value.encoded_size());
        assert!(written < buf.len());
        assert_eq!(T::decode_exact(&buf[..written]), Ok(value));

        for end in 0..written {
            assert!(T::decode_exact(&buf[..end]).is_err());
        }

        buf[written] = 0xa5;
        assert_eq!(
            T::decode_exact(&buf[..=written]),
            Err(DecodeError::TrailingBytes { remaining: 1 }),
        );
    }

    #[test]
    fn private_coin_and_edge_payloads_round_trip_only_through_their_codecs() {
        let coin = Coin::new(Key::from_bytes([1; Key::LENGTH]), 23);
        let mut coin_buf = [0; Coin::MAX_ENCODED_SIZE + 1];
        assert_canonical_round_trip(coin, &mut coin_buf);
        assert_eq!(&coin_buf[..2], &[1, tag::COIN]);

        let edge = Edge::new(
            100,
            10,
            Fees::new(1, 2, 3, 4),
            BlockHeight::new(99),
            Parties::new(
                Key::from_bytes([2; Key::LENGTH]),
                Key::from_bytes([3; Key::LENGTH]),
            ),
            TermsHash::from_bytes([4; TermsHash::LENGTH]),
            CloseKindSet::all(),
        );
        let mut edge_buf = [0; Edge::MAX_ENCODED_SIZE + 1];
        assert_canonical_round_trip(edge, &mut edge_buf);
        assert_eq!(&edge_buf[..2], &[1, tag::EDGE]);

        assert_eq!(
            Edge::decode_exact(&coin_buf[..Coin::MAX_ENCODED_SIZE]),
            Err(DecodeError::InvalidTag { tag: tag::COIN }),
        );
        assert_eq!(
            Coin::decode_exact(&edge_buf[..Edge::MAX_ENCODED_SIZE]),
            Err(DecodeError::InvalidTag { tag: tag::EDGE }),
        );
    }
}
