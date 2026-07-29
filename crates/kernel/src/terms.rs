//! Concrete edge terms and their deterministic commitment.
//!
//! No direct abstract counterpart — the L1 model treats terms as opaque
//! constants (`TimeoutHeight`, `MakerPayout`, `TakerPayout` in
//! `models/types.qnt`). The Rust kernel commits to a structured [`Terms`]
//! body and binds it via [`TermsHash`] so closes can carry only the
//! commitment, not the full payload.
//!
//! [`Terms`] computes its [`TermsHash`] at construction and stores it
//! alongside the body. Callers that need the hash get a field load; no
//! type that contains a `Terms` ever needs to cache `terms_hash`
//! separately.

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    consts::MAX_EDGE_OUTPUTS,
    context::BlockHeight,
    list::List,
    object::Parties,
    primitive::{Key, ProtocolCode, TermsHash},
    tx::{CloseKindSet, Payout},
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

    /// Stake bond backing a fraud game: the maker (provider) locks stake
    /// that a proven violation slashes.
    StakeBond(StakeBondTerms),
}

const BASIC_TAG: u8 = 0;
const STAKE_BOND_TAG: u8 = 1;

/// Epoch policy committed by a stake-bond edge.
///
/// The maker is the provider funding the stake; the taker is the client,
/// who co-signs the open and is the committed beneficiary of a
/// `Violation` close. The bond admits only `Timeout` (stake returned via
/// `timeout_outputs`) and `Violation` (stake slashed into exactly
/// `[(taker, award + surplus), (treasury, stake − award)]` — enforced
/// structurally by the kernel, so no seal verifier can redirect the
/// payout). There is deliberately no `Mutual` exit: the provider must
/// never be able to co-sign its way out from under a pending fraud
/// proof.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct StakeBondTerms {
    /// Chain-version-local protocol code selecting the seal circuit.
    pub protocol: ProtocolCode,
    /// Maker = provider (stake funder), taker = client (beneficiary).
    pub parties: Parties,
    /// Bond expiry; `Timeout` returns the stake at or after this height.
    pub timeout: BlockHeight,
    /// Committed timeout payout shape (the provider's stake return).
    pub timeout_outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    /// Settlement key receiving the non-award remainder of a slash.
    pub treasury: Key,
    /// Exact challenger award `A` paid to the client on a proven
    /// violation, `0 < A ≤ stake`.
    pub award: u64,
    /// Net stake `S`; must equal the bond edge's locked value at open.
    pub stake: u64,
    /// Largest job price this bond may cover; with `max_dispute_cost`
    /// it floors the award so a slash always makes the client whole.
    /// At least 1 — a bond that can cover no job is not a bond.
    pub max_job_price: u64,
    /// Largest dispute cost this bond may cover.
    pub max_dispute_cost: u64,
    /// Challenge margin in blocks: the challenge window plus inclusion
    /// and finality margins. A job is only covered when its terminal
    /// deadline leaves at least this margin before `timeout`, otherwise
    /// a stalling provider could push the challenge past the bond's
    /// expiry and escape into a stake refund.
    pub challenge_margin: u64,
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

    /// Creates stake-bond terms.
    #[must_use]
    pub fn stake_bond(bond: StakeBondTerms) -> Self {
        let body = TermsBody::StakeBond(bond);
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
            TermsBody::StakeBond(bond) => bond.protocol,
        }
    }

    /// Returns the committed parties.
    #[must_use]
    pub const fn parties(&self) -> Parties {
        match &self.body {
            TermsBody::Basic { parties, .. } => *parties,
            TermsBody::StakeBond(bond) => bond.parties,
        }
    }

    /// Returns the earliest valid timeout height.
    #[must_use]
    pub const fn timeout(&self) -> BlockHeight {
        match &self.body {
            TermsBody::Basic { timeout, .. } => *timeout,
            TermsBody::StakeBond(bond) => bond.timeout,
        }
    }

    /// Returns the deterministic timeout payout shape, including any reserve
    /// surplus left after the open-time committed timeout close fee.
    #[must_use]
    pub const fn timeout_outputs(&self) -> &List<Payout, MAX_EDGE_OUTPUTS> {
        match &self.body {
            TermsBody::Basic {
                timeout_outputs, ..
            } => timeout_outputs,
            TermsBody::StakeBond(bond) => &bond.timeout_outputs,
        }
    }

    /// Returns the close kinds this terms shape admits.
    ///
    /// Fixed structurally per shape — no field to misconfigure. Every
    /// shape admits `Timeout`, so an open edge always has a unilateral
    /// exit.
    #[must_use]
    pub const fn allowed_closes(&self) -> CloseKindSet {
        match &self.body {
            TermsBody::Basic { .. } => CloseKindSet::all(),
            TermsBody::StakeBond(_) => CloseKindSet::empty()
                .with(crate::tx::CloseKind::Timeout)
                .with(crate::tx::CloseKind::Violation),
        }
    }

    /// Returns the committed stake-bond policy when this is a bond.
    #[must_use]
    pub const fn as_stake_bond(&self) -> Option<&StakeBondTerms> {
        match &self.body {
            TermsBody::Basic { .. } => None,
            TermsBody::StakeBond(bond) => Some(bond),
        }
    }
}

impl TermsBody {
    fn compute_hash(&self) -> TermsHash {
        // The hash domain is the structural tag for this body shape:
        // different semantics can never share the same canonical bytes.
        let domain = match self {
            Self::Basic { .. } => crate::consts::TERMS_BASIC,
            Self::StakeBond(_) => crate::consts::TERMS_STAKE_BOND,
        };
        TermsHash::from_bytes(crate::canonical::hash(domain, self))
    }
}

impl Encode for Terms {
    const MAX_ENCODED_SIZE: usize = TermsBody::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        self.body.encoded_size()
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.body.encode_to(writer);
    }
}

impl Decode for Terms {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (body, consumed) = TermsBody::decode(buf)?;
        let hash = body.compute_hash();
        Ok((Self { body, hash }, consumed))
    }
}

const BASIC_BODY_SIZE: usize = ProtocolCode::MAX_ENCODED_SIZE
    + Parties::MAX_ENCODED_SIZE
    + BlockHeight::MAX_ENCODED_SIZE
    + <List<Payout, MAX_EDGE_OUTPUTS> as Encode>::MAX_ENCODED_SIZE;

impl Encode for StakeBondTerms {
    const MAX_ENCODED_SIZE: usize =
        BASIC_BODY_SIZE + Key::MAX_ENCODED_SIZE + 5 * u64::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        ProtocolCode::MAX_ENCODED_SIZE
            + Parties::MAX_ENCODED_SIZE
            + BlockHeight::MAX_ENCODED_SIZE
            + self.timeout_outputs.encoded_size()
            + Key::MAX_ENCODED_SIZE
            + 5 * u64::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.protocol.encode_to(writer);
        self.parties.encode_to(writer);
        self.timeout.encode_to(writer);
        self.timeout_outputs.encode_to(writer);
        self.treasury.encode_to(writer);
        self.award.encode_to(writer);
        self.stake.encode_to(writer);
        self.max_job_price.encode_to(writer);
        self.max_dispute_cost.encode_to(writer);
        self.challenge_margin.encode_to(writer);
    }
}

impl Decode for StakeBondTerms {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = 0;
        let protocol = decode_field(buf, &mut consumed)?;
        let parties = decode_field(buf, &mut consumed)?;
        let timeout = decode_field(buf, &mut consumed)?;
        let timeout_outputs = decode_field(buf, &mut consumed)?;
        let treasury = decode_field(buf, &mut consumed)?;
        let award = decode_field(buf, &mut consumed)?;
        let stake = decode_field(buf, &mut consumed)?;
        let max_job_price = decode_field(buf, &mut consumed)?;
        let max_dispute_cost = decode_field(buf, &mut consumed)?;
        let challenge_margin = decode_field(buf, &mut consumed)?;
        Ok((
            Self {
                protocol,
                parties,
                timeout,
                timeout_outputs,
                treasury,
                award,
                stake,
                max_job_price,
                max_dispute_cost,
                challenge_margin,
            },
            consumed,
        ))
    }
}

impl Encode for TermsBody {
    const MAX_ENCODED_SIZE: usize = {
        let basic = BASIC_BODY_SIZE;
        let stake_bond = StakeBondTerms::MAX_ENCODED_SIZE;
        let max_body = if basic > stake_bond {
            basic
        } else {
            stake_bond
        };
        ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + max_body
    };

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE
            + u8::MAX_ENCODED_SIZE
            + match self {
                Self::Basic {
                    protocol,
                    parties,
                    timeout,
                    timeout_outputs,
                } => {
                    protocol.encoded_size()
                        + parties.encoded_size()
                        + timeout.encoded_size()
                        + timeout_outputs.encoded_size()
                }
                Self::StakeBond(bond) => bond.encoded_size(),
            }
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::TERMS);
        match self {
            Self::Basic {
                protocol,
                parties,
                timeout,
                timeout_outputs,
            } => {
                BASIC_TAG.encode_to(writer);
                protocol.encode_to(writer);
                parties.encode_to(writer);
                timeout.encode_to(writer);
                timeout_outputs.encode_to(writer);
            }
            Self::StakeBond(bond) => {
                STAKE_BOND_TAG.encode_to(writer);
                bond.encode_to(writer);
            }
        }
    }
}

impl Decode for TermsBody {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::TERMS)?;
        let variant = decode_field::<u8>(buf, &mut consumed)?;
        match variant {
            BASIC_TAG => {
                let protocol = decode_field(buf, &mut consumed)?;
                let parties = decode_field(buf, &mut consumed)?;
                let timeout = decode_field(buf, &mut consumed)?;
                let timeout_outputs = decode_field(buf, &mut consumed)?;
                Ok((
                    Self::Basic {
                        protocol,
                        parties,
                        timeout,
                        timeout_outputs,
                    },
                    consumed,
                ))
            }
            STAKE_BOND_TAG => {
                let bond = decode_field(buf, &mut consumed)?;
                Ok((Self::StakeBond(bond), consumed))
            }
            tag => Err(DecodeError::InvalidTag { tag }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test constants are in-bounds")]
mod tests {
    use super::*;
    use crate::{
        canonical::{BufferWriter, hash},
        consts::{TERMS_BASIC, TERMS_STAKE_BOND},
        primitive::Key,
        tx::CloseKind,
    };

    fn sample_bond() -> StakeBondTerms {
        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
        outputs[0] = Payout::new(maker, 12);
        StakeBondTerms {
            protocol: ProtocolCode::new(2),
            parties: Parties::new(maker, taker),
            timeout: BlockHeight::new(77),
            timeout_outputs: List::take(outputs, 1),
            treasury: Key::from_bytes([9; Key::LENGTH]),
            award: 7,
            stake: 12,
            max_job_price: 4,
            max_dispute_cost: 3,
            challenge_margin: 5,
        }
    }

    #[test]
    fn stake_bond_terms_round_trip_under_their_own_domain() {
        let bond = sample_bond();
        let terms = Terms::stake_bond(bond.clone());

        let expected = TermsHash::from_bytes(hash(TERMS_STAKE_BOND, &terms.body));
        assert_eq!(terms.hash(), expected);
        assert_eq!(terms.as_stake_bond(), Some(&bond));
        assert_eq!(terms.protocol(), bond.protocol);
        assert_eq!(terms.parties(), bond.parties);
        assert_eq!(terms.timeout(), bond.timeout);
        assert_eq!(terms.timeout_outputs(), &bond.timeout_outputs);

        let mut buf = [0; TermsBody::MAX_ENCODED_SIZE];
        let written = terms.write_to(&mut buf);
        assert_eq!(written, terms.encoded_size());
        let Ok((decoded, consumed)) = Terms::decode(&buf[..written]) else {
            panic!("bond terms decode");
        };
        assert_eq!(consumed, written);
        assert_eq!(decoded, terms);
    }

    #[test]
    fn close_kind_sets_are_fixed_per_terms_shape() {
        let bond = Terms::stake_bond(sample_bond());
        assert!(!bond.allowed_closes().contains(CloseKind::Mutual));
        assert!(bond.allowed_closes().contains(CloseKind::Timeout));
        assert!(bond.allowed_closes().contains(CloseKind::Violation));

        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let basic = Terms::basic(
            ProtocolCode::new(1),
            Parties::new(maker, taker),
            BlockHeight::new(99),
            List::take([Payout::default(); MAX_EDGE_OUTPUTS], 0),
        );
        for kind in [CloseKind::Mutual, CloseKind::Timeout, CloseKind::Violation] {
            assert!(basic.allowed_closes().contains(kind));
        }
    }

    #[test]
    fn basic_terms_hash_is_bound_to_basic_terms_domain() {
        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
        outputs[0] = Payout::new(maker, 7);
        outputs[1] = Payout::new(taker, 8);
        let outputs = List::take(outputs, 2);
        let terms = Terms::basic(
            ProtocolCode::new(1),
            Parties::new(maker, taker),
            BlockHeight::new(99),
            outputs,
        );

        let expected = TermsHash::from_bytes(hash(TERMS_BASIC, &terms.body));
        assert_eq!(terms.hash(), expected);
    }

    #[test]
    fn basic_terms_body_size_matches_canonical_encoding() {
        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let outputs = List::all([Payout::new(maker, 7); MAX_EDGE_OUTPUTS]);
        let body = TermsBody::Basic {
            protocol: ProtocolCode::new(1),
            parties: Parties::new(maker, taker),
            timeout: BlockHeight::new(99),
            timeout_outputs: outputs,
        };
        let mut buf = [0; TermsBody::MAX_ENCODED_SIZE];
        let mut writer = BufferWriter::new(&mut buf);

        body.encode_to(&mut writer);

        assert_eq!(
            TermsBody::MAX_ENCODED_SIZE,
            ENVELOPE_SIZE
                + u8::MAX_ENCODED_SIZE
                + ProtocolCode::MAX_ENCODED_SIZE
                + Parties::MAX_ENCODED_SIZE
                + BlockHeight::MAX_ENCODED_SIZE
                + <usize as Encode>::MAX_ENCODED_SIZE
                + MAX_EDGE_OUTPUTS * Payout::MAX_ENCODED_SIZE
                + Key::MAX_ENCODED_SIZE
                + 5 * u64::MAX_ENCODED_SIZE,
        );
        assert_eq!(body.encoded_size(), writer.position());
        assert!(body.encoded_size() <= TermsBody::MAX_ENCODED_SIZE);
        let maker_start =
            ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + ProtocolCode::MAX_ENCODED_SIZE + ENVELOPE_SIZE;
        let taker_start = maker_start + Key::LENGTH;
        let parties_end = taker_start + Key::LENGTH;

        assert_eq!(&buf[..4], &[1, tag::TERMS, BASIC_TAG, 1]);
        assert_eq!(&buf[4..maker_start], &[1, tag::PARTIES]);
        assert_eq!(&buf[maker_start..taker_start], maker.as_bytes());
        assert_eq!(&buf[taker_start..parties_end], taker.as_bytes());
    }
}
