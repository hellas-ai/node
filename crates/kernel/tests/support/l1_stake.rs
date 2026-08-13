//! Concrete kernel bindings for the `models/l1_stake.qnt` replay.
//!
//! The abstract model names a bond by a terms *variant*; this module
//! turns each variant into real [`StakeBondTerms`] and the abstract
//! open/close inputs into real kernel transactions, so the replay
//! exercises `check_stake_bond_open` and `check_violation_payouts`
//! rather than a paraphrase of them.

use super::{
    CANARY_REGISTRY_SLOTS, FixedStore, canary_registry_slots, coin_id, open_tx, placeholder_mutual,
    placeholder_seal, state,
};

use hellas_kernel::{
    BlockHash, BlockHeight, CoinId, Context, EdgeId, Fees, Funding, Genesis, Key, List,
    MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties, Payout, Proof, ProtocolCode, StakeBondTerms,
    State, Terms, Tx, View,
};

/// Bond maker: the provider funding the stake.
pub(crate) const PROVIDER: Key = Key::from_bytes([21; Key::LENGTH]);
/// Bond taker: the client, committed violation beneficiary.
pub(crate) const CLIENT: Key = Key::from_bytes([22; Key::LENGTH]);
/// Neither party — the kernel rejects a party-controlled treasury.
pub(crate) const TREASURY: Key = Key::from_bytes([23; Key::LENGTH]);

pub(crate) const PROTOCOL: ProtocolCode = ProtocolCode::new(3);
pub(crate) const PROVIDER_COIN: CoinId = coin_id(21);

pub(crate) const STAKE: u64 = 10;
pub(crate) const AWARD: u64 = 7;
pub(crate) const JOB_PRICE_CAP: u64 = 4;
pub(crate) const DISPUTE_COST_CAP: u64 = 3;
pub(crate) const TIMEOUT: BlockHeight = BlockHeight::new(2);

/// The dev fee schedule the model assumes: zero, so the reserve
/// surplus is zero and the client's slash payout is exactly the award.
pub(crate) const FEES: Fees = Fees::new(0, 0, 0, 0);

pub(crate) type TraceState = State<FixedStore<5, 2, CANARY_REGISTRY_SLOTS>>;
pub(crate) type TraceView = View<5, 2, CANARY_REGISTRY_SLOTS>;

/// Mirrors `TermsVariant` in `models/l1_stake.qnt`: one well-formed
/// bond plus a witness for each open rejection the kernel raises.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum Variant {
    Valid,
    StakeMismatch,
    ZeroAward,
    AwardAboveStake,
    AwardBelowFloor,
    TreasuryIsParty,
    JobPriceCapZero,
    ChallengeMarginZero,
}

/// Abstract close witness kind.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum ProofKey {
    Mutual,
    Timeout,
    Violation,
}

fn bond_for(variant: Variant) -> StakeBondTerms {
    let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
    outputs[0] = Payout::new(PROVIDER, STAKE);
    let base = StakeBondTerms {
        protocol: PROTOCOL,
        parties: Parties::new(PROVIDER, CLIENT),
        timeout: TIMEOUT,
        timeout_outputs: List::take(outputs, 1),
        treasury: TREASURY,
        award: AWARD,
        stake: STAKE,
        max_job_price: JOB_PRICE_CAP,
        max_dispute_cost: DISPUTE_COST_CAP,
        challenge_margin: 1,
    };
    match variant {
        Variant::Valid => base,
        Variant::StakeMismatch => StakeBondTerms {
            stake: STAKE - 1,
            ..base
        },
        Variant::ZeroAward => StakeBondTerms { award: 0, ..base },
        Variant::AwardAboveStake => StakeBondTerms {
            award: STAKE + 1,
            ..base
        },
        Variant::AwardBelowFloor => StakeBondTerms {
            award: AWARD - 1,
            ..base
        },
        Variant::TreasuryIsParty => StakeBondTerms {
            treasury: PROVIDER,
            ..base
        },
        Variant::JobPriceCapZero => StakeBondTerms {
            max_job_price: 0,
            ..base
        },
        Variant::ChallengeMarginZero => StakeBondTerms {
            challenge_margin: 0,
            ..base
        },
    }
}

pub(crate) fn terms_for(variant: Variant) -> Terms {
    Terms::stake_bond(bond_for(variant))
}

const fn funding() -> Funding {
    Funding::new(
        List::take([PROVIDER_COIN; MAX_PARTY_INPUTS], 1),
        List::take([PROVIDER_COIN; MAX_PARTY_INPUTS], 0),
    )
}

pub(crate) fn edge_id(variant: Variant) -> EdgeId {
    Tx::edge_id_of(&funding(), &terms_for(variant))
}

/// The provider funds the bond; the client co-signs without funding.
pub(crate) fn open(variant: Variant) -> Tx {
    open_tx(funding(), terms_for(variant), PROVIDER, CLIENT)
}

fn two_payouts(first: Payout, second: Payout) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let mut slots = [Payout::default(); MAX_EDGE_OUTPUTS];
    slots[0] = first;
    slots[1] = second;
    List::take(slots, 2)
}

/// A violation close paying `client_pay` to the client and
/// `treasury_pay` to the treasury. The kernel pins the treasury's value
/// and lets conservation pin the client's.
pub(crate) fn close_violation(client_pay: u64, treasury_pay: u64) -> Tx {
    let terms = terms_for(Variant::Valid);
    let outputs = two_payouts(
        Payout::new(CLIENT, client_pay),
        Payout::new(TREASURY, treasury_pay),
    );
    let edge = edge_id(Variant::Valid);
    let seal = placeholder_seal(edge, &terms, &outputs);
    Tx::close(edge, Proof::violation(terms, seal), outputs)
}

/// A timeout close returning the stake to the provider.
pub(crate) fn close_timeout(provider_pay: u64) -> Tx {
    let terms = terms_for(Variant::Valid);
    let mut slots = [Payout::default(); MAX_EDGE_OUTPUTS];
    slots[0] = Payout::new(PROVIDER, provider_pay);
    let outputs = List::take(slots, 1);
    Tx::close(edge_id(Variant::Valid), Proof::timeout(terms), outputs)
}

/// A *validly dual-signed* mutual close. The bond's committed
/// close-kind set must reject it anyway — that is the point of the
/// `mutualCloseForbiddenTest` trace.
pub(crate) fn close_mutual(provider_pay: u64, client_pay: u64) -> Tx {
    let terms = terms_for(Variant::Valid);
    let outputs = two_payouts(
        Payout::new(PROVIDER, provider_pay),
        Payout::new(CLIENT, client_pay),
    );
    let edge = edge_id(Variant::Valid);
    let proof = placeholder_mutual(edge, terms.hash(), &outputs, PROVIDER, CLIENT);
    Tx::close(edge, proof, outputs)
}

pub(crate) fn context(height: i64) -> Context {
    let height = u64::try_from(height).unwrap_or(1);
    Context::with_fees(
        super::NETWORK,
        BlockHeight::new(height),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        FEES,
    )
}

/// Genesis seeds one provider-owned coin; every id a modelled close
/// could materialise is pre-declared so the store can accept it.
pub(crate) fn initial_state() -> TraceState {
    let edge = edge_id(Variant::Valid);
    state(
        FixedStore::empty_with_registry(
            [
                PROVIDER_COIN,
                Payout::new(CLIENT, 0).id(edge, 0),
                Payout::new(TREASURY, 0).id(edge, 1),
                Payout::new(PROVIDER, 0).id(edge, 0),
                Payout::new(CLIENT, 0).id(edge, 1),
            ],
            [edge, edge_id(Variant::StakeMismatch)],
            canary_registry_slots(),
        ),
        [Genesis::coin(PROVIDER_COIN, PROVIDER, STAKE)],
    )
}
