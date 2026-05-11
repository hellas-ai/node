//! Channel open/resolve tests.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]

mod support;

#[path = "channel/batch.rs"]
mod batch;
#[path = "channel/op.rs"]
mod op;
#[path = "channel/open.rs"]
mod open;
#[path = "channel/resolve.rs"]
mod resolve;

use support::{FAKE_VERIFIER, FixedStore, REJECT_VERIFIER, coin_id, coin_view, edge_view, state};

use hellas_kernel::{
    Agreement, ApplyError, Block, BlockHash, BlockHeight, CoinId, Context, Cost, EdgeId, Event,
    EventKind, Fees, Funding, Genesis, InsertError, InvalidOpenReason, InvalidProofReason,
    InvalidResolveReason, Key, List, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties,
    Payout, Proof, ProtocolCode, ResolveHash, ResolveKind, Seal, Sig, State, Terms, TermsHash, Tx,
    View,
};

const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
const FEE_CONTEXT: Context = Context::with_fees(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
    Fees::new(3, 0, 0),
);
const RESOURCE_CONTEXT: Context = Context::with_fees(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
    Fees::new(1, 3, 0),
);
const TIMEOUT: BlockHeight = BlockHeight::new(1);
const EARLY_CONTEXT: Context = Context::new(
    BlockHeight::new(0),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
const TIMEOUT_CONTEXT: Context =
    Context::new(TIMEOUT, BlockHash::from_bytes([0; BlockHash::LENGTH]));

const MAKER: Key = Key::from_bytes([7; Key::LENGTH]);
const TAKER: Key = Key::from_bytes([8; Key::LENGTH]);
const PARTIES: Parties = Parties::new(MAKER, TAKER);
const PROTOCOL: ProtocolCode = ProtocolCode::new(1);
const OTHER_PROTOCOL: ProtocolCode = ProtocolCode::new(2);

const MAKER_COIN: CoinId = coin_id(1);
const TAKER_COIN: CoinId = coin_id(2);
const EXTRA_COIN: CoinId = coin_id(7);

const TIMEOUT_OUTPUTS: List<Payout, MAX_EDGE_OUTPUTS> =
    payouts_const(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
fn basic_terms() -> Terms {
    Terms::basic(PROTOCOL, PARTIES, TIMEOUT, TIMEOUT_OUTPUTS)
}

fn other_terms_value() -> Terms {
    Terms::basic(OTHER_PROTOCOL, PARTIES, TIMEOUT, TIMEOUT_OUTPUTS)
}

const MAKER_SEED: Genesis = Genesis::coin(MAKER_COIN, MAKER, 10);
const TAKER_SEED: Genesis = Genesis::coin(TAKER_COIN, TAKER, 5);

fn terms() -> TermsHash {
    basic_terms().hash()
}

fn other_terms() -> TermsHash {
    other_terms_value().hash()
}

fn terms_with(outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Terms {
    Terms::basic(PROTOCOL, PARTIES, TIMEOUT, outputs.clone())
}

fn proof() -> Proof {
    Proof::timeout(basic_terms())
}

fn other_proof() -> Proof {
    Proof::timeout(other_terms_value())
}

fn agreement_proof(input: EdgeId, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Proof {
    Proof::agreement(
        terms(),
        Agreement::new(maker_sig(input, outputs), taker_sig(input, outputs)),
    )
}

fn maker_sig(input: EdgeId, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Sig {
    Sig::placeholder(MAKER, agreement_hash(input, outputs))
}

fn taker_sig(input: EdgeId, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Sig {
    Sig::placeholder(TAKER, agreement_hash(input, outputs))
}

fn agreement_hash(input: EdgeId, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> ResolveHash {
    resolve_hash(ResolveKind::Agreement, input, outputs)
}

fn claimant_proof(input: EdgeId, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Proof {
    Proof::claimant_wins(basic_terms(), seal(ResolveKind::ClaimantWins, input, outputs))
}

fn challenger_proof(input: EdgeId, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Proof {
    Proof::challenger_wins(
        basic_terms(),
        seal(ResolveKind::ChallengerWins, input, outputs),
    )
}

fn seal(kind: ResolveKind, input: EdgeId, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Seal {
    Seal::placeholder(PROTOCOL, kind, resolve_hash(kind, input, outputs))
}

fn other_seal(kind: ResolveKind, input: EdgeId, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Seal {
    Seal::placeholder(
        OTHER_PROTOCOL,
        kind,
        other_resolve_hash(kind, input, outputs),
    )
}

fn resolve_hash(
    kind: ResolveKind,
    input: EdgeId,
    outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
) -> ResolveHash {
    Tx::payload_hash(input, kind, terms(), outputs)
}

fn other_resolve_hash(
    kind: ResolveKind,
    input: EdgeId,
    outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
) -> ResolveHash {
    Tx::payload_hash(input, kind, other_terms(), outputs)
}

fn edge() -> EdgeId {
    Tx::edge_id_of(&funding(MAKER_COIN, TAKER_COIN), &basic_terms())
}

fn maker_out() -> CoinId {
    nth(&output_ids(), 0)
}

fn taker_out() -> CoinId {
    nth(&output_ids(), 1)
}

fn extra_out() -> CoinId {
    nth(&output_ids3_values(), 2)
}

fn funded_state() -> State<FixedStore<6, 1>> {
    state(empty_store(), [MAKER_SEED, TAKER_SEED])
}

fn funded_state_for(open: &Tx) -> State<FixedStore<6, 1>> {
    state(store_for(open), [MAKER_SEED, TAKER_SEED])
}

fn open_state() -> State<FixedStore<6, 1>> {
    let mut state = funded_state();
    let _event = apply(&mut state, &open_op());
    state
}

fn open_op() -> Tx {
    Tx::open(funding(MAKER_COIN, TAKER_COIN), basic_terms())
}

fn open_edge_id(open: &Tx) -> EdgeId {
    match open {
        Tx::Open { funding, terms } => Tx::edge_id_of(funding, terms),
        Tx::Resolve { .. } => panic!("expected Tx::Open"),
    }
}

fn funding(maker: CoinId, taker: CoinId) -> Funding {
    Funding::new(party1(maker), party1(taker))
}

fn maker2_funding(first: CoinId, second: CoinId, taker: CoinId) -> Funding {
    Funding::new(party2(first, second), party1(taker))
}

fn empty_party() -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([MAKER_COIN; MAX_PARTY_INPUTS], 0) else {
        panic!("invalid test party list");
    };
    inputs
}

fn party1(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([id; MAX_PARTY_INPUTS], 1) else {
        panic!("invalid test party list");
    };
    inputs
}

fn party2(first: CoinId, second: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([first, second, first, first], 2) else {
        panic!("invalid test party list");
    };
    inputs
}

fn payouts(first: Payout, second: Payout) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let Some(outputs) = List::new([first, second, first, first], 2) else {
        panic!("invalid test payout list");
    };
    outputs
}

fn payouts3(first: Payout, second: Payout, third: Payout) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let Some(outputs) = List::new([first, second, third, first], 3) else {
        panic!("invalid test payout list");
    };
    outputs
}

const fn payouts4() -> List<Payout, MAX_EDGE_OUTPUTS> {
    List::all([
        Payout::new(MAKER, 4),
        Payout::new(TAKER, 4),
        Payout::new(MAKER, 4),
        Payout::new(TAKER, 3),
    ])
}

const fn payouts_const(first: Payout, second: Payout) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let Some(outputs) = List::new([first, second, first, first], 2) else {
        panic!("invalid test payout list");
    };
    outputs
}

fn no_payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    let payout = Payout::new(MAKER, 0);
    let Some(outputs) = List::new([payout; MAX_EDGE_OUTPUTS], 0) else {
        panic!("invalid test payout list");
    };
    outputs
}

fn input_ids0() -> List<CoinId, MAX_EDGE_INPUTS> {
    let Some(ids) = List::new([MAKER_COIN; MAX_EDGE_INPUTS], 0) else {
        panic!("invalid test input id list");
    };
    ids
}

fn input_ids2(first: CoinId, second: CoinId) -> List<CoinId, MAX_EDGE_INPUTS> {
    let Some(ids) = List::new([first, second, first, first, first, first, first, first], 2) else {
        panic!("invalid test input id list");
    };
    ids
}

fn input_ids1(id: CoinId) -> List<CoinId, MAX_EDGE_INPUTS> {
    let Some(ids) = List::new([id; MAX_EDGE_INPUTS], 1) else {
        panic!("invalid test input id list");
    };
    ids
}

fn input_ids3(first: CoinId, second: CoinId, third: CoinId) -> List<CoinId, MAX_EDGE_INPUTS> {
    let Some(ids) = List::new([first, second, third, first, first, first, first, first], 3) else {
        panic!("invalid test input id list");
    };
    ids
}

fn output_ids0() -> List<CoinId, MAX_EDGE_OUTPUTS> {
    let Some(ids) = List::new([maker_out(); MAX_EDGE_OUTPUTS], 0) else {
        panic!("invalid test output id list");
    };
    ids
}

fn output_ids() -> List<CoinId, MAX_EDGE_OUTPUTS> {
    Tx::resolve_output_ids(
        edge(),
        &payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
    )
}

fn output_ids3_values() -> List<CoinId, MAX_EDGE_OUTPUTS> {
    Tx::resolve_output_ids(
        edge(),
        &payouts3(
            Payout::new(MAKER, 6),
            Payout::new(TAKER, 5),
            Payout::new(MAKER, 4),
        ),
    )
}

fn nth<const N: usize>(ids: &List<CoinId, N>, index: usize) -> CoinId {
    ids.as_slice()[index]
}

fn output_ids2(first: CoinId, second: CoinId) -> List<CoinId, MAX_EDGE_OUTPUTS> {
    let Some(ids) = List::new([first, second, first, first], 2) else {
        panic!("invalid test output id list");
    };
    ids
}

fn output_ids3(first: CoinId, second: CoinId, third: CoinId) -> List<CoinId, MAX_EDGE_OUTPUTS> {
    let Some(ids) = List::new([first, second, third, first], 3) else {
        panic!("invalid test output id list");
    };
    ids
}

fn apply<const C: usize, const E: usize>(
    state: &mut State<FixedStore<C, E>>,
    op: &Tx,
) -> hellas_kernel::Event {
    apply_with(state, CONTEXT, op)
}

fn apply_with<const C: usize, const E: usize>(
    state: &mut State<FixedStore<C, E>>,
    context: Context,
    op: &Tx,
) -> hellas_kernel::Event {
    let Ok(event) = state.apply(context, &FAKE_VERIFIER, op) else {
        panic!("operation rejected");
    };
    event
}

fn empty_store() -> FixedStore<6, 1> {
    store_for(&open_op())
}

fn store_for(open: &Tx) -> FixedStore<6, 1> {
    FixedStore::empty(
        [
            MAKER_COIN,
            TAKER_COIN,
            EXTRA_COIN,
            maker_out(),
            taker_out(),
            extra_out(),
        ],
        [open_edge_id(open)],
    )
}

fn store_for_resolve(open: &Tx, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> FixedStore<6, 1> {
    let edge_id = open_edge_id(open);
    let ids = Tx::resolve_output_ids(edge_id, outputs);
    let first = ids.as_slice().first().copied().unwrap_or_else(maker_out);
    let second = ids.as_slice().get(1).copied().unwrap_or_else(taker_out);
    let third = ids.as_slice().get(2).copied().unwrap_or_else(extra_out);

    FixedStore::empty(
        [MAKER_COIN, TAKER_COIN, EXTRA_COIN, first, second, third],
        [edge_id],
    )
}

fn coin_store() -> FixedStore<6, 0> {
    FixedStore::empty(
        [
            MAKER_COIN,
            TAKER_COIN,
            EXTRA_COIN,
            maker_out(),
            taker_out(),
            extra_out(),
        ],
        [],
    )
}
