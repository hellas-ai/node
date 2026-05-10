//! Channel open/resolve tests.

mod support;

use support::{FixedStore, coin_id, coin_view, edge_view, state};

use hellas_kernel::{
    Agreement, ApplyError, Block, BlockHash, BlockHeight, CoinId, Context, Cost, EdgeId, EventKind,
    Fees, Funding, Genesis, InsertError, Key, List, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS,
    MAX_PARTY_INPUTS, Op, Open, Parties, Payout, Proof, ProtocolCode, Resolve, ResolveHash,
    ResolveKind, Seal, Sig, State, Terms, TermsHash, View,
};

const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
const FEE_CONTEXT: Context = Context::with_fees(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
    Fees::new(3, 0, 0, 0),
);
const RESOURCE_CONTEXT: Context = Context::with_fees(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
    Fees::new(1, 2, 1, 0),
);
const TIMEOUT: BlockHeight = BlockHeight::new(2);
const TIMEOUT_CONTEXT: Context =
    Context::new(TIMEOUT, BlockHash::from_bytes([0; BlockHash::LENGTH]));

const MAKER: Key = Key::from_bytes([7; Key::LENGTH]);
const TAKER: Key = Key::from_bytes([8; Key::LENGTH]);
const PARTIES: Parties = Parties::new(MAKER, TAKER);
const PROTOCOL: ProtocolCode = ProtocolCode::new(1);
const OTHER_PROTOCOL: ProtocolCode = ProtocolCode::new(2);
const BASIC_TERMS: Terms = Terms::basic(PROTOCOL, PARTIES, TIMEOUT);
const OTHER_TERMS_VALUE: Terms = Terms::basic(OTHER_PROTOCOL, PARTIES, TIMEOUT);

const MAKER_COIN: CoinId = coin_id(1);
const TAKER_COIN: CoinId = coin_id(2);
const EXTRA_COIN: CoinId = coin_id(7);

const MAKER_SEED: Genesis = Genesis::coin(MAKER_COIN, MAKER, 10);
const TAKER_SEED: Genesis = Genesis::coin(TAKER_COIN, TAKER, 5);

fn terms() -> TermsHash {
    BASIC_TERMS.hash()
}

fn other_terms() -> TermsHash {
    OTHER_TERMS_VALUE.hash()
}

fn proof() -> Proof {
    Proof::basic(terms())
}

fn other_proof() -> Proof {
    Proof::basic(other_terms())
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
    Proof::claimant_wins(BASIC_TERMS, seal(ResolveKind::ClaimantWins, input, outputs))
}

fn challenger_proof(input: EdgeId, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Proof {
    Proof::challenger_wins(
        BASIC_TERMS,
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
    Resolve::payload_hash(input, kind, terms(), outputs)
}

fn other_resolve_hash(
    kind: ResolveKind,
    input: EdgeId,
    outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
) -> ResolveHash {
    Resolve::payload_hash(input, kind, other_terms(), outputs)
}

fn edge() -> EdgeId {
    open_op().output()
}

fn maker_out() -> CoinId {
    nth(output_ids(), 0)
}

fn taker_out() -> CoinId {
    nth(output_ids(), 1)
}

fn extra_out() -> CoinId {
    nth(output_ids3_values(), 2)
}

#[test]
fn open_locks_two_coins_into_one_edge() {
    let mut state = funded_state();
    let event = apply(
        &mut state,
        &Op::Open(Open::new(funding(MAKER_COIN, TAKER_COIN), PARTIES, terms())),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: edge(),
        },
    );
    assert_eq!(state.store().coin(MAKER_COIN), None);
    assert_eq!(state.store().coin(TAKER_COIN), None);
    assert_eq!(
        state.store().edge(edge()).map(edge_view),
        Some((15, 0, PARTIES, terms())),
    );
}

#[test]
fn open_locks_three_coins_into_one_edge() {
    let open = Open::new(
        maker2_funding(MAKER_COIN, EXTRA_COIN, TAKER_COIN),
        PARTIES,
        terms(),
    );
    let mut state = state(
        store_for(&open),
        [MAKER_SEED, TAKER_SEED, Genesis::coin(EXTRA_COIN, MAKER, 3)],
    );
    let event = apply(&mut state, &Op::Open(open));

    assert_eq!(
        event.kind(),
        EventKind::EdgeOpened {
            inputs: input_ids3(MAKER_COIN, EXTRA_COIN, TAKER_COIN),
            output: open.output(),
        },
    );
    assert_eq!(state.store().coin(EXTRA_COIN), None);
    assert_eq!(
        state.store().edge(open.output()).map(edge_view),
        Some((18, 0, PARTIES, terms())),
    );
}

#[test]
fn open_allows_maker_only_funding() {
    let open = Open::new(
        Funding::new(party1(MAKER_COIN), empty_party()),
        PARTIES,
        terms(),
    );
    let mut state = funded_state_for(&open);
    let event = apply(&mut state, &Op::Open(open));

    assert_eq!(
        event.kind(),
        EventKind::EdgeOpened {
            inputs: input_ids1(MAKER_COIN),
            output: open.output(),
        },
    );
    assert_eq!(state.store().coin(MAKER_COIN), None);
    assert_eq!(
        state.store().coin(TAKER_COIN).map(coin_view),
        Some((TAKER, 5))
    );
    assert_eq!(
        state.store().edge(open.output()).map(edge_view),
        Some((10, 0, PARTIES, terms())),
    );
}

#[test]
fn open_allows_taker_only_funding() {
    let open = Open::new(
        Funding::new(empty_party(), party1(TAKER_COIN)),
        PARTIES,
        terms(),
    );
    let mut state = funded_state_for(&open);
    let event = apply(&mut state, &Op::Open(open));

    assert_eq!(
        event.kind(),
        EventKind::EdgeOpened {
            inputs: input_ids1(TAKER_COIN),
            output: open.output(),
        },
    );
    assert_eq!(
        state.store().coin(MAKER_COIN).map(coin_view),
        Some((MAKER, 10))
    );
    assert_eq!(state.store().coin(TAKER_COIN), None);
    assert_eq!(
        state.store().edge(open.output()).map(edge_view),
        Some((5, 0, PARTIES, terms())),
    );
}

#[test]
fn open_allows_empty_funding_when_fee_is_zero() {
    let open = Open::new(Funding::new(empty_party(), empty_party()), PARTIES, terms());
    let mut state = funded_state_for(&open);
    let event = apply(&mut state, &Op::Open(open));

    assert_eq!(
        event.kind(),
        EventKind::EdgeOpened {
            inputs: input_ids0(),
            output: open.output(),
        },
    );
    assert_eq!(
        state.store().coin(MAKER_COIN).map(coin_view),
        Some((MAKER, 10)),
    );
    assert_eq!(
        state.store().coin(TAKER_COIN).map(coin_view),
        Some((TAKER, 5)),
    );
    assert_eq!(
        state.store().edge(open.output()).map(edge_view),
        Some((0, 0, PARTIES, terms())),
    );
}

#[test]
fn open_pays_fee_from_funding() {
    let mut state = funded_state();
    let Ok(event) = state.apply(
        FEE_CONTEXT,
        &Op::Open(Open::from_terms(
            funding(MAKER_COIN, TAKER_COIN),
            BASIC_TERMS,
        )),
    ) else {
        panic!("operation rejected");
    };

    assert_eq!(
        event.kind(),
        EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: edge(),
        },
    );
    assert_eq!(
        state.store().edge(edge()).map(edge_view),
        Some((9, 3, PARTIES, terms())),
    );
}

#[test]
fn open_fee_uses_resource_cost() {
    let mut state = state(
        empty_store(),
        [
            Genesis::coin(MAKER_COIN, MAKER, 30),
            Genesis::coin(TAKER_COIN, TAKER, 20),
        ],
    );
    let open = open_op();
    let Ok(event) = state.apply(RESOURCE_CONTEXT, &Op::Open(open)) else {
        panic!("operation rejected");
    };

    assert_eq!(
        event.kind(),
        EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: edge(),
        },
    );
    assert_eq!(RESOURCE_CONTEXT.fee(open.cost()), Some(10));
    assert_eq!(RESOURCE_CONTEXT.fee(open.reserve_cost()), Some(16));
    assert_eq!(
        state.store().edge(edge()).map(edge_view),
        Some((24, 16, PARTIES, terms())),
    );
}

#[test]
fn operations_report_deterministic_cost() {
    let open = open_op();
    let resolve = Resolve::new(
        edge(),
        proof(),
        payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
    );

    assert_eq!(open.cost(), Cost::new(1, 3, 3, 0));
    assert_eq!(Op::Open(open).cost(), open.cost());
    assert_eq!(resolve.cost(), Cost::new(1, 3, 3, 1));
    assert_eq!(Op::Resolve(resolve).cost(), resolve.cost());
    assert_eq!(
        agreement_proof(edge(), resolve.outputs()).cost(),
        Cost::new(0, 0, 0, 2)
    );
    assert_eq!(proof().kind(), ResolveKind::Basic);
    assert_eq!(proof().terms(), terms());
    assert_eq!(Proof::timeout(BASIC_TERMS).terms(), terms());
    assert_eq!(Proof::timeout(BASIC_TERMS).cost(), Cost::new(0, 0, 0, 1));
    assert_eq!(
        claimant_proof(edge(), resolve.outputs()).cost(),
        Cost::new(0, 0, 0, 2),
    );
    assert_eq!(
        challenger_proof(edge(), resolve.outputs()).kind(),
        ResolveKind::ChallengerWins,
    );
}

#[test]
fn operations_derive_output_ids() {
    let open = open_op();
    let resolve = Resolve::new(
        open.output(),
        proof(),
        payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
    );
    let ids = resolve.output_ids();

    assert_eq!(
        open.output(),
        Open::from_terms(funding(MAKER_COIN, TAKER_COIN), BASIC_TERMS).output(),
    );
    assert_eq!(ids.as_slice()[0], Payout::new(MAKER, 7).id(edge(), 0));
    assert_eq!(ids.as_slice()[1], Payout::new(TAKER, 8).id(edge(), 1));
    assert_ne!(ids.as_slice()[0], ids.as_slice()[1]);
}

#[test]
fn operations_report_access_sets() {
    let open = open_op();
    let resolve = Resolve::new(
        open.output(),
        proof(),
        payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
    );
    let open_access = Op::Open(open).access();
    let resolve_access = Op::Resolve(resolve).access();

    assert_eq!(open.inputs(), input_ids2(MAKER_COIN, TAKER_COIN));
    assert_eq!(*open_access.coins(), input_ids2(MAKER_COIN, TAKER_COIN));
    assert_eq!(*open_access.edges(), edge_ids0());
    assert_eq!(*open_access.new_coins(), output_ids0());
    assert_eq!(*open_access.new_edges(), edge_ids1(edge()));

    assert_eq!(*resolve_access.coins(), input_ids0());
    assert_eq!(*resolve_access.edges(), edge_ids1(edge()));
    assert_eq!(
        *resolve_access.new_coins(),
        output_ids2(maker_out(), taker_out())
    );
    assert_eq!(*resolve_access.new_edges(), edge_ids0());
}

#[test]
fn operations_report_access_conflicts() {
    let open = open_op();
    let resolve = Resolve::new(
        open.output(),
        proof(),
        payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
    );
    let other_open = Open::new(funding(coin_id(20), coin_id(21)), PARTIES, terms());
    let open_op = Op::Open(open);
    let resolve_op = Op::Resolve(resolve);
    let other_op = Op::Open(other_open);

    assert!(open_op.conflicts(&resolve_op));
    assert!(open_op.access().conflicts(&resolve_op.access()));
    assert!(!open_op.conflicts(&other_op));
    assert!(!open_op.access().conflicts(&other_op.access()));
}

#[test]
fn block_reports_deterministic_cost_and_fee() {
    let ops = List::all([
        Op::Open(open_op()),
        Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        )),
    ]);
    let block = Block::new(RESOURCE_CONTEXT, ops);

    assert_eq!(block.cost(), Some(Cost::new(2, 6, 6, 1)));
    assert_eq!(block.fee(), Some(20));
}

#[test]
fn block_reports_access_conflicts() {
    let open = open_op();
    let resolve = Resolve::new(
        open.output(),
        proof(),
        payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
    );
    let other_open = Open::new(funding(coin_id(20), coin_id(21)), PARTIES, terms());
    let serial = Block::new(CONTEXT, List::all([Op::Open(open), Op::Resolve(resolve)]));
    let disjoint = Block::new(CONTEXT, List::all([Op::Open(open), Op::Open(other_open)]));

    assert!(serial.conflicts());
    assert!(!disjoint.conflicts());
}

#[test]
fn resolve_zero_edge_without_outputs() {
    let open = Open::new(Funding::new(empty_party(), empty_party()), PARTIES, terms());
    let mut state = funded_state_for(&open);
    let _event = apply(&mut state, &Op::Open(open));
    let event = apply(
        &mut state,
        &Op::Resolve(Resolve::new(open.output(), proof(), no_payouts())),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: open.output(),
            outputs: output_ids0(),
        },
    );
    assert_eq!(state.store().edge(open.output()), None);
    assert_eq!(
        state.store().coin(MAKER_COIN).map(coin_view),
        Some((MAKER, 10)),
    );
    assert_eq!(
        state.store().coin(TAKER_COIN).map(coin_view),
        Some((TAKER, 5)),
    );
}

#[test]
fn resolve_spends_edge_into_two_payout_coins() {
    let mut state = open_state();
    let event = apply(
        &mut state,
        &Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 7))
    );
    assert_eq!(
        state.store().coin(taker_out()).map(coin_view),
        Some((TAKER, 8)),
    );
}

#[test]
fn resolve_uses_prepaid_reserve() {
    let mut state = state(
        empty_store(),
        [
            Genesis::coin(MAKER_COIN, MAKER, 30),
            Genesis::coin(TAKER_COIN, TAKER, 20),
        ],
    );
    let _event = apply_with(
        &mut state,
        RESOURCE_CONTEXT,
        &Op::Open(Open::from_terms(
            funding(MAKER_COIN, TAKER_COIN),
            BASIC_TERMS,
        )),
    );
    let event = apply_with(
        &mut state,
        RESOURCE_CONTEXT,
        &Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 12), Payout::new(TAKER, 12)),
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 12)),
    );
    assert_eq!(
        state.store().coin(taker_out()).map(coin_view),
        Some((TAKER, 12)),
    );
}

#[test]
fn resolve_rejects_unpaid_fee_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            RESOURCE_CONTEXT,
            &Op::Resolve(Resolve::new(
                edge(),
                proof(),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            )),
        ),
        Err(ApplyError::InvalidResolve { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_accepts_agreement_witness() {
    let mut state = open_state();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let event = apply(
        &mut state,
        &Op::Resolve(Resolve::new(
            edge(),
            agreement_proof(edge(), &outputs),
            outputs,
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 7))
    );
    assert_eq!(
        state.store().coin(taker_out()).map(coin_view),
        Some((TAKER, 8)),
    );
}

#[test]
fn resolve_rejects_bad_agreement_signature_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let bad_hash = Resolve::payload_hash(edge(), ResolveKind::Agreement, other_terms(), &outputs);
    let proof = Proof::agreement(
        terms(),
        Agreement::new(
            Sig::placeholder(MAKER, bad_hash),
            taker_sig(edge(), &outputs),
        ),
    );

    assert_eq!(
        state.apply(CONTEXT, &Op::Resolve(Resolve::new(edge(), proof, outputs))),
        Err(ApplyError::InvalidProof { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_accepts_timeout_witness_at_deadline() {
    let mut state = open_state();
    let event = apply_with(
        &mut state,
        TIMEOUT_CONTEXT,
        &Op::Resolve(Resolve::new(
            edge(),
            Proof::timeout(BASIC_TERMS),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
}

#[test]
fn resolve_rejects_timeout_before_deadline_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &Op::Resolve(Resolve::new(
                edge(),
                Proof::timeout(BASIC_TERMS),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            )),
        ),
        Err(ApplyError::InvalidProof { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_rejects_wrong_timeout_terms_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            TIMEOUT_CONTEXT,
            &Op::Resolve(Resolve::new(
                edge(),
                Proof::timeout(OTHER_TERMS_VALUE),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            )),
        ),
        Err(ApplyError::InvalidProof { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_accepts_claimant_wins_witness() {
    let mut state = open_state();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let event = apply(
        &mut state,
        &Op::Resolve(Resolve::new(
            edge(),
            claimant_proof(edge(), &outputs),
            outputs,
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
}

#[test]
fn resolve_accepts_challenger_wins_witness() {
    let mut state = open_state();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let event = apply(
        &mut state,
        &Op::Resolve(Resolve::new(
            edge(),
            challenger_proof(edge(), &outputs),
            outputs,
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
}

#[test]
fn resolve_rejects_bad_dispute_seal_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let proof = Proof::claimant_wins(
        BASIC_TERMS,
        seal(ResolveKind::ChallengerWins, edge(), &outputs),
    );

    assert_eq!(
        state.apply(CONTEXT, &Op::Resolve(Resolve::new(edge(), proof, outputs))),
        Err(ApplyError::InvalidProof { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_rejects_wrong_dispute_terms_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let proof = Proof::claimant_wins(
        OTHER_TERMS_VALUE,
        other_seal(ResolveKind::ClaimantWins, edge(), &outputs),
    );

    assert_eq!(
        state.apply(CONTEXT, &Op::Resolve(Resolve::new(edge(), proof, outputs))),
        Err(ApplyError::InvalidProof { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn apply_all_opens_and_resolves_one_batch() {
    let mut state = funded_state();
    let ops = List::all([
        Op::Open(Open::new(funding(MAKER_COIN, TAKER_COIN), PARTIES, terms())),
        Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        )),
    ]);

    let block = Block::new(CONTEXT, ops);
    let Ok(diff) = state.apply_block(&block) else {
        panic!("valid batch rejected");
    };

    assert_eq!(diff.len(), 2);
    assert_eq!(
        diff.event(0).map(|event| event.kind()),
        Some(EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: edge(),
        }),
    );
    assert_eq!(
        diff.event(1).map(|event| event.kind()),
        Some(EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        }),
    );
    assert_eq!(diff.event(2), None);
    assert_eq!(state.store().edge(edge()), None);
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 7)),
    );
    assert_eq!(
        state.store().coin(taker_out()).map(coin_view),
        Some((TAKER, 8)),
    );
}

#[test]
fn apply_all_allows_empty_batch() {
    let mut state = funded_state();
    let store = *state.store();
    let ops: List<Op, 0> = List::all([]);
    let Ok(diff) = state.apply_all(CONTEXT, &ops) else {
        panic!("empty batch rejected");
    };

    assert!(diff.is_empty());
    assert_eq!(diff.len(), 0);
    assert_eq!(*state.store(), store);
}

#[test]
fn apply_all_rolls_back_on_error() {
    let mut state = funded_state();
    let store = *state.store();
    let ops = List::all([
        Op::Open(Open::new(funding(MAKER_COIN, TAKER_COIN), PARTIES, terms())),
        Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 9)),
        )),
    ]);

    let Err(error) = state.apply_all(CONTEXT, &ops) else {
        panic!("invalid batch accepted");
    };

    assert_eq!(error.index(), 1);
    assert_eq!(error.source(), ApplyError::InvalidResolve { input: edge() });
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_spends_edge_into_three_payout_coins() {
    let mut state = open_state();
    let event = apply(
        &mut state,
        &Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts3(
                Payout::new(MAKER, 6),
                Payout::new(TAKER, 5),
                Payout::new(MAKER, 4),
            ),
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids3(maker_out(), taker_out(), extra_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
    assert_eq!(
        state.store().coin(extra_out()).map(coin_view),
        Some((MAKER, 4))
    );
}

#[test]
fn resolve_allows_zero_value_payout_coin() {
    let mut state = open_state();
    let event = apply(
        &mut state,
        &Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 0), Payout::new(TAKER, 15)),
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 0)),
    );
    assert_eq!(
        state.store().coin(taker_out()).map(coin_view),
        Some((TAKER, 15)),
    );
}

#[test]
fn view_tracks_live_objects() {
    let funded = funded_state();
    let funded_view: View<6, 1> = funded.view();

    assert_eq!(funded_view.coin_len(), 2);
    assert_eq!(funded_view.edge_len(), 0);
    assert_eq!(
        funded_view.coin(MAKER_COIN).map(coin_view),
        Some((MAKER, 10))
    );
    assert_eq!(
        funded_view.coin(TAKER_COIN).map(coin_view),
        Some((TAKER, 5))
    );

    let mut resolved = open_state();
    let _event = apply(
        &mut resolved,
        &Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        )),
    );
    let resolved_view: View<6, 1> = resolved.view();

    assert_eq!(resolved_view.coin_len(), 2);
    assert_eq!(resolved_view.edge_len(), 0);
    assert_eq!(resolved_view.edge(edge()), None);
    assert_eq!(
        resolved_view.coin(maker_out()).map(coin_view),
        Some((MAKER, 7)),
    );
    assert_eq!(
        resolved_view.coin(taker_out()).map(coin_view),
        Some((TAKER, 8)),
    );
}

#[test]
fn resolve_rejects_non_conserving_payouts_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &Op::Resolve(Resolve::new(
                edge(),
                proof(),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 9),),
            )),
        ),
        Err(ApplyError::InvalidResolve { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_rejects_wrong_proof_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &Op::Resolve(Resolve::new(
                edge(),
                other_proof(),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8),),
            )),
        ),
        Err(ApplyError::InvalidProof { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_funding_below_fee_without_mutation() {
    let open = Open::new(Funding::new(empty_party(), empty_party()), PARTIES, terms());
    let mut state = funded_state();
    let store = *state.store();

    assert_eq!(
        state.apply(FEE_CONTEXT, &Op::Open(open)),
        Err(ApplyError::InvalidOpen {
            output: open.output(),
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_duplicate_funding_without_mutation() {
    let mut state = funded_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &Op::Open(Open::new(
                Funding::new(party1(MAKER_COIN), party1(MAKER_COIN)),
                PARTIES,
                terms()
            )),
        ),
        Err(ApplyError::DuplicateInput { id: MAKER_COIN }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_unavailable_edge_without_mutation() {
    let mut state = state(coin_store(), [MAKER_SEED, TAKER_SEED]);
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &Op::Open(Open::new(funding(MAKER_COIN, TAKER_COIN), PARTIES, terms())),
        ),
        Err(ApplyError::EdgeInsertRejected {
            id: edge(),
            reason: InsertError::Unavailable,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_overflow_without_mutation() {
    let mut state = state(
        empty_store(),
        [
            Genesis::coin(MAKER_COIN, MAKER, u64::MAX),
            Genesis::coin(TAKER_COIN, TAKER, 1),
        ],
    );
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &Op::Open(Open::new(funding(MAKER_COIN, TAKER_COIN), PARTIES, terms())),
        ),
        Err(ApplyError::InvalidOpen { output: edge() }),
    );
    assert_eq!(*state.store(), store);
}

fn funded_state() -> State<FixedStore<6, 1>> {
    state(empty_store(), [MAKER_SEED, TAKER_SEED])
}

fn funded_state_for(open: &Open) -> State<FixedStore<6, 1>> {
    state(store_for(open), [MAKER_SEED, TAKER_SEED])
}

fn open_state() -> State<FixedStore<6, 1>> {
    let mut state = funded_state();
    let _event = apply(&mut state, &Op::Open(open_op()));
    state
}

fn open_op() -> Open {
    Open::new(funding(MAKER_COIN, TAKER_COIN), PARTIES, terms())
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
    Resolve::new(
        edge(),
        proof(),
        payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
    )
    .output_ids()
}

fn output_ids3_values() -> List<CoinId, MAX_EDGE_OUTPUTS> {
    Resolve::new(
        edge(),
        proof(),
        payouts3(
            Payout::new(MAKER, 6),
            Payout::new(TAKER, 5),
            Payout::new(MAKER, 4),
        ),
    )
    .output_ids()
}

fn nth<const N: usize>(ids: List<CoinId, N>, index: usize) -> CoinId {
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

fn edge_ids0() -> List<EdgeId, 1> {
    let Some(ids) = List::new([edge()], 0) else {
        panic!("invalid test edge id list");
    };
    ids
}

const fn edge_ids1(id: EdgeId) -> List<EdgeId, 1> {
    List::all([id])
}

fn apply<const C: usize, const E: usize>(
    state: &mut State<FixedStore<C, E>>,
    op: &Op,
) -> hellas_kernel::Event {
    apply_with(state, CONTEXT, op)
}

fn apply_with<const C: usize, const E: usize>(
    state: &mut State<FixedStore<C, E>>,
    context: Context,
    op: &Op,
) -> hellas_kernel::Event {
    let Ok(event) = state.apply(context, op) else {
        panic!("operation rejected");
    };
    event
}

fn empty_store() -> FixedStore<6, 1> {
    store_for(&open_op())
}

fn store_for(open: &Open) -> FixedStore<6, 1> {
    FixedStore::empty(
        [
            MAKER_COIN,
            TAKER_COIN,
            EXTRA_COIN,
            maker_out(),
            taker_out(),
            extra_out(),
        ],
        [open.output()],
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
