use super::*;

#[test]
fn operations_report_deterministic_cost() {
    let open = open_op();
    let resolve = Resolve::new(
        edge(),
        proof(),
        payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
    );
    let open_cost = open.cost();
    let resolve_cost = resolve.cost();
    let reserve_cost = open.reserve_cost();
    let resolve_outputs = resolve.outputs().clone();

    assert_eq!(open_cost, Cost::new(1, 3, 0));
    assert_eq!(Op::Open(open).cost(), open_cost);
    assert_eq!(resolve_cost, Cost::new(1, 3, 1));
    assert_eq!(Op::Resolve(resolve).cost(), resolve_cost);
    assert_eq!(reserve_cost, Cost::new(1, 5, 2));
    assert!(resolve_cost.fits(reserve_cost));
    assert_eq!(
        agreement_proof(edge(), &resolve_outputs).cost(),
        Cost::new(0, 0, 2)
    );
    assert_eq!(proof().kind(), ResolveKind::Timeout);
    assert_eq!(proof().terms(), terms());
    assert_eq!(Proof::timeout(BASIC_TERMS).terms(), terms());
    assert_eq!(Proof::timeout(BASIC_TERMS).cost(), Cost::new(0, 0, 1));
    assert_eq!(
        claimant_proof(edge(), &resolve_outputs).cost(),
        Cost::new(0, 0, 2),
    );
    assert_eq!(
        challenger_proof(edge(), &resolve_outputs).kind(),
        ResolveKind::ChallengerWins,
    );
}

#[test]
fn open_reserves_worst_case_resolve_cost() {
    let open = open_op();
    let outputs = payouts4();
    let claimant = Resolve::new(edge(), claimant_proof(edge(), &outputs), outputs.clone());
    let challenger = Resolve::new(edge(), challenger_proof(edge(), &outputs), outputs);

    assert_eq!(claimant.cost(), open.reserve_cost());
    assert_eq!(challenger.cost(), open.reserve_cost());
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
    let open_inputs = open.inputs();
    let open_access = Op::Open(open).access();
    let resolve_access = Op::Resolve(resolve).access();

    assert_eq!(open_inputs, input_ids2(MAKER_COIN, TAKER_COIN));
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
    let other_open = Open::from_terms(funding(coin_id(20), coin_id(21)), BASIC_TERMS);
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

    assert_eq!(block.cost(), Some(Cost::new(2, 6, 1)));
    // 1*2 + 3*6 + 0*1 = 20 under RESOURCE_CONTEXT.
    assert_eq!(block.fee(), Some(20));
    assert!(Cost::new(2, 6, 1).fits(Cost::new(2, 6, 1)));
    assert!(block.fits(Cost::new(2, 6, 1)));
    assert!(block.fits(Cost::new(3, 6, 1)));
    assert!(!block.fits(Cost::new(1, 6, 1)));
    assert!(!block.fits(Cost::new(2, 5, 1)));
    assert!(!block.fits(Cost::new(2, 6, 0)));
}

#[test]
fn block_reports_access_conflicts() {
    let open = open_op();
    let resolve = Resolve::new(
        open.output(),
        proof(),
        payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
    );
    let other_open = Open::from_terms(funding(coin_id(20), coin_id(21)), BASIC_TERMS);
    let serial = Block::new(
        CONTEXT,
        List::all([Op::Open(open.clone()), Op::Resolve(resolve)]),
    );
    let disjoint = Block::new(CONTEXT, List::all([Op::Open(open), Op::Open(other_open)]));

    assert!(serial.conflicts());
    assert!(!disjoint.conflicts());
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
