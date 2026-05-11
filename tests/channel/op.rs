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
