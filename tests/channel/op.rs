use super::*;

#[test]
fn operations_report_deterministic_cost() {
    let open = open_op();
    let resolve_outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let resolve = Tx::resolve(edge(), proof(), resolve_outputs.clone());
    let open_cost = open.cost();
    let resolve_cost = resolve.cost();
    // Worst-case reserve mirrors `apply_open` reserve_cost: MAX_EDGE_OUTPUTS
    // payouts under `ClaimantWins`.
    let worst_case = Tx::resolve(
        edge(),
        claimant_proof(edge(), &payouts4()),
        payouts4(),
    )
    .cost();

    assert_eq!(open_cost, Cost::new(1, 3, 0));
    assert_eq!(resolve_cost, Cost::new(1, 3, 1));
    assert_eq!(worst_case, Cost::new(1, 5, 2));
    assert!(resolve_cost.fits(worst_case));
    assert_eq!(
        agreement_proof(edge(), &resolve_outputs).cost(),
        Cost::new(0, 0, 2)
    );
    assert_eq!(proof().kind(), ResolveKind::Timeout);
    assert_eq!(proof().terms(), terms());
    assert_eq!(Proof::timeout(basic_terms()).terms(), terms());
    assert_eq!(Proof::timeout(basic_terms()).cost(), Cost::new(0, 0, 1));
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
    let outputs = payouts4();
    let claimant = Tx::resolve(edge(), claimant_proof(edge(), &outputs), outputs.clone());
    let challenger = Tx::resolve(edge(), challenger_proof(edge(), &outputs), outputs);
    let expected = Cost::new(1, 5, 2);

    assert_eq!(claimant.cost(), expected);
    assert_eq!(challenger.cost(), expected);
}

#[test]
fn operations_derive_output_ids() {
    let open = open_op();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let edge_id = open_edge_id(&open);
    let resolve = Tx::resolve(edge_id, proof(), outputs.clone());
    let ids = Tx::resolve_output_ids(edge_id, &outputs);

    assert_eq!(
        edge_id,
        Tx::edge_id_of(&funding(MAKER_COIN, TAKER_COIN), &basic_terms()),
    );
    assert_eq!(ids.as_slice()[0], Payout::new(MAKER, 7).id(edge(), 0));
    assert_eq!(ids.as_slice()[1], Payout::new(TAKER, 8).id(edge(), 1));
    assert_ne!(ids.as_slice()[0], ids.as_slice()[1]);
    // Sanity: the resolve still reports the configured outputs through pattern match.
    let Tx::Resolve {
        outputs: tx_outputs,
        ..
    } = &resolve
    else {
        panic!("expected resolve");
    };
    assert_eq!(tx_outputs, &outputs);
}

#[test]
fn block_reports_deterministic_cost_and_fee() {
    let ops = List::all([
        open_op(),
        Tx::resolve(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
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
        &Tx::resolve(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
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
