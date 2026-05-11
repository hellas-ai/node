use super::*;

#[test]
fn apply_all_opens_and_resolves_one_batch() {
    let mut state = funded_state();
    let ops = List::all([
        Op::Open(Open::from_terms(
            funding(MAKER_COIN, TAKER_COIN),
            BASIC_TERMS,
        )),
        Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        )),
    ]);

    let block = Block::new(CONTEXT, ops);
    let Ok(diff) = state.apply_block(&FAKE_VERIFIER, &block) else {
        panic!("valid batch rejected");
    };

    assert_eq!(diff.len(), 2);
    assert_eq!(
        diff.event(0).map(Event::kind),
        Some(&EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: edge(),
        }),
    );
    assert_eq!(
        diff.event(1).map(Event::kind),
        Some(&EventKind::EdgeResolved {
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
    let Ok(diff) = state.apply_all(CONTEXT, &FAKE_VERIFIER, &ops) else {
        panic!("empty batch rejected");
    };

    assert!(diff.is_empty());
    assert_eq!(diff.len(), 0);
    assert_eq!(*state.store(), store);
}

#[test]
fn apply_all_rolls_back_on_error() {
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 9));
    let terms = terms_with(&outputs);
    let open = Open::from_terms(funding(MAKER_COIN, TAKER_COIN), terms.clone());
    let edge = open.output();
    let mut state = state(store_for_resolve(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let store = *state.store();
    let ops = List::all([
        Op::Open(open),
        Op::Resolve(Resolve::new(edge, Proof::timeout(terms), outputs)),
    ]);

    let Err(error) = state.apply_all(CONTEXT, &FAKE_VERIFIER, &ops) else {
        panic!("invalid batch accepted");
    };

    assert_eq!(error.index(), 1);
    assert_eq!(
        error.source(),
        ApplyError::InvalidResolve {
            input: edge,
            reason: InvalidResolveReason::ValueMismatch,
        },
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn apply_iter_emits_events_per_op() {
    let mut state = funded_state();
    let open = Open::from_terms(funding(MAKER_COIN, TAKER_COIN), BASIC_TERMS);
    let edge_id = open.output();
    let ops = [
        Op::Open(open),
        Op::Resolve(Resolve::new(
            edge_id,
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        )),
    ];

    let mut observed: Vec<(usize, EventKind)> = Vec::new();
    let Ok(()) = state.apply_iter(CONTEXT, &FAKE_VERIFIER, ops, |i, ev| {
        observed.push((i, ev.kind().clone()));
    }) else {
        panic!("valid batch rejected");
    };

    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0].0, 0);
    assert!(matches!(
        observed[0].1,
        EventKind::EdgeOpened { output, .. } if output == edge_id,
    ));
    assert_eq!(observed[1].0, 1);
    assert!(matches!(
        observed[1].1,
        EventKind::EdgeResolved { input, .. } if input == edge_id,
    ));
    assert_eq!(state.store().edge(edge_id), None);
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 7)),
    );
}

#[test]
fn apply_iter_rolls_back_on_mid_batch_failure() {
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 9));
    let terms = terms_with(&outputs);
    let open = Open::from_terms(funding(MAKER_COIN, TAKER_COIN), terms.clone());
    let edge_id = open.output();
    let mut state = state(store_for_resolve(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let store_before = *state.store();
    let ops = [
        Op::Open(open),
        Op::Resolve(Resolve::new(edge_id, Proof::timeout(terms), outputs)),
    ];

    let mut observed = Vec::new();
    let Err(error) = state.apply_iter(CONTEXT, &FAKE_VERIFIER, ops, |i, ev| {
        observed.push((i, ev.kind().clone()));
    }) else {
        panic!("invalid batch accepted");
    };

    assert_eq!(error.index(), 1);
    assert_eq!(
        error.source(),
        ApplyError::InvalidResolve {
            input: edge_id,
            reason: InvalidResolveReason::ValueMismatch,
        },
    );
    // op-0's event was observed before op-1 failed, but the transaction
    // rolled back, so the store must be unchanged regardless.
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].0, 0);
    assert_eq!(*state.store(), store_before);
}

#[test]
fn apply_iter_accepts_empty_batch() {
    let mut state = funded_state();
    let store_before = *state.store();
    let ops: [Op; 0] = [];

    let mut observed: Vec<usize> = Vec::new();
    let Ok(()) = state.apply_iter(CONTEXT, &FAKE_VERIFIER, ops, |i, _| observed.push(i)) else {
        panic!("empty batch rejected");
    };

    assert!(observed.is_empty());
    assert_eq!(*state.store(), store_before);
}
