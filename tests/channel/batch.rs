use super::*;

#[test]
fn apply_all_opens_and_closes_one_batch() {
    let mut state = funded_state();
    let ops = List::all([
        Tx::open(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
        Tx::close(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
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
        Some(&EventKind::EdgeClosed {
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
    let ops: List<Tx, 0> = List::all([]);
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
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = Tx::open(funding_value, terms_value.clone());
    let mut state = state(store_for_close(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let store = *state.store();
    let ops = List::all([
        open,
        Tx::close(edge, Proof::timeout(terms_value), outputs),
    ]);

    let Err(error) = state.apply_all(CONTEXT, &FAKE_VERIFIER, &ops) else {
        panic!("invalid batch accepted");
    };

    assert_eq!(error.index(), 1);
    assert_eq!(
        error.source(),
        ApplyError::InvalidClose {
            input: edge,
            reason: InvalidCloseReason::ValueMismatch,
        },
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn apply_iter_emits_events_per_op() {
    let mut state = funded_state();
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge_id = Tx::edge_id_of(&funding_value, &basic_terms());
    let open = Tx::open(funding_value, basic_terms());
    let ops = [
        open,
        Tx::close(
            edge_id,
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
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
        EventKind::EdgeClosed { input, .. } if input == edge_id,
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
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge_id = Tx::edge_id_of(&funding_value, &terms_value);
    let open = Tx::open(funding_value, terms_value.clone());
    let mut state = state(store_for_close(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let store_before = *state.store();
    let ops = [
        open,
        Tx::close(edge_id, Proof::timeout(terms_value), outputs),
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
        ApplyError::InvalidClose {
            input: edge_id,
            reason: InvalidCloseReason::ValueMismatch,
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
    let ops: [Tx; 0] = [];

    let mut observed: Vec<usize> = Vec::new();
    let Ok(()) = state.apply_iter(CONTEXT, &FAKE_VERIFIER, ops, |i, _| observed.push(i)) else {
        panic!("empty batch rejected");
    };

    assert!(observed.is_empty());
    assert_eq!(*state.store(), store_before);
}
