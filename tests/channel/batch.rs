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
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 9));
    let terms = terms_with(outputs);
    let open = Open::from_terms(funding(MAKER_COIN, TAKER_COIN), terms);
    let mut state = state(store_for_resolve(&open, outputs), [MAKER_SEED, TAKER_SEED]);
    let store = *state.store();
    let ops = List::all([
        Op::Open(open),
        Op::Resolve(Resolve::new(open.output(), Proof::timeout(terms), outputs)),
    ]);

    let Err(error) = state.apply_all(CONTEXT, &ops) else {
        panic!("invalid batch accepted");
    };

    assert_eq!(error.index(), 1);
    assert_eq!(
        error.source(),
        ApplyError::InvalidResolve {
            input: open.output(),
        },
    );
    assert_eq!(*state.store(), store);
}
