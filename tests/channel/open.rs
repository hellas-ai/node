use super::*;

#[test]
fn open_locks_two_coins_into_one_edge() {
    let mut state = funded_state();
    let event = apply(
        &mut state,
        &Op::Open(Open::from_terms(
            funding(MAKER_COIN, TAKER_COIN),
            BASIC_TERMS,
        )),
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
    let open = Open::from_terms(
        maker2_funding(MAKER_COIN, EXTRA_COIN, TAKER_COIN),
        BASIC_TERMS,
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
    let open = Open::from_terms(Funding::new(party1(MAKER_COIN), empty_party()), BASIC_TERMS);
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
    let open = Open::from_terms(Funding::new(empty_party(), party1(TAKER_COIN)), BASIC_TERMS);
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
fn open_allows_same_maker_and_taker_party() {
    let parties = Parties::new(MAKER, MAKER);
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(MAKER, 8));
    let terms = Terms::basic(PROTOCOL, parties, TIMEOUT, outputs);
    let open = Open::from_terms(funding(MAKER_COIN, TAKER_COIN), terms);
    let mut state = funded_state_for(&open);
    let event = apply(&mut state, &Op::Open(open));

    assert_eq!(
        event.kind(),
        EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: open.output(),
        },
    );
    assert_eq!(
        state.store().edge(open.output()).map(edge_view),
        Some((15, 0, parties, terms.hash())),
    );
}

#[test]
fn open_allows_empty_funding_when_fee_is_zero() {
    let open = Open::from_terms(Funding::new(empty_party(), empty_party()), BASIC_TERMS);
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
fn open_allows_exact_fee_and_reserve_funding() {
    let open = open_op();
    let mut state = state(
        empty_store(),
        [
            Genesis::coin(MAKER_COIN, MAKER, 20),
            Genesis::coin(TAKER_COIN, TAKER, 6),
        ],
    );
    let event = apply_with(&mut state, RESOURCE_CONTEXT, &Op::Open(open));

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
        Some((0, 16, PARTIES, terms())),
    );
}

#[test]
fn open_rejects_funding_below_fee_and_reserve_without_mutation() {
    let open = open_op();
    let mut state = state(
        empty_store(),
        [
            Genesis::coin(MAKER_COIN, MAKER, 20),
            Genesis::coin(TAKER_COIN, TAKER, 5),
        ],
    );
    let store = *state.store();

    assert_eq!(RESOURCE_CONTEXT.fee(open.cost()), Some(10));
    assert_eq!(RESOURCE_CONTEXT.fee(open.reserve_cost()), Some(16));
    assert_eq!(
        state.apply(RESOURCE_CONTEXT, &Op::Open(open)),
        Err(ApplyError::InvalidOpen {
            output: open.output(),
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_funding_below_fee_without_mutation() {
    let open = Open::from_terms(Funding::new(empty_party(), empty_party()), BASIC_TERMS);
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
            &Op::Open(Open::from_terms(
                Funding::new(party1(MAKER_COIN), party1(MAKER_COIN)),
                BASIC_TERMS
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
            &Op::Open(Open::from_terms(
                funding(MAKER_COIN, TAKER_COIN),
                BASIC_TERMS,
            )),
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
            &Op::Open(Open::from_terms(
                funding(MAKER_COIN, TAKER_COIN),
                BASIC_TERMS,
            )),
        ),
        Err(ApplyError::InvalidOpen { output: edge() }),
    );
    assert_eq!(*state.store(), store);
}
