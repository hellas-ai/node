use super::*;

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
