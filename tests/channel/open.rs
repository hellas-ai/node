use super::*;

#[test]
fn open_locks_two_coins_into_one_edge() {
    let mut state = funded_state();
    let event = apply(
        &mut state,
        &Tx::open(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
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
    let funding_value = maker2_funding(MAKER_COIN, EXTRA_COIN, TAKER_COIN);
    let output = Tx::edge_id_of(&funding_value, &basic_terms());
    let open = Tx::open(funding_value, basic_terms());
    let mut state = state(
        store_for(&open),
        [MAKER_SEED, TAKER_SEED, Genesis::coin(EXTRA_COIN, MAKER, 3)],
    );
    let event = apply(&mut state, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids3(MAKER_COIN, EXTRA_COIN, TAKER_COIN),
            output,
        },
    );
    assert_eq!(state.store().coin(EXTRA_COIN), None);
    assert_eq!(
        state.store().edge(output).map(edge_view),
        Some((18, 0, PARTIES, terms())),
    );
}

#[test]
fn open_allows_maker_only_funding() {
    let funding_value = Funding::new(party1(MAKER_COIN), empty_party());
    let output = Tx::edge_id_of(&funding_value, &basic_terms());
    let open = Tx::open(funding_value, basic_terms());
    let mut state = funded_state_for(&open);
    let event = apply(&mut state, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids1(MAKER_COIN),
            output,
        },
    );
    assert_eq!(state.store().coin(MAKER_COIN), None);
    assert_eq!(
        state.store().coin(TAKER_COIN).map(coin_view),
        Some((TAKER, 5))
    );
    assert_eq!(
        state.store().edge(output).map(edge_view),
        Some((10, 0, PARTIES, terms())),
    );
}

#[test]
fn open_allows_taker_only_funding() {
    let funding_value = Funding::new(empty_party(), party1(TAKER_COIN));
    let output = Tx::edge_id_of(&funding_value, &basic_terms());
    let open = Tx::open(funding_value, basic_terms());
    let mut state = funded_state_for(&open);
    let event = apply(&mut state, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids1(TAKER_COIN),
            output,
        },
    );
    assert_eq!(
        state.store().coin(MAKER_COIN).map(coin_view),
        Some((MAKER, 10))
    );
    assert_eq!(state.store().coin(TAKER_COIN), None);
    assert_eq!(
        state.store().edge(output).map(edge_view),
        Some((5, 0, PARTIES, terms())),
    );
}

#[test]
fn open_allows_same_maker_and_taker_party() {
    let parties = Parties::new(MAKER, MAKER);
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(MAKER, 8));
    let terms_value = Terms::basic(PROTOCOL, parties, TIMEOUT, outputs);
    let terms_hash = terms_value.hash();
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = Tx::open(funding_value, terms_value);
    let mut state = funded_state_for(&open);
    let event = apply(&mut state, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output,
        },
    );
    assert_eq!(
        state.store().edge(output).map(edge_view),
        Some((15, 0, parties, terms_hash)),
    );
}

#[test]
fn open_allows_empty_funding_when_fee_is_zero() {
    let funding_value = Funding::new(empty_party(), empty_party());
    let output = Tx::edge_id_of(&funding_value, &basic_terms());
    let open = Tx::open(funding_value, basic_terms());
    let mut state = funded_state_for(&open);
    let event = apply(&mut state, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids0(),
            output,
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
        state.store().edge(output).map(edge_view),
        Some((0, 0, PARTIES, terms())),
    );
}

#[test]
fn open_pays_fee_from_funding() {
    let mut state = funded_state();
    let Ok(event) = state.apply(
        FEE_CONTEXT,
        &FAKE_VERIFIER,
        &Tx::open(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
    ) else {
        panic!("operation rejected");
    };

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
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
    let cost = open.cost();
    let reserve_cost = reserve_cost_for(&open);
    let Ok(event) = state.apply(RESOURCE_CONTEXT, &FAKE_VERIFIER, &open) else {
        panic!("operation rejected");
    };

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: edge(),
        },
    );
    assert_eq!(RESOURCE_CONTEXT.fee(cost), Some(10));
    assert_eq!(RESOURCE_CONTEXT.fee(reserve_cost), Some(16));
    assert_eq!(
        state.store().edge(edge()).map(edge_view),
        Some((24, 16, PARTIES, terms())),
    );
}

#[test]
fn open_allows_exact_fee_and_reserve_funding() {
    let open = open_op();
    let cost = open.cost();
    let reserve_cost = reserve_cost_for(&open);
    let mut state = state(
        empty_store(),
        [
            Genesis::coin(MAKER_COIN, MAKER, 20),
            Genesis::coin(TAKER_COIN, TAKER, 6),
        ],
    );
    let event = apply_with(&mut state, RESOURCE_CONTEXT, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: edge(),
        },
    );
    assert_eq!(RESOURCE_CONTEXT.fee(cost), Some(10));
    assert_eq!(RESOURCE_CONTEXT.fee(reserve_cost), Some(16));
    assert_eq!(
        state.store().edge(edge()).map(edge_view),
        Some((0, 16, PARTIES, terms())),
    );
}

#[test]
fn open_rejects_funding_below_fee_and_reserve_without_mutation() {
    let open = open_op();
    let output = open_edge_id(&open);
    let cost = open.cost();
    let reserve_cost = reserve_cost_for(&open);
    let mut state = state(
        empty_store(),
        [
            Genesis::coin(MAKER_COIN, MAKER, 20),
            Genesis::coin(TAKER_COIN, TAKER, 5),
        ],
    );
    let store = *state.store();

    assert_eq!(RESOURCE_CONTEXT.fee(cost), Some(10));
    assert_eq!(RESOURCE_CONTEXT.fee(reserve_cost), Some(16));
    assert_eq!(
        state.apply(RESOURCE_CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::FundingInsufficient,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn open_rejects_funding_below_fee_without_mutation() {
    let funding_value = Funding::new(empty_party(), empty_party());
    let output = Tx::edge_id_of(&funding_value, &basic_terms());
    let open = Tx::open(funding_value, basic_terms());
    let mut state = funded_state();
    let store = *state.store();

    assert_eq!(
        state.apply(FEE_CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::FundingInsufficient,
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
            &FAKE_VERIFIER,
            &Tx::open(
                Funding::new(party1(MAKER_COIN), party1(MAKER_COIN)),
                basic_terms()
            ),
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
            &FAKE_VERIFIER,
            &Tx::open(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
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
            &FAKE_VERIFIER,
            &Tx::open(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
        ),
        Err(ApplyError::InvalidOpen {
            output: edge(),
            reason: InvalidOpenReason::FundingOverflow,
        }),
    );
    assert_eq!(*state.store(), store);
}

/// Worst-case close cost reserved at open-time. Mirrors `apply_open`'s
/// `reserve_cost`: `MAX_EDGE_OUTPUTS` payouts under `Mutual` (the proof
/// kind charging the most proof units).
fn reserve_cost_for(_open: &Tx) -> Cost {
    Tx::close(
        edge(),
        mutual_proof(edge(), &payouts4()),
        payouts4(),
    )
    .cost()
}
