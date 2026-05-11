use super::*;

#[test]
fn open_locks_two_coins_into_one_edge() {
    let mut state = funded_state();
    let event = apply(
        &mut state,
        &open_tx(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
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
    let open = open_tx(funding_value, basic_terms());
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
    let open = open_tx(funding_value, basic_terms());
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
    let open = open_tx(funding_value, basic_terms());
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
    // Both parties = MAKER. The funding ownership rule now requires every
    // coin to be owned by the matching party key, so both coins are seeded
    // as MAKER-owned (using `EXTRA_COIN` as the second slot).
    let parties = Parties::new(MAKER, MAKER);
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(MAKER, 8));
    let terms_value = Terms::basic(PROTOCOL, parties, TIMEOUT, outputs);
    let terms_hash = terms_value.hash();
    let funding_value = funding(MAKER_COIN, EXTRA_COIN);
    let output = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx_with(funding_value, terms_value, MAKER, MAKER);
    let mut state = state(
        store_for(&open),
        [MAKER_SEED, TAKER_SEED, Genesis::coin(EXTRA_COIN, MAKER, 5)],
    );
    let event = apply(&mut state, &open);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, EXTRA_COIN),
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
    let open = open_tx(funding_value, basic_terms());
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
        &open_tx(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
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
    let open = open_tx(funding_value, basic_terms());
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
            &open_tx(
                Funding::new(party1(MAKER_COIN), party1(MAKER_COIN)),
                basic_terms(),
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
            &open_tx(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
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
            &open_tx(funding(MAKER_COIN, TAKER_COIN), basic_terms()),
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
    Tx::close(edge(), mutual_proof(edge(), &payouts4()), payouts4()).cost()
}

// ---------------------------------------------------------------------
// Authorization
//
// `Tx::Open` consumes coins. Each coin is owner-keyed; opening an edge
// must require consent from each consumed coin's owner. Without that,
// any party who knows live coin ids can lock them into terms of their
// choosing and drain them via a structural Timeout close at the
// committed height.
//
// The tests below construct unauthorized opens — opens where the coins
// being consumed are owned by keys distinct from the claimed party
// identities, with no signature binding consent — and assert the kernel
// rejects them. They demonstrate the security property the open path
// must enforce.
// ---------------------------------------------------------------------

const EVE: Key = Key::from_bytes([0xee; Key::LENGTH]);
const EVE_PARTIES: Parties = Parties::new(EVE, EVE);

fn eve_terms() -> Terms {
    Terms::basic(
        PROTOCOL,
        EVE_PARTIES,
        TIMEOUT,
        payouts(Payout::new(EVE, 7), Payout::new(EVE, 8)),
    )
}

#[test]
fn open_rejects_funding_owned_by_other_keys() {
    // Eve constructs an Open consuming Maker's + Taker's coins while
    // naming herself as both parties. Without an authorization check,
    // the kernel accepts this; a subsequent timeout close at the
    // committed height pays everything to Eve.
    let funding = funding(MAKER_COIN, TAKER_COIN);
    // Eve constructs sigs over EVE/EVE (the parties she names). She
    // cannot produce Maker's or Taker's signature, so any choice she
    // makes here is unauthenticated; the funding ownership check fires
    // first regardless.
    let attack = open_tx_with(funding, eve_terms(), EVE, EVE);
    let mut state = funded_state_for(&attack);

    let result = state.apply(CONTEXT, &FAKE_VERIFIER, &attack);

    assert!(
        matches!(result, Err(ApplyError::InvalidOpen { .. })),
        "kernel must reject opens that consume coins not owned by the \
         claimed party; got {result:?}",
    );
}

#[test]
fn open_rejects_maker_coin_owned_by_someone_other_than_maker_party() {
    // The taker is honest (TAKER owns TAKER_COIN), but the "maker"
    // slot is filled with a coin Eve doesn't own. The kernel must
    // reject; otherwise Eve can launder Maker's coin through a
    // self-dealing edge whose timeout payouts target her.
    let funding = funding(MAKER_COIN, TAKER_COIN);
    let mixed_terms = Terms::basic(
        PROTOCOL,
        Parties::new(EVE, TAKER),
        TIMEOUT,
        payouts(Payout::new(EVE, 10), Payout::new(TAKER, 5)),
    );
    let attack = open_tx_with(funding, mixed_terms, EVE, TAKER);
    let mut state = funded_state_for(&attack);

    let result = state.apply(CONTEXT, &FAKE_VERIFIER, &attack);

    assert!(
        matches!(result, Err(ApplyError::InvalidOpen { .. })),
        "kernel must reject opens where a party's funding coins are not \
         owned by that party's key; got {result:?}",
    );
}
