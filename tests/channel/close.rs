use super::*;

#[test]
fn close_zero_edge_without_outputs() {
    let terms_value = terms_with(&no_payouts());
    let funding_value = Funding::new(empty_party(), empty_party());
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value.clone());
    let mut state = funded_state_for(&open);
    let _event = apply(&mut state, &open);
    let event = apply(
        &mut state,
        &Tx::close(edge, Proof::timeout(terms_value), no_payouts()),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge,
            outputs: output_ids0(),
        },
    );
    assert_eq!(state.store().edge(edge), None);
    assert_eq!(
        state.store().coin(MAKER_COIN).map(coin_view),
        Some((MAKER, 10)),
    );
    assert_eq!(
        state.store().coin(TAKER_COIN).map(coin_view),
        Some((TAKER, 5)),
    );
}

#[test]
fn close_spends_edge_into_two_payout_coins() {
    let mut state = open_state();
    let event = apply(
        &mut state,
        &Tx::close(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 7))
    );
    assert_eq!(
        state.store().coin(taker_out()).map(coin_view),
        Some((TAKER, 8)),
    );
}

#[test]
fn close_uses_prepaid_reserve() {
    let outputs = payouts(Payout::new(MAKER, 12), Payout::new(TAKER, 12));
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value.clone());
    let close = Tx::close(edge, Proof::timeout(terms_value), outputs.clone());
    let output_ids = Tx::close_output_ids(edge, &outputs);
    let maker_out = nth(&output_ids, 0);
    let taker_out = nth(&output_ids, 1);
    let mut state = state(
        store_for_close(&open, &outputs),
        [
            Genesis::coin(MAKER_COIN, MAKER, 30),
            Genesis::coin(TAKER_COIN, TAKER, 20),
        ],
    );
    let Some(open_fee) = RESOURCE_CONTEXT.fee(open.cost()) else {
        panic!("open fee overflow");
    };
    let Some(reserve) = RESOURCE_CONTEXT.fee(worst_case_close_cost(edge)) else {
        panic!("reserve fee overflow");
    };
    let _event = apply_with(&mut state, RESOURCE_CONTEXT, &open);
    let event = apply_with(&mut state, RESOURCE_CONTEXT, &close);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge,
            outputs: output_ids2(maker_out, taker_out),
        },
    );
    assert_eq!(state.store().edge(edge), None);
    assert_eq!(
        state.store().coin(maker_out).map(coin_view),
        Some((MAKER, 12)),
    );
    assert_eq!(
        state.store().coin(taker_out).map(coin_view),
        Some((TAKER, 12)),
    );
    assert_eq!(12 + 12 + open_fee + reserve, 50);
}

#[test]
fn close_rejects_unpaid_fee_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            RESOURCE_CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(
                edge(),
                proof(),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            ),
        ),
        Err(ApplyError::InvalidClose {
            input: edge(),
            reason: InvalidCloseReason::ReserveTooSmall,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_rejects_when_current_fee_exceeds_reserve_without_mutation() {
    let cheap = Context::with_fees(
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        Fees::new(0, 0, 1),
    );
    let expensive = Context::with_fees(
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        Fees::new(0, 0, 3),
    );
    let outputs = payouts(Payout::new(MAKER, 14), Payout::new(TAKER, 14));
    let terms_value = terms_with(&outputs);
    let terms_hash = terms_value.hash();
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value.clone());
    let reserve_cost = worst_case_close_cost(edge);
    let mut state = state(
        store_for_close(&open, &outputs),
        [
            Genesis::coin(MAKER_COIN, MAKER, 20),
            Genesis::coin(TAKER_COIN, TAKER, 10),
        ],
    );
    let _event = apply_with(&mut state, cheap, &open);
    let store = *state.store();
    let close = Tx::close(edge, Proof::timeout(terms_value), outputs);
    let close_cost = close.cost();

    assert_eq!(cheap.fee(reserve_cost), Some(2));
    assert_eq!(
        state.store().edge(edge).map(edge_view),
        Some((28, 2, PARTIES, terms_hash)),
    );
    assert_eq!(expensive.fee(close_cost), Some(3));
    assert_eq!(
        state.apply(expensive, &FAKE_VERIFIER, &close),
        Err(ApplyError::InvalidClose {
            input: edge,
            reason: InvalidCloseReason::ReserveTooSmall,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_accepts_mutual_witness() {
    let mut state = open_state();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let event = apply(
        &mut state,
        &Tx::close(edge(), mutual_proof(edge(), &outputs), outputs),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 7))
    );
    assert_eq!(
        state.store().coin(taker_out()).map(coin_view),
        Some((TAKER, 8)),
    );
}

#[test]
fn close_rejects_bad_mutual_signature_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let bad_hash = Tx::payload_hash(edge(), CloseKind::Mutual, other_terms(), &outputs);
    let proof = Proof::mutual(
        Sig::placeholder(MAKER, bad_hash),
        taker_sig(edge(), &outputs),
    );

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &Tx::close(edge(), proof, outputs),),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::BadSignature,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_accepts_timeout_witness_at_deadline() {
    let mut state = open_state();
    let event = apply_with(
        &mut state,
        TIMEOUT_CONTEXT,
        &Tx::close(
            edge(),
            Proof::timeout(basic_terms()),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
}

#[test]
fn close_rejects_timeout_before_deadline_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            EARLY_CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(
                edge(),
                Proof::timeout(basic_terms()),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            ),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::TimeoutNotReached,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_rejects_timeout_with_nondefault_payouts_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            TIMEOUT_CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(
                edge(),
                Proof::timeout(basic_terms()),
                payouts(Payout::new(MAKER, 8), Payout::new(TAKER, 7)),
            ),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::PayoutMismatch,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_rejects_wrong_timeout_terms_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            TIMEOUT_CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(
                edge(),
                Proof::timeout(other_terms_value()),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            ),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::TermsMismatch,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_accepts_violation_witness() {
    let mut state = open_state();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let event = apply(
        &mut state,
        &Tx::close(edge(), violation_proof(edge(), &outputs), outputs),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
}

#[test]
fn placeholder_witnesses_do_not_verify_under_reject_verifier() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));

    assert_eq!(
        state.apply(
            CONTEXT,
            &REJECT_VERIFIER,
            &Tx::close(edge(), mutual_proof(edge(), &outputs), outputs),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::BadSignature,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_rejects_bad_dispute_seal_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    // Seal bound to a non-canonical payload (different terms hash); the
    // verifier rejects with `BadSeal` rather than `TermsMismatch` because
    // the proof's own terms commitment is correct.
    let bad_hash = Tx::payload_hash(edge(), CloseKind::Violation, other_terms(), &outputs);
    let bad_seal = Seal::placeholder(PROTOCOL, CloseKind::Violation, bad_hash);
    let proof = Proof::violation(basic_terms(), bad_seal);

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &Tx::close(edge(), proof, outputs),),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::BadSeal,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_rejects_wrong_dispute_terms_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let proof = Proof::violation(
        other_terms_value(),
        other_seal(CloseKind::Violation, edge(), &outputs),
    );

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &Tx::close(edge(), proof, outputs),),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::TermsMismatch,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_spends_edge_into_three_payout_coins() {
    let outputs = payouts3(
        Payout::new(MAKER, 6),
        Payout::new(TAKER, 5),
        Payout::new(MAKER, 4),
    );
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value.clone());
    let close = Tx::close(edge, Proof::timeout(terms_value), outputs.clone());
    let output_ids = Tx::close_output_ids(edge, &outputs);
    let maker_out = nth(&output_ids, 0);
    let taker_out = nth(&output_ids, 1);
    let extra_out = nth(&output_ids, 2);
    let mut state = state(store_for_close(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let event = apply(&mut state, &open);
    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: edge,
        },
    );
    let event = apply(&mut state, &close);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge,
            outputs: output_ids3(maker_out, taker_out, extra_out),
        },
    );
    assert_eq!(state.store().edge(edge), None);
    assert_eq!(
        state.store().coin(extra_out).map(coin_view),
        Some((MAKER, 4))
    );
}

#[test]
fn close_allows_zero_value_payout_coin() {
    let outputs = payouts(Payout::new(MAKER, 0), Payout::new(TAKER, 15));
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value.clone());
    let close = Tx::close(edge, Proof::timeout(terms_value), outputs.clone());
    let output_ids = Tx::close_output_ids(edge, &outputs);
    let maker_out = nth(&output_ids, 0);
    let taker_out = nth(&output_ids, 1);
    let mut state = state(store_for_close(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let _event = apply(&mut state, &open);
    let event = apply(&mut state, &close);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: edge,
            outputs: output_ids2(maker_out, taker_out),
        },
    );
    assert_eq!(
        state.store().coin(maker_out).map(coin_view),
        Some((MAKER, 0)),
    );
    assert_eq!(
        state.store().coin(taker_out).map(coin_view),
        Some((TAKER, 15)),
    );
}

#[test]
fn close_rejects_non_conserving_payouts_without_mutation() {
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 9));
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = open_tx(funding_value, terms_value.clone());
    let mut state = state(store_for_close(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let _event = apply(&mut state, &open);
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(edge, Proof::timeout(terms_value), outputs),
        ),
        Err(ApplyError::InvalidClose {
            input: edge,
            reason: InvalidCloseReason::ValueMismatch,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn close_rejects_wrong_proof_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    // other_proof() is a Timeout proof under different terms; the terms hash
    // differs from the edge's commitment, so the kernel rejects with
    // TermsMismatch regardless of feature config.
    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(
                edge(),
                other_proof(),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            ),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::TermsMismatch,
        }),
    );
    assert_eq!(*state.store(), store);
}

/// Worst-case close cost reserved at open-time: `MAX_EDGE_OUTPUTS` payouts
/// under `Mutual` (the proof kind charging the most proof units).
fn worst_case_close_cost(edge: EdgeId) -> Cost {
    Tx::close(edge, mutual_proof(edge, &payouts4()), payouts4()).cost()
}
