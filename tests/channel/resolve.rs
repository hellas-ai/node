use super::*;

#[test]
fn resolve_zero_edge_without_outputs() {
    let terms_value = terms_with(&no_payouts());
    let funding_value = Funding::new(empty_party(), empty_party());
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = Tx::open(funding_value, terms_value.clone());
    let mut state = funded_state_for(&open);
    let _event = apply(&mut state, &open);
    let event = apply(
        &mut state,
        &Tx::resolve(edge, Proof::timeout(terms_value), no_payouts()),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeResolved {
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
fn resolve_spends_edge_into_two_payout_coins() {
    let mut state = open_state();
    let event = apply(
        &mut state,
        &Tx::resolve(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeResolved {
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
#[cfg(feature = "fake-crypto")]
fn resolve_accepts_basic_witness_with_fake_crypto() {
    let mut state = open_state();
    let event = apply(
        &mut state,
        &Tx::resolve(
            edge(),
            Proof::basic(terms()),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
}

#[test]
#[cfg(not(feature = "fake-crypto"))]
fn resolve_rejects_basic_witness_without_fake_crypto() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::resolve(
                edge(),
                Proof::basic(terms()),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            ),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::BasicNotAccepted,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_uses_prepaid_reserve() {
    let outputs = payouts(Payout::new(MAKER, 12), Payout::new(TAKER, 12));
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = Tx::open(funding_value, terms_value.clone());
    let resolve = Tx::resolve(edge, Proof::timeout(terms_value), outputs.clone());
    let output_ids = Tx::resolve_output_ids(edge, &outputs);
    let maker_out = nth(&output_ids, 0);
    let taker_out = nth(&output_ids, 1);
    let mut state = state(
        store_for_resolve(&open, &outputs),
        [
            Genesis::coin(MAKER_COIN, MAKER, 30),
            Genesis::coin(TAKER_COIN, TAKER, 20),
        ],
    );
    let Some(open_fee) = RESOURCE_CONTEXT.fee(open.cost()) else {
        panic!("open fee overflow");
    };
    let Some(reserve) = RESOURCE_CONTEXT.fee(worst_case_resolve_cost(edge)) else {
        panic!("reserve fee overflow");
    };
    let _event = apply_with(&mut state, RESOURCE_CONTEXT, &open);
    let event = apply_with(&mut state, RESOURCE_CONTEXT, &resolve);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeResolved {
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
fn resolve_rejects_unpaid_fee_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            RESOURCE_CONTEXT,
            &FAKE_VERIFIER,
            &Tx::resolve(
                edge(),
                proof(),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            ),
        ),
        Err(ApplyError::InvalidResolve {
            input: edge(),
            reason: InvalidResolveReason::ReserveTooSmall,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_rejects_when_current_fee_exceeds_reserve_without_mutation() {
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
    let open = Tx::open(funding_value, terms_value.clone());
    let reserve_cost = worst_case_resolve_cost(edge);
    let mut state = state(
        store_for_resolve(&open, &outputs),
        [
            Genesis::coin(MAKER_COIN, MAKER, 20),
            Genesis::coin(TAKER_COIN, TAKER, 10),
        ],
    );
    let _event = apply_with(&mut state, cheap, &open);
    let store = *state.store();
    let resolve = Tx::resolve(edge, Proof::timeout(terms_value), outputs);
    let resolve_cost = resolve.cost();

    assert_eq!(cheap.fee(reserve_cost), Some(2));
    assert_eq!(
        state.store().edge(edge).map(edge_view),
        Some((28, 2, PARTIES, terms_hash)),
    );
    assert_eq!(expensive.fee(resolve_cost), Some(3));
    assert_eq!(
        state.apply(expensive, &FAKE_VERIFIER, &resolve),
        Err(ApplyError::InvalidResolve {
            input: edge,
            reason: InvalidResolveReason::ReserveTooSmall,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
#[cfg(feature = "fake-crypto")]
fn resolve_accepts_agreement_witness() {
    let mut state = open_state();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let event = apply(
        &mut state,
        &Tx::resolve(edge(), agreement_proof(edge(), &outputs), outputs),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeResolved {
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
fn resolve_rejects_bad_agreement_signature_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let bad_hash = Tx::payload_hash(edge(), ResolveKind::Agreement, other_terms(), &outputs);
    let proof = Proof::agreement(
        terms(),
        Agreement::new(
            Sig::placeholder(MAKER, bad_hash),
            taker_sig(edge(), &outputs),
        ),
    );

    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::resolve(edge(), proof, outputs),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::BadSignature,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_accepts_timeout_witness_at_deadline() {
    let mut state = open_state();
    let event = apply_with(
        &mut state,
        TIMEOUT_CONTEXT,
        &Tx::resolve(
            edge(),
            Proof::timeout(basic_terms()),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        ),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
}

#[test]
fn resolve_rejects_timeout_before_deadline_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            EARLY_CONTEXT,
            &FAKE_VERIFIER,
            &Tx::resolve(
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
fn resolve_rejects_timeout_with_nondefault_payouts_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            TIMEOUT_CONTEXT,
            &FAKE_VERIFIER,
            &Tx::resolve(
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
fn resolve_rejects_wrong_timeout_terms_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            TIMEOUT_CONTEXT,
            &FAKE_VERIFIER,
            &Tx::resolve(
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
#[cfg(feature = "fake-crypto")]
fn resolve_accepts_claimant_wins_witness() {
    let mut state = open_state();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let event = apply(
        &mut state,
        &Tx::resolve(edge(), claimant_proof(edge(), &outputs), outputs),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
}

#[test]
#[cfg(feature = "fake-crypto")]
fn resolve_accepts_challenger_wins_witness() {
    let mut state = open_state();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let event = apply(
        &mut state,
        &Tx::resolve(edge(), challenger_proof(edge(), &outputs), outputs),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeResolved {
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
            &Tx::resolve(edge(), agreement_proof(edge(), &outputs), outputs),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::BadSignature,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_rejects_bad_dispute_seal_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let proof = Proof::claimant_wins(
        basic_terms(),
        seal(ResolveKind::ChallengerWins, edge(), &outputs),
    );

    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::resolve(edge(), proof, outputs),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::BadSeal,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_rejects_wrong_dispute_terms_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let proof = Proof::claimant_wins(
        other_terms_value(),
        other_seal(ResolveKind::ClaimantWins, edge(), &outputs),
    );

    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::resolve(edge(), proof, outputs),
        ),
        Err(ApplyError::InvalidProof {
            input: edge(),
            reason: InvalidProofReason::TermsMismatch,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_spends_edge_into_three_payout_coins() {
    let outputs = payouts3(
        Payout::new(MAKER, 6),
        Payout::new(TAKER, 5),
        Payout::new(MAKER, 4),
    );
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = Tx::open(funding_value, terms_value.clone());
    let resolve = Tx::resolve(edge, Proof::timeout(terms_value), outputs.clone());
    let output_ids = Tx::resolve_output_ids(edge, &outputs);
    let maker_out = nth(&output_ids, 0);
    let taker_out = nth(&output_ids, 1);
    let extra_out = nth(&output_ids, 2);
    let mut state = state(store_for_resolve(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let event = apply(&mut state, &open);
    assert_eq!(
        event.kind(),
        &EventKind::EdgeOpened {
            inputs: input_ids2(MAKER_COIN, TAKER_COIN),
            output: edge,
        },
    );
    let event = apply(&mut state, &resolve);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeResolved {
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
fn resolve_allows_zero_value_payout_coin() {
    let outputs = payouts(Payout::new(MAKER, 0), Payout::new(TAKER, 15));
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = Tx::open(funding_value, terms_value.clone());
    let resolve = Tx::resolve(edge, Proof::timeout(terms_value), outputs.clone());
    let output_ids = Tx::resolve_output_ids(edge, &outputs);
    let maker_out = nth(&output_ids, 0);
    let taker_out = nth(&output_ids, 1);
    let mut state = state(store_for_resolve(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let _event = apply(&mut state, &open);
    let event = apply(&mut state, &resolve);

    assert_eq!(
        event.kind(),
        &EventKind::EdgeResolved {
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
fn resolve_rejects_non_conserving_payouts_without_mutation() {
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 9));
    let terms_value = terms_with(&outputs);
    let funding_value = funding(MAKER_COIN, TAKER_COIN);
    let edge = Tx::edge_id_of(&funding_value, &terms_value);
    let open = Tx::open(funding_value, terms_value.clone());
    let mut state = state(store_for_resolve(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let _event = apply(&mut state, &open);
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::resolve(edge, Proof::timeout(terms_value), outputs),
        ),
        Err(ApplyError::InvalidResolve {
            input: edge,
            reason: InvalidResolveReason::ValueMismatch,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_rejects_wrong_proof_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    // other_proof() is a Timeout proof under different terms; the terms hash
    // differs from the edge's commitment, so the kernel rejects with
    // TermsMismatch regardless of feature config.
    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::resolve(
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

/// Worst-case resolve cost reserved at open-time: `MAX_EDGE_OUTPUTS` payouts
/// under `ClaimantWins`.
fn worst_case_resolve_cost(edge: EdgeId) -> Cost {
    Tx::resolve(
        edge,
        claimant_proof(edge, &payouts4()),
        payouts4(),
    )
    .cost()
}
