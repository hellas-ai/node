use super::*;

#[test]
fn resolve_zero_edge_without_outputs() {
    let open = Open::new(Funding::new(empty_party(), empty_party()), PARTIES, terms());
    let mut state = funded_state_for(&open);
    let _event = apply(&mut state, &Op::Open(open));
    let event = apply(
        &mut state,
        &Op::Resolve(Resolve::new(open.output(), proof(), no_payouts())),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: open.output(),
            outputs: output_ids0(),
        },
    );
    assert_eq!(state.store().edge(open.output()), None);
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
        &Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
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
fn resolve_uses_prepaid_reserve() {
    let mut state = state(
        empty_store(),
        [
            Genesis::coin(MAKER_COIN, MAKER, 30),
            Genesis::coin(TAKER_COIN, TAKER, 20),
        ],
    );
    let open = Open::from_terms(funding(MAKER_COIN, TAKER_COIN), BASIC_TERMS);
    let Some(open_fee) = RESOURCE_CONTEXT.fee(open.cost()) else {
        panic!("open fee overflow");
    };
    let Some(reserve) = RESOURCE_CONTEXT.fee(open.reserve_cost()) else {
        panic!("reserve fee overflow");
    };
    let _event = apply_with(&mut state, RESOURCE_CONTEXT, &Op::Open(open));
    let event = apply_with(
        &mut state,
        RESOURCE_CONTEXT,
        &Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 12), Payout::new(TAKER, 12)),
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 12)),
    );
    assert_eq!(
        state.store().coin(taker_out()).map(coin_view),
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
            &Op::Resolve(Resolve::new(
                edge(),
                proof(),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            )),
        ),
        Err(ApplyError::InvalidResolve { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_rejects_when_current_fee_exceeds_reserve_without_mutation() {
    let cheap = Context::with_fees(
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        Fees::new(0, 0, 0, 1),
    );
    let expensive = Context::with_fees(
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        Fees::new(0, 0, 0, 3),
    );
    let mut state = state(
        empty_store(),
        [
            Genesis::coin(MAKER_COIN, MAKER, 20),
            Genesis::coin(TAKER_COIN, TAKER, 10),
        ],
    );
    let open = open_op();
    let _event = apply_with(&mut state, cheap, &Op::Open(open));
    let store = *state.store();
    let resolve = Resolve::new(
        edge(),
        proof(),
        payouts(Payout::new(MAKER, 14), Payout::new(TAKER, 14)),
    );

    assert_eq!(cheap.fee(open.reserve_cost()), Some(2));
    assert_eq!(
        state.store().edge(edge()).map(edge_view),
        Some((28, 2, PARTIES, terms())),
    );
    assert_eq!(expensive.fee(resolve.cost()), Some(3));
    assert_eq!(
        state.apply(expensive, &Op::Resolve(resolve)),
        Err(ApplyError::InvalidResolve { input: edge() }),
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
        &Op::Resolve(Resolve::new(
            edge(),
            agreement_proof(edge(), &outputs),
            outputs,
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
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
    let bad_hash = Resolve::payload_hash(edge(), ResolveKind::Agreement, other_terms(), &outputs);
    let proof = Proof::agreement(
        terms(),
        Agreement::new(
            Sig::placeholder(MAKER, bad_hash),
            taker_sig(edge(), &outputs),
        ),
    );

    assert_eq!(
        state.apply(CONTEXT, &Op::Resolve(Resolve::new(edge(), proof, outputs))),
        Err(ApplyError::InvalidProof { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_accepts_timeout_witness_at_deadline() {
    let mut state = open_state();
    let event = apply_with(
        &mut state,
        TIMEOUT_CONTEXT,
        &Op::Resolve(Resolve::new(
            edge(),
            Proof::timeout(BASIC_TERMS),
            payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
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
            CONTEXT,
            &Op::Resolve(Resolve::new(
                edge(),
                Proof::timeout(BASIC_TERMS),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            )),
        ),
        Err(ApplyError::InvalidProof { input: edge() }),
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
            &Op::Resolve(Resolve::new(
                edge(),
                Proof::timeout(OTHER_TERMS_VALUE),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8)),
            )),
        ),
        Err(ApplyError::InvalidProof { input: edge() }),
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
        &Op::Resolve(Resolve::new(
            edge(),
            claimant_proof(edge(), &outputs),
            outputs,
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
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
        &Op::Resolve(Resolve::new(
            edge(),
            challenger_proof(edge(), &outputs),
            outputs,
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
}

#[test]
#[cfg(not(feature = "fake-crypto"))]
fn placeholder_witnesses_do_not_verify_without_fake_crypto() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));

    assert_eq!(
        state.apply(
            CONTEXT,
            &Op::Resolve(Resolve::new(
                edge(),
                agreement_proof(edge(), &outputs),
                outputs,
            )),
        ),
        Err(ApplyError::InvalidProof { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_rejects_bad_dispute_seal_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let proof = Proof::claimant_wins(
        BASIC_TERMS,
        seal(ResolveKind::ChallengerWins, edge(), &outputs),
    );

    assert_eq!(
        state.apply(CONTEXT, &Op::Resolve(Resolve::new(edge(), proof, outputs))),
        Err(ApplyError::InvalidProof { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_rejects_wrong_dispute_terms_without_mutation() {
    let mut state = open_state();
    let store = *state.store();
    let outputs = payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8));
    let proof = Proof::claimant_wins(
        OTHER_TERMS_VALUE,
        other_seal(ResolveKind::ClaimantWins, edge(), &outputs),
    );

    assert_eq!(
        state.apply(CONTEXT, &Op::Resolve(Resolve::new(edge(), proof, outputs))),
        Err(ApplyError::InvalidProof { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_spends_edge_into_three_payout_coins() {
    let mut state = open_state();
    let event = apply(
        &mut state,
        &Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts3(
                Payout::new(MAKER, 6),
                Payout::new(TAKER, 5),
                Payout::new(MAKER, 4),
            ),
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids3(maker_out(), taker_out(), extra_out()),
        },
    );
    assert_eq!(state.store().edge(edge()), None);
    assert_eq!(
        state.store().coin(extra_out()).map(coin_view),
        Some((MAKER, 4))
    );
}

#[test]
fn resolve_allows_zero_value_payout_coin() {
    let mut state = open_state();
    let event = apply(
        &mut state,
        &Op::Resolve(Resolve::new(
            edge(),
            proof(),
            payouts(Payout::new(MAKER, 0), Payout::new(TAKER, 15)),
        )),
    );

    assert_eq!(
        event.kind(),
        EventKind::EdgeResolved {
            input: edge(),
            outputs: output_ids2(maker_out(), taker_out()),
        },
    );
    assert_eq!(
        state.store().coin(maker_out()).map(coin_view),
        Some((MAKER, 0)),
    );
    assert_eq!(
        state.store().coin(taker_out()).map(coin_view),
        Some((TAKER, 15)),
    );
}

#[test]
fn resolve_rejects_non_conserving_payouts_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &Op::Resolve(Resolve::new(
                edge(),
                proof(),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 9),),
            )),
        ),
        Err(ApplyError::InvalidResolve { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn resolve_rejects_wrong_proof_without_mutation() {
    let mut state = open_state();
    let store = *state.store();

    assert_eq!(
        state.apply(
            CONTEXT,
            &Op::Resolve(Resolve::new(
                edge(),
                other_proof(),
                payouts(Payout::new(MAKER, 7), Payout::new(TAKER, 8),),
            )),
        ),
        Err(ApplyError::InvalidProof { input: edge() }),
    );
    assert_eq!(*state.store(), store);
}
