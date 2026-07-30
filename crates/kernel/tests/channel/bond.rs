//! Stake-bond lifecycle: open validation, the committed close-kind set,
//! and structural slash-payout routing.
//!
//! The bond is maker-funded (provider posts the stake); the taker
//! (client) contributes nothing but must still co-sign the open. A
//! proven violation pays exactly `[(taker, award + surplus),
//! (treasury, stake − award)]`; a `Mutual` close is forbidden by the
//! committed close-kind set even when both signatures verify.

use super::*;
use hellas_kernel::StakeBondTerms;

const TREASURY: Key = Key::from_bytes([9; Key::LENGTH]);
const STAKE: u64 = 10;
const AWARD: u64 = 7;

fn bond_terms_shaped(award: u64, stake: u64, price: u64, dispute: u64) -> Terms {
    Terms::stake_bond(StakeBondTerms {
        protocol: PROTOCOL,
        parties: PARTIES,
        timeout: TIMEOUT,
        timeout_outputs: payouts1(Payout::new(MAKER, STAKE)),
        treasury: TREASURY,
        award,
        stake,
        max_job_price: price,
        max_dispute_cost: dispute,
        challenge_margin: 1,
    })
}

fn bond_terms() -> Terms {
    bond_terms_shaped(AWARD, STAKE, 4, 3)
}

fn bond_funding() -> Funding {
    Funding::new(list(&[MAKER_COIN]), empty_party())
}

fn bond_open() -> Tx {
    open_tx(bond_funding(), bond_terms())
}

fn bond_edge() -> EdgeId {
    Tx::edge_id_of(&bond_funding(), &bond_terms())
}

fn payouts1(only: Payout) -> List<Payout, MAX_EDGE_OUTPUTS> {
    list(&[only])
}

fn slash_outputs() -> List<Payout, MAX_EDGE_OUTPUTS> {
    payouts(
        Payout::new(TAKER, AWARD),
        Payout::new(TREASURY, STAKE - AWARD),
    )
}

fn bond_violation(outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Proof {
    Proof::violation(
        bond_terms(),
        placeholder_seal(bond_edge(), &bond_terms(), outputs),
    )
}

fn open_bond_state(outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> State<FixedStore<6, 1>> {
    let open = bond_open();
    let mut state = state(store_for_close(&open, outputs), [MAKER_SEED, TAKER_SEED]);
    let _event = apply(&mut state, &open);
    state
}

#[test]
fn bond_open_locks_the_stake_under_a_taker_cosigned_open() {
    let outputs = slash_outputs();
    let state = open_bond_state(&outputs);
    let Some(edge) = state.store().edge(bond_edge()) else {
        panic!("bond edge live");
    };
    assert_eq!(edge.value(), STAKE);
    assert!(!edge.allows(CloseKind::Mutual));
    assert!(edge.allows(CloseKind::Timeout));
    assert!(edge.allows(CloseKind::Violation));
    assert_eq!(state.store().coin(MAKER_COIN), None);
    assert_eq!(
        state.store().coin(TAKER_COIN).map(coin_view),
        Some((TAKER, 5)),
    );
}

#[test]
fn mutual_close_of_a_bond_is_forbidden_even_with_both_valid_signatures() {
    let outputs = payouts(Payout::new(MAKER, 5), Payout::new(TAKER, 5));
    let mut state = open_bond_state(&outputs);
    let store = *state.store();
    let proof = placeholder_mutual(bond_edge(), bond_terms().hash(), &outputs, MAKER, TAKER);

    assert_eq!(
        state.apply(
            CONTEXT,
            &FAKE_VERIFIER,
            &Tx::close(bond_edge(), proof, outputs),
        ),
        Err(ApplyError::InvalidClose {
            input: bond_edge(),
            reason: InvalidCloseReason::KindForbidden,
        }),
    );
    assert_eq!(*state.store(), store);
}

#[test]
fn bond_violation_slashes_into_committed_beneficiary_and_treasury() {
    let outputs = slash_outputs();
    let mut state = open_bond_state(&outputs);
    let ids = Tx::close_output_ids(bond_edge(), &outputs);
    let event = apply(
        &mut state,
        &Tx::close(bond_edge(), bond_violation(&outputs), outputs.clone()),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: bond_edge(),
            outputs: ids.clone(),
        },
    );
    assert_eq!(state.store().edge(bond_edge()), None);
    assert_eq!(
        state.store().coin(nth(&ids, 0)).map(coin_view),
        Some((TAKER, AWARD)),
    );
    assert_eq!(
        state.store().coin(nth(&ids, 1)).map(coin_view),
        Some((TREASURY, STAKE - AWARD)),
    );
}

#[test]
fn bond_violation_rejects_rerouted_payouts_without_mutation() {
    // The provider awarding itself, a shorted treasury, and a collapsed
    // single payout are all structural rejections — the seal is never
    // even consulted for routing.
    let wrong_shapes = [
        payouts(
            Payout::new(MAKER, AWARD),
            Payout::new(TREASURY, STAKE - AWARD),
        ),
        payouts(
            Payout::new(TAKER, AWARD + 1),
            Payout::new(TREASURY, STAKE - AWARD - 1),
        ),
        payouts1(Payout::new(TAKER, STAKE)),
    ];
    for outputs in wrong_shapes {
        let mut state = open_bond_state(&outputs);
        let store = *state.store();
        assert_eq!(
            state.apply(
                CONTEXT,
                &FAKE_VERIFIER,
                &Tx::close(bond_edge(), bond_violation(&outputs), outputs.clone()),
            ),
            Err(ApplyError::InvalidProof {
                input: bond_edge(),
                reason: InvalidProofReason::PayoutMismatch,
            }),
        );
        assert_eq!(*state.store(), store);
    }
}

#[test]
fn bond_timeout_returns_the_stake_to_the_provider() {
    let outputs = payouts1(Payout::new(MAKER, STAKE));
    let mut state = open_bond_state(&outputs);
    let ids = Tx::close_output_ids(bond_edge(), &outputs);
    let event = apply_with(
        &mut state,
        TIMEOUT_CONTEXT,
        &Tx::close(bond_edge(), Proof::timeout(bond_terms()), outputs),
    );

    assert_eq!(
        event.kind(),
        &EventKind::EdgeClosed {
            input: bond_edge(),
            outputs: ids.clone(),
        },
    );
    assert_eq!(state.store().edge(bond_edge()), None);
    assert_eq!(
        state.store().coin(nth(&ids, 0)).map(coin_view),
        Some((MAKER, STAKE)),
    );
}

#[test]
fn bond_open_rejects_bad_slash_arithmetic_without_mutation() {
    let cases = [
        // Committed stake does not equal the locked value.
        (
            bond_terms_shaped(AWARD, STAKE - 1, 4, 3),
            InvalidOpenReason::StakeMismatch,
        ),
        // Zero award and award above stake are both out of range.
        (
            bond_terms_shaped(0, STAKE, 0, 0),
            InvalidOpenReason::AwardOutOfRange,
        ),
        (
            bond_terms_shaped(STAKE + 1, STAKE, 4, 3),
            InvalidOpenReason::AwardOutOfRange,
        ),
        // Award below max_job_price + max_dispute_cost cannot make the
        // client whole.
        (
            bond_terms_shaped(6, STAKE, 4, 3),
            InvalidOpenReason::AwardBelowFloor,
        ),
        // Floor arithmetic must not wrap.
        (
            bond_terms_shaped(AWARD, STAKE, u64::MAX, 1),
            InvalidOpenReason::AwardFloorOverflow,
        ),
        // A party-controlled treasury would collapse the penalty to A.
        (
            Terms::stake_bond(StakeBondTerms {
                protocol: PROTOCOL,
                parties: PARTIES,
                timeout: TIMEOUT,
                timeout_outputs: payouts1(Payout::new(MAKER, STAKE)),
                treasury: MAKER,
                award: AWARD,
                stake: STAKE,
                max_job_price: 4,
                max_dispute_cost: 3,
                challenge_margin: 1,
            }),
            InvalidOpenReason::TreasuryIsParty,
        ),
        // A zero job-price cap covers no job.
        (
            bond_terms_shaped(AWARD, STAKE, 0, 0),
            InvalidOpenReason::JobPriceCapZero,
        ),
        // A zero challenge margin leaves no block to challenge in.
        (
            Terms::stake_bond(StakeBondTerms {
                protocol: PROTOCOL,
                parties: PARTIES,
                timeout: TIMEOUT,
                timeout_outputs: payouts1(Payout::new(MAKER, STAKE)),
                treasury: TREASURY,
                award: AWARD,
                stake: STAKE,
                max_job_price: 4,
                max_dispute_cost: 3,
                challenge_margin: 0,
            }),
            InvalidOpenReason::ChallengeMarginZero,
        ),
    ];
    for (terms, reason) in cases {
        let funding = Funding::new(list(&[MAKER_COIN]), empty_party());
        let output = Tx::edge_id_of(&funding, &terms);
        let open = open_tx(funding, terms);
        let mut state = funded_state_for(&bond_open());
        let store = *state.store();
        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &open),
            Err(ApplyError::InvalidOpen { output, reason }),
        );
        assert_eq!(*state.store(), store);
    }
}
