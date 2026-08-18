//! Work-channel terms: the tag-4 bond whose only exit is `Timeout`, and
//! the payment edge whose exits are `Freeze` and `Adjudicated`.
//!
//! On the development filesystem this repo lives on, `cargo` has been
//! seen to reuse a stale prebuilt binary for this target and report
//! payment-close failures that the current source does not produce; if
//! these fail inexplicably, `touch` a source file to force a recompile
//! and confirm the run says "Compiling" before believing it.

use super::*;
use hellas_kernel::{
    BOND_LEASE_CHUNKS, BondLease, BondLeaseFault, PaymentContestCommitment, WebAuthnAssertion,
    WorkPaymentTerms, WorkStakeBondTerms, bond_lease_slot, bond_lease_slots,
};

/// A third key, party to nothing here.
const OUTSIDER: Key = Key::from_bytes([9; Key::LENGTH]);
const STAKE: u64 = 10;

/// The provider's stake coin, and the provider of a *payment* channel
/// is its taker: a bond funded from the maker's side would be the
/// client staking its own recourse.
const BOND_COIN: CoinId = coin_id(0x51);
const BOND_SEED: Genesis = Genesis::coin(BOND_COIN, TAKER, STAKE);

/// Provider = maker = `MAKER` (funds the stake), client = taker.
fn bond() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: PARTIES,
        timeout: TIMEOUT,
        timeout_outputs: list(&[Payout::new(MAKER, STAKE)]),
        max_job_price: 4,
    }
}

fn work_terms_of(bond: WorkStakeBondTerms) -> Terms {
    Terms::work_stake_bond(bond)
}

fn work_terms() -> Terms {
    work_terms_of(bond())
}

fn work_funding() -> Funding {
    Funding::new(list(&[MAKER_COIN]), empty_party())
}

fn work_open() -> Tx {
    open_tx(work_funding(), work_terms())
}

fn work_edge() -> EdgeId {
    Tx::edge_id_of(&work_funding(), &work_terms())
}

/// The bond a payment channel leases: the same policy as
/// [`work_terms`], with the roles mirrored so the provider — the
/// payment's taker — is the one who stakes.
/// A live tag-4 bond, opened into a store sized for its timeout close.
/// The move tests use it as "a live edge that is not a payment
/// channel".
fn open_work_bond_state() -> State<FixedStore<6, 1>> {
    let outputs = list(&[Payout::new(MAKER, STAKE)]);
    let open = work_open();
    let mut state = state(store_for_close(&open, &outputs), [MAKER_SEED, TAKER_SEED]);
    let _event = apply(&mut state, &open);
    state
}

fn payment_bond() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(TAKER, MAKER),
        timeout_outputs: list(&[Payout::new(TAKER, STAKE)]),
        ..bond()
    }
}

fn payment_bond_terms() -> Terms {
    Terms::work_stake_bond(payment_bond())
}

/// The stake is the provider's alone, so the bond is funded from the
/// provider's own coin and its taker list is empty.
fn payment_bond_funding() -> Funding {
    Funding::new(list(&[BOND_COIN]), empty_party())
}

fn payment_bond_edge() -> EdgeId {
    Tx::edge_id_of(&payment_bond_funding(), &payment_bond_terms())
}

/// Authorized by the mirrored pair: this bond's maker is the payment
/// channel's taker, so the provider signs the maker side of it.
fn payment_bond_open() -> Tx {
    open_tx_with(payment_bond_funding(), payment_bond_terms(), TAKER, MAKER)
}

/// The one payout an unleased or expired bond returns to its provider.
fn bond_timeout_outputs() -> List<Payout, MAX_EDGE_OUTPUTS> {
    list(&[Payout::new(TAKER, STAKE)])
}

fn bond_timeout_out() -> CoinId {
    nth(
        &Tx::close_output_ids(payment_bond_edge(), &bond_timeout_outputs()),
        0,
    )
}

fn bond_timeout_tx() -> Tx {
    Tx::close(
        payment_bond_edge(),
        Proof::timeout(payment_bond_terms()),
        bond_timeout_outputs(),
    )
}

/// Client-funded payment edge naming the provider's bond. Mirrored
/// roles: the payment maker is the bond's taker.
fn payment_of(mutate: impl FnOnce(&mut WorkPaymentTerms)) -> Terms {
    let mut payment = WorkPaymentTerms {
        bond_edge: payment_bond_edge(),
        bond_terms: payment_bond(),
        private_policy_commitment: [4; 32],
        omit_response_blocks: 64,
        start_validity_blocks: 8,
        omission_bond: 2,
    };
    mutate(&mut payment);
    Terms::work_payment(payment)
}

fn payment_terms() -> Terms {
    payment_of(|_| {})
}

fn payment_funding() -> Funding {
    Funding::new(list(&[MAKER_COIN]), empty_party())
}

#[test]
fn work_bond_open_locks_the_stake_under_its_own_close_kinds() {
    let open = work_open();
    let mut state = funded_state_for(&open);
    let _event = apply(&mut state, &open);

    let Some(edge) = state.store().edge(work_edge()) else {
        panic!("work bond edge live");
    };
    assert_eq!(edge.value(), STAKE);
    assert!(edge.allows(CloseKind::Timeout));
    assert!(!edge.allows(CloseKind::Mutual));
    assert!(!edge.allows(CloseKind::Freeze));
    assert!(!edge.allows(CloseKind::Adjudicated));
}

/// The whole of a tag-4 bond's own open policy, one mutation per
/// conjunct. Each case moves exactly one thing about an otherwise legal
/// bond, so no rule here can be satisfied by another.
#[test]
fn work_bond_open_checks_every_conjunct_of_its_policy() {
    let cases = [
        // A bond that can cover no job insures nothing.
        (
            work_terms_of(WorkStakeBondTerms {
                max_job_price: 0,
                ..bond()
            }),
            InvalidOpenReason::JobPriceCapZero,
        ),
        // Sum-preserving, party-changing: the stake would time out to
        // the client, who staked nothing.
        (
            work_terms_of(WorkStakeBondTerms {
                timeout_outputs: list(&[Payout::new(TAKER, STAKE)]),
                ..bond()
            }),
            InvalidOpenReason::WorkStakeReturnRouting,
        ),
    ];

    for (terms, reason) in cases {
        let funding = work_funding();
        let output = Tx::edge_id_of(&funding, &terms);
        let open = open_tx(funding, terms);
        let mut state = funded_state_for(&work_open());
        let store = *state.store();
        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &open),
            Err(ApplyError::InvalidOpen { output, reason }),
        );
        assert_eq!(*state.store(), store);
    }
}

/// The stake is the edge's own value, so an unfunded bond is refused as
/// a zero-value stake rather than accepted as a bond insuring nothing.
#[test]
fn work_bond_open_rejects_a_zero_value_stake() {
    let terms = work_terms_of(WorkStakeBondTerms {
        timeout_outputs: list(&[Payout::new(MAKER, 0)]),
        ..bond()
    });
    let funding = Funding::new(empty_party(), empty_party());
    let output = Tx::edge_id_of(&funding, &terms);
    let open = open_tx(funding, terms);
    let mut state = funded_state_for(&work_open());
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::WorkStakeValueZero,
        }),
    );
    assert_eq!(*state.store(), store);
}

/// The stake is the provider's alone: an unleased bond times out
/// permissionlessly, so a client contribution would be a gift to the
/// provider.
#[test]
fn work_bond_open_rejects_client_funding() {
    let terms = work_terms_of(WorkStakeBondTerms {
        timeout_outputs: list(&[Payout::new(MAKER, STAKE + 5)]),
        ..bond()
    });
    let funding = Funding::new(list(&[MAKER_COIN]), list(&[TAKER_COIN]));
    let output = Tx::edge_id_of(&funding, &terms);
    let open = open_tx(funding, terms);
    let mut state = funded_state_for(&work_open());
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::WorkStakeTakerFunded,
        }),
    );
    assert_eq!(*state.store(), store);
}

/// Work profiles run on the parties' own secp256k1 keys. An open a
/// passkey authorized would commit a channel neither party could move.
#[test]
fn work_opens_admit_native_authorization_only() {
    let assertion = WebAuthnAssertion::new([1; 32], [2; 32], [3; 32], [4; 32], list(&[5, 6, 7]));
    for terms in [work_terms(), payment_terms()] {
        let funding = work_funding();
        let output = Tx::edge_id_of(&funding, &terms);
        let hash = Tx::open_hash(support::NETWORK, &funding, &terms);
        let open = Tx::open(
            funding,
            terms,
            Auth::webauthn(assertion.clone()),
            Auth::native(Sig::placeholder(TAKER, hash)),
        );
        let mut state = funded_state_for(&work_open());
        let store = *state.store();

        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &open),
            Err(ApplyError::InvalidOpen {
                output,
                reason: InvalidOpenReason::WorkAuthNotNative,
            }),
        );
        assert_eq!(*state.store(), store);
    }
}

/// The payment edge has no timeout close and no payout fixed at open:
/// its horizon buys admission and rent, nothing else.
#[test]
fn work_payment_open_commits_freeze_and_adjudicated_only() {
    let terms = payment_terms();
    let funding = payment_funding();
    let edge_id = Tx::edge_id_of(&funding, &terms);
    let open = open_tx(funding, terms.clone());
    let mut state = bonded_state_for(edge_id);
    apply_payment_open(&mut state, &open);

    let Some(edge) = state.store().edge(edge_id) else {
        panic!("payment edge live");
    };
    assert_eq!(edge.value(), 10);
    assert!(edge.allows(CloseKind::Freeze));
    assert!(edge.allows(CloseKind::Adjudicated));
    assert!(!edge.allows(CloseKind::Timeout));
    assert!(!edge.allows(CloseKind::Mutual));
    assert_eq!(terms.timeout_outputs(), None);
    assert!(Tx::timeout_close(edge_id, &terms).is_none());
}

/// A payment is only as good as the bond it names. Its parties and its
/// horizon are *derived* from the embedded witness, so the cases here
/// are the bond's own policy plus this body's own windows.
#[test]
fn work_payment_open_rejects_a_bond_it_does_not_match() {
    let cases = [
        (
            payment_of(|payment| payment.bond_terms.max_job_price = 0),
            InvalidOpenReason::JobPriceCapZero,
        ),
        // A bond whose stake returns to a third key is not this
        // provider's stake.
        (
            payment_of(|payment| {
                payment.bond_terms.timeout_outputs = list(&[Payout::new(OUTSIDER, STAKE)]);
            }),
            InvalidOpenReason::WorkStakeReturnRouting,
        ),
        (
            payment_of(|payment| payment.omit_response_blocks = 0),
            InvalidOpenReason::WorkResponseWindowOutOfRange,
        ),
        (
            payment_of(|payment| {
                payment.omit_response_blocks = hellas_kernel::MAX_OMIT_RESPONSE_BLOCKS + 1;
            }),
            InvalidOpenReason::WorkResponseWindowOutOfRange,
        ),
        (
            payment_of(|payment| payment.start_validity_blocks = 0),
            InvalidOpenReason::WorkStartValidityOutOfRange,
        ),
        (
            payment_of(|payment| {
                payment.start_validity_blocks = hellas_kernel::MAX_START_VALIDITY_BLOCKS + 1;
            }),
            InvalidOpenReason::WorkStartValidityOutOfRange,
        ),
    ];

    for (terms, reason) in cases {
        let funding = payment_funding();
        let output = Tx::edge_id_of(&funding, &terms);
        let open = open_tx(funding, terms);
        let mut state = funded_state_for(&work_open());
        let store = *state.store();
        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &open),
            Err(ApplyError::InvalidOpen { output, reason }),
        );
        assert_eq!(*state.store(), store);
    }
}

// ── The payment close ─────────────────────────────────────────────────
//
// One scalar is contested and one scalar is paid. The fixtures below
// build the whole vertical: a funded payment edge worth `PAYMENT_VALUE`,
// certificates the client signs against it, the two moves, and the two
// closes. Every amount here is chosen so the arithmetic is checkable by
// eye — capacity 8, bond 2, and a payout pair that always sums to 10.

use hellas_kernel::{
    Batch as _, Decode, EarnedCertificate, Encode as _, InvalidMoveReason, Move, Party,
    PaymentCloseResponse, PaymentCloseStart, PendingCloseFault, PendingPaymentClose, PendingSlot,
    RegistryChunk, RegistryChunkId, RegistryNamespace, RegistryRecordTag, StartAuthorization,
    StartId, Store as _, freeze_digest, no_earned_digest, pending_payment_close_slot,
    response_digest, start_digest, start_id,
};

/// Value the payment edge locks: the client's whole funding coin, since
/// this fixture's fee schedule is zero.
const PAYMENT_VALUE: u64 = 10;
/// Omission bond `payment_of` commits.
const OMISSION_BOND: u64 = 2;
/// Largest certificate this channel may admit.
const PAYMENT_CAPACITY: u64 = PAYMENT_VALUE - OMISSION_BOND;
/// Response window `payment_of` commits.
const RESPONSE_WINDOW: u64 = 64;
/// Height every fixture opens and starts at.
const START_HEIGHT: u64 = 1;
/// Height the response window shuts at.
const RESPONSE_DEADLINE: u64 = START_HEIGHT + RESPONSE_WINDOW;
/// Validity span `payment_of` commits for a start.
const START_VALIDITY: (u64, u64) = (START_HEIGHT, START_HEIGHT);

const fn at(height: u64) -> Context {
    Context::new(
        support::NETWORK,
        BlockHeight::new(height),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
    )
}

fn payment_edge_id() -> EdgeId {
    Tx::edge_id_of(&payment_funding(), &payment_terms())
}

fn payment_terms_hash() -> TermsHash {
    payment_terms().hash()
}

fn pending_slot() -> RegistryChunkId {
    pending_payment_close_slot(support::NETWORK, payment_edge_id())
}

/// Provider first, client second — the fixed shape every work-payment
/// close pays into.
fn payment_payouts(provider: u64, client: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    payouts(Payout::new(TAKER, provider), Payout::new(MAKER, client))
}

fn payment_payout_ids() -> List<CoinId, MAX_EDGE_OUTPUTS> {
    Tx::close_output_ids(payment_edge_id(), &payment_payouts(0, 0))
}

fn lease_slots() -> [RegistryChunkId; BOND_LEASE_CHUNKS as usize] {
    bond_lease_slots(support::NETWORK, payment_bond_edge())
}

/// The whole vertical the payment tests run against: the client's
/// funding coin and the provider's stake coin, the payment edge and the
/// bond it leases, the three payout coins those two edges close into,
/// and the three registry slots — one contest, two lease chunks.
type PaymentStore = FixedStore<6, 2, 3>;

fn payment_store() -> PaymentStore {
    let ids = payment_payout_ids();
    let [first_lease, second_lease] = lease_slots();
    FixedStore::empty_with_registry(
        [
            MAKER_COIN,
            TAKER_COIN,
            BOND_COIN,
            nth(&ids, 0),
            nth(&ids, 1),
            bond_timeout_out(),
        ],
        [payment_edge_id(), payment_bond_edge()],
        [pending_slot(), first_lease, second_lease],
    )
}

/// Seeds the store and posts the bond, leaving the payment unopened.
///
/// The bond comes first because it has to: a payment open leases a live
/// bond, so a channel whose bond has not landed cannot be opened at all.
fn bonded_state() -> State<PaymentStore> {
    let mut state = state(payment_store(), [MAKER_SEED, TAKER_SEED, BOND_SEED]);
    let Ok(outcome) = state.apply(CONTEXT, &FAKE_VERIFIER, &payment_bond_open()) else {
        panic!("bond open rejected");
    };
    assert!(
        outcome.registry().is_empty(),
        "posting a bond takes no lease over it",
    );
    state
}

/// A posted bond and a store sized for one payment edge of the caller's
/// choosing.
///
/// The standard fixture declares [`payment_edge_id`]; a test that varies
/// the terms produces a different edge and needs its own slot for it.
fn bonded_state_for(payment_edge: EdgeId) -> State<FixedStore<2, 2, 2>> {
    let store = FixedStore::empty_with_registry(
        [MAKER_COIN, BOND_COIN],
        [payment_edge, payment_bond_edge()],
        lease_slots(),
    );
    let mut state = state(store, [MAKER_SEED, BOND_SEED]);
    let _event = apply(&mut state, &payment_bond_open());
    state
}

/// Applies a payment open, asserting the two halves of what one is: an
/// announced edge and the lease it takes over its bond.
fn apply_payment_open<const C: usize, const E: usize, const R: usize>(
    state: &mut State<FixedStore<C, E, R>>,
    open: &Tx,
) {
    let Ok(outcome) = state.apply(CONTEXT, &FAKE_VERIFIER, open) else {
        panic!("payment open rejected");
    };
    assert!(
        outcome.public_event().is_some(),
        "an open produces an edge, so it announces itself",
    );
    assert_eq!(
        outcome.registry().len(),
        usize::from(BOND_LEASE_CHUNKS),
        "a payment open leases its bond",
    );
}

fn open_payment_state() -> State<PaymentStore> {
    let open = open_tx(payment_funding(), payment_terms());
    let mut state = bonded_state();
    let Ok(outcome) = state.apply(CONTEXT, &FAKE_VERIFIER, &open) else {
        panic!("payment open rejected");
    };
    assert_eq!(
        outcome.registry().len(),
        usize::from(BOND_LEASE_CHUNKS),
        "an open writes no contest, and exactly the lease it takes",
    );
    state
}

fn certificate(amount: u64) -> EarnedCertificate {
    EarnedCertificate::new(payment_edge_id(), payment_terms_hash(), amount)
}

/// A certificate signed by the client, which is the only party whose
/// signature the kernel accepts on one.
fn signed_certificate(amount: u64) -> (EarnedCertificate, Sig) {
    signed_certificate_by(MAKER, certificate(amount))
}

fn signed_certificate_by(key: Key, certificate: EarnedCertificate) -> (EarnedCertificate, Sig) {
    let sig = Sig::placeholder(key, certificate.digest(support::NETWORK));
    (certificate, sig)
}

const fn key_of(role: Party) -> Key {
    match role {
        Party::Maker => MAKER,
        Party::Taker => TAKER,
    }
}

fn earned_digest_of(certificate: Option<&(EarnedCertificate, Sig)>) -> PayloadHash {
    certificate.map_or_else(
        || no_earned_digest(payment_edge_id(), payment_terms_hash()),
        |(certificate, _)| certificate.digest(support::NETWORK),
    )
}

fn start_body(
    role: Party,
    validity: (u64, u64),
    certificate: Option<(EarnedCertificate, Sig)>,
    signer: Key,
) -> PaymentCloseStart {
    let digest = start_digest(
        support::NETWORK,
        payment_edge_id(),
        payment_terms_hash(),
        role,
        validity,
        earned_digest_of(certificate.as_ref()),
    );
    PaymentCloseStart::new(
        payment_edge_id(),
        payment_terms(),
        role,
        validity,
        certificate,
        Sig::placeholder(signer, digest),
    )
}

fn start_tx(role: Party, amount: Option<u64>) -> Tx {
    Tx::move_action(Move::StartPaymentClose(start_body(
        role,
        START_VALIDITY,
        amount.map(signed_certificate),
        key_of(role),
    )))
}

fn response_body(
    start: StartId,
    role: Party,
    certificate: (EarnedCertificate, Sig),
    signer: Key,
) -> PaymentCloseResponse {
    let digest = response_digest(
        support::NETWORK,
        payment_edge_id(),
        payment_terms_hash(),
        start,
        role,
        certificate.0.digest(support::NETWORK),
    );
    PaymentCloseResponse::new(
        payment_edge_id(),
        start,
        role,
        certificate,
        Sig::placeholder(signer, digest),
    )
}

fn response_tx(start: StartId, amount: u64) -> Tx {
    Tx::move_action(Move::RespondPaymentClose(response_body(
        start,
        Party::Taker,
        signed_certificate(amount),
        TAKER,
    )))
}

fn adjudicated_tx(record: &PendingPaymentClose, provider: u64) -> Tx {
    let seal = record.contest_commitment(support::NETWORK, payment_edge_id(), payment_terms_hash());
    Tx::close(
        payment_edge_id(),
        Proof::adjudicated(seal),
        payment_payouts(provider, PAYMENT_VALUE - provider),
    )
}

fn freeze_tx(earned: u64, validity: (u64, u64), provider: u64) -> Tx {
    let digest = freeze_digest(
        support::NETWORK,
        payment_edge_id(),
        payment_terms_hash(),
        earned,
        validity,
    );
    Tx::close(
        payment_edge_id(),
        Proof::freeze(
            earned,
            validity,
            Sig::placeholder(MAKER, digest),
            Sig::placeholder(TAKER, digest),
        ),
        payment_payouts(provider, PAYMENT_VALUE - provider),
    )
}

fn pending_record<const C: usize, const E: usize, const R: usize>(
    state: &State<FixedStore<C, E, R>>,
) -> Option<PendingPaymentClose> {
    let chunk = state.store().registry_chunk(pending_slot())?;
    let Ok(record) = PendingPaymentClose::decode_exact(chunk.data()) else {
        panic!("a stored contest record decodes");
    };
    Some(record)
}

/// Applies a move and asserts it announces nothing publicly.
fn apply_move<const C: usize, const E: usize, const R: usize>(
    state: &mut State<FixedStore<C, E, R>>,
    context: Context,
    op: &Tx,
) {
    let Ok(outcome) = state.apply(context, &FAKE_VERIFIER, op) else {
        panic!("move rejected");
    };
    assert_eq!(
        outcome.public_event(),
        None,
        "a move settles nothing, so it announces nothing",
    );
    assert_eq!(
        outcome.registry().len(),
        1,
        "a payment-close move writes exactly the one contest slot",
    );
}

/// One side of a work-payment payout: its owner and its value.
type PayoutView = Option<(Key, u64)>;

/// Applies a work-payment close and returns the coins it produced.
fn apply_payment_close<const C: usize, const E: usize, const R: usize>(
    state: &mut State<FixedStore<C, E, R>>,
    context: Context,
    op: &Tx,
) -> (PayoutView, PayoutView) {
    let ids = payment_payout_ids();
    let Ok(outcome) = state.apply(context, &FAKE_VERIFIER, op) else {
        panic!("close rejected");
    };
    assert!(
        outcome.public_event().is_some(),
        "a close consumes an edge, so it announces itself",
    );
    (
        state.store().coin(nth(&ids, 0)).map(coin_view),
        state.store().coin(nth(&ids, 1)).map(coin_view),
    )
}

/// The complete unilateral close: the provider opens with the greatest
/// certificate it holds, the client says nothing, and after the window
/// the contested scalar is what gets paid.
#[test]
fn a_provider_start_settles_its_certificate_once_the_window_closes() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));

    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    assert_eq!(record.payment_edge(), payment_edge_id());
    assert_eq!(record.opener_role(), Party::Taker);
    assert_eq!(record.start_cumulative(), 5);
    assert_eq!(record.final_cumulative(), 5);
    assert!(!record.responded());
    assert!(!record.penalty_due());
    assert_eq!(record.penalty_amount(), OMISSION_BOND);
    assert_eq!(record.response_deadline(), RESPONSE_DEADLINE);

    let close = adjudicated_tx(&record, 5);
    let (provider, client) = apply_payment_close(&mut state, at(RESPONSE_DEADLINE), &close);

    assert_eq!(provider, Some((TAKER, 5)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 5)));
    assert_eq!(state.store().edge(payment_edge_id()), None);
    assert_eq!(
        pending_record(&state),
        None,
        "the close retires the contest it settled",
    );
}

/// The heart of the slice. A client opens low; the provider answers with
/// the client's own higher signature; the contradiction forfeits the
/// funded bond on top of the raised amount.
#[test]
fn a_proved_client_understatement_forfeits_the_omission_bond() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));

    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    apply_move(&mut state, at(2), &response_tx(opened.start_id(), 7));

    let Some(answered) = pending_record(&state) else {
        panic!("the response advanced the contest");
    };
    assert_eq!(answered.start_cumulative(), 3, "the opener's claim is kept");
    assert_eq!(answered.final_cumulative(), 7);
    assert!(answered.responded());
    assert!(
        answered.penalty_due(),
        "the client contradicted its own start",
    );

    // An advancing response ends the window immediately: there is no
    // legal second response, so nothing is gained by waiting.
    let (provider, client) = apply_payment_close(&mut state, at(3), &adjudicated_tx(&answered, 9));

    assert_eq!(provider, Some((TAKER, 7 + OMISSION_BOND)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 7 - OMISSION_BOND)));
}

/// A provider opener that is merely raised has proved nothing about the
/// client, so the same response shape forfeits nothing.
#[test]
fn a_response_to_a_provider_start_advances_payment_without_a_penalty() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(3)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    apply_move(&mut state, at(2), &response_tx(opened.start_id(), 7));
    let Some(answered) = pending_record(&state) else {
        panic!("the response advanced the contest");
    };
    assert!(!answered.penalty_due());

    let (provider, client) = apply_payment_close(&mut state, at(3), &adjudicated_tx(&answered, 7));
    assert_eq!(provider, Some((TAKER, 7)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 7)));
}

/// An opener with no certificate claims zero, which is the implicit
/// certificate rather than an absent one.
#[test]
fn a_start_with_no_certificate_claims_zero() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, None));

    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    assert_eq!(record.start_cumulative(), 0);
    assert_eq!(record.final_cumulative(), 0);

    let (provider, client) = apply_payment_close(
        &mut state,
        at(RESPONSE_DEADLINE),
        &adjudicated_tx(&record, 0),
    );
    assert_eq!(provider, Some((TAKER, 0)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE)));
}

/// The cooperative exit. With no contest live it is a one-transaction
/// close at the amount both parties sign.
#[test]
fn a_cooperative_freeze_pays_the_jointly_signed_amount() {
    let mut state = open_payment_state();
    let (provider, client) = apply_payment_close(&mut state, CONTEXT, &freeze_tx(6, (1, 1), 6));

    assert_eq!(provider, Some((TAKER, 6)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 6)));
    assert_eq!(state.store().edge(payment_edge_id()), None);
}

/// A freeze may end a contest, but it inherits both of the contest's
/// results: it cannot settle below what the contest reached, and it
/// cannot erase a penalty the contest proved.
#[test]
fn a_freeze_over_a_proved_understatement_still_forfeits_the_bond() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    apply_move(&mut state, at(2), &response_tx(opened.start_id(), 7));

    let too_low = freeze_tx(6, (3, 3), 6);
    let store = *state.store();
    assert_eq!(
        state.apply(at(3), &FAKE_VERIFIER, &too_low),
        Err(ApplyError::InvalidProof {
            input: payment_edge_id(),
            reason: InvalidProofReason::FreezeBelowSettled,
        }),
    );
    assert_eq!(*state.store(), store);

    let (provider, client) =
        apply_payment_close(&mut state, at(3), &freeze_tx(7, (3, 3), 7 + OMISSION_BOND));
    assert_eq!(provider, Some((TAKER, 7 + OMISSION_BOND)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 7 - OMISSION_BOND)));
    assert_eq!(pending_record(&state), None);
}

/// A client opener that co-signs a higher freeze has understated just as
/// visibly as one caught by a response, and forfeits the same bond.
#[test]
fn a_freeze_above_a_client_start_proves_the_understatement_itself() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));

    let (provider, client) =
        apply_payment_close(&mut state, at(2), &freeze_tx(5, (2, 2), 5 + OMISSION_BOND));
    assert_eq!(provider, Some((TAKER, 5 + OMISSION_BOND)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 5 - OMISSION_BOND)));
}

/// Freezing at exactly the client opener's own claim proves nothing
/// beyond it, so no bond moves.
#[test]
fn a_freeze_at_the_client_start_amount_forfeits_nothing() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));

    let (provider, client) = apply_payment_close(&mut state, at(2), &freeze_tx(3, (2, 2), 3));
    assert_eq!(provider, Some((TAKER, 3)));
    assert_eq!(client, Some((MAKER, PAYMENT_VALUE - 3)));
}

// ── Contest rules ─────────────────────────────────────────────────────

/// Every rejection below leaves the store exactly as it found it. A move
/// that mutated on its way to a rejection would be a move that could be
/// spammed for its side effect.
fn assert_start_rejected(
    state: &mut State<PaymentStore>,
    context: Context,
    op: &Tx,
    reason: InvalidMoveReason,
) {
    let store = *state.store();
    assert_eq!(
        state.apply(context, &FAKE_VERIFIER, op),
        Err(ApplyError::InvalidMove {
            input: payment_edge_id(),
            reason,
        }),
    );
    assert_eq!(*state.store(), store);
}

fn assert_close_rejected(
    state: &mut State<PaymentStore>,
    context: Context,
    op: &Tx,
    reason: InvalidProofReason,
) {
    let store = *state.store();
    assert_eq!(
        state.apply(context, &FAKE_VERIFIER, op),
        Err(ApplyError::InvalidProof {
            input: payment_edge_id(),
            reason,
        }),
    );
    assert_eq!(*state.store(), store);
}

/// A start binds to the edge's own terms and to a payment channel. The
/// bond case is the one that matters: it is a live work edge with a
/// matching terms hash whose profile still has no close contest.
#[test]
fn a_start_binds_to_the_payment_terms_of_a_payment_edge() {
    let mut state = open_payment_state();
    let mismatched = Tx::move_action(Move::StartPaymentClose(PaymentCloseStart::new(
        payment_edge_id(),
        basic_terms(),
        Party::Taker,
        START_VALIDITY,
        None,
        Sig::from_bytes([0; 64]),
    )));
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &mismatched,
        InvalidMoveReason::TermsMismatch,
    );

    let mut bond_state = open_work_bond_state();
    let on_a_bond = Tx::move_action(Move::StartPaymentClose(PaymentCloseStart::new(
        work_edge(),
        work_terms(),
        Party::Taker,
        START_VALIDITY,
        None,
        Sig::from_bytes([0; 64]),
    )));
    let store = *bond_state.store();
    assert_eq!(
        bond_state.apply(CONTEXT, &FAKE_VERIFIER, &on_a_bond),
        Err(ApplyError::InvalidMove {
            input: work_edge(),
            reason: InvalidMoveReason::NotAPaymentChannel,
        }),
    );
    assert_eq!(*bond_state.store(), store);
}

/// A start signature is spendable only inside the interval it names, and
/// that interval may be no wider than the terms allow.
#[test]
fn a_start_is_bounded_by_its_signed_validity_window() {
    let mut state = open_payment_state();

    let early = Tx::move_action(Move::StartPaymentClose(start_body(
        Party::Taker,
        (5, 6),
        None,
        TAKER,
    )));
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &early,
        InvalidMoveReason::OutsideValidityWindow,
    );

    let late = Tx::move_action(Move::StartPaymentClose(start_body(
        Party::Taker,
        (1, 1),
        None,
        TAKER,
    )));
    assert_start_rejected(
        &mut state,
        at(2),
        &late,
        InvalidMoveReason::OutsideValidityWindow,
    );

    // `start_validity_blocks` is 8, so a nine-block interval is one
    // block too wide even though the inclusion height is inside it.
    let too_wide = Tx::move_action(Move::StartPaymentClose(start_body(
        Party::Taker,
        (1, 9),
        None,
        TAKER,
    )));
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &too_wide,
        InvalidMoveReason::ValiditySpanTooWide,
    );

    // The widest interval the terms admit is accepted.
    let widest = Tx::move_action(Move::StartPaymentClose(start_body(
        Party::Taker,
        (1, 8),
        None,
        TAKER,
    )));
    apply_move(&mut state, CONTEXT, &widest);
}

/// One contest per edge, opened by whoever gets there first. A second
/// start by the opener would extend its own deadline; one by the other
/// role would replace the deadline the response is bound to.
#[test]
fn a_live_contest_refuses_a_second_start_from_either_role() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    for role in [Party::Taker, Party::Maker] {
        assert_start_rejected(
            &mut state,
            at(2),
            &Tx::move_action(Move::StartPaymentClose(start_body(
                role,
                (2, 2),
                Some(signed_certificate(6)),
                key_of(role),
            ))),
            InvalidMoveReason::ClosePending,
        );
    }
    assert_eq!(
        pending_record(&state),
        Some(opened),
        "a refused start extends no deadline and raises no amount",
    );
}

/// A certificate is evidence about one channel at one amount, and the
/// kernel checks all three of those claims before it checks a signature.
#[test]
fn a_start_certificate_must_bind_this_channel_and_fit_its_capacity() {
    let mut state = open_payment_state();

    let elsewhere = signed_certificate_by(
        MAKER,
        EarnedCertificate::new(
            EdgeId::from_bytes([0x77; EdgeId::LENGTH]),
            payment_terms_hash(),
            5,
        ),
    );
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &Tx::move_action(Move::StartPaymentClose(start_body(
            Party::Taker,
            START_VALIDITY,
            Some(elsewhere),
            TAKER,
        ))),
        InvalidMoveReason::CertificateNotBound,
    );

    let other_terms =
        signed_certificate_by(MAKER, EarnedCertificate::new(payment_edge_id(), terms(), 5));
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &Tx::move_action(Move::StartPaymentClose(start_body(
            Party::Taker,
            START_VALIDITY,
            Some(other_terms),
            TAKER,
        ))),
        InvalidMoveReason::CertificateNotBound,
    );

    // Zero has exactly one encoding, and it is the absent one.
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &start_tx(Party::Taker, Some(0)),
        InvalidMoveReason::CertificateNotPositive,
    );

    // Capacity is the value the cheaper close route distributes, less
    // the funded bond: 10 − 2.
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &start_tx(Party::Taker, Some(PAYMENT_CAPACITY + 1)),
        InvalidMoveReason::CertificateOverCapacity,
    );
    apply_move(
        &mut state,
        CONTEXT,
        &start_tx(Party::Taker, Some(PAYMENT_CAPACITY)),
    );
}

/// Only the client signs a certificate, and only the named opener signs
/// a start.
#[test]
fn a_start_needs_the_client_on_the_certificate_and_the_opener_on_the_action() {
    let mut state = open_payment_state();

    let provider_signed = signed_certificate_by(TAKER, certificate(5));
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &Tx::move_action(Move::StartPaymentClose(start_body(
            Party::Taker,
            START_VALIDITY,
            Some(provider_signed),
            TAKER,
        ))),
        InvalidMoveReason::BadCertificateSignature,
    );

    // The role selects the key: a start claiming to be the provider's
    // but carrying the client's signature is not the provider's.
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &Tx::move_action(Move::StartPaymentClose(start_body(
            Party::Taker,
            START_VALIDITY,
            None,
            MAKER,
        ))),
        InvalidMoveReason::BadSignature,
    );
}

/// The response is the certificate holder's one chance, bound to the
/// contest that won and shut at the deadline.
#[test]
fn the_response_is_one_bounded_answer_from_the_beneficiary() {
    let mut state = open_payment_state();

    // Nothing to answer yet.
    assert_start_rejected(
        &mut state,
        CONTEXT,
        &response_tx(StartId::from_bytes([0; 32]), 5),
        InvalidMoveReason::ClosePendingMissing,
    );

    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    assert_start_rejected(
        &mut state,
        at(2),
        &response_tx(StartId::from_bytes([9; 32]), 5),
        InvalidMoveReason::StartIdMismatch,
    );
    assert_start_rejected(
        &mut state,
        at(2),
        &Tx::move_action(Move::RespondPaymentClose(response_body(
            opened.start_id(),
            Party::Maker,
            signed_certificate(5),
            MAKER,
        ))),
        InvalidMoveReason::ResponderNotBeneficiary,
    );
    // Equal is not an advance: it would consume the one answer and
    // change nothing.
    assert_start_rejected(
        &mut state,
        at(2),
        &response_tx(opened.start_id(), 3),
        InvalidMoveReason::CertificateNotIncreasing,
    );
    assert_start_rejected(
        &mut state,
        at(2),
        &response_tx(opened.start_id(), PAYMENT_CAPACITY + 1),
        InvalidMoveReason::CertificateOverCapacity,
    );
    // Strictly below the deadline. At it, the adjudicated close is
    // already legal, so admitting both would make one height ambiguous.
    assert_start_rejected(
        &mut state,
        at(RESPONSE_DEADLINE),
        &response_tx(opened.start_id(), 5),
        InvalidMoveReason::ResponseWindowClosed,
    );

    // Both bounds are pinned by admitting the answer that sits exactly on
    // each of them: the last block of the window, and the largest
    // certificate the channel can fund. A response one block early or one
    // unit short would leave an off-by-one free to deny the provider the
    // very remedy the window exists to give it — and the height bound in
    // particular has to admit `deadline - 1`, because the adjudicated
    // close is refused there, and a height where neither move is legal
    // would be a gap in a contest that must always be resolvable.
    apply_move(
        &mut state,
        at(RESPONSE_DEADLINE - 1),
        &response_tx(opened.start_id(), PAYMENT_CAPACITY),
    );
    assert_start_rejected(
        &mut state,
        at(RESPONSE_DEADLINE - 1),
        &response_tx(opened.start_id(), PAYMENT_CAPACITY),
        InvalidMoveReason::AlreadyResponded,
    );
}

/// A response certificate is evidence about one channel, and it has to
/// be evidence about *this* one.
///
/// This is the check that has no signature standing behind it. A provider
/// holding a certificate the client signed for another channel between
/// the same two keys carries a digest the client really did sign, under
/// an answer the provider really did sign: both verifications pass, and
/// only the binding refuses it. The start path is guarded the same way
/// and for the same reason.
#[test]
fn a_response_certificate_must_bind_this_channel() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    let elsewhere = signed_certificate_by(
        MAKER,
        EarnedCertificate::new(
            EdgeId::from_bytes([0x77; EdgeId::LENGTH]),
            payment_terms_hash(),
            5,
        ),
    );
    assert_start_rejected(
        &mut state,
        at(2),
        &Tx::move_action(Move::RespondPaymentClose(response_body(
            opened.start_id(),
            Party::Taker,
            elsewhere,
            TAKER,
        ))),
        InvalidMoveReason::CertificateNotBound,
    );

    let other_terms =
        signed_certificate_by(MAKER, EarnedCertificate::new(payment_edge_id(), terms(), 5));
    assert_start_rejected(
        &mut state,
        at(2),
        &Tx::move_action(Move::RespondPaymentClose(response_body(
            opened.start_id(),
            Party::Taker,
            other_terms,
            TAKER,
        ))),
        InvalidMoveReason::CertificateNotBound,
    );
}

/// A response reveals no terms, so the close-kind set is the only thing
/// that identifies the profile. A work-stake bond is a live edge between
/// two roles that commits no adjudicated exit, and a response on it is
/// refused for that structural reason rather than for a missing contest.
#[test]
fn a_response_is_refused_on_an_edge_that_is_not_a_payment_channel() {
    let mut bond_state = open_work_bond_state();
    let on_a_bond = Tx::move_action(Move::RespondPaymentClose(PaymentCloseResponse::new(
        work_edge(),
        StartId::from_bytes([0; StartId::LENGTH]),
        Party::Taker,
        signed_certificate_by(
            MAKER,
            EarnedCertificate::new(work_edge(), work_terms().hash(), 1),
        ),
        Sig::from_bytes([0; 64]),
    )));
    let store = *bond_state.store();
    assert_eq!(
        bond_state.apply(CONTEXT, &FAKE_VERIFIER, &on_a_bond),
        Err(ApplyError::InvalidMove {
            input: work_edge(),
            reason: InvalidMoveReason::NotAPaymentChannel,
        }),
    );
    assert_eq!(*bond_state.store(), store);
}

/// A start and the response that answers it, in one block.
///
/// The contest slot has to be read through the staged batch, not through
/// committed state: §4.6 requires the charged lookup to observe earlier
/// same-block mutations, and the kernel gets that by folding each
/// operation into one shared transaction before the next is validated.
/// Every other test here applies its moves in separate committed
/// batches, which cannot tell that apart from a kernel that only ever
/// sees the previous block.
#[test]
fn a_response_answers_a_start_in_the_same_block() {
    let mut state = open_payment_state();
    let claimed = signed_certificate(3);
    // The identifier the start will be given, derived exactly as the
    // kernel derives it, since no committed state exists to read it from.
    let opened = start_id(
        start_digest(
            support::NETWORK,
            payment_edge_id(),
            payment_terms_hash(),
            Party::Maker,
            START_VALIDITY,
            earned_digest_of(Some(&claimed)),
        ),
        START_HEIGHT,
    );
    let ops = List::all([start_tx(Party::Maker, Some(3)), response_tx(opened, 5)]);

    let Ok(diff) = state.apply_all(CONTEXT, &FAKE_VERIFIER, &ops) else {
        panic!("a start and its answer share one block");
    };
    assert_eq!(diff.len(), 2);

    let Some(record) = pending_record(&state) else {
        panic!("the block left one contest");
    };
    assert_eq!(record.start_id(), opened, "the response found this start");
    assert!(record.responded(), "the second move saw the first");
    assert_eq!(record.start_cumulative(), 3);
    assert_eq!(record.final_cumulative(), 5);
    assert!(
        record.penalty_due(),
        "a client opener raised by its own later signature forfeits the bond",
    );
}

/// A response carries two signatures and needs both: the client's on the
/// certificate, the provider's on the answer.
#[test]
fn a_response_needs_both_of_its_signatures() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Maker, Some(3)));
    let Some(opened) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    let forged = signed_certificate_by(TAKER, certificate(5));
    let digest = response_digest(
        support::NETWORK,
        payment_edge_id(),
        payment_terms_hash(),
        opened.start_id(),
        Party::Taker,
        forged.0.digest(support::NETWORK),
    );
    assert_start_rejected(
        &mut state,
        at(2),
        &Tx::move_action(Move::RespondPaymentClose(PaymentCloseResponse::new(
            payment_edge_id(),
            opened.start_id(),
            Party::Taker,
            forged,
            Sig::placeholder(TAKER, digest),
        ))),
        InvalidMoveReason::BadCertificateSignature,
    );
    assert_start_rejected(
        &mut state,
        at(2),
        &Tx::move_action(Move::RespondPaymentClose(response_body(
            opened.start_id(),
            Party::Taker,
            signed_certificate(5),
            MAKER,
        ))),
        InvalidMoveReason::BadSignature,
    );
}

/// The adjudicated close is the contest's result and nothing else: no
/// contest, no close; window still open, no close; a seal naming another
/// state, no close.
#[test]
fn an_adjudicated_close_settles_only_a_finished_contest() {
    let mut state = open_payment_state();

    assert_close_rejected(
        &mut state,
        CONTEXT,
        &Tx::close(
            payment_edge_id(),
            Proof::adjudicated(PaymentContestCommitment::from_bytes([0; 32])),
            payment_payouts(0, PAYMENT_VALUE),
        ),
        InvalidProofReason::ClosePendingMissing,
    );

    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));
    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };

    // One block short of the deadline the provider can still speak, so
    // the contest is not over.
    assert_close_rejected(
        &mut state,
        at(RESPONSE_DEADLINE - 1),
        &adjudicated_tx(&record, 5),
        InvalidProofReason::ResponseWindowOpen,
    );
    assert_close_rejected(
        &mut state,
        at(RESPONSE_DEADLINE),
        &Tx::close(
            payment_edge_id(),
            Proof::adjudicated(PaymentContestCommitment::from_bytes([0xab; 32])),
            payment_payouts(5, PAYMENT_VALUE - 5),
        ),
        InvalidProofReason::ContestMismatch,
    );

    // At the deadline exactly, the window is shut and the close lands.
    let (provider, _client) = apply_payment_close(
        &mut state,
        at(RESPONSE_DEADLINE),
        &adjudicated_tx(&record, 5),
    );
    assert_eq!(provider, Some((TAKER, 5)));
}

/// The payout shape is derived, not chosen. Its owners, its order, its
/// fanout, and the amount the contest ended on are all pinned.
#[test]
fn an_adjudicated_close_pays_only_the_derived_split() {
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));
    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    let seal = record.contest_commitment(support::NETWORK, payment_edge_id(), payment_terms_hash());

    let wrong_shapes = [
        // Provider paid more than the contest reached, client less.
        payment_payouts(6, PAYMENT_VALUE - 6),
        // Right amounts, swapped owners.
        payouts(Payout::new(MAKER, 5), Payout::new(TAKER, PAYMENT_VALUE - 5)),
        // One output instead of two.
        list(&[Payout::new(TAKER, PAYMENT_VALUE)]),
    ];
    for outputs in wrong_shapes {
        assert_close_rejected(
            &mut state,
            at(RESPONSE_DEADLINE),
            &Tx::close(payment_edge_id(), Proof::adjudicated(seal), outputs),
            InvalidProofReason::PayoutMismatch,
        );
    }
}

/// A freeze is bounded by the interval it names, and consensus bounds
/// that interval itself: it reveals no terms to bound it with.
#[test]
fn a_freeze_is_bounded_by_its_signed_window_and_by_consensus() {
    let mut state = open_payment_state();

    assert_close_rejected(
        &mut state,
        CONTEXT,
        &freeze_tx(6, (5, 6), 6),
        InvalidProofReason::FreezeOutsideValidityWindow,
    );
    assert_close_rejected(
        &mut state,
        CONTEXT,
        &freeze_tx(6, (1, hellas_kernel::MAX_FREEZE_AUTH_BLOCKS + 1), 6),
        InvalidProofReason::FreezeOutsideValidityWindow,
    );
    // The widest interval consensus admits is accepted.
    let widest = (1, hellas_kernel::MAX_FREEZE_AUTH_BLOCKS);
    let (provider, _client) = apply_payment_close(&mut state, CONTEXT, &freeze_tx(6, widest, 6));
    assert_eq!(provider, Some((TAKER, 6)));
}

/// A freeze is cooperative, so it needs both parties. One signature is
/// one party's opinion.
#[test]
fn a_freeze_needs_both_parties() {
    let mut state = open_payment_state();
    let validity = (1, 1);
    let digest = freeze_digest(
        support::NETWORK,
        payment_edge_id(),
        payment_terms_hash(),
        6,
        validity,
    );
    for (maker, taker) in [
        (
            Sig::placeholder(MAKER, digest),
            Sig::placeholder(MAKER, digest),
        ),
        (
            Sig::placeholder(TAKER, digest),
            Sig::placeholder(TAKER, digest),
        ),
    ] {
        assert_close_rejected(
            &mut state,
            CONTEXT,
            &Tx::close(
                payment_edge_id(),
                Proof::freeze(6, validity, maker, taker),
                payment_payouts(6, PAYMENT_VALUE - 6),
            ),
            InvalidProofReason::BadSignature,
        );
    }
}

// ── Absence is a permission, so nothing may be mistaken for it ────────

/// Overwrites the pending slot with `chunk`, bypassing the transitions.
///
/// The only way to reach the corrupt-state branches: no move can write
/// one of these, which is exactly why a reader that treated them as
/// absence would never be caught by a test that only submits moves.
fn poison_pending(state: &mut State<PaymentStore>, chunk: RegistryChunk) {
    let mut store = *state.store();
    {
        let mut batch = store.begin();
        let _ = batch.remove_registry_chunk(pending_slot());
        let Ok(()) = batch.insert_registry_chunk(pending_slot(), chunk) else {
            panic!("the fixture declares the pending slot");
        };
        batch.commit();
    }
    *state = State::new(store);
}

/// How to break a live contest's stored bytes.
#[derive(Clone, Copy)]
enum Corruption {
    /// Flip one byte, keeping the record's width.
    Byte(usize),
    /// Make the value one byte longer, so it splits into two chunks.
    Longer,
    /// Make the value one byte shorter than a record.
    Shorter,
}

/// A live contest's bytes, broken as `corruption` says.
fn corrupted_record_bytes(
    state: &State<PaymentStore>,
    corruption: Corruption,
) -> List<u8, { hellas_kernel::REGISTRY_CHUNK_DATA_CAPACITY + 1 }> {
    let Some(chunk) = state.store().registry_chunk(pending_slot()) else {
        panic!("a contest is live");
    };
    let mut bytes = [0_u8; hellas_kernel::REGISTRY_CHUNK_DATA_CAPACITY + 1];
    bytes[..102].copy_from_slice(chunk.data());
    match corruption {
        Corruption::Byte(offset) => {
            bytes[offset] ^= 0xff;
            list(&bytes[..102])
        }
        // 121 bytes is one past a chunk's data capacity.
        Corruption::Longer => list(&bytes[..]),
        Corruption::Shorter => list(&bytes[..101]),
    }
}

/// Every way a present chunk can fail to be this edge's record is a
/// rejection, and never "no contest is live". Absence is what lets a
/// start open a contest and lets a freeze skip the pending rules, so a
/// reader that fell back to it would hand both permissions to whoever
/// corrupted the slot.
#[test]
fn a_present_but_unreadable_contest_is_never_read_as_absence() {
    // Offsets into the record body: the envelope is two bytes, then the
    // version byte, then the payment edge.
    const VERSION_OFFSET: usize = 2;
    const EDGE_OFFSET: usize = 3;

    // One case per conjunct of the reader's shape rule, plus the body
    // and edge rules. A case list that only covered the record tag would
    // leave the count, index, length, and namespace clauses free to be
    // deleted without a test noticing.
    let faults = [
        // Another namespace's value parked in this slot.
        (
            RegistryNamespace::BondLease,
            RegistryRecordTag::PaymentPending,
            Corruption::Byte(EDGE_OFFSET),
            PendingCloseFault::Shape,
        ),
        // Wrong record kind under the right namespace.
        (
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::BondLease,
            Corruption::Byte(EDGE_OFFSET),
            PendingCloseFault::Shape,
        ),
        // The first chunk of a longer value: right kind, wrong count.
        (
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::PaymentPending,
            Corruption::Longer,
            PendingCloseFault::Shape,
        ),
        // A shorter value of the right kind: the record has one width.
        (
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::PaymentPending,
            Corruption::Shorter,
            PendingCloseFault::Shape,
        ),
        // Right kind and width, bytes that are not a canonical record.
        (
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::PaymentPending,
            Corruption::Byte(VERSION_OFFSET),
            PendingCloseFault::Body,
        ),
        // A whole canonical record — for a different edge.
        (
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::PaymentPending,
            Corruption::Byte(EDGE_OFFSET),
            PendingCloseFault::Edge,
        ),
    ];

    for (namespace, record_tag, corruption, fault) in faults {
        let mut state = open_payment_state();
        apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));
        let bytes = corrupted_record_bytes(&state, corruption);
        let Some(chunk) = RegistryChunk::split(namespace, record_tag, bytes.as_slice(), 0) else {
            panic!("the corrupted value splits into a first chunk");
        };
        poison_pending(&mut state, chunk);

        // A start must not read the corruption as a free contest slot.
        assert_start_rejected(
            &mut state,
            at(2),
            &Tx::move_action(Move::StartPaymentClose(start_body(
                Party::Taker,
                (2, 2),
                None,
                TAKER,
            ))),
            InvalidMoveReason::ClosePendingFault { fault },
        );
        // A freeze must not read it as "no contest", which would let it
        // settle below a contest and skip a proved penalty.
        assert_close_rejected(
            &mut state,
            at(2),
            &freeze_tx(6, (2, 2), 6),
            InvalidProofReason::ClosePendingFault { fault },
        );
        // An adjudicated close must not read it as a missing contest
        // either — same rejection, different reason from absence.
        assert_close_rejected(
            &mut state,
            at(RESPONSE_DEADLINE),
            &Tx::close(
                payment_edge_id(),
                Proof::adjudicated(PaymentContestCommitment::from_bytes([0; 32])),
                payment_payouts(5, PAYMENT_VALUE - 5),
            ),
            InvalidProofReason::ClosePendingFault { fault },
        );
    }
}

// ── The write-ahead cutoff ────────────────────────────────────────────

/// Signing a start closes the signer's certificate gate. Left there, a
/// crash between signing and broadcasting would shut that gate for good
/// and kill the channel's payment issuance; the rule below is the
/// correction, and it reopens on three proved facts and nothing less.
#[test]
fn an_unincluded_start_retires_only_on_all_three_facts() {
    let authorization = StartAuthorization::new(payment_edge_id(), 20);
    assert_eq!(authorization.valid_through_height(), 20);
    assert_eq!(authorization.payment_edge(), payment_edge_id());

    // All three: past the last includable height, edge still live, slot
    // exactly empty.
    assert!(authorization.may_reopen_gate(21, true, PendingSlot::Absent));

    // The signature is still includable at its last height, and a
    // finalized view *at* that height proves nothing about it. Strictly
    // greater or nothing.
    assert!(!authorization.may_reopen_gate(20, true, PendingSlot::Absent));
    assert!(!authorization.may_reopen_gate(19, true, PendingSlot::Absent));

    // The edge is gone: some close consumed it, so reopening a gate on
    // it would be reopening a gate on a channel that no longer exists.
    assert!(!authorization.may_reopen_gate(21, false, PendingSlot::Absent));

    // A contest is live: the start landed after all.
    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));
    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    assert!(!authorization.may_reopen_gate(21, true, PendingSlot::Present(record)));

    // A present malformed chunk is not absence here either. This is the
    // endpoint-side half of the same rule the transitions enforce.
    for fault in [
        PendingCloseFault::Shape,
        PendingCloseFault::Body,
        PendingCloseFault::Edge,
    ] {
        assert!(!authorization.may_reopen_gate(21, true, PendingSlot::Faulty(fault)));
    }
}

// ── Prices and windows ────────────────────────────────────────────────

/// The exact cost vectors the design assigns. Slots count every physical
/// store slot a transition touches, including the contest slot a start
/// reads before it writes and a close reads whether or not it is there.
#[test]
fn payment_close_costs_are_the_assigned_vectors() {
    assert_eq!(start_tx(Party::Taker, None).cost(), Cost::new(1, 2, 1));
    assert_eq!(start_tx(Party::Taker, Some(5)).cost(), Cost::new(1, 2, 2));
    assert_eq!(
        response_tx(StartId::from_bytes([0; 32]), 5).cost(),
        Cost::new(1, 2, 2),
    );
    assert_eq!(freeze_tx(6, (1, 1), 6).cost(), Cost::new(1, 4, 2));
    assert_eq!(
        Tx::close(
            payment_edge_id(),
            Proof::adjudicated(PaymentContestCommitment::from_bytes([0; 32])),
            payment_payouts(0, PAYMENT_VALUE),
        )
        .cost(),
        Cost::new(1, 4, 1),
    );
}

/// Fees make the slot count visible in the money, and the tag-4 timeout
/// touches two slots no other timeout does.
///
/// Under the zero schedule every count is free and the whole of this
/// arithmetic collapses to one number, so a timeout priced by the wrong
/// profile would be invisible everywhere else in this file. Here the
/// open commits the payout its own timeout's price leaves, and the
/// timeout then pays exactly that: if the two ever read the price from
/// different places, one of these two operations is refused.
#[test]
fn a_work_bond_prices_its_lease_reading_timeout_under_nonzero_fees() {
    /// The provider's coin: open fee 7, lifetime fee 3, reserve 22.
    const FUNDED: u64 = 40;
    /// What the edge locks once those three are taken.
    const STAKED: u64 = 8;
    /// `STAKED` plus the reserve left after a 13-unit timeout close.
    const RETURNED: u64 = 17;

    const FEE_COIN: CoinId = coin_id(0x53);
    let seed = Genesis::coin(FEE_COIN, TAKER, FUNDED);
    let outputs = list(&[Payout::new(TAKER, RETURNED)]);
    let terms = Terms::work_stake_bond(WorkStakeBondTerms {
        parties: Parties::new(TAKER, MAKER),
        timeout_outputs: outputs.clone(),
        ..bond()
    });
    let funding = Funding::new(list(&[FEE_COIN]), empty_party());
    let edge = Tx::edge_id_of(&funding, &terms);
    let open = open_tx_with(funding, terms.clone(), TAKER, MAKER);

    let store = FixedStore::empty_with_registry(
        [FEE_COIN, nth(&Tx::close_output_ids(edge, &outputs), 0)],
        [edge],
        bond_lease_slots(support::NETWORK, edge),
    );
    let mut state = state(store, [seed]);
    let _event = apply_with(&mut state, RESOURCE_CONTEXT, &open);
    let Some(live) = state.store().edge(edge) else {
        panic!("bond edge live");
    };
    assert_eq!(live.value(), STAKED);
    assert_eq!(live.reserve(), 22);

    // Unleased, so it closes at once — and for exactly the committed
    // payout, which the open accepted only because both sides priced
    // the close the same way.
    let _event = apply_with(
        &mut state,
        RESOURCE_CONTEXT,
        &Tx::close(edge, Proof::timeout(terms), outputs),
    );
    assert_eq!(
        state
            .store()
            .coin(nth(
                &Tx::close_output_ids(edge, &list(&[Payout::new(TAKER, RETURNED)])),
                0
            ))
            .map(coin_view),
        Some((TAKER, RETURNED)),
    );
}

/// The exact cost vectors the design assigns to the work profiles'
/// opens and to a tag-4 timeout.
///
/// Slots count every physical store slot a transition touches: a
/// payment open reaches for its funding coin, the edge it creates, the
/// bond it verifies, and both chunks of the lease it writes, and a
/// tag-4 timeout reads both lease chunks before it can know which
/// height rule governs it. The generic Basic vectors are pinned beside
/// them because the work profiles must not reprice them.
#[test]
fn work_open_and_bond_timeout_costs_are_the_assigned_vectors() {
    assert_eq!(
        open_tx(payment_funding(), payment_terms()).cost(),
        Cost::new(1, 5, 2),
    );
    assert_eq!(payment_bond_open().cost(), Cost::new(1, 2, 2));
    assert_eq!(bond_timeout_tx().cost(), Cost::new(1, 4, 1));

    // Generic, unchanged: one funding coin and one edge at open, one
    // edge and one payout at timeout, and no charged proof units on the
    // open's two signatures.
    let generic = basic_terms();
    let funding = Funding::new(list(&[MAKER_COIN]), empty_party());
    let edge = Tx::edge_id_of(&funding, &generic);
    assert_eq!(open_tx(funding, generic.clone()).cost(), Cost::new(1, 2, 0));
    assert_eq!(
        Tx::close(
            edge,
            Proof::timeout(generic),
            list(&[Payout::new(MAKER, STAKE)]),
        )
        .cost(),
        Cost::new(1, 2, 1),
    );
}

/// The response window has a derived floor, not a chosen one: below it
/// the provider has no measured opportunity to observe the start and get
/// an answer included, so the omission theorem the channel is priced on
/// does not hold and consensus refuses the open.
#[test]
fn a_payment_open_refuses_a_window_below_the_derived_floor() {
    let floor = hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS;
    let too_short = payment_of(|payment| payment.omit_response_blocks = floor - 1);
    let funding = payment_funding();
    let output = Tx::edge_id_of(&funding, &too_short);
    let mut state = funded_state_for(&work_open());
    let store = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open_tx(funding, too_short)),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::WorkResponseWindowOutOfRange,
        }),
    );
    assert_eq!(*state.store(), store);

    // Exactly at the floor is admitted, so the bound is the floor and
    // not something above it.
    let exact = payment_of(|payment| payment.omit_response_blocks = floor);
    let funding = payment_funding();
    let edge = Tx::edge_id_of(&funding, &exact);
    let open = open_tx(funding, exact);
    let mut state = bonded_state_for(edge);
    apply_payment_open(&mut state, &open);
}

/// A channel whose omission bond swallows everything a close
/// distributes can admit no certificate at all, so it is refused at
/// open rather than opened as a channel in name only.
#[test]
fn a_payment_open_refuses_an_unfunded_capacity() {
    // The edge locks 10, so a bond of 10 leaves capacity zero and a
    // bond of 11 leaves none at all.
    for bond in [PAYMENT_VALUE, PAYMENT_VALUE + 1] {
        let terms = payment_of(|payment| payment.omission_bond = bond);
        let funding = payment_funding();
        let output = Tx::edge_id_of(&funding, &terms);
        let mut state = funded_state_for(&work_open());
        let store = *state.store();

        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &open_tx(funding, terms)),
            Err(ApplyError::InvalidOpen {
                output,
                reason: InvalidOpenReason::WorkPaymentCapacityUnfunded,
            }),
        );
        assert_eq!(*state.store(), store);
    }
}

/// Neither work-payment exit expires at the admission horizon. That
/// horizon buys admission and rent; a channel that stopped being
/// settleable once it stopped admitting jobs would strand every amount
/// already earned against it.
#[test]
fn the_payment_exits_stay_open_past_the_admission_horizon() {
    // `TIMEOUT` is the committed horizon, and every height below is
    // well past it.
    let horizon = TIMEOUT.get();

    let mut state = open_payment_state();
    apply_move(&mut state, CONTEXT, &start_tx(Party::Taker, Some(5)));
    let Some(record) = pending_record(&state) else {
        panic!("the start wrote a contest");
    };
    assert!(RESPONSE_DEADLINE > horizon);
    let (provider, _client) = apply_payment_close(
        &mut state,
        at(RESPONSE_DEADLINE),
        &adjudicated_tx(&record, 5),
    );
    assert_eq!(provider, Some((TAKER, 5)));

    let mut state = open_payment_state();
    let past = horizon + 40;
    let (provider, _client) =
        apply_payment_close(&mut state, at(past), &freeze_tx(6, (past, past), 6));
    assert_eq!(provider, Some((TAKER, 6)));
}

/// A start within one committed window of the height ceiling would wrap
/// its own deadline into the past. The work profile is disabled there
/// rather than opening a contest that is already over.
#[test]
fn a_start_too_close_to_the_height_ceiling_is_refused() {
    let mut state = open_payment_state();
    let height = u64::MAX - RESPONSE_WINDOW + 1;
    let start = Tx::move_action(Move::StartPaymentClose(start_body(
        Party::Taker,
        (height, height),
        None,
        TAKER,
    )));

    assert_start_rejected(
        &mut state,
        at(height),
        &start,
        InvalidMoveReason::DeadlineOverflow,
    );
}

/// A move on an edge that is not there is a missing edge, not an
/// invalid move: the distinction is what lets a host retain a
/// transaction whose edge has not been synced yet.
#[test]
fn a_move_on_an_absent_edge_reports_the_missing_edge() {
    let mut state = state(payment_store(), [MAKER_SEED, TAKER_SEED]);
    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &start_tx(Party::Taker, Some(5))),
        Err(ApplyError::MissingEdge {
            id: payment_edge_id(),
        }),
    );
}

// ── The bond lease ────────────────────────────────────────────────────
//
// A payment channel is only worth what its bond can be slashed for, and
// nothing in a signed payment open proves that bond exists. These tests
// are the attack the design names: `C` signs a bond open and a payment
// open for the same block, and `P` submits the payment alone — or
// submits it against a bond it has already committed elsewhere.

/// A second client-funded channel over the *same* bond. Its policy
/// commitment differs, so it is a different edge with different terms
/// and its own funding coin — everything about it is fresh except the
/// bond it tries to lease.
const SECOND_CLIENT_COIN: CoinId = coin_id(0x52);
const SECOND_CLIENT_SEED: Genesis = Genesis::coin(SECOND_CLIENT_COIN, MAKER, PAYMENT_VALUE);

fn second_payment_terms() -> Terms {
    payment_of(|payment| payment.private_policy_commitment = [5; 32])
}

fn second_payment_funding() -> Funding {
    Funding::new(list(&[SECOND_CLIENT_COIN]), empty_party())
}

fn second_payment_edge() -> EdgeId {
    Tx::edge_id_of(&second_payment_funding(), &second_payment_terms())
}

/// A live tag-4 bond the payment did *not* embed: same parties, same
/// stake, one different price cap, so its terms hash is not the one the
/// payment commits to.
fn other_bond_terms() -> Terms {
    Terms::work_stake_bond(WorkStakeBondTerms {
        max_job_price: 6,
        ..payment_bond()
    })
}

fn other_bond_edge() -> EdgeId {
    Tx::edge_id_of(&payment_bond_funding(), &other_bond_terms())
}

/// Reassembles the lease the store holds, exactly as a host would: two
/// chunks, in slot order, decoded as one record.
fn stored_lease<const C: usize, const E: usize, const R: usize>(
    state: &State<FixedStore<C, E, R>>,
) -> BondLease {
    let mut bytes = Vec::new();
    for (index, slot) in lease_slots().into_iter().enumerate() {
        let Some(chunk) = state.store().registry_chunk(slot) else {
            panic!("lease chunk {index} stored");
        };
        assert_eq!(chunk.namespace(), RegistryNamespace::BondLease);
        assert_eq!(chunk.record_tag(), RegistryRecordTag::BondLease);
        assert_eq!(chunk.chunk_count(), BOND_LEASE_CHUNKS);
        assert_eq!(chunk.chunk_index(), u8::try_from(index).unwrap_or(u8::MAX));
        bytes.extend_from_slice(chunk.data());
    }
    let Ok(lease) = BondLease::decode_exact(&bytes) else {
        panic!("the stored lease decodes");
    };
    lease
}

fn lease_is_absent<const C: usize, const E: usize, const R: usize>(
    state: &State<FixedStore<C, E, R>>,
) -> bool {
    lease_slots()
        .into_iter()
        .all(|slot| state.store().registry_chunk(slot).is_none())
}

/// The open half of the bond's exclusivity rule: the edge and the lease
/// land together, and the lease says which channel now holds the bond.
#[test]
fn a_payment_open_leases_the_bond_it_names() {
    let mut state = bonded_state();
    let open = open_tx(payment_funding(), payment_terms());
    let Ok(outcome) = state.apply(CONTEXT, &FAKE_VERIFIER, &open) else {
        panic!("payment open rejected");
    };

    // One change: the public edge event and the private lease writes.
    assert_eq!(
        outcome.public_event().map(hellas_kernel::Event::kind),
        Some(&EventKind::EdgeOpened {
            inputs: list(&[MAKER_COIN]),
            output: payment_edge_id(),
        }),
    );
    let slots: Vec<RegistryChunkId> = outcome
        .registry()
        .iter()
        .map(|mutation| mutation.id())
        .collect();
    assert_eq!(slots, lease_slots().to_vec());

    let lease = stored_lease(&state);
    assert_eq!(lease.bond_edge(), payment_bond_edge());
    assert_eq!(lease.payment_edge(), payment_edge_id());
    assert_eq!(lease.payment_terms_hash(), payment_terms_hash());
    assert_eq!(lease.private_policy_commitment(), [4; 32]);
    assert_eq!(lease.admission_horizon(), TIMEOUT.get());
    // A fresh lease is empty in both of its mutable fields: no game is
    // live and no challenge slot has been spent.
    assert_eq!(lease.live_game_id(), None);
    assert_eq!(lease.challenged_bitmap(), [0; 32]);
}

/// The attack, in three shapes: a payment open naming a bond that never
/// landed, one naming a bond already spent, and one naming a bond
/// another channel is already leasing. Each would put a client's funding
/// into a channel with no stake behind it.
#[test]
fn a_payment_open_needs_a_bond_that_is_live_and_unleased() {
    let payment = open_tx(payment_funding(), payment_terms());

    // 1. `P` withholds the bond open and submits the payment open `C`
    //    already signed. The bond edge is simply not there.
    let mut absent = state(payment_store(), [MAKER_SEED, TAKER_SEED, BOND_SEED]);
    let before = *absent.store();
    assert_eq!(
        absent.apply(CONTEXT, &FAKE_VERIFIER, &payment),
        Err(ApplyError::MissingEdge {
            id: payment_bond_edge(),
        }),
    );
    assert_eq!(*absent.store(), before, "a refused open moves nothing");

    // 2. The bond landed and was taken back. An unleased bond times out
    //    at any height, which is exactly what makes a payment open held
    //    back until after that timeout fail here rather than lease a
    //    bond the provider has already recovered.
    let mut closed = bonded_state();
    let _event = apply(&mut closed, &bond_timeout_tx());
    let before = *closed.store();
    assert_eq!(
        closed.apply(CONTEXT, &FAKE_VERIFIER, &payment),
        Err(ApplyError::MissingEdge {
            id: payment_bond_edge(),
        }),
    );
    assert_eq!(*closed.store(), before);

    // 3. One bond, one channel. The second open finds the slots taken.
    let store = FixedStore::empty_with_registry(
        [MAKER_COIN, BOND_COIN, SECOND_CLIENT_COIN],
        [payment_edge_id(), payment_bond_edge()],
        lease_slots(),
    );
    let mut leased = state(store, [MAKER_SEED, BOND_SEED, SECOND_CLIENT_SEED]);
    let _event = apply(&mut leased, &payment_bond_open());
    let Ok(_outcome) = leased.apply(CONTEXT, &FAKE_VERIFIER, &payment) else {
        panic!("the first payment open leases the bond");
    };
    let second = open_tx(second_payment_funding(), second_payment_terms());
    let before = *leased.store();
    assert_eq!(
        leased.apply(CONTEXT, &FAKE_VERIFIER, &second),
        Err(ApplyError::InvalidOpen {
            output: second_payment_edge(),
            reason: InvalidOpenReason::WorkBondAlreadyLeased,
        }),
    );
    assert_eq!(*leased.store(), before);
    // The lease that was already there is the first channel's, unchanged.
    assert_eq!(stored_lease(&leased).payment_edge(), payment_edge_id());
}

/// A live bond is not enough: it has to be *this* bond. The embedded
/// witness is the bond's own canonical bytes, so one comparison decides
/// the stake, the award, the horizon, and the two parties at once.
#[test]
fn a_payment_open_needs_the_bond_whose_terms_it_embeds() {
    let payment = payment_of(|payment| payment.bond_edge = other_bond_edge());
    let funding = payment_funding();
    let output = Tx::edge_id_of(&funding, &payment);
    let open = open_tx(funding, payment);
    // Both bonds' lease slots are declared, so nothing but the check
    // itself stands between this open and a lease over the wrong bond.
    let [first, second] = lease_slots();
    let [other_first, other_second] = bond_lease_slots(support::NETWORK, other_bond_edge());
    let store = FixedStore::empty_with_registry(
        [MAKER_COIN, BOND_COIN],
        [output, other_bond_edge()],
        [first, second, other_first, other_second],
    );
    let mut state = state(store, [MAKER_SEED, BOND_SEED]);
    let _event = apply(
        &mut state,
        &open_tx_with(payment_bond_funding(), other_bond_terms(), TAKER, MAKER),
    );
    let before = *state.store();

    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output,
            reason: InvalidOpenReason::WorkBondTermsMismatch,
        }),
    );
    assert_eq!(*state.store(), before);
}

/// Writes `chunk` into lease slot `index`, leaving the other empty.
///
/// Nothing in the kernel can produce this state — a lease is created
/// whole in one registry diff — so it is written directly, which is the
/// only way to test that a reader refuses it rather than rounding it to
/// "no lease".
fn poison_lease<const C: usize, const E: usize, const R: usize>(
    state: &mut State<FixedStore<C, E, R>>,
    index: u8,
    chunk: RegistryChunk,
) {
    let slot = bond_lease_slot(support::NETWORK, payment_bond_edge(), index);
    let mut store = *state.store();
    {
        let mut batch = store.begin();
        let _ = batch.remove_registry_chunk(slot);
        let Ok(()) = batch.insert_registry_chunk(slot, chunk) else {
            panic!("the fixture declares both lease slots");
        };
        batch.commit();
    }
    *state = State::new(store);
}

/// One well-formed chunk of a lease-shaped value, with its partner
/// missing.
fn half_lease_chunk(index: u8) -> RegistryChunk {
    let value = [0x5a_u8; BondLease::ENCODED_SIZE];
    let Some(chunk) = RegistryChunk::split(
        RegistryNamespace::BondLease,
        RegistryRecordTag::BondLease,
        &value,
        index,
    ) else {
        panic!("a lease-width value splits at both indices");
    };
    chunk
}

/// The lease is two chunks, so "unleased" is a statement about both
/// slots. Half of one is not the absence of one.
#[test]
fn a_half_written_lease_is_never_read_as_an_unleased_bond() {
    let payment = open_tx(payment_funding(), payment_terms());

    for occupied in 0..BOND_LEASE_CHUNKS {
        let mut state = bonded_state();
        poison_lease(&mut state, occupied, half_lease_chunk(occupied));
        let before = *state.store();

        // The open cannot take a lease over slots it cannot read...
        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &payment),
            Err(ApplyError::InvalidOpen {
                output: payment_edge_id(),
                reason: InvalidOpenReason::WorkBondLeaseFault {
                    fault: BondLeaseFault::Partial,
                },
            }),
        );
        // ...and the bond cannot take the exit that only an unleased
        // bond has.
        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &bond_timeout_tx()),
            Err(ApplyError::InvalidProof {
                input: payment_bond_edge(),
                reason: InvalidProofReason::BondLeaseFault {
                    fault: BondLeaseFault::Partial,
                },
            }),
        );
        assert_eq!(*state.store(), before, "neither refusal moved anything");
    }
}

/// Writes a whole two-chunk value into the lease slots.
fn poison_whole_lease<const C: usize, const E: usize, const R: usize>(
    state: &mut State<FixedStore<C, E, R>>,
    record_tag: RegistryRecordTag,
    value: &[u8],
) {
    for index in 0..BOND_LEASE_CHUNKS {
        let Some(chunk) =
            RegistryChunk::split(RegistryNamespace::BondLease, record_tag, value, index)
        else {
            panic!("a lease-width value splits at both indices");
        };
        poison_lease(state, index, chunk);
    }
}

/// Absence is a permission — it is what opens the immediate exit — so
/// every present-but-unreadable shape is refused instead of rounded to
/// it. A bond whose lease slots hold something nobody can read is not a
/// bond nobody has recourse against.
#[test]
fn a_present_but_unreadable_lease_is_never_read_as_absence() {
    let readable = {
        let mut state = open_payment_state();
        let mut bytes = [0_u8; BondLease::ENCODED_SIZE];
        let written = stored_lease(&state).write_to(&mut bytes);
        assert_eq!(written, BondLease::ENCODED_SIZE);
        let _ = &mut state;
        bytes
    };
    // The bond edge is the 32 bytes after the envelope and version.
    let mut other_bond = readable;
    other_bond[3..35].copy_from_slice(&[0x2c; 32]);

    let cases = [
        // A whole, well-formed value of another record kind.
        (
            RegistryRecordTag::LiveGame,
            readable,
            BondLeaseFault::Shape,
            "another record kind",
        ),
        // Lease-shaped chunks whose reassembled bytes are not a lease.
        (
            RegistryRecordTag::BondLease,
            [0x5a; BondLease::ENCODED_SIZE],
            BondLeaseFault::Body,
            "noncanonical body",
        ),
        // A readable lease over some other bond, in this bond's slots.
        (
            RegistryRecordTag::BondLease,
            other_bond,
            BondLeaseFault::Edge,
            "another bond's lease",
        ),
    ];

    for (record_tag, value, fault, case) in cases {
        let mut state = open_payment_state();
        poison_whole_lease(&mut state, record_tag, &value);
        assert_eq!(
            state.apply(CONTEXT, &FAKE_VERIFIER, &bond_timeout_tx()),
            Err(ApplyError::InvalidProof {
                input: payment_bond_edge(),
                reason: InvalidProofReason::BondLeaseFault { fault },
            }),
            "{case}",
        );
    }
}

/// The close half of the rule, and the fix for the other side of the
/// same setup race: a client that co-signs a bond open and then never
/// sends the payment open must not be able to lock the provider's stake
/// for the whole horizon at no cost to itself.
#[test]
fn an_unleased_work_bond_times_out_at_once() {
    let mut state = bonded_state();
    assert!(lease_is_absent(&state), "nothing leased this bond");

    // Strictly before the committed timeout — the height rule every
    // other profile is governed by would refuse this exact close.
    assert!(CONTEXT.block_height() < TIMEOUT);
    let _event = apply(&mut state, &bond_timeout_tx());

    assert_eq!(state.store().edge(payment_bond_edge()), None);
    assert_eq!(
        state.store().coin(bond_timeout_out()).map(coin_view),
        Some((TAKER, STAKE)),
        "the stake returns to the provider that posted it",
    );
}

/// Once a channel is leasing the bond, the provider's stake stays where
/// the client's recourse can reach it until the horizon both sides
/// committed to — and the lease leaves with it.
#[test]
fn a_leased_work_bond_waits_for_its_horizon_and_takes_the_lease_with_it() {
    let mut state = open_payment_state();
    let timeout = bond_timeout_tx();

    let before = *state.store();
    assert_eq!(
        state.apply(CONTEXT, &FAKE_VERIFIER, &timeout),
        Err(ApplyError::InvalidProof {
            input: payment_bond_edge(),
            reason: InvalidProofReason::TimeoutNotReached,
        }),
    );
    assert_eq!(*state.store(), before, "a refused close moves nothing");

    // At the horizon it goes, and the lease goes with it: a record
    // about an edge that no longer exists is unreachable state.
    let Ok(outcome) = state.apply(at(TIMEOUT.get()), &FAKE_VERIFIER, &timeout) else {
        panic!("the horizon close is admitted");
    };
    let slots: Vec<RegistryChunkId> = outcome
        .registry()
        .iter()
        .map(|mutation| mutation.id())
        .collect();
    assert_eq!(slots, lease_slots().to_vec());
    assert!(
        outcome
            .registry()
            .iter()
            .all(|mutation| mutation.chunk().is_none()),
        "the close deletes both chunks rather than rewriting them",
    );
    assert_eq!(state.store().edge(payment_bond_edge()), None);
    assert!(lease_is_absent(&state));
    assert_eq!(
        state.store().coin(bond_timeout_out()).map(coin_view),
        Some((TAKER, STAKE)),
    );

    // The payment channel it insured is untouched: its own exits stay
    // open past the admission horizon.
    assert!(state.store().edge(payment_edge_id()).is_some());
}

/// A lease pointing at a live game refuses the bond's timeout outright,
/// at any height. Nothing sets that pointer yet, so the record is
/// written directly here — the guard exists so the step that lands game
/// state cannot accidentally let a bond be recovered out from under the
/// game playing for it.
#[test]
fn a_lease_naming_a_live_game_refuses_the_timeout() {
    let mut state = open_payment_state();
    let live = stored_lease(&state);
    let mut bytes = [0_u8; BondLease::ENCODED_SIZE];
    let written = live.write_to(&mut bytes);
    assert_eq!(written, BondLease::ENCODED_SIZE);
    // The live game id is the 32 bytes after the envelope, version,
    // three ids, the policy commitment, and the horizon.
    let offset = 3 + 32 * 4 + 8;
    bytes[offset..offset + 32].copy_from_slice(&[0x7e; 32]);
    for index in 0..BOND_LEASE_CHUNKS {
        let Some(chunk) = RegistryChunk::split(
            RegistryNamespace::BondLease,
            RegistryRecordTag::BondLease,
            &bytes,
            index,
        ) else {
            panic!("a lease-width value splits at both indices");
        };
        poison_lease(&mut state, index, chunk);
    }
    assert_eq!(stored_lease(&state).live_game_id(), Some([0x7e; 32]));

    for height in [
        CONTEXT.block_height().get(),
        TIMEOUT.get(),
        TIMEOUT.get() + 1,
    ] {
        assert_eq!(
            state.apply(at(height), &FAKE_VERIFIER, &bond_timeout_tx()),
            Err(ApplyError::InvalidProof {
                input: payment_bond_edge(),
                reason: InvalidProofReason::BondLeaseGameLive,
            }),
            "height {height}",
        );
    }
}

/// A payment channel cannot open at or after its own admission horizon:
/// there would be no block left in which to admit a job. The rule is
/// enforced by the generic lifetime check — a payment's committed
/// horizon *is* its `Terms::timeout()` — and is pinned here because it
/// is the horizon rule the bond lease depends on, not because of where
/// it happens to live.
#[test]
fn a_payment_open_at_its_admission_horizon_is_refused() {
    let mut state = bonded_state();
    let open = open_tx(payment_funding(), payment_terms());

    assert_eq!(
        state.apply(at(TIMEOUT.get()), &FAKE_VERIFIER, &open),
        Err(ApplyError::InvalidOpen {
            output: payment_edge_id(),
            reason: InvalidOpenReason::TimeoutNotFuture,
        }),
    );
    assert!(lease_is_absent(&state), "a refused open takes no lease");
}
