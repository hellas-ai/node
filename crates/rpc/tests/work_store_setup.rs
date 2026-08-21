//! The setup journal, and the one decision that recovers a handshake.
//!
//! Every crash here is a real one: the store is dropped, its file is
//! left exactly as it was, and a new store is opened over it. What is
//! asserted is what the second process may do — never what the first
//! one meant to do.

#![cfg(feature = "work")]

use std::collections::BTreeSet;

use hellas_kernel::{
    Auth, BlockHeight, CoinId, Decode as _, Edge, EdgeId, Funding, Key, LeaseSlots, List,
    MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, NetworkId, Parties, Payout, RegistryChunk,
    RegistryNamespace, RegistryRecordTag, Secp256k1Signer, Secp256k1Verifier, Terms, TermsHash, Tx,
    WorkPaymentTerms, WorkStakeBondTerms,
};
use hellas_rpc::protocol::work_bundle::WorkChannelSetupBundleV1;
use hellas_rpc::work_store::journal::JournalError;
use hellas_rpc::work_store::setup::setup_key;
use hellas_rpc::work_store::{
    ObservedSetup, Role, SetupAbort, SetupDecision, SetupEnd, SetupFault, SetupRecord, SetupState,
    SetupStateError, SetupStore, WorkStoreError,
};

// ── Fixture ───────────────────────────────────────────────────────────

const HORIZON: u64 = 500;
const STAKE: u64 = 64;
const BOND_COIN: u8 = 0xa1;
const PAYMENT_COIN: u8 = 0xb1;

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-test") else {
        panic!("a short ascii id is a legal network id");
    };
    network
}

fn other_network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-other") else {
        panic!("a short ascii id is a legal network id");
    };
    network
}

fn provider() -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([0x22; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

fn client() -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([0x21; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

fn coins(ids: &[u8]) -> List<CoinId, MAX_PARTY_INPUTS> {
    let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
    for (slot, id) in slots.iter_mut().zip(ids) {
        *slot = CoinId::from_bytes([*id; CoinId::LENGTH]);
    }
    List::take(slots, ids.len())
}

fn empty_coins() -> List<CoinId, MAX_PARTY_INPUTS> {
    coins(&[])
}

fn bond_terms() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(provider().party_key(), client().party_key()),
        timeout: BlockHeight::new(HORIZON),
        timeout_outputs: List::take(
            [Payout::new(provider().party_key(), STAKE); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: 40,
    }
}

fn bond_funding() -> Funding {
    Funding::new(coins(&[BOND_COIN]), empty_coins())
}

fn payment_funding() -> Funding {
    Funding::new(coins(&[PAYMENT_COIN]), empty_coins())
}

fn payment_terms(bond_edge: EdgeId) -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge,
        bond_terms: bond_terms(),
        private_policy_commitment: [0x25; 32],
        omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: 8,
        omission_bond: 4,
    }
}

fn proposed() -> WorkChannelSetupBundleV1 {
    let hash = Tx::open_hash(
        network(),
        &bond_funding(),
        &Terms::work_stake_bond(bond_terms()),
    );
    match WorkChannelSetupBundleV1::propose_bond(
        network(),
        bond_funding(),
        bond_terms(),
        Auth::native(provider().sign(hash)),
    ) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture bond proposes: {error}"),
    }
}

fn countersigned(bundle: WorkChannelSetupBundleV1) -> WorkChannelSetupBundleV1 {
    let bond_hash = bundle.bond_open_hash();
    let terms = payment_terms(bundle.bond_edge());
    let payment_hash = Tx::open_hash(
        network(),
        &payment_funding(),
        &Terms::work_payment(terms.clone()),
    );
    match bundle.countersign_bond_and_propose_payment(
        Auth::native(client().sign(bond_hash)),
        payment_funding(),
        terms,
        Auth::native(client().sign(payment_hash)),
    ) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture payment proposes: {error}"),
    }
}

fn completed(bundle: WorkChannelSetupBundleV1) -> WorkChannelSetupBundleV1 {
    let Some(hash) = bundle.payment_open_hash() else {
        panic!("a proposed payment has an open hash");
    };
    match bundle.countersign_payment(Auth::native(provider().sign(hash))) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture payment countersigns: {error}"),
    }
}

fn bundle_record(bundle: &WorkChannelSetupBundleV1) -> SetupRecord {
    SetupRecord::Bundle {
        bundle: bundle.encode(),
    }
}

fn bond_edge() -> EdgeId {
    proposed().bond_edge()
}

fn payment_edge() -> EdgeId {
    let Some(edge) = countersigned(proposed()).payment_edge() else {
        panic!("a proposed payment derives its edge");
    };
    edge
}

fn store(root: &std::path::Path, role: Role) -> SetupStore {
    match SetupStore::open(
        root,
        network(),
        bond_edge(),
        role,
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the fixture journal opens: {error}"),
    }
}

/// A provider store that has durably retained the complete handshake.
fn completed_store(root: &std::path::Path) -> SetupStore {
    let mut store = store(root, Role::Provider);
    let verifier = Secp256k1Verifier::new();
    let one = proposed();
    let two = countersigned(one.clone());
    let three = completed(two.clone());
    for bundle in [&one, &two, &three] {
        if let Err(error) = store.commit(bundle_record(bundle), &verifier) {
            panic!("the fixture revision commits: {error}");
        }
    }
    store
}

// ── Observed objects, written out ─────────────────────────────────────

const FORMAT_VERSION: u8 = 1;
const TAG_BLOCK_HEIGHT: u8 = 1;
const TAG_FEES: u8 = 2;
const TAG_PARTIES: u8 = 3;
const TAG_EDGE: u8 = 5;
const TAG_BOND_LEASE: u8 = 31;
const WORK_PAYMENT_CLOSES: u8 = 0b0001_1000;
const WORK_STAKE_CLOSES: u8 = 0b0000_0010;

fn edge(terms: TermsHash, maker: Key, taker: Key, allowed: u8) -> Edge {
    let mut out = vec![FORMAT_VERSION, TAG_EDGE];
    out.extend_from_slice(&64_u64.to_be_bytes()); // value
    out.extend_from_slice(&0_u64.to_be_bytes()); // reserve
    out.extend_from_slice(&[FORMAT_VERSION, TAG_FEES]);
    for _ in 0..4 {
        out.extend_from_slice(&0_u64.to_be_bytes());
    }
    out.extend_from_slice(&[FORMAT_VERSION, TAG_BLOCK_HEIGHT]);
    out.extend_from_slice(&HORIZON.to_be_bytes());
    out.extend_from_slice(&[FORMAT_VERSION, TAG_PARTIES]);
    out.extend_from_slice(&maker.to_bytes());
    out.extend_from_slice(&taker.to_bytes());
    out.extend_from_slice(terms.as_bytes());
    out.push(allowed);
    match Edge::decode_exact(&out) {
        Ok(edge) => edge,
        Err(error) => panic!("the hand-written edge is canonical: {error:?}"),
    }
}

fn bond_object() -> Edge {
    edge(
        Terms::work_stake_bond(bond_terms()).hash(),
        provider().party_key(),
        client().party_key(),
        WORK_STAKE_CLOSES,
    )
}

fn payment_object() -> Edge {
    edge(
        Terms::work_payment(payment_terms(bond_edge())).hash(),
        client().party_key(),
        provider().party_key(),
        WORK_PAYMENT_CLOSES,
    )
}

/// The canonical bytes of one bond lease, written out field by field.
fn lease_over(bond: EdgeId, payment: EdgeId) -> LeaseSlots {
    let mut value = vec![FORMAT_VERSION, TAG_BOND_LEASE];
    value.push(2); // body version
    value.extend_from_slice(&bond.to_bytes());
    value.extend_from_slice(&payment.to_bytes());
    value.extend_from_slice(
        Terms::work_payment(payment_terms(bond_edge()))
            .hash()
            .as_bytes(),
    );
    value.extend_from_slice(&payment_terms(bond_edge()).private_policy_commitment);
    value.extend_from_slice(&HORIZON.to_be_bytes());
    let slots = [0, 1].map(|index| {
        RegistryChunk::split(
            RegistryNamespace::BondLease,
            RegistryRecordTag::BondLease,
            &value,
            index,
        )
    });
    assert!(slots.iter().all(Option::is_some), "the lease splits");
    let parsed = hellas_kernel::parse_bond_lease(slots, bond);
    assert!(
        matches!(parsed, LeaseSlots::Present(_)),
        "the hand-written lease is readable, got {parsed:?}",
    );
    parsed
}

fn faulty_lease() -> LeaseSlots {
    let Some(chunk) = RegistryChunk::split(
        RegistryNamespace::BondLease,
        RegistryRecordTag::BondLease,
        &[0xff; 8],
        0,
    ) else {
        panic!("a short value splits into one chunk");
    };
    hellas_kernel::parse_bond_lease([Some(chunk), Some(chunk)], bond_edge())
}

fn all_live() -> BTreeSet<CoinId> {
    [BOND_COIN, PAYMENT_COIN]
        .into_iter()
        .map(|id| CoinId::from_bytes([id; CoinId::LENGTH]))
        .collect()
}

fn without(coin: u8) -> BTreeSet<CoinId> {
    let mut live = all_live();
    live.remove(&CoinId::from_bytes([coin; CoinId::LENGTH]));
    live
}

struct Observed {
    height: u64,
    bond: Option<Edge>,
    payment: Option<Edge>,
    lease: LeaseSlots,
    live: BTreeSet<CoinId>,
}

impl Observed {
    /// Neither edge exists, every coin is live, and the height is well
    /// inside the horizon: the state the first submission is decided
    /// from.
    fn before_anything() -> Self {
        Self {
            height: 10,
            bond: None,
            payment: None,
            lease: LeaseSlots::Absent,
            live: all_live(),
        }
    }

    fn decide(&self, state: &SetupState) -> SetupDecision {
        state.decide(&ObservedSetup {
            height: self.height,
            bond: self.bond.as_ref(),
            payment: self.payment.as_ref(),
            lease: self.lease,
            live_funding: &self.live,
        })
    }
}

fn temp() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("a temporary directory: {error}"),
    }
}

// ── The journal ───────────────────────────────────────────────────────

/// A revision is durable before its signature is exported, and a crash
/// between the two re-exports the same artifact rather than a new one.
#[test]
fn a_retained_revision_is_re_exported_byte_for_byte() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let two = countersigned(proposed());

    // The client's process: retain revision 1, then retain revision 2 —
    // which carries its own two signatures — and crash before exporting
    // it.
    {
        let mut client_store = store(dir.path(), Role::Client);
        if let Err(error) = client_store.commit(bundle_record(&proposed()), &verifier) {
            panic!("revision 1 commits: {error}");
        }
        if let Err(error) = client_store.commit(bundle_record(&two), &verifier) {
            panic!("revision 2 commits: {error}");
        }
    }

    let recovered = store(dir.path(), Role::Client);
    assert_eq!(recovered.state().revision(), Some(2));
    assert_eq!(
        recovered.state().bundle_bytes(),
        Some(two.encode().as_slice())
    );
    assert_eq!(recovered.len(), 2);
}

/// The three revisions go in order, and nothing else does.
#[test]
fn revisions_extend_and_never_rewind() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let one = proposed();
    let two = countersigned(one.clone());
    let three = completed(two.clone());

    // Revision 2 without revision 1 is not a conversation this endpoint
    // took part in.
    let mut skipping = store(dir.path(), Role::Provider);
    let error = skipping
        .commit(bundle_record(&two), &verifier)
        .expect_err("a first record must be revision 1");
    assert!(
        matches!(
            error,
            WorkStoreError::Setup(SetupStateError::WrongStage { .. })
        ),
        "unexpected error: {error}"
    );
    assert!(skipping.is_empty(), "a refused record writes nothing");
    drop(skipping);

    let mut ordered = store(dir.path(), Role::Provider);
    for bundle in [&one, &two, &three] {
        if let Err(error) = ordered.commit(bundle_record(bundle), &verifier) {
            panic!("the revision commits: {error}");
        }
    }
    assert_eq!(ordered.state().revision(), Some(3));

    // A replayed stale revision.
    let error = ordered
        .commit(bundle_record(&two), &verifier)
        .expect_err("revision 2 does not follow revision 3");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Bundle(_))),
        "unexpected error: {error}"
    );
    assert_eq!(ordered.state().revision(), Some(3));
    assert_eq!(ordered.len(), 3);
}

/// A revision whose signatures do not check never reaches the file —
/// and could not be read back out of one.
#[test]
fn an_unverified_revision_is_not_journaled() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();

    // The client signs the bond where the provider must: the same
    // bytes, the wrong party.
    let hash = Tx::open_hash(
        network(),
        &bond_funding(),
        &Terms::work_stake_bond(bond_terms()),
    );
    let Ok(forged) = WorkChannelSetupBundleV1::propose_bond(
        network(),
        bond_funding(),
        bond_terms(),
        Auth::native(client().sign(hash)),
    ) else {
        panic!("the bundle assembles");
    };

    let mut journal = store(dir.path(), Role::Provider);
    let error = journal
        .commit(bundle_record(&forged), &verifier)
        .expect_err("the provider did not sign this");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Bundle(_))),
        "unexpected error: {error}"
    );
    assert!(journal.is_empty());
}

/// The bundle decoder is exact, so bytes with anything after a whole
/// revision are not a revision.
#[test]
fn a_noncanonical_revision_is_refused() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut bytes = proposed().encode();
    bytes.push(0);
    let mut journal = store(dir.path(), Role::Provider);
    let error = journal
        .commit(SetupRecord::Bundle { bundle: bytes }, &verifier)
        .expect_err("a trailing byte is not canonical");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Bundle(_))),
        "unexpected error: {error}"
    );
}

/// The journal is keyed to one network and one bond. Reopening it as
/// another channel's fails closed rather than replaying as empty.
#[test]
fn a_journal_belongs_to_one_network_and_one_bond() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    drop(completed_store(dir.path()));

    for (label, network, bond) in [
        ("another network", other_network(), bond_edge()),
        (
            "another bond",
            network(),
            EdgeId::from_bytes([0x99; EdgeId::LENGTH]),
        ),
    ] {
        // A different key is a different file name, so this is a fresh
        // empty journal rather than this one misread — which is the
        // point: no state crosses over.
        let Ok(other) = SetupStore::open(dir.path(), network, bond, Role::Provider, &verifier)
        else {
            panic!("a fresh journal opens");
        };
        assert!(
            other.state().revision().is_none(),
            "{label} shares no state with this channel"
        );
    }

    // And this channel's own file, moved to where another channel's
    // journal would be found. The name is not the binding: the header
    // inside is, and it does not describe that channel.
    let elsewhere = EdgeId::from_bytes([0x99; EdgeId::LENGTH]);
    let theirs = journal_path(dir.path(), network(), elsewhere);
    if let Err(error) = std::fs::copy(journal_path(dir.path(), network(), bond_edge()), &theirs) {
        panic!("the copy succeeds: {error}");
    }
    let error = SetupStore::open(dir.path(), network(), elsewhere, Role::Provider, &verifier)
        .expect_err("this file is not that channel's journal");
    assert!(
        matches!(
            error,
            WorkStoreError::Journal(JournalError::HeaderMismatch { .. })
        ),
        "unexpected error: {error}"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Two processes over one journal: the second fails before it can act.
#[test]
fn a_second_holder_is_refused() {
    let dir = temp();
    let held = store(dir.path(), Role::Provider);
    let verifier = Secp256k1Verifier::new();
    let error = SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &verifier,
    )
    .expect_err("the journal is already held");
    assert!(
        matches!(error, WorkStoreError::Journal(JournalError::Locked { .. })),
        "unexpected error: {error}"
    );
    drop(held);
    assert!(
        SetupStore::open(
            dir.path(),
            network(),
            bond_edge(),
            Role::Provider,
            &verifier
        )
        .is_ok(),
        "the lock is released with the store"
    );
}

/// A frame interrupted mid-write is the state before it; a frame that
/// is whole and does not verify is not a state at all.
#[test]
fn a_torn_tail_recovers_and_a_corrupt_frame_does_not() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    drop(completed_store(dir.path()));
    let path = journal_path(dir.path(), network(), bond_edge());
    let Ok(whole) = std::fs::read(&path) else {
        panic!("the journal reads");
    };

    // Interrupted inside the last frame: the caller was never told the
    // write happened, so the state is the one before it.
    for cut in [1_usize, 8, 64] {
        let truncated = whole.len().saturating_sub(cut);
        if let Err(error) = std::fs::write(&path, &whole[..truncated]) {
            panic!("the truncated journal writes: {error}");
        }
        let recovered = match SetupStore::open(
            dir.path(),
            network(),
            bond_edge(),
            Role::Provider,
            &verifier,
        ) {
            Ok(store) => store,
            Err(error) => panic!("a torn tail recovers: {error}"),
        };
        assert_eq!(
            recovered.state().revision(),
            Some(2),
            "the interrupted third revision is not state"
        );
    }

    // A byte changed inside the *last* frame is the same interruption
    // wearing another shape: a page that never landed. Nothing follows
    // it, nothing acknowledged it, and it goes the same way.
    let mut torn = whole.clone();
    let last = torn.len().saturating_sub(64);
    if let Some(byte) = torn.get_mut(last) {
        *byte ^= 0xff;
    }
    if let Err(error) = std::fs::write(&path, &torn) {
        panic!("the torn journal writes: {error}");
    }
    let recovered = match SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &verifier,
    ) {
        Ok(store) => store,
        Err(error) => panic!("a torn last frame recovers: {error}"),
    };
    assert!(recovered.recovered_torn_tail());
    assert_eq!(recovered.state().revision(), Some(2));
    drop(recovered);

    // A byte changed in a frame with two more written after it. Those
    // two say this one was whole when they were written, so what
    // changed it was not a crash, and no earlier state is invented from
    // it.
    let mut corrupt = whole;
    if let Some(byte) = corrupt.get_mut(header_len() + 8) {
        *byte ^= 0xff;
    }
    if let Err(error) = std::fs::write(&path, &corrupt) {
        panic!("the corrupt journal writes: {error}");
    }
    let error = SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &verifier,
    )
    .expect_err("a corrupt frame is refused");
    assert!(
        matches!(error, WorkStoreError::Journal(JournalError::Corrupt { .. })),
        "unexpected error: {error}"
    );
}

/// The file one setup journal is kept in, derived the way the store
/// derives it rather than by looking for whatever is in the directory.
fn journal_path(root: &std::path::Path, network: NetworkId, bond: EdgeId) -> std::path::PathBuf {
    root.join(format!(
        "setup-{}.journal",
        hex(&setup_key(network, bond).into_bytes())
    ))
}

// ── The recovery decision ─────────────────────────────────────────────

/// The first submission and every resubmission are the same decision,
/// and the payment-funding preflight is a premise of it.
#[test]
fn locking_stake_requires_every_payment_input_to_be_live() {
    let dir = temp();
    let held = completed_store(dir.path());
    let state = held.state();

    let ready = Observed::before_anything();
    assert_eq!(ready.decide(state), SetupDecision::SubmitBond);

    // MUTATION of exactly one input: a coin funding the client's
    // already-signed payment Open is spent. The provider does not lock
    // its stake, and its own funding is untouched.
    let spent_payment = Observed {
        live: without(PAYMENT_COIN),
        ..Observed::before_anything()
    };
    assert_eq!(
        spent_payment.decide(state),
        SetupDecision::Abort(SetupAbort::PaymentFundingSpent)
    );

    // The same read after the bond was already broadcast and included:
    // the decision is about the chain, not about the attempt.
    let after_broadcast = Observed {
        bond: Some(bond_object()),
        ..Observed::before_anything()
    };
    assert_eq!(after_broadcast.decide(state), SetupDecision::SubmitPayment);
}

/// Every branch of the recovery machine, each differing from the
/// submit-bond case in exactly one fact.
#[test]
fn the_recovery_decision_covers_every_finalized_shape() {
    let dir = temp();
    let held = completed_store(dir.path());
    let state = held.state();
    let bond = bond_object();
    let payment = payment_object();
    let ours = lease_over(bond_edge(), payment_edge());
    let elsewhere = lease_over(bond_edge(), EdgeId::from_bytes([0x77; EdgeId::LENGTH]));

    let cases: Vec<(&str, Observed, SetupDecision)> = vec![
        (
            "both edges and this channel's lease",
            Observed {
                bond: Some(bond),
                payment: Some(payment),
                lease: ours,
                ..Observed::before_anything()
            },
            SetupDecision::Complete,
        ),
        (
            "a live pair leased to another channel",
            Observed {
                bond: Some(bond),
                payment: Some(payment),
                lease: elsewhere,
                ..Observed::before_anything()
            },
            SetupDecision::Fault(SetupFault::LeasedElsewhere),
        ),
        (
            "a live pair with an unreadable lease",
            Observed {
                bond: Some(bond),
                payment: Some(payment),
                lease: faulty_lease(),
                ..Observed::before_anything()
            },
            SetupDecision::Fault(SetupFault::LeaseMalformed),
        ),
        (
            "a live pair with no lease at all",
            Observed {
                bond: Some(bond),
                payment: Some(payment),
                ..Observed::before_anything()
            },
            SetupDecision::Fault(SetupFault::UnexplainedState),
        ),
        (
            "a payment edge whose bond is gone",
            Observed {
                payment: Some(payment),
                ..Observed::before_anything()
            },
            SetupDecision::Fault(SetupFault::UnexplainedState),
        ),
        (
            "a live unleased bond",
            Observed {
                bond: Some(bond),
                ..Observed::before_anything()
            },
            SetupDecision::SubmitPayment,
        ),
        (
            "a live unleased bond whose capacity funding is gone",
            Observed {
                bond: Some(bond),
                live: without(PAYMENT_COIN),
                ..Observed::before_anything()
            },
            SetupDecision::TimeoutBond,
        ),
        (
            "a live unleased bond at the horizon",
            Observed {
                bond: Some(bond),
                height: HORIZON,
                ..Observed::before_anything()
            },
            SetupDecision::TimeoutBond,
        ),
        (
            "a live bond leased to another channel",
            Observed {
                bond: Some(bond),
                lease: elsewhere,
                ..Observed::before_anything()
            },
            SetupDecision::Fault(SetupFault::LeasedElsewhere),
        ),
        (
            "nothing on chain, and the stake input spent",
            Observed {
                live: without(BOND_COIN),
                ..Observed::before_anything()
            },
            SetupDecision::Fault(SetupFault::BondFundingSpent),
        ),
        (
            "nothing on chain, past the bond open's own timeout",
            Observed {
                height: HORIZON,
                ..Observed::before_anything()
            },
            SetupDecision::Abort(SetupAbort::BondOpenExpired),
        ),
        (
            "nothing on chain, one block inside it",
            Observed {
                height: HORIZON - 1,
                ..Observed::before_anything()
            },
            SetupDecision::SubmitBond,
        ),
    ];

    for (label, observed, expected) in cases {
        assert_eq!(observed.decide(state), expected, "case: {label}");
    }
}

/// A client holds no countersigned payment Open. It never decides to
/// submit or to time anything out, whatever the chain looks like.
#[test]
fn a_client_never_submits_the_providers_transactions() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut client_store = store(dir.path(), Role::Client);
    let one = proposed();
    let two = countersigned(one.clone());
    for bundle in [&one, &two] {
        if let Err(error) = client_store.commit(bundle_record(bundle), &verifier) {
            panic!("the revision commits: {error}");
        }
    }
    let state = client_store.state();

    assert_eq!(
        Observed::before_anything().decide(state),
        SetupDecision::AwaitingCounterparty
    );
    assert_eq!(
        Observed {
            bond: Some(bond_object()),
            ..Observed::before_anything()
        }
        .decide(state),
        SetupDecision::AwaitingCounterparty
    );
    // What it can still see is that the channel is finished.
    assert_eq!(
        Observed {
            bond: Some(bond_object()),
            payment: Some(payment_object()),
            lease: lease_over(bond_edge(), payment_edge()),
            ..Observed::before_anything()
        }
        .decide(state),
        SetupDecision::Complete
    );
}

/// Revision 1 alone says nothing about the chain: there is no payment
/// edge to look for yet.
#[test]
fn a_proposal_alone_decides_nothing() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = store(dir.path(), Role::Provider);
    if let Err(error) = journal.commit(bundle_record(&proposed()), &verifier) {
        panic!("revision 1 commits: {error}");
    }
    assert_eq!(
        Observed::before_anything().decide(journal.state()),
        SetupDecision::AwaitingCounterparty
    );
}

/// The broadcast journal precedes the broadcast, and a step that has no
/// executable transaction behind it is not recorded.
#[test]
fn submission_markers_follow_the_transactions_they_are_about() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = store(dir.path(), Role::Provider);
    if let Err(error) = journal.commit(bundle_record(&proposed()), &verifier) {
        panic!("revision 1 commits: {error}");
    }

    // No countersigned bond exists yet, so there is nothing to have
    // broadcast.
    let error = journal
        .commit(SetupRecord::BondSubmitted, &verifier)
        .expect_err("revision 1 holds no executable transaction");
    assert!(
        matches!(
            error,
            WorkStoreError::Setup(SetupStateError::WrongStage { .. })
        ),
        "unexpected error: {error}"
    );

    let two = countersigned(proposed());
    let three = completed(two.clone());
    for bundle in [&two, &three] {
        if let Err(error) = journal.commit(bundle_record(bundle), &verifier) {
            panic!("the revision commits: {error}");
        }
    }

    // The payment is not broadcast before the bond it needs.
    let error = journal
        .commit(SetupRecord::PaymentSubmitted, &verifier)
        .expect_err("the bond goes first");
    assert!(
        matches!(
            error,
            WorkStoreError::Setup(SetupStateError::WrongStage { .. })
        ),
        "unexpected error: {error}"
    );

    for record in [SetupRecord::BondSubmitted, SetupRecord::PaymentSubmitted] {
        if let Err(error) = journal.commit(record, &verifier) {
            panic!("the marker commits: {error}");
        }
    }
    assert!(journal.state().bond_submitted());
    assert!(journal.state().payment_submitted());

    // A marker already held is not written twice.
    let before = journal.len();
    if let Err(error) = journal.commit(SetupRecord::BondSubmitted, &verifier) {
        panic!("an idempotent marker commits: {error}");
    }
    assert_eq!(journal.len(), before);

    // A client cannot record having broadcast what it does not hold.
    let other = temp();
    let mut client_store = store(other.path(), Role::Client);
    for bundle in [&proposed(), &two, &three] {
        if let Err(error) = client_store.commit(bundle_record(bundle), &verifier) {
            panic!("the revision commits: {error}");
        }
    }
    let error = client_store
        .commit(SetupRecord::BondSubmitted, &verifier)
        .expect_err("a client does not broadcast the bond");
    assert!(
        matches!(
            error,
            WorkStoreError::Setup(SetupStateError::WrongRole { .. })
        ),
        "unexpected error: {error}"
    );
}

/// Completion carries the watcher's starting cursor, and setup ends
/// once.
#[test]
fn completion_records_the_channels_origin_and_is_terminal() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path());

    // The payment edge is the retained bundle's, never a supplied one.
    let error = journal
        .commit(
            SetupRecord::Complete {
                payment_edge: EdgeId::from_bytes([0x66; EdgeId::LENGTH]),
                origin_height: 44,
                origin_payload: [0x01; 32],
                origin_parent: [0x02; 32],
            },
            &verifier,
        )
        .expect_err("another edge is not this channel's");
    assert!(
        matches!(
            error,
            WorkStoreError::Setup(SetupStateError::WrongPaymentEdge { .. })
        ),
        "unexpected error: {error}"
    );

    let complete = SetupRecord::Complete {
        payment_edge: payment_edge(),
        origin_height: 44,
        origin_payload: [0x01; 32],
        origin_parent: [0x02; 32],
    };
    if let Err(error) = journal.commit(complete.clone(), &verifier) {
        panic!("completion commits: {error}");
    }
    let Some(origin) = journal.state().origin() else {
        panic!("completion records an origin");
    };
    assert_eq!(origin.height, 44);
    assert_eq!(origin.parent, [0x02; 32]);
    assert_eq!(journal.state().end(), Some(SetupEnd::Complete));

    // Recording it again is the same fact.
    let before = journal.len();
    if let Err(error) = journal.commit(complete, &verifier) {
        panic!("an idempotent completion commits: {error}");
    }
    assert_eq!(journal.len(), before);

    // Ending an ended setup is not.
    let error = journal
        .commit(
            SetupRecord::Ended {
                outcome: SetupEnd::Aborted(SetupAbort::BondOpenExpired),
            },
            &verifier,
        )
        .expect_err("setup ended already");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Ended(_))),
        "unexpected error: {error}"
    );

    // And a completed setup decides completion, whatever it is shown.
    assert_eq!(
        Observed::before_anything().decide(journal.state()),
        SetupDecision::Complete
    );
}

/// An ended setup stays ended across a restart, and never resubmits.
#[test]
fn an_aborted_setup_does_not_come_back() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    {
        let mut journal = completed_store(dir.path());
        if let Err(error) = journal.commit(
            SetupRecord::Ended {
                outcome: SetupEnd::Aborted(SetupAbort::BondOpenExpired),
            },
            &verifier,
        ) {
            panic!("the abort commits: {error}");
        }
    }
    let recovered = store(dir.path(), Role::Provider);
    assert_eq!(
        recovered.state().end(),
        Some(SetupEnd::Aborted(SetupAbort::BondOpenExpired))
    );
    assert_eq!(
        Observed::before_anything().decide(recovered.state()),
        SetupDecision::Abort(SetupAbort::BondOpenExpired),
        "a state that stopped is not resubmitted because the coins are live"
    );
}

/// A crash before the bond is broadcast, with a payment input spent in
/// the meantime: recovery aborts, and the provider's funding is never
/// named by a transaction it would send.
#[test]
fn a_crash_before_broadcast_recovers_into_the_preflight() {
    let dir = temp();
    drop(completed_store(dir.path()));

    let recovered = store(dir.path(), Role::Provider);
    let observed = Observed {
        live: without(PAYMENT_COIN),
        ..Observed::before_anything()
    };
    assert_eq!(
        observed.decide(recovered.state()),
        SetupDecision::Abort(SetupAbort::PaymentFundingSpent)
    );
    assert!(
        !recovered.state().bond_submitted(),
        "nothing was broadcast, so nothing spent the stake input"
    );
}

/// The coins the caller must read liveness for are the ones the
/// retained transactions actually spend.
#[test]
fn the_funding_coins_come_from_the_retained_transactions() {
    let dir = temp();
    let journal = completed_store(dir.path());
    assert_eq!(journal.state().funding_coins(), all_live());
    assert_eq!(journal.state().horizon(), Some(HORIZON));
    assert_eq!(journal.state().payment_edge(), Some(payment_edge()));
    assert_eq!(journal.state().bond_edge(), bond_edge());
}

/// The record codec is exact: an unknown tag, a short body, and a
/// trailing byte are all refused.
#[test]
fn the_record_codec_is_exact() {
    let complete = SetupRecord::Complete {
        payment_edge: payment_edge(),
        origin_height: 44,
        origin_payload: [0x01; 32],
        origin_parent: [0x02; 32],
    };
    let bytes = complete.encode();
    // tag || edge || height || payload || parent
    assert_eq!(bytes.len(), 1 + 32 + 8 + 32 + 32);
    assert_eq!(SetupRecord::decode(&bytes), Ok(complete));

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        SetupRecord::decode(&trailing),
        Err(SetupStateError::Malformed)
    );
    assert_eq!(
        SetupRecord::decode(&bytes[..bytes.len() - 1]),
        Err(SetupStateError::Malformed)
    );
    assert_eq!(SetupRecord::decode(&[9]), Err(SetupStateError::Malformed));
    assert_eq!(SetupRecord::decode(&[]), Err(SetupStateError::Malformed));

    // The fields are in the order the encoder writes them: swapping the
    // two 32-byte block digests is a different record, and only a
    // reader that agrees with the layout can see it.
    let Ok(SetupRecord::Complete {
        origin_payload,
        origin_parent,
        ..
    }) = SetupRecord::decode(&bytes)
    else {
        panic!("the record decodes");
    };
    assert_eq!(origin_payload, [0x01; 32]);
    assert_eq!(origin_parent, [0x02; 32]);
}

/// Every ending this handshake can reach survives the journal, under
/// the code it has always had.
///
/// All seven are reachable — `decide` returns each of them from the
/// chain state it observes — so none of this is a test of dead surface.
/// The codes are pinned rather than only round-tripped, because a
/// round-trip is a conversation between an encoder and a decoder that
/// renumber together, and it is the *disk* that has to agree: a store
/// that reads yesterday's `Ended` as a different ending resumes a
/// handshake that ended for another reason.
#[test]
fn every_setup_ending_round_trips_under_its_own_code() {
    // The tag `4` and the seven codes, written out here rather than
    // read from the module that assigns them.
    let endings: [(SetupEnd, u8); 7] = [
        (SetupEnd::Complete, 0),
        (SetupEnd::Aborted(SetupAbort::BondOpenExpired), 1),
        (SetupEnd::Aborted(SetupAbort::PaymentFundingSpent), 2),
        (SetupEnd::Faulted(SetupFault::BondFundingSpent), 3),
        (SetupEnd::Faulted(SetupFault::LeaseMalformed), 4),
        (SetupEnd::Faulted(SetupFault::LeasedElsewhere), 5),
        (SetupEnd::Faulted(SetupFault::UnexplainedState), 6),
    ];
    for (outcome, code) in endings {
        let bytes = SetupRecord::Ended { outcome }.encode();
        assert_eq!(bytes, [4, code], "the bytes of {outcome:?}");
        assert_eq!(
            SetupRecord::decode(&bytes),
            Ok(SetupRecord::Ended { outcome }),
            "{outcome:?} reads back as itself"
        );
    }
    // Seven codes, and nothing beyond them is an ending.
    assert_eq!(
        SetupRecord::decode(&[4, 7]),
        Err(SetupStateError::Malformed)
    );
}

/// A frame is bound to its journal and to its position in it.
///
/// Not by the reader's care: by the digest. A frame copied to another
/// position, or lifted from another channel's journal, is not a record
/// this journal ever wrote, and replay never replays it.
///
/// What replay *does* with it depends on what is after it, and that is
/// the journal's crash rule rather than a second opinion about binding:
/// a frame nothing follows is indistinguishable from an interrupted
/// append, so it is dropped; a frame with records after it cannot be
/// one, so the file is refused.
#[test]
fn a_frame_cannot_be_moved_duplicated_or_lifted() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    drop(completed_store(dir.path()));
    let path = journal_path(dir.path(), network(), bond_edge());
    let Ok(whole) = std::fs::read(&path) else {
        panic!("the journal reads");
    };

    // The undamaged file first. A store that reported a tear whatever
    // it read would satisfy every assertion below, and an operator who
    // is told this after a clean shutdown stops believing it.
    match SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &verifier,
    ) {
        Ok(clean) => assert!(!clean.recovered_torn_tail(), "nothing was interrupted"),
        Err(error) => panic!("the clean journal opens: {error}"),
    }

    // The last frame, appended a second time. Its digest is the one for
    // the position it came from.
    let Ok(revision_three) = std::fs::read(&path) else {
        panic!("the journal reads");
    };
    let two = completed_store_bytes();
    let last = revision_three
        .len()
        .checked_sub(two)
        .expect("the third frame is a suffix");
    let mut duplicated = whole.clone();
    duplicated.extend_from_slice(&revision_three[last..]);
    if let Err(error) = std::fs::write(&path, &duplicated) {
        panic!("the duplicated journal writes: {error}");
    }
    let recovered = match SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &verifier,
    ) {
        Ok(store) => store,
        Err(error) => panic!("the journal opens: {error}"),
    };
    assert!(
        recovered.recovered_torn_tail(),
        "a frame at another position does not verify at it"
    );
    assert_eq!(
        recovered.len(),
        3,
        "the copy is not a fourth record, and the three real ones stand"
    );
    drop(recovered);

    // The same frames, under another channel's header.
    let elsewhere = EdgeId::from_bytes([0x88; EdgeId::LENGTH]);
    {
        // Create the other journal so its header exists, then graft
        // this one's frames onto it.
        let _ = store_for(dir.path(), elsewhere);
    }
    let theirs = journal_path(dir.path(), network(), elsewhere);
    let Ok(header) = std::fs::read(&theirs) else {
        panic!("the fresh journal reads");
    };
    let mut grafted = header;
    grafted.extend_from_slice(&whole[header_len()..]);
    if let Err(error) = std::fs::write(&theirs, &grafted) {
        panic!("the grafted journal writes: {error}");
    }
    let error = SetupStore::open(dir.path(), network(), elsewhere, Role::Provider, &verifier)
        .expect_err("those frames were written for another journal");
    assert!(
        matches!(error, WorkStoreError::Journal(JournalError::Corrupt { .. })),
        "unexpected error: {error}"
    );
}

/// How many bytes the third revision's frame occupies, measured rather
/// than assumed.
fn completed_store_bytes() -> usize {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = store(dir.path(), Role::Provider);
    let one = proposed();
    let two = countersigned(one.clone());
    for bundle in [&one, &two] {
        if let Err(error) = journal.commit(bundle_record(bundle), &verifier) {
            panic!("the revision commits: {error}");
        }
    }
    drop(journal);
    let Ok(short) = std::fs::read(journal_path(dir.path(), network(), bond_edge())) else {
        panic!("the journal reads");
    };
    let mut journal = store(dir.path(), Role::Provider);
    if let Err(error) = journal.commit(bundle_record(&completed(two)), &verifier) {
        panic!("the revision commits: {error}");
    }
    drop(journal);
    let Ok(long) = std::fs::read(journal_path(dir.path(), network(), bond_edge())) else {
        panic!("the journal reads");
    };
    long.len() - short.len()
}

/// The fixed header, measured the same way.
fn header_len() -> usize {
    let dir = temp();
    drop(store(dir.path(), Role::Provider));
    let Ok(bytes) = std::fs::read(journal_path(dir.path(), network(), bond_edge())) else {
        panic!("the journal reads");
    };
    bytes.len()
}

fn store_for(root: &std::path::Path, bond: EdgeId) -> SetupStore {
    match SetupStore::open(
        root,
        network(),
        bond,
        Role::Provider,
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("a fresh journal opens: {error}"),
    }
}

/// After a torn tail is truncated, the next append lands where the next
/// frame's digest says it does.
#[test]
fn a_recovered_journal_can_be_written_again() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    drop(completed_store(dir.path()));
    let path = journal_path(dir.path(), network(), bond_edge());
    let Ok(whole) = std::fs::read(&path) else {
        panic!("the journal reads");
    };
    if let Err(error) = std::fs::write(&path, &whole[..whole.len() - 30]) {
        panic!("the truncated journal writes: {error}");
    }

    {
        let mut recovered = store(dir.path(), Role::Provider);
        assert_eq!(recovered.state().revision(), Some(2));
        // The interrupted revision, retried.
        if let Err(error) = recovered.commit(
            bundle_record(&completed(countersigned(proposed()))),
            &verifier,
        ) {
            panic!("the retried revision commits: {error}");
        }
    }

    let reopened = store(dir.path(), Role::Provider);
    assert_eq!(reopened.state().revision(), Some(3));
    assert_eq!(reopened.len(), 3);
}

/// Signatures are checked when the journal is read back, not only when
/// it is written.
///
/// Committed under a verifier that accepts anything, then reopened
/// under the real one: what was journaled is refused, rather than being
/// trusted because it is already on the disk.
#[test]
fn replay_checks_the_signatures_again() {
    let dir = temp();
    let hash = Tx::open_hash(
        network(),
        &bond_funding(),
        &Terms::work_stake_bond(bond_terms()),
    );
    let Ok(forged) = WorkChannelSetupBundleV1::propose_bond(
        network(),
        bond_funding(),
        bond_terms(),
        Auth::native(client().sign(hash)),
    ) else {
        panic!("the bundle assembles");
    };
    {
        let Ok(mut credulous) = SetupStore::open(
            dir.path(),
            network(),
            bond_edge(),
            Role::Provider,
            &AcceptAll,
        ) else {
            panic!("the journal opens");
        };
        if let Err(error) = credulous.commit(bundle_record(&forged), &AcceptAll) {
            panic!("a credulous verifier accepts it: {error}");
        }
    }
    let error = SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    )
    .expect_err("the provider never signed that");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Bundle(_))),
        "unexpected error: {error}"
    );
}

/// A verifier that accepts everything, so a test can write a journal
/// the real verifier will refuse.
struct AcceptAll;

impl hellas_kernel::SigVerifier for AcceptAll {
    fn verify_sig(
        &self,
        _sig: hellas_kernel::Sig,
        _key: Key,
        _hash: hellas_kernel::PayloadHash,
    ) -> bool {
        true
    }
}
