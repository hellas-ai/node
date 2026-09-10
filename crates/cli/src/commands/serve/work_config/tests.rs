use super::*;

fn hex32(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn route(peer: u8, bond: u8, client: u8) -> serde_json::Value {
    serde_json::json!({
        "peer": hex32(peer),
        "bond": hex32(bond),
        "client": hex::encode([client; 33]),
    })
}

fn validators() -> Vec<serde_json::Value> {
    (1..=VALIDATOR_COUNT)
        .map(|index| serde_json::Value::String(format!("http://127.0.0.1:900{index}")))
        .collect()
}

/// A threshold identity the consensus verifier accepts.
///
/// The BLS12-381 G1 generator, compressed: a real point in the real
/// subgroup, so what this fixture proves is that the loader runs
/// consensus's own decoder rather than a length check wearing its
/// name.
fn threshold_identity() -> String {
    hex::encode(THRESHOLD_IDENTITY)
}

const THRESHOLD_IDENTITY: [u8; 48] = [
    0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
    0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
    0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
];

fn config() -> serde_json::Value {
    serde_json::json!({
        "chain": {
            "network_id": "hellas-devnet",
            "genesis_payload_digest": hex32(0x01),
            "threshold_identity": threshold_identity(),
        },
        "validators": validators(),
        "journal": {
            "root": "/var/lib/hellas/work",
        },
        "routes": [route(0x31, 0x41, 0x02)],
        "policies": {
            "policy_salt": hex32(0x5a),
            "channel": {
                "compute_credit_limit": 40,
                "delivery_credit_limit": 40,
            },
            "execution": {
                "allowed_environment": hex32(0x11),
                "generation_policy_digest": hex32(0x12),
                "identity_source_digest": hex32(0x13),
                "max_prompt_tokens": 512,
                "max_new_tokens": 128,
                "max_stop_token_ids": 4,
                "max_spool_bytes": 1_048_576_u64,
                "max_encoded_result_frame": 262_144,
                "max_encoded_quote_response": 1_048_576_u64,
                "dispatch_margin_blocks": 4,
                "delivery_margin_blocks": 2,
                "oracle_grace_blocks": 6,
                "fixed_price": 10,
            },
        },
        "poll_ms": 250,
        // F+G+I+S+R+1 over the fixture budget below, exactly.
        "response_alarm_margin_blocks": 16,
        "artifact": {
            "path": "/var/lib/hellas/work/artifact.json",
            "digest": hex32(0x77),
        },
    })
}

fn write(dir: &tempfile::TempDir, value: &serde_json::Value) -> PathBuf {
    let path = dir.path().join("work-config.json");
    fs::write(&path, value.to_string()).unwrap();
    path
}

fn load(value: serde_json::Value) -> CliResult<WorkConfig> {
    let dir = tempfile::tempdir().unwrap();
    load_work_config(&write(&dir, &value))
}

/// Delete `field` from the object at `path`.
fn without(mut value: serde_json::Value, path: &[&str], field: &str) -> serde_json::Value {
    let mut cursor = &mut value;
    for step in path {
        cursor = cursor.get_mut(step).unwrap();
    }
    cursor.as_object_mut().unwrap().remove(field).unwrap();
    value
}

fn with(mut value: serde_json::Value, field: &str, entry: serde_json::Value) -> serde_json::Value {
    value
        .as_object_mut()
        .unwrap()
        .insert(field.to_string(), entry);
    value
}

#[test]
fn a_work_config_round_trips_from_a_file() {
    let loaded = load(config()).expect("the fixture config loads");

    assert_eq!(loaded.chain.network.as_str(), "hellas-devnet");
    assert_eq!(
        loaded.chain.genesis_payload_digest,
        Digest::from_bytes([0x01; 32]),
    );
    assert_eq!(loaded.chain.threshold_identity, THRESHOLD_IDENTITY.to_vec());
    assert_eq!(loaded.validators.len(), VALIDATOR_COUNT);
    assert_eq!(loaded.journal_root, PathBuf::from("/var/lib/hellas/work"));
    let peer = PeerId::from_bytes([0x31; 32]);
    let route = loaded
        .routes
        .iter()
        .find(|route| route.peer == peer)
        .expect("the bilateral route is loaded under its peer");
    assert_eq!(route.bond, EdgeId::from_bytes([0x41; EdgeId::LENGTH]));
    assert_eq!(route.client, Key::from_bytes([0x02; Key::LENGTH]));
    assert_eq!(loaded.policy_salt, [0x5a; 32]);
    assert_eq!(loaded.channel_policy.compute_credit_limit, 40);
    assert_eq!(loaded.execution_policy.fixed_price, 10);
    assert_eq!(loaded.execution_policy.max_stop_token_ids, 4);
    assert_eq!(loaded.poll, Duration::from_millis(250));
    assert_eq!(loaded.response_alarm_margin_blocks, 16);
    assert_eq!(
        loaded.measured_artifact().map(|artifact| artifact.digest),
        Some(Digest::from_bytes([0x77; 32])),
    );
}

#[test]
fn two_routes_cannot_name_the_same_peer() {
    let routes = serde_json::json!([route(0x31, 0x41, 0x02), route(0x31, 0x42, 0x03),]);
    let error = format!(
        "{:?}",
        load(with(config(), "routes", routes))
            .expect_err("one authenticated peer cannot resolve to two routes"),
    );
    assert!(
        error.contains("names peer") && error.contains("twice"),
        "unexpected error: {error}",
    );
}

#[test]
fn two_routes_cannot_name_the_same_bond() {
    let routes = serde_json::json!([route(0x31, 0x41, 0x02), route(0x32, 0x41, 0x03),]);
    let error = format!(
        "{:?}",
        load(with(config(), "routes", routes))
            .expect_err("one provider journal cannot resolve from two peers"),
    );
    assert!(
        error.contains("names bond") && error.contains("twice"),
        "unexpected error: {error}",
    );
}

/// Every required field is required, and the refusal names it.
#[test]
fn a_missing_field_is_refused_by_name() {
    for (path, field) in [
        (&[][..], "poll_ms"),
        (&[][..], "response_alarm_margin_blocks"),
        (&[][..], "validators"),
        (&[][..], "routes"),
        (&["chain"][..], "threshold_identity"),
        (&["chain"][..], "genesis_payload_digest"),
        (&["journal"][..], "root"),
        (&["policies"][..], "policy_salt"),
        (&["policies", "execution"][..], "fixed_price"),
    ] {
        let error = format!(
            "{:?}",
            load(without(config(), path, field))
                .expect_err("a config missing a required field is refused"),
        );
        assert!(
            error.contains(field),
            "the refusal for a missing {field} does not name it: {error}",
        );
    }
}

/// The two fields that were deleted from the design cannot be
/// configured back into existence.
#[test]
fn a_deleted_field_is_refused_by_name() {
    for field in ["start_validity_blocks", "mutual_margin_blocks"] {
        let error = format!(
            "{:?}",
            load(with(config(), field, serde_json::json!(64))).unwrap_err(),
        );
        assert!(
            error.contains(field),
            "the refusal for {field} does not name it: {error}",
        );
    }
}

/// The three journal caps the journal fixes for itself cannot be
/// configured back into existence.
///
/// [`MAX_ACTIVE_JOURNAL_BYTES`], [`MAX_ACTIVE_FRAMES`] and
/// [`MAX_CHECKPOINT_BYTES`] are constants the journal enforces on
/// itself. A file still naming them is an operator writing 128 MiB
/// and getting 64 with nothing said, so the loader refuses it by the
/// name they wrote.
///
/// [`MAX_ACTIVE_JOURNAL_BYTES`]: hellas_rpc::work_store::journal::MAX_ACTIVE_JOURNAL_BYTES
/// [`MAX_ACTIVE_FRAMES`]: hellas_rpc::work_store::journal::MAX_ACTIVE_FRAMES
/// [`MAX_CHECKPOINT_BYTES`]: hellas_rpc::work_store::journal::MAX_CHECKPOINT_BYTES
#[test]
fn a_journal_cap_the_journal_fixes_is_refused_by_name() {
    for field in [
        "max_active_bytes",
        "max_active_frames",
        "max_checkpoint_bytes",
    ] {
        let error = format!(
            "{:?}",
            load(with_unknown(config(), &["journal"], field))
                .expect_err("a cap the journal fixes is not an operator's to set"),
        );
        assert!(
            error.contains(field),
            "the refusal for {field} does not name it: {error}",
        );
    }
}

#[test]
fn a_fan_out_is_exactly_six_distinct_validators() {
    let five = validators()[..5].to_vec();
    let error = format!(
        "{:?}",
        load(with(config(), "validators", serde_json::json!(five))).unwrap_err(),
    );
    assert!(error.contains("exactly 6"), "unexpected error: {error}");

    let mut duplicated = validators();
    duplicated[5] = duplicated[0].clone();
    let error = format!(
        "{:?}",
        load(with(config(), "validators", serde_json::json!(duplicated))).unwrap_err(),
    );
    assert!(error.contains("twice"), "unexpected error: {error}");
}

/// A validator entry has to be an address, not merely a string.
///
/// `"not a URL"` is trimmed, non-empty, and distinct from the other
/// five, which is all the loader used to ask. It is also nothing this
/// node can ever fan a write to, and the first symptom of that would
/// be one validator out of six that never answers.
#[test]
fn a_validator_that_is_not_a_url_is_refused() {
    let mut malformed = validators();
    malformed[3] = serde_json::Value::String("not a URL".to_string());
    let error = format!(
        "{:?}",
        load(with(config(), "validators", serde_json::json!(malformed))).unwrap_err(),
    );
    assert!(error.contains("not a URL"), "unexpected error: {error}");

    // A URL with no host parses and is still not a validator.
    let mut hostless = validators();
    hostless[0] = serde_json::Value::String("mailto:ops@example.com".to_string());
    let error = format!(
        "{:?}",
        load(with(config(), "validators", serde_json::json!(hostless))).unwrap_err(),
    );
    assert!(error.contains("no host"), "unexpected error: {error}");
}

/// Two spellings of one address are one validator, not two.
///
/// Distinctness is a question about addresses. `HTTP://127.0.0.1:9001`
/// and `http://127.0.0.1:9001/` differ as strings and name the same
/// node, so a string comparison would accept a fan-out to five.
#[test]
fn a_validator_named_twice_in_two_spellings_is_refused() {
    let mut spelled = validators();
    spelled[5] = serde_json::Value::String("HTTP://127.0.0.1:9001".to_string());
    let error = format!(
        "{:?}",
        load(with(config(), "validators", serde_json::json!(spelled))).unwrap_err(),
    );
    assert!(error.contains("twice"), "unexpected error: {error}");
}

/// The loaded list is the normalised one, because that is what gets
/// dialled and what was compared.
#[test]
fn validators_are_loaded_normalised() {
    let loaded = load(config()).expect("the fixture config loads");
    assert_eq!(
        loaded.validators[0], "http://127.0.0.1:9001/",
        "the parsed URL, not the string the operator typed",
    );
}

/// A zero execution-policy field is refused at load, by the
/// protocol's own check.
///
/// Every one of these is a value both parties sign, and each zero is
/// an absent bound rather than a small one. Copying them through
/// unchecked moves the refusal to the first admission, with a
/// counterparty already waiting.
#[test]
fn a_zero_execution_policy_field_is_refused() {
    for field in [
        "fixed_price",
        "max_prompt_tokens",
        "max_new_tokens",
        "max_spool_bytes",
        "max_encoded_result_frame",
        "max_encoded_quote_response",
        "dispatch_margin_blocks",
        "delivery_margin_blocks",
        "oracle_grace_blocks",
    ] {
        let mut value = config();
        value["policies"]["execution"][field] = serde_json::json!(0);
        let Err(refusal) = load(value) else {
            panic!("a zero {field} loaded");
        };
        let error = format!("{refusal:?}");
        assert!(
            error.contains(field),
            "the refusal for a zero {field} does not name it: {error}",
        );
    }

    // The one bound that may be zero: a channel admitting no stop
    // tokens is a channel whose jobs run to `max_new_tokens`.
    let mut value = config();
    value["policies"]["execution"]["max_stop_token_ids"] = serde_json::json!(0);
    let loaded = load(value).expect("no stop tokens is a usable channel");
    assert_eq!(loaded.execution_policy.max_stop_token_ids, 0);
}

#[test]
fn a_threshold_identity_consensus_cannot_decode_is_refused() {
    // A prefix of a real identity: hexadecimal, non-empty, and not a
    // point. A length check wearing consensus's name would take it.
    let mut broken = THRESHOLD_IDENTITY.to_vec();
    broken.truncate(32);
    let chain = serde_json::json!({
        "network_id": "hellas-devnet",
        "genesis_payload_digest": hex32(0x01),
        "threshold_identity": hex::encode(&broken),
    });
    let error = format!("{:?}", load(with(config(), "chain", chain)).unwrap_err());
    assert!(
        error.contains("threshold_identity"),
        "unexpected error: {error}",
    );
}

#[test]
fn a_watcher_that_never_polls_is_refused() {
    let error = format!(
        "{:?}",
        load(with(config(), "poll_ms", serde_json::json!(0))).unwrap_err(),
    );
    assert!(error.contains("poll_ms"), "unexpected error: {error}");
}

// ── The measured artifact ─────────────────────────────────────────

use hellas_kernel::{
    BlockHeight, CoinId, EdgeId, Funding, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties,
    Payout, Secp256k1Signer, Secp256k1Verifier, Terms, Tx, WorkPaymentTerms, WorkStakeBondTerms,
};
use hellas_rpc::protocol::mount::MountBudget;
use hellas_rpc::protocol::work::private_policy_commitment;
use hellas_rpc::protocol::work_setup::WorkSetupError;
use hellas_rpc::work_handshake::SetupEndpoint;
use hellas_rpc::work_store::{Role, SetupScan, SetupStore};

/// The window the fixture's terms admit.
const WINDOW: u64 = hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS + 4;
/// One over half the funding, so the bond exceeds the capacity it
/// leaves behind at zero fees.
const OMISSION_BOND: u64 = 601;
const PAYMENT_VALUE: u64 = 1_000;
const PAYMENT_RESERVE: u64 = 200;

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-devnet") else {
        panic!("the fixture configuration's network id is one");
    };
    network
}

/// The window the run's own timestamps sit inside.
const RUN_STARTED_AT: u64 = 1_756_339_000_000;
const RUN_FINISHED_AT: u64 = 1_756_339_200_000;

fn measured(value: u64) -> serde_json::Value {
    serde_json::json!({ "value": value, "evidence": "measured", "samples": 3_000 })
}

fn assumed(value: u64) -> serde_json::Value {
    serde_json::json!({ "value": value, "evidence": "assumed", "samples": 0 })
}

/// One §4 budget term, as the observations behind it rather than as
/// an answer. The reader takes the tail itself.
fn observed(values: &[u64]) -> serde_json::Value {
    let samples: Vec<serde_json::Value> = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            serde_json::json!({
                "at_unix_ms": RUN_STARTED_AT + index as u64,
                "value": value,
            })
        })
        .collect();
    serde_json::json!({ "evidence": "measured", "samples": samples })
}

/// One §4 budget term nobody observed.
fn written_down(value: u64) -> serde_json::Value {
    serde_json::json!({ "evidence": "assumed", "value": value })
}

/// The budget a completed bootstrap run leaves behind.
///
/// Small explicit sample sets, so the tail of each term is visible
/// at a glance and the floor over them is hand-checkable. Every
/// value is a plausible one for a node with an SSD and a
/// half-second block, and none of them is round: a term dropped
/// from a formula shows up as a wrong total rather than as a wash.
fn budget() -> serde_json::Value {
    serde_json::json!({
        "fsync_tail_ms": observed(&[2, 5, 3]),
        "rotation_tail_ms": observed(&[9, 12]),
        "response_build_ms": observed(&[3, 4]),
        "one_block_fetch_ms": observed(&[18, 25]),
        "fresh_tip_ms": observed(&[11, 14]),
        "close_prepared_fsync_ms": observed(&[4, 6]),
        "rpc_ms": observed(&[30, 44]),
        "response_worker_ms": observed(&[7, 9]),
        "general_worker_ms": observed(&[5, 8]),
        "validation_ms": observed(&[2, 3]),
        "restart_replay_ms_at_cap": observed(&[430, 520]),
        "restart_downtime_ms": observed(&[820, 900]),
        // The one term whose tail is the small end: a short block
        // buys less time, so 480 is the conservative reading of
        // these three.
        "lower_tail_block_ms": observed(&[520, 480, 505]),
        "general_inclusion_blocks": observed(&[2, 3]),
    })
}

/// The artifact a completed bootstrap run leaves behind: every
/// number measured, and every number one this fixture's terms are
/// priced by.
fn artifact() -> serde_json::Value {
    let binary = running_binary_digest().expect("the test executable identifies itself");
    serde_json::json!({
        "provenance": {
            "binary": hex::encode(binary.as_bytes()),
            "config": hex32(0x22),
            "machine": "bootstrap-1",
            "started_at_unix_ms": RUN_STARTED_AT,
            "measured_at_unix_ms": RUN_FINISHED_AT,
        },
        "expected_payment_values": {
            "value": measured(PAYMENT_VALUE),
            "reserve": measured(PAYMENT_RESERVE),
            "close_fees": {
                "base": measured(0),
                "slot": measured(0),
                "proof": measured(0),
                "lifetime": measured(0),
            },
        },
        "budget": budget(),
    })
}

/// The same artifact with one budget term replaced.
fn artifact_with(term: &str, entry: serde_json::Value) -> serde_json::Value {
    let mut value = artifact();
    value["budget"][term] = entry;
    value
}

/// Writes one artifact beside a configuration that pins it, and
/// answers what that node's evidence lets it do.
///
/// The pin is the digest of the bytes actually written, unless
/// `pin` overrides it: the changed-evidence case then differs from
/// the matching one in exactly the field under test and in nothing
/// else.
fn duties_for(artifact: &serde_json::Value, pin: Option<String>) -> CliResult<PaidWorkDuties> {
    duties_for_config(config(), artifact, pin)
}

/// The same load with an explicitly chosen work configuration.
fn duties_for_config(
    config: serde_json::Value,
    artifact: &serde_json::Value,
    pin: Option<String>,
) -> CliResult<PaidWorkDuties> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("artifact.json");
    let bytes = artifact.to_string();
    fs::write(&path, &bytes).unwrap();
    let digest = pin.unwrap_or_else(|| hex::encode(Digest::hash(bytes.as_bytes()).as_bytes()));
    let loaded = load(with(
        config,
        "artifact",
        serde_json::json!({ "path": path.display().to_string(), "digest": digest }),
    ))?;
    load_paid_work_duties(&loaded)
}

/// Inserts `field` into the object at `path`, which the schema does
/// not define.
fn with_unknown(mut value: serde_json::Value, path: &[&str], field: &str) -> serde_json::Value {
    let mut cursor = &mut value;
    for step in path {
        cursor = cursor.get_mut(step).unwrap();
    }
    cursor
        .as_object_mut()
        .unwrap()
        .insert(field.to_string(), serde_json::json!(1));
    value
}

fn signer(byte: u8) -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
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

fn bond_terms() -> WorkStakeBondTerms {
    bond_terms_staked_by(&signer(0x22))
}

/// The same bond, staked by whichever key this node settles with.
///
/// A provider signs its own bond, so the staking party is not a
/// fixture constant when the key comes from an identity file.
fn bond_terms_staked_by(provider: &Secp256k1Signer) -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(provider.party_key(), signer(0x21).party_key()),
        timeout: BlockHeight::new(500),
        timeout_outputs: List::take([Payout::new(provider.party_key(), 64); MAX_EDGE_OUTPUTS], 1),
        max_job_price: 40,
    }
}

/// The provider's stake funding: its own coins, none of the
/// client's.
fn bond_funding() -> Funding {
    Funding::new(coins(&[0xa1]), coins(&[]))
}

/// The edge the bond opens at, which is also the key the setup
/// journal is opened under.
fn bond_edge() -> EdgeId {
    Tx::edge_id_of(&bond_funding(), &Terms::work_stake_bond(bond_terms()))
}

/// The terms a client proposes over that bond.
///
/// The commitment is opened against the *configuration's* own salt
/// and credit policy, because that is what a provider's admission
/// re-derives: terms committing to any other policy are refused
/// rather than countersigned. The Start span is the profile's fixed
/// maximum, so tests aimed at later admission gates reach them.
fn payment_terms() -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bond_edge(),
        bond_terms: bond_terms(),
        private_policy_commitment: private_policy_commitment(
            network(),
            &[0x5a; 32],
            &PaidChannelPolicyV1 {
                compute_credit_limit: 40,
                delivery_credit_limit: 40,
            },
        ),
        omit_response_blocks: WINDOW,
        start_validity_blocks: hellas_kernel::MAX_START_VALIDITY_BLOCKS,
        omission_bond: OMISSION_BOND,
    }
}

fn payment_edge() -> EdgeId {
    EdgeId::from_bytes([0xc0; EdgeId::LENGTH])
}

/// Opens a provider's setup journal under its own directory, with
/// its immutable history floor armed.
///
/// The floor is armed here because a provider's own first revision
/// is refused without one: recovery arming is not a step evidence
/// gates, it is the step every later one is refused before.
fn setup_endpoint(dir: &tempfile::TempDir, admission: PaymentAdmission) -> SetupEndpoint {
    let store = match SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the fixture journal opens: {error}"),
    };
    let mut endpoint = SetupEndpoint::new(store, signer(0x22), admission);
    if let Err(error) = endpoint.arm_scan(SetupScan {
        height: 7,
        payload: [0x47; 32],
    }) {
        panic!("the fixture arms its immutable history floor: {error}");
    }
    endpoint
}

fn write_provider_offer(dir: &tempfile::TempDir) {
    let duties = duties_for(&artifact(), None).expect("the route fixture's policy loads");
    let admission = duties
        .payment_admission()
        .expect("the route fixture carries measured evidence");
    let mut endpoint = setup_endpoint(dir, admission);
    endpoint
        .propose_bond(network(), bond_funding(), bond_terms())
        .expect("the provider offer is durable");
}

fn config_for_route(root: &Path, client: Key) -> WorkConfig {
    load(with(
        with(
            config(),
            "journal",
            serde_json::json!({ "root": root.display().to_string() }),
        ),
        "routes",
        serde_json::json!([{
            "peer": hex32(0x51),
            "bond": hex::encode(bond_edge().to_bytes()),
            "client": hex::encode(client.to_bytes()),
        }]),
    ))
    .expect("the route fixture configuration loads")
}

#[test]
fn a_route_loads_and_verifies_its_journals_client_taker() {
    let dir = tempfile::tempdir().unwrap();
    write_provider_offer(&dir);
    let loaded = config_for_route(dir.path(), signer(0x21).party_key());

    validate_work_routes(&loaded).expect("the route and its provider journal name the same client");
    assert_eq!(loaded.routes.len(), 1);
}

#[test]
fn a_route_is_refused_when_its_journal_names_another_client_taker() {
    let dir = tempfile::tempdir().unwrap();
    write_provider_offer(&dir);
    let expected = signer(0x23).party_key();
    let journal_client = signer(0x21).party_key();
    let loaded = config_for_route(dir.path(), expected);

    let error = format!(
        "{:#}",
        validate_work_routes(&loaded)
            .expect_err("the configured client must be the bond terms' taker"),
    );
    assert!(
        error.contains(&hex::encode(expected.to_bytes()))
            && error.contains(&hex::encode(journal_client.to_bytes()))
            && error.contains("taker"),
        "unexpected error: {error}",
    );
}

#[test]
fn a_route_is_refused_when_its_journal_is_not_under_the_configured_root() {
    let elsewhere = tempfile::tempdir().unwrap();
    write_provider_offer(&elsewhere);
    let configured = tempfile::tempdir().unwrap();
    let loaded = config_for_route(configured.path(), signer(0x21).party_key());

    let error = format!(
        "{:#}",
        validate_work_routes(&loaded)
            .expect_err("a route cannot reach a journal outside journal.root"),
    );
    assert!(
        error.contains("not under journal.root")
            && error.contains(&configured.path().display().to_string()),
        "unexpected error: {error}",
    );
}

/// The artifact round-trips: every labelled number arrives in the
/// policy, and what the policy has no field for arrives beside it.
#[test]
fn a_measured_artifact_round_trips_into_a_policy() {
    let duties = duties_for(&artifact(), None).expect("the fixture artifact loads");

    assert!(duties.admits_paid_work());
    let evidence = duties.evidence().expect("a read artifact is evidence");
    assert_eq!(
        evidence.provenance,
        ArtifactProvenance {
            binary: running_binary_digest().expect("the test executable identifies itself"),
            config: Digest::from_bytes([0x22; 32]),
            machine: "bootstrap-1".to_string(),
            started_at_unix_ms: RUN_STARTED_AT,
            measured_at_unix_ms: RUN_FINISHED_AT,
        },
    );
    // The weakest link and not an average: the budget's shortest
    // sample set is `rotation_tail_ms` at two observations, and two
    // is what the whole artifact rests on.
    assert_eq!(evidence.samples, 2);
    assert_eq!(
        evidence.policy.expected_payment_values,
        EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0)),
    );
    // The four fields a provider fixes for itself come from the
    // configuration and never from the artifact.
    assert_eq!(evidence.policy.network.as_str(), "hellas-devnet");
    assert_eq!(evidence.policy.policy_salt, [0x5a; 32]);
    assert_eq!(evidence.policy.channel_policy.compute_credit_limit, 40);
    assert_eq!(evidence.policy.execution_policy.fixed_price, 10);
    assert_eq!(
        duties.summary(),
        "paid admission is on: every field of the pinned artifact is measured, \
         and its floor needs T=11 of the 64-block start span",
    );
}

/// An unknown artifact field is refused by name, wherever it sits.
///
/// The names are §4-B's on purpose: the confidence bound, the
/// lower-tail block time and the restart downtime are what a later
/// measured gate consumes, and a file carrying one today is an
/// operator configuring something this node does not implement.
#[test]
fn an_unknown_artifact_field_is_refused_by_name() {
    for (path, field) in [
        (&[][..], "lower_tail_block_ms"),
        (&["provenance"][..], "restart_downtime_ms"),
        (&["budget"][..], "confidence_upper"),
        (&["expected_payment_values", "close_fees"][..], "settlement"),
    ] {
        let error = format!(
            "{:?}",
            duties_for(&with_unknown(artifact(), path, field), None)
                .expect_err("an unknown artifact field is refused"),
        );
        assert!(
            error.contains(field),
            "the refusal for {field} does not name it: {error}",
        );
    }
}

/// Every artifact field is required, and the label most of all: a
/// number with no `evidence` beside it would be a measurement
/// nobody claimed.
#[test]
fn a_missing_artifact_field_is_refused_by_name() {
    for (path, field) in [
        (&["provenance"][..], "machine"),
        (&["provenance"][..], "measured_at_unix_ms"),
        (&["expected_payment_values"][..], "close_fees"),
        (&["expected_payment_values", "close_fees"][..], "lifetime"),
    ] {
        let error = format!(
            "{:?}",
            duties_for(&without(artifact(), path, field), None)
                .expect_err("an artifact missing a required field is refused"),
        );
        assert!(
            error.contains(field),
            "the refusal for a missing {field} does not name it: {error}",
        );
    }
}

/// A label its own sample count contradicts is refused by name.
///
/// Both directions, because both are dishonest: a `measured` number
/// resting on nothing is not a measurement, and an `assumed` number
/// reporting samples is a measurement wearing the wrong label — and
/// the second one would turn paid admission *off* for a node that
/// had actually earned it.
#[test]
fn a_label_its_samples_contradict_is_refused_by_name() {
    let mut unsampled = artifact();
    unsampled["expected_payment_values"]["value"] =
        serde_json::json!({ "value": PAYMENT_VALUE, "evidence": "measured", "samples": 0 });
    let error = format!("{:?}", duties_for(&unsampled, None).unwrap_err());
    assert!(
        error.contains("expected_payment_values.value") && error.contains("no samples"),
        "unexpected error: {error}",
    );

    let mut oversampled = artifact();
    oversampled["expected_payment_values"]["reserve"] = serde_json::json!({
        "value": PAYMENT_RESERVE,
        "evidence": "assumed",
        "samples": 12,
    });
    let error = format!("{:?}", duties_for(&oversampled, None).unwrap_err());
    assert!(
        error.contains("expected_payment_values.reserve"),
        "unexpected error: {error}",
    );
}

/// A fully measured artifact yields a policy that admits, and an
/// admission that countersigns.
#[test]
fn a_measured_artifact_yields_a_policy_that_admits() {
    let duties = duties_for(&artifact(), None).expect("the fixture artifact loads");
    let policy = &duties
        .evidence()
        .expect("a read artifact is evidence")
        .policy;

    let descriptor = policy
        .admit(payment_edge(), payment_terms())
        .expect("a measured policy admits the terms it was measured for");

    assert_eq!(descriptor.bond_edge(), bond_edge());
    assert!(matches!(
        duties.payment_admission(),
        Some(PaymentAdmission::Admits(_)),
    ));
}

/// One `assumed` field is a node that countersigns nothing and
/// still runs setup and the close duty.
///
/// The numbers are the measured fixture's, to the byte: only the
/// label moves. So what refuses admission is the absence of
/// evidence and not a value that failed a check — `admit` on this
/// very policy still succeeds, and the endpoint built over it never
/// gets to ask, because `Proposes` declines every proposed payment.
#[test]
fn an_assumed_field_refuses_admission_and_keeps_setup_and_close() {
    let mut value = artifact();
    value["expected_payment_values"]["close_fees"]["base"] = assumed(0);
    let duties = duties_for(&value, None).expect("an assumed artifact still loads");
    let measured = duties_for(&artifact(), None).expect("the fixture artifact loads");

    assert!(!duties.admits_paid_work());
    let evidence = duties.evidence().expect("a read artifact is evidence");
    assert_eq!(evidence.samples, 0, "an assumed field rests on no samples");
    assert_eq!(
        evidence.policy,
        measured
            .evidence()
            .expect("a read artifact is evidence")
            .policy,
        "only the label moved",
    );
    evidence
        .policy
        .admit(payment_edge(), payment_terms())
        .expect("the numbers themselves still price these terms");

    // Setup and the close duty still run: close state is derivable
    // from this policy, and an endpoint is built over an admission
    // that countersigns nothing.
    evidence
        .policy
        .describe_close(payment_edge(), payment_terms())
        .expect("close state is derivable from an assumed policy");
    let admission = duties.payment_admission().expect("an artifact was read");
    assert!(matches!(admission, PaymentAdmission::Proposes(_)));
    let dir = tempfile::tempdir().unwrap();
    let mut endpoint = setup_endpoint(&dir, admission);
    endpoint
        .propose_bond(network(), bond_funding(), bond_terms())
        .expect("an unmeasured provider still journals its half of a setup");

    assert!(
        duties.summary().contains("no paid admission"),
        "unexpected summary: {}",
        duties.summary(),
    );
}

/// No file at the configured path is a node before its bootstrap
/// run, not a broken one: §4 disables new work on missing evidence
/// and never disables recovery or the close duty.
#[test]
fn a_missing_artifact_admits_no_paid_work() {
    let dir = tempfile::tempdir().unwrap();
    let loaded = load(with(
        config(),
        "artifact",
        serde_json::json!({
            "path": dir.path().join("artifact.json").display().to_string(),
            "digest": hex32(0x77),
        }),
    ))
    .expect("a configuration pinning an artifact that is not there still loads");

    let duties =
        load_paid_work_duties(&loaded).expect("a missing artifact is an answer, not an error");

    assert_eq!(duties, PaidWorkDuties::NotFound);
    assert!(!duties.admits_paid_work());
    assert!(duties.payment_admission().is_none());
    assert!(
        duties.summary().contains("no paid admission"),
        "unexpected summary: {}",
        duties.summary(),
    );
}

/// A configuration naming no artifact at all is the same answer in
/// different words.
#[test]
fn a_config_without_an_artifact_admits_no_paid_work() {
    let loaded = load(without(config(), &[], "artifact")).expect("the config still loads");
    assert!(loaded.measured_artifact().is_none());

    let duties = load_paid_work_duties(&loaded).expect("no artifact is not an error");

    assert_eq!(duties, PaidWorkDuties::NotConfigured);
    assert!(duties.payment_admission().is_none());
    assert!(
        duties.summary().contains("no paid admission"),
        "unexpected summary: {}",
        duties.summary(),
    );
}

/// An artifact that is not the one the configuration pins is
/// refused as evidence, and the node still starts.
///
/// §4 groups changed evidence with missing evidence: both disable
/// setup and new work, and neither disables recovery or the close
/// duty. Refusing to start would be the one way to guarantee an
/// open contest is never answered.
#[test]
fn an_artifact_that_is_not_the_pinned_one_is_refused() {
    let duties = duties_for(&artifact(), Some(hex32(0x77)))
        .expect("changed evidence is an answer, not a startup failure");

    assert_eq!(duties, PaidWorkDuties::Changed);
    assert!(duties.payment_admission().is_none());
    assert!(
        duties.summary().contains("no paid admission"),
        "unexpected summary: {}",
        duties.summary(),
    );
}

/// A byte-for-byte pinned artifact is still evidence about the
/// binary that measured it, not whichever binary happens to read
/// it later.
#[test]
fn an_artifact_measured_by_another_binary_is_changed() {
    let mut foreign = artifact();
    let binary = Digest::from_bytes([0x21; 32]);
    assert_ne!(
        running_binary_digest().expect("the test executable identifies itself"),
        binary,
        "the fixture must name another binary",
    );
    foreign["provenance"]["binary"] = serde_json::json!(hex::encode(binary.as_bytes()));

    let duties = duties_for(&foreign, None)
        .expect("another measuring binary is changed evidence, not a startup failure");

    assert_eq!(duties, PaidWorkDuties::Changed);
    assert!(duties.payment_admission().is_none());
    assert!(
        duties.summary().contains("another measuring binary"),
        "unexpected summary: {}",
        duties.summary(),
    );
}

/// Bytes that do not match the pin are not this node's evidence to
/// interpret. Even an unparseable stale file is therefore changed
/// evidence, not a startup failure that prevents the close duty.
#[test]
fn a_mismatching_unparseable_artifact_is_changed_before_it_is_parsed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("artifact.json");
    let bytes = b"this is not an artifact";
    fs::write(&path, bytes).unwrap();
    let pin = Digest::from_bytes([0x77; 32]);
    assert_ne!(Digest::hash(bytes), pin, "the fixture must miss its pin");
    let loaded = load(with(
        config(),
        "artifact",
        serde_json::json!({
            "path": path.display().to_string(),
            "digest": hex::encode(pin.as_bytes()),
        }),
    ))
    .expect("a configuration pinning stale bytes still loads");

    let duties = load_paid_work_duties(&loaded)
        .expect("mismatching bytes are changed evidence before they are parsed");

    assert_eq!(duties, PaidWorkDuties::Changed);
    assert!(duties.payment_admission().is_none());
}

/// A `ProviderChannelPolicy` is built from a configuration and its
/// artifact, and a `SetupEndpoint` over that — which is the pair
/// nothing in this crate could construct at all.
#[test]
fn a_setup_endpoint_is_built_from_the_loaded_policy() {
    let duties = duties_for(&artifact(), None).expect("the fixture artifact loads");
    let admission = duties
        .payment_admission()
        .expect("a measured artifact carries an admission");
    let dir = tempfile::tempdir().unwrap();
    let mut endpoint = setup_endpoint(&dir, admission);

    assert!(endpoint.state().revision().is_none());
    let state = endpoint
        .propose_bond(network(), bond_funding(), bond_terms())
        .expect("the endpoint signs and journals its bond proposal");

    assert_eq!(state.revision(), Some(1));
}

// ── §4-B: the floor, and the grading ──────────────────────────────

/// The floor this artifact yields, hand-checked term by term.
///
/// Every number below is arithmetic over [`budget`]'s sample sets
/// and nothing else, so a coefficient dropped or a term summed into
/// the wrong wait fails here rather than in a deployment:
///
/// tails: `fsync 5, rotation 12, build 4, fetch 25, tip 14,`
/// `close-fsync 6, rpc 44, resp-worker 9, gen-worker 8,`
/// `validation 3, replay 520, downtime 900`, and the *shortest*
/// block, `480`, with `Ig = 3`.
///
/// `Wresp  = 3×5 + 12 + 4 + 25 + (44+9+3) = 15+12+4+25+56 = 112`
/// `S      = ceil(112/480) = 1`
/// `Wstart = 14 + 6 + 12 + (44+8+3) = 14+6+12+55 = 87`
/// `Sg     = ceil(87/480) = 1`
/// `R      = ceil((900+520)/480) = ceil(1420/480) = 3`
/// `T      = 2 + 1 + 3 + 1 + 3 + 1 = 11`
/// `omit   = 2 + 4 + 1 + 8 + 1 + 3 + 1 = 20`
/// `alarm  = 2 + 1 + 8 + 1 + 3 + 1 = 16`
#[test]
fn the_floor_over_this_artifact_is_the_hand_checked_one() {
    let duties = duties_for(&artifact(), None).expect("the fixture artifact loads");
    let floor = duties
        .evidence()
        .expect("a read artifact is evidence")
        .floor;

    assert_eq!(floor.wresp_ms(), 112);
    assert_eq!(floor.s(), 1);
    assert_eq!(floor.wstart_ms(), 87);
    assert_eq!(floor.sg(), 1);
    assert_eq!(floor.r(), 3);
    assert_eq!(floor.t(), 11);
    assert_eq!(floor.min_omit_response_blocks(), 20);
    assert_eq!(floor.alarm_margin_blocks(), 16);
    // The two the configuration and the terms are held to, met
    // exactly rather than comfortably: the fixture's window is
    // `MIN_OMIT_RESPONSE_BLOCKS + 4 = 20` and its alarm margin 16.
    assert_eq!(floor.min_omit_response_blocks(), WINDOW);
    assert_eq!(
        floor.alarm_margin_blocks(),
        load(config())
            .expect("the fixture config loads")
            .response_alarm_margin_blocks,
    );
}

/// The watcher may consume the four blocks the response floor
/// prices for polling, but not one millisecond more at this
/// artifact's own conservative block tail.
#[test]
fn the_poll_cadence_fits_inside_the_artifacts_priced_blocks() {
    let artifact = artifact_with("lower_tail_block_ms", observed(&[520, 500, 505]));
    let priced_poll_ms = RESPONSE_POLL_BLOCKS * 500;
    let at_limit = duties_for_config(
        with(config(), "poll_ms", serde_json::json!(priced_poll_ms)),
        &artifact,
        None,
    )
    .expect("the exact four-block cadence is priced");
    assert!(at_limit.admits_paid_work());

    let error = format!(
        "{:#}",
        duties_for_config(
            with(config(), "poll_ms", serde_json::json!(priced_poll_ms + 1)),
            &artifact,
            None,
        )
        .expect_err("one millisecond beyond four blocks is not priced"),
    );
    assert!(
        error.contains("poll_ms 2001")
            && error.contains("2000 ms")
            && error.contains("RESPONSE_POLL_BLOCKS=4")
            && error.contains("lower_tail_block_ms=500"),
        "unexpected refusal: {error}",
    );
}

/// `64 >= T` admits and `T > 64` refuses — at startup, and again at
/// provider admission over the very same policy.
///
/// The two are separate gates on purpose. Startup is where an
/// operator learns; admission is where a counterparty is told. A
/// node whose artifact was swapped under it between the two still
/// countersigns nothing.
#[test]
fn a_budget_that_does_not_fit_the_start_span_refuses_at_startup_and_at_admission() {
    // T = F + G + Ig + Sg + R + 1 = 2 + 1 + Ig + 1 + 3 + 1, so Ig
    // is what carries it across the span.
    let admits = duties_for(
        &artifact_with("general_inclusion_blocks", observed(&[56])),
        None,
    )
    .expect("the artifact loads");
    assert!(admits.admits_paid_work());
    assert_eq!(
        admits.evidence().expect("evidence").floor.t(),
        64,
        "the largest budget the fixed start span admits",
    );

    let refuses = duties_for(
        &artifact_with("general_inclusion_blocks", observed(&[57])),
        None,
    )
    .expect("a refusing floor is an answer, not a startup failure");

    assert_eq!(
        refuses,
        PaidWorkDuties::Refused(FloorError::StartSpanTooShort { t: 65, span: 64 }),
    );
    assert!(!refuses.admits_paid_work());
    assert!(
        refuses.payment_admission().is_none(),
        "a node that cannot fit the start span holds no policy to countersign with",
    );
    assert!(
        refuses.summary().contains("no paid admission"),
        "unexpected summary: {}",
        refuses.summary(),
    );

    // And the same refusal at provider admission, over a policy
    // that is otherwise the admitting one to the byte.
    let mut policy = admits.evidence().expect("evidence").policy.clone();
    policy.floor = over_the_span();
    assert_eq!(
        policy.admit(payment_edge(), payment_terms()),
        Err(WorkSetupError::Floor(FloorError::StartSpanTooShort {
            t: 65,
            span: 64,
        })),
    );
}

/// A floor whose `T` is one past the fixed start span.
fn over_the_span() -> MountFloor {
    let mut over = MountBudget {
        fsync_tail_ms: 5,
        rotation_tail_ms: 12,
        response_build_ms: 4,
        one_block_fetch_ms: 25,
        fresh_tip_ms: 14,
        close_prepared_fsync_ms: 6,
        rpc_ms: 44,
        response_worker_ms: 9,
        general_worker_ms: 8,
        validation_ms: 3,
        restart_replay_ms_at_cap: 520,
        restart_downtime_ms: 900,
        lower_tail_block_ms: 480,
        general_inclusion_blocks: 3,
    };
    over.general_inclusion_blocks = 57;
    match over.floor() {
        Ok(floor) => floor,
        Err(error) => panic!("a positive lower tail prices every wait: {error}"),
    }
}

/// Terms that leave less time to answer than the measured floor
/// needs are refused at provider admission, by both numbers.
///
/// The kernel's own `MIN_OMIT_RESPONSE_BLOCKS` is 16 and would take
/// these terms; the measured floor is 20, because this deployment's
/// own seek and restart cost `S = 1` and `R = 3` blocks the kernel
/// constant cannot know about.
#[test]
fn terms_under_the_measured_response_window_are_refused_at_admission() {
    let duties = duties_for(&artifact(), None).expect("the fixture artifact loads");
    let policy = &duties.evidence().expect("evidence").policy;
    let mut short = payment_terms();
    short.omit_response_blocks = WINDOW - 1;

    assert!(
        short.omit_response_blocks > hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        "the kernel's own floor would take these terms",
    );
    assert_eq!(
        policy.admit(payment_edge(), short),
        Err(WorkSetupError::Floor(
            FloorError::ResponseWindowBelowFloor {
                window: WINDOW - 1,
                floor: 20,
            }
        )),
    );
}

/// A configured alarm that fires later than the budget needs is a
/// refusal, not a warning.
#[test]
fn an_alarm_margin_under_the_measured_floor_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("artifact.json");
    let bytes = artifact().to_string();
    fs::write(&path, &bytes).unwrap();
    let loaded = load(with(
        with(
            config(),
            "response_alarm_margin_blocks",
            serde_json::json!(15),
        ),
        "artifact",
        serde_json::json!({
            "path": path.display().to_string(),
            "digest": hex::encode(Digest::hash(bytes.as_bytes()).as_bytes()),
        }),
    ))
    .expect("a configuration with a short alarm margin still loads");

    let duties = load_paid_work_duties(&loaded).expect("the pinned artifact is read");

    assert_eq!(
        duties,
        PaidWorkDuties::Refused(FloorError::AlarmMarginBelowFloor {
            margin: 15,
            floor: 16,
        }),
    );
    assert!(duties.payment_admission().is_none());
}

/// A block that takes no time refuses admission, by §4's name for
/// it.
///
/// The tail taken for `lower_tail_block_ms` is the *shortest*
/// sample, so one zero in the set is enough — which is the point:
/// a run that observed one instantaneous block observed a clock
/// nobody can price a wait against.
#[test]
fn a_non_positive_lower_tail_block_time_refuses() {
    let duties = duties_for(
        &artifact_with("lower_tail_block_ms", observed(&[520, 0, 505])),
        None,
    )
    .expect("the artifact still loads");

    assert_eq!(duties, PaidWorkDuties::Refused(FloorError::NoLowerTail));
    assert!(!duties.admits_paid_work());
    assert!(duties.payment_admission().is_none());
}

/// A budget term's label answers to its samples, exactly as every
/// other artifact number's does — and a term that names a value
/// beside its samples is refused, because only one of the two would
/// ever be read.
#[test]
fn a_budget_term_whose_label_its_samples_contradict_is_refused_by_name() {
    for (entry, expected) in [
        (
            serde_json::json!({ "evidence": "measured", "samples": [] }),
            "no samples",
        ),
        (
            serde_json::json!({ "evidence": "assumed", "value": 7, "samples": [
                { "at_unix_ms": RUN_STARTED_AT, "value": 5 },
            ] }),
            "reports 1 samples",
        ),
        (
            serde_json::json!({ "evidence": "assumed" }),
            "names no value",
        ),
        (
            serde_json::json!({
                "evidence": "measured",
                "value": 7,
                "samples": [{ "at_unix_ms": RUN_STARTED_AT, "value": 5 }],
            }),
            "writes 7 down beside its samples",
        ),
    ] {
        let error = format!(
            "{:?}",
            duties_for(&artifact_with("rpc_ms", entry), None)
                .expect_err("a contradicted budget label is refused"),
        );
        assert!(
            error.contains("budget.rpc_ms") && error.contains(expected),
            "unexpected refusal: {error}",
        );
    }
}

/// A sample stamped outside the run that claims it is not a sample
/// of that run, and a floor computed over one would be a floor for
/// a machine nobody named.
#[test]
fn a_sample_from_outside_the_run_is_refused() {
    let stray = serde_json::json!({
        "evidence": "measured",
        "samples": [
            { "at_unix_ms": RUN_STARTED_AT, "value": 30 },
            { "at_unix_ms": RUN_FINISHED_AT + 1, "value": 44 },
        ],
    });

    let error = format!(
        "{:?}",
        duties_for(&artifact_with("rpc_ms", stray), None)
            .expect_err("a sample outside the run window is refused"),
    );

    assert!(
        error.contains("budget.rpc_ms") && error.contains("outside the run"),
        "unexpected refusal: {error}",
    );
}

/// An `assumed` budget term keeps setup and the close duty and
/// takes away the countersignature, exactly as an assumed payment
/// value does. The floor is still computed over it — a written
/// number is still a number the arithmetic has to hold for.
#[test]
fn an_assumed_budget_term_refuses_admission_and_keeps_the_floor() {
    let duties = duties_for(&artifact_with("validation_ms", written_down(3)), None)
        .expect("an artifact with one written-down term still loads");

    assert!(!duties.admits_paid_work());
    assert!(matches!(duties, PaidWorkDuties::Assumed(_)));
    let evidence = duties.evidence().expect("a read artifact is evidence");
    assert_eq!(evidence.samples, 0);
    assert_eq!(
        evidence.floor.t(),
        11,
        "the written-down 3 is the same 3 the run would have measured",
    );
    assert!(matches!(
        duties.payment_admission(),
        Some(PaymentAdmission::Proposes(_)),
    ));
}

/// The demo bypass is both explicit and exact-network scoped. Merely
/// naming a network that sounds like a devnet must not arm it.
#[test]
fn unsafe_assumed_admission_is_refused_outside_the_shipped_devnet() {
    for network in ["hellas-testnet-1", "someone-elses-devnet", "hellas-devnet"] {
        let mut value = config();
        value["chain"]["network_id"] = serde_json::json!(network);
        value["unsafe_devnet_admit_assumed_measurements"] = serde_json::json!(true);

        let error = format!(
            "{:#}",
            load(value).expect_err("only the exact shipped devnet may arm the bypass"),
        );
        assert!(
            error.contains("unsafe_devnet_admit_assumed_measurements")
                && error.contains(UNSAFE_ASSUMED_ADMISSION_NETWORK),
            "unexpected refusal for {network}: {error}",
        );
    }
}

/// The isolated demo may use honest written-down numbers while the
/// remaining probes are being built, without relabelling them measured.
#[test]
fn explicit_shipped_devnet_bypass_admits_an_assumed_artifact() {
    let mut value = config();
    value["chain"]["network_id"] = serde_json::json!(UNSAFE_ASSUMED_ADMISSION_NETWORK);
    value["unsafe_devnet_admit_assumed_measurements"] = serde_json::json!(true);
    let artifact = artifact_with("validation_ms", written_down(3));

    let duties = duties_for_config(value, &artifact, None)
        .expect("the explicit devnet bypass reads the pinned artifact");

    assert!(matches!(
        duties,
        PaidWorkDuties::UnsafeDevnetAdmitsAssumed(_)
    ));
    assert!(duties.admits_paid_work());
    assert!(matches!(
        duties.payment_admission(),
        Some(PaymentAdmission::Admits(_)),
    ));
    assert!(
        duties.summary().starts_with("UNSAFE DEVNET"),
        "the operator output must not resemble measured admission: {}",
        duties.summary(),
    );
    assert_eq!(
        duties
            .evidence()
            .expect("assumed evidence stays visible")
            .samples,
        0,
    );
}

/// The bypass changes only the assumed-label decision. It never invents
/// an artifact or ignores the configured content pin.
#[test]
fn unsafe_devnet_bypass_still_requires_the_exact_pinned_artifact() {
    let mut missing = config();
    missing["chain"]["network_id"] = serde_json::json!(UNSAFE_ASSUMED_ADMISSION_NETWORK);
    missing["unsafe_devnet_admit_assumed_measurements"] = serde_json::json!(true);
    missing
        .as_object_mut()
        .expect("config is an object")
        .remove("artifact");
    let loaded = load(missing).expect("an artifact remains optional for recovery");
    let duties = load_paid_work_duties(&loaded).expect("missing evidence is a state");
    assert_eq!(duties, PaidWorkDuties::NotConfigured);
    assert!(!duties.admits_paid_work());

    let mut changed = config();
    changed["chain"]["network_id"] = serde_json::json!(UNSAFE_ASSUMED_ADMISSION_NETWORK);
    changed["unsafe_devnet_admit_assumed_measurements"] = serde_json::json!(true);
    let duties = duties_for_config(changed, &artifact(), Some(hex32(0xff)))
        .expect("a changed pin is an evidence state");
    assert_eq!(duties, PaidWorkDuties::Changed);
    assert!(!duties.admits_paid_work());
}

/// The probe writes an artifact this loader reads — and grades
/// exactly as honestly as the run deserves.
///
/// This is the whole of what §4-A was missing: before it, nothing
/// in the tree could produce an artifact at all, and the only
/// `measured` one anywhere was a fixture. What the operator path
/// produces here is a *real* one — three terms from real fsyncs,
/// real rotations and real replays on a real journal, and eleven
/// written down. Those eleven make a floor that fits this deployment
/// `assumed`; a machine whose measured waits do not fit is `refused`
/// by that exact floor instead. The assertion below derives which
/// answer this run earned from its raw samples, so machine speed can
/// change the grade but cannot change whether the correspondence
/// passes.
#[test]
fn the_probe_writes_an_artifact_this_loader_reads_and_grades() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = write(&dir, &config());
    let assume_path = dir.path().join("assume.json");
    // The three measured slots are overwritten from the artifact
    // before this becomes a budget; they are not assumptions the
    // probe is handed.
    let assumed_budget = MountBudget {
        fsync_tail_ms: 0,
        rotation_tail_ms: 0,
        response_build_ms: 4,
        one_block_fetch_ms: 25,
        fresh_tip_ms: 14,
        close_prepared_fsync_ms: 6,
        rpc_ms: 44,
        response_worker_ms: 9,
        general_worker_ms: 8,
        validation_ms: 3,
        restart_replay_ms_at_cap: 0,
        restart_downtime_ms: 100,
        lower_tail_block_ms: 5_000,
        general_inclusion_blocks: 3,
    };
    fs::write(
        &assume_path,
        serde_json::json!({
            "budget": {
                "response_build_ms": assumed_budget.response_build_ms,
                "one_block_fetch_ms": assumed_budget.one_block_fetch_ms,
                "fresh_tip_ms": assumed_budget.fresh_tip_ms,
                "close_prepared_fsync_ms": assumed_budget.close_prepared_fsync_ms,
                "rpc_ms": assumed_budget.rpc_ms,
                "response_worker_ms": assumed_budget.response_worker_ms,
                "general_worker_ms": assumed_budget.general_worker_ms,
                "validation_ms": assumed_budget.validation_ms,
                "restart_downtime_ms": assumed_budget.restart_downtime_ms,
                "lower_tail_block_ms": assumed_budget.lower_tail_block_ms,
                "general_inclusion_blocks": assumed_budget.general_inclusion_blocks,
            },
            "expected_payment_values": {
                "value": PAYMENT_VALUE,
                "reserve": PAYMENT_RESERVE,
                "base": 0,
                "slot": 0,
                "proof": 0,
                "lifetime": 0,
            },
        })
        .to_string(),
    )
    .unwrap();
    let out = dir.path().join("artifact.json");

    crate::commands::serve::run_probe(crate::commands::serve::ProbeOptions {
        work_config: config_path,
        journal_root: dir.path().join("journals"),
        machine: "bootstrap-1".to_string(),
        assume: assume_path,
        out: out.clone(),
    })
    .expect("the bootstrap run completes and writes its artifact");

    // Pinned by the digest of the bytes the probe wrote, which is
    // what the probe told the operator to pin.
    let bytes = fs::read(&out).expect("the artifact is on the disk");
    let loaded = load(with(
        config(),
        "artifact",
        serde_json::json!({
            "path": out.display().to_string(),
            "digest": hex::encode(Digest::hash(&bytes).as_bytes()),
        }),
    ))
    .expect("the configuration pinning the probe's artifact loads");

    // Derive the grade from the bytes before asking the loader for
    // it. A loaded floor answers to the durations this run actually
    // saw; no duration here is a test threshold.
    let artifact: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let longest = |term: &str| {
        artifact["budget"][term]["samples"]
            .as_array()
            .unwrap_or_else(|| panic!("{term} carries raw samples"))
            .iter()
            .map(|sample| {
                sample["value"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("{term} carries a whole-millisecond sample"))
            })
            .max()
            .unwrap_or_else(|| panic!("{term} carries at least one sample"))
    };
    let measured_budget = MountBudget {
        fsync_tail_ms: longest("fsync_tail_ms"),
        rotation_tail_ms: longest("rotation_tail_ms"),
        restart_replay_ms_at_cap: longest("restart_replay_ms_at_cap"),
        ..assumed_budget
    };
    let expected_grade = measured_budget.floor().and_then(|floor| {
        floor.check_start_span()?;
        floor.check_alarm_margin(loaded.response_alarm_margin_blocks)?;
        Ok(floor)
    });

    let duties = load_paid_work_duties(&loaded).expect("the probe's artifact parses");
    assert!(!duties.admits_paid_work());
    assert_eq!(artifact["provenance"]["machine"], "bootstrap-1");
    let started_at = artifact["provenance"]["started_at_unix_ms"]
        .as_u64()
        .expect("the probe writes a whole-millisecond start");
    let measured_at = artifact["provenance"]["measured_at_unix_ms"]
        .as_u64()
        .expect("the probe writes a whole-millisecond finish");
    assert!(started_at <= measured_at, "the run's own window is one",);
    for term in [
        "fsync_tail_ms",
        "rotation_tail_ms",
        "restart_replay_ms_at_cap",
    ] {
        assert_eq!(artifact["budget"][term]["evidence"], "measured", "{term}");
    }
    for term in [
        "response_build_ms",
        "one_block_fetch_ms",
        "fresh_tip_ms",
        "close_prepared_fsync_ms",
        "rpc_ms",
        "response_worker_ms",
        "general_worker_ms",
        "validation_ms",
        "restart_downtime_ms",
        "lower_tail_block_ms",
        "general_inclusion_blocks",
    ] {
        assert_eq!(artifact["budget"][term]["evidence"], "assumed", "{term}");
    }
    match (expected_grade, duties) {
        (Ok(expected_floor), PaidWorkDuties::Assumed(evidence)) => {
            assert_eq!(evidence.samples, 0, "an assumed field rests on no samples");
            assert_eq!(evidence.provenance.machine, "bootstrap-1");
            assert_eq!(evidence.floor, expected_floor);
        }
        (Err(expected), PaidWorkDuties::Refused(actual)) => {
            assert_eq!(actual, expected, "the loader grades this run's own floor");
        }
        (expected, actual) => {
            panic!("the loader graded the probe as {actual:?}, expected {expected:?}")
        }
    }
}

/// A restarted node rebuilds the endpoint from what serve holds: the
/// configured journal root, the stored identity, and the journals
/// themselves.
///
/// This is the whole of the gap. `SetupStore::open` is keyed by a
/// bond edge and a role, and a `SetupEndpoint` needs a settlement
/// key: the configuration below carries none of the three, the bond
/// edge is recovered from the file, the role from its header, and
/// the key from the identity `identity init` wrote. Re-proposing the
/// retained bond is what proves the rebuilt endpoint is the one that
/// wrote the journal — a different key signs different bytes, and
/// the journal refuses a revision that rewrites the one it holds.
#[test]
fn a_restarted_node_rebuilds_its_endpoint_from_the_root_and_the_identity() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("work-journals");
    let artifact_path = dir.path().join("artifact.json");
    let bytes = artifact().to_string();
    fs::write(&artifact_path, &bytes).unwrap();
    let loaded = load(with(
        with(
            config(),
            "journal",
            serde_json::json!({ "root": root.display().to_string() }),
        ),
        "artifact",
        serde_json::json!({
            "path": artifact_path.display().to_string(),
            "digest": hex::encode(Digest::hash(bytes.as_bytes()).as_bytes()),
        }),
    ))
    .expect("the fixture configuration loads");
    let duties = load_paid_work_duties(&loaded).expect("the pinned artifact is read");

    // The identity `identity init` wrote, and the key it settles
    // with. Nothing in the configuration above names either.
    let identity_path = dir.path().join("identity");
    let identity = crate::identity::load_or_create(Some(&identity_path), true)
        .expect("the operator's identity is created once");
    let settlement = crate::identity::settlement_signer(&identity);
    let terms = bond_terms_staked_by(&settlement);
    let bond_edge = Tx::edge_id_of(&bond_funding(), &Terms::work_stake_bond(terms.clone()));

    // The first process: one setup journal under the configured
    // root, staking the bond this node's own key is the maker of.
    {
        let store = SetupStore::open(
            &loaded.journal_root,
            loaded.chain.network,
            bond_edge,
            Role::Provider,
            &Secp256k1Verifier::new(),
        )
        .expect("the journal opens under the configured root");
        let mut endpoint = SetupEndpoint::new(
            store,
            settlement.clone(),
            duties.payment_admission().expect("an artifact was read"),
        );
        endpoint
            .arm_scan(SetupScan {
                height: 7,
                payload: [0x47; 32],
            })
            .expect("the immutable history floor is armed");
        endpoint
            .propose_bond(loaded.chain.network, bond_funding(), terms.clone())
            .expect("the endpoint signs and journals its bond proposal");
    }

    // The restart: the root and the network, and no bond edge or
    // role anywhere in the configuration to be told them by.
    let found = hellas_rpc::work_store::discover_setups(&loaded.journal_root, loaded.chain.network)
        .expect("the configured root enumerates");
    assert!(found.unidentified.is_empty(), "{:?}", found.unidentified);
    let [discovered] = found.setups.as_slice() else {
        panic!("one journal was written, one is found: {:?}", found.setups);
    };
    assert_eq!(discovered.bond_edge, bond_edge);
    assert_eq!(discovered.role, Role::Provider);

    let store = SetupStore::open(
        &loaded.journal_root,
        loaded.chain.network,
        discovered.bond_edge,
        discovered.role,
        &Secp256k1Verifier::new(),
    )
    .expect("the discovered journal reopens");
    assert_eq!(store.state().revision(), Some(1));
    let mut endpoint = SetupEndpoint::new(
        store,
        crate::identity::settlement_signer(&identity),
        duties.payment_admission().expect("an artifact was read"),
    );

    let state = endpoint
        .propose_bond(loaded.chain.network, bond_funding(), terms)
        .expect("the rebuilt endpoint answers for the journal it reopened");

    assert_eq!(state.revision(), Some(1));
}
