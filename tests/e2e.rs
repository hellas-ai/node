use commonware_codec::{Decode, Encode};
use commonware_consensus::elector::RoundRobin;
use commonware_consensus::minimmit::{
    mocks::reporter::{Config as ReporterConfig, Reporter as MockReporter},
    scheme::ed25519 as minimmit_ed25519,
    types::Finalization,
};
use commonware_consensus::types::View;
use commonware_cryptography::Signer;
use commonware_cryptography::certificate::{Scheme as _, mocks::Fixture};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, Metrics, Quota, Runner, deterministic};
use commonware_storage::{
    qmdb::current::unordered::fixed::Db as FixedUtxoDb, translator::EightCap,
};
use hellas_chain::config::Config;
use hellas_chain::engine::Engine;
use hellas_chain::object::{
    Coin, GENESIS_BALANCE, Transaction, genesis_object_id, output_object_id,
};
use hellas_chain::shard::AuthenticatedShardTransport;
use hellas_types::{Activity, PrivateKey, PublicKey, Scheme};
use rand::rngs::OsRng;
use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};

const NAMESPACE: &[u8] = b"hellas-e2e";
const N: u32 = 6;

type Finalizations = Arc<std::sync::Mutex<HashMap<View, Finalization<Scheme, Digest>>>>;
type Faults =
    Arc<std::sync::Mutex<HashMap<PublicKey, HashMap<View, std::collections::HashSet<Activity>>>>>;
type ProofVerifierDb = FixedUtxoDb<deterministic::Context, Digest, Coin, Sha256, EightCap, 32>;

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

#[derive(Clone, Copy)]
struct SubmitTransfer {
    sender: usize,
    recipient: usize,
    amount: u64,
}

fn assert_sustained_progress(
    scenario: &str,
    handles: &[(Finalizations, Faults)],
    min_per_validator: usize,
    min_total: usize,
    min_validators_at_or_above: usize,
) {
    let per_validator_finalizations: Vec<usize> = handles
        .iter()
        .map(|(finalizations, _)| finalizations.lock().unwrap().len())
        .collect();
    let total_finalizations: usize = per_validator_finalizations.iter().sum();
    let validators_at_or_above = per_validator_finalizations
        .iter()
        .filter(|count| **count >= min_per_validator)
        .count();

    println!(
        "{scenario} sustained progress: total_finalizations={total_finalizations}, per_validator_finalizations={per_validator_finalizations:?}, min_per_validator={min_per_validator}, min_total={min_total}, min_validators_at_or_above={min_validators_at_or_above}, validators_at_or_above={validators_at_or_above}"
    );
    assert!(
        total_finalizations >= min_total,
        "{scenario}: expected sustained progress with total_finalizations >= {min_total}, got {total_finalizations}"
    );
    assert!(
        validators_at_or_above >= min_validators_at_or_above,
        "{scenario}: expected at least {min_validators_at_or_above} validators to reach {min_per_validator} finalizations, got {validators_at_or_above} (per-validator {per_validator_finalizations:?})"
    );
}

fn run_network(
    config: Config,
    link: Link,
    duration: Duration,
    transfer: Option<SubmitTransfer>,
) -> Vec<(Finalizations, Faults)> {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));

    let handles: Arc<std::sync::Mutex<Vec<(Finalizations, Faults)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let handles_ref = handles.clone();

    runner.start(|mut context| async move {
        let (network, oracle) = Network::new(
            context.with_label("network"),
            NetworkConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: None,
            },
        );
        network.start();

        let Fixture {
            participants,
            schemes,
            private_keys,
            ..
        }: Fixture<Scheme> = minimmit_ed25519::fixture(&mut context, NAMESPACE, N);

        let quota = Quota::per_second(NonZeroU32::MAX);
        let mut registrations = HashMap::new();
        for validator in participants.iter() {
            let control = oracle.control(validator.clone());
            let vote = control.register(0, quota).await.unwrap();
            let certificate = control.register(1, quota).await.unwrap();
            let resolver = control.register(2, quota).await.unwrap();
            let shard = control.register(3, quota).await.unwrap();
            registrations.insert(validator.clone(), (vote, certificate, resolver, shard));
        }

        for v1 in participants.iter() {
            for v2 in participants.iter() {
                if v1 != v2 {
                    oracle
                        .add_link(v1.clone(), v2.clone(), link.clone())
                        .await
                        .unwrap();
                }
            }
        }

        let mut tx_mailboxes = Vec::new();
        for (idx, validator) in participants.iter().enumerate() {
            let ctx = context.with_label(&format!("validator_{idx}"));
            let blocker = oracle.control(validator.clone());

            let reporter = MockReporter::new(
                context.clone(),
                ReporterConfig {
                    participants: schemes[idx].participants().clone(),
                    scheme: schemes[idx].clone(),
                    elector: RoundRobin::<Sha256>::default(),
                },
            );
            handles
                .lock()
                .unwrap()
                .push((reporter.finalizations.clone(), reporter.faults.clone()));

            let (vote, certificate, resolver, (shard_sender, shard_receiver)) = registrations
                .remove(validator)
                .expect("validator should be registered");
            let relay = Arc::new(AuthenticatedShardTransport::new(
                validator,
                shard_sender,
                shard_receiver,
            ));
            for participant in participants.iter() {
                relay.declare(participant);
            }
            relay.finalize_validators();
            let _shard_transport = relay.clone().start(context.clone());

            let (engine, tx_mailbox) = Engine::new(
                ctx,
                config,
                schemes[idx].clone(),
                blocker,
                relay,
                validator,
                reporter,
            );
            tx_mailboxes.push(tx_mailbox);
            engine.start(vote, certificate, resolver);
        }

        if let Some(transfer) = transfer {
            let sender_key: PrivateKey = private_keys[transfer.sender].clone();
            let sender_pk = sender_key.public_key();
            let recipient_pk = participants[transfer.recipient].clone();
            let mut app_validators: Vec<PublicKey> =
                schemes[0].participants().iter().cloned().collect();
            app_validators.sort();
            let sender_index = app_validators
                .binary_search(&sender_pk)
                .expect("sender must exist in validator set");
            let input =
                genesis_object_id(u16::try_from(sender_index).expect("sender index in u16"));
            let tx =
                Transaction::transfer(&sender_key, input, recipient_pk.clone(), transfer.amount);
            let tx_digest = Sha256::hash(&tx.encode());
            let recipient_output = output_object_id(&tx_digest, 0);
            let change_output = output_object_id(&tx_digest, 1);
            for mailbox in tx_mailboxes.clone() {
                mailbox.submit_tx(tx.clone()).await;
            }

            context.sleep(duration).await;

            let finalized_payloads = {
                let handles = handles.lock().unwrap();
                let (finalizations, _) = &handles[0];
                let finalizations = finalizations.lock().unwrap();
                let mut views: Vec<_> = finalizations.keys().cloned().collect();
                views.sort();
                views
                    .into_iter()
                    .filter_map(|view| finalizations.get(&view).map(|f| f.proposal.payload))
                    .collect::<Vec<_>>()
            };
            assert!(
                !finalized_payloads.is_empty(),
                "expected at least one finalization before state assertions"
            );

            let mut matched_payload = None;
            for payload in finalized_payloads.iter().copied() {
                let mailbox = tx_mailboxes[0].clone();
                let Some(coin) = mailbox.get_coin(payload, recipient_output).await else {
                    continue;
                };
                if coin.owner == recipient_pk && coin.value == transfer.amount {
                    matched_payload = Some(payload);
                    break;
                }
            }

            let payload = matched_payload
                .expect("submitted transfer was not observed in any finalized payload state");

            let expected_recipient = Coin {
                owner: recipient_pk.clone(),
                value: transfer.amount,
            };
            let expected_change = Coin {
                owner: sender_pk.clone(),
                value: GENESIS_BALANCE - transfer.amount,
            };

            for mailbox in &tx_mailboxes {
                assert_eq!(
                    mailbox.get_coin(payload, recipient_output).await,
                    Some(expected_recipient.clone()),
                    "recipient output missing in finalized state"
                );
                assert_eq!(
                    mailbox.get_coin(payload, input).await,
                    None,
                    "sender input should be consumed in finalized state"
                );
                assert_eq!(
                    mailbox.get_coin(payload, change_output).await,
                    Some(expected_change.clone()),
                    "change output missing in finalized state"
                );
            }

            // E2E retrieval checks:
            // 1) retrieve and verify the finalized certificate bytes,
            // 2) retrieve a root and proof and verify QMDB proof validity.
            //
            // NOTE: This test does NOT assert a full trust chain between the certificate and
            // returned state root. Under lagged-anchor, proofs are anchored to persisted state
            // roots tracked separately from the finalized payload certificate.
            let validator_mailbox = tx_mailboxes[0].clone();
            let mut cert = None;
            for _ in 0..50 {
                if let Ok(Some(bytes)) = validator_mailbox.get_finalization(payload).await {
                    cert = Some(bytes);
                    break;
                }
                context.sleep(Duration::from_millis(100)).await;
            }
            let cert = cert.expect("expected persisted finalization certificate for payload");

            let finalization = Finalization::<Scheme, Digest>::decode_cfg(
                cert.as_slice(),
                &schemes[0].participants().len(),
            )
            .expect("finalization certificate should decode");
            assert_eq!(
                finalization.proposal.payload, payload,
                "certificate must match finalized payload"
            );
            assert!(
                finalization.verify(&mut OsRng, &schemes[0], &Sequential),
                "finalization certificate should verify"
            );

            let mut proof_verified_against_reported_root = false;
            for _ in 0..50 {
                let Some(root) = validator_mailbox
                    .get_state_root()
                    .await
                    .expect("state root request should not fail")
                else {
                    context.sleep(Duration::from_millis(100)).await;
                    continue;
                };
                let Some(proof) = validator_mailbox
                    .get_proof(recipient_output)
                    .await
                    .expect("proof request should not fail")
                else {
                    context.sleep(Duration::from_millis(100)).await;
                    continue;
                };

                let mut hasher = Sha256::default();
                if ProofVerifierDb::verify_key_value_proof(
                    &mut hasher,
                    recipient_output,
                    expected_recipient.clone(),
                    &proof,
                    &root,
                ) {
                    proof_verified_against_reported_root = true;
                    break;
                }
                context.sleep(Duration::from_millis(100)).await;
            }
            assert!(
                proof_verified_against_reported_root,
                "expected recipient coin proof to verify against a persisted root"
            );
            return;
        }

        context.sleep(duration).await;
    });

    Arc::try_unwrap(handles_ref)
        .expect("runner finished")
        .into_inner()
        .unwrap()
}

#[test_log::test]
fn healthy_network_finalizes() {
    let duration_secs = env_u64("E2E_HEALTHY_DURATION_SECS", 12);
    let min_per_validator = env_usize("E2E_HEALTHY_MIN_PER_VALIDATOR", 12);
    let min_validators = env_usize("E2E_HEALTHY_MIN_VALIDATORS", N as usize);
    let min_total = env_usize("E2E_HEALTHY_MIN_TOTAL", min_per_validator * min_validators);
    let link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    let handles = run_network(
        Config::test(),
        link,
        Duration::from_secs(duration_secs),
        None,
    );
    assert_sustained_progress(
        "healthy",
        &handles,
        min_per_validator,
        min_total,
        min_validators,
    );

    for (_, faults) in &handles {
        let faults = faults.lock().unwrap();
        assert!(faults.is_empty(), "unexpected faults detected");
    }
}

#[test_log::test]
fn lossy_network_finalizes() {
    let success_rate = env_f64("E2E_LOSSY_SUCCESS_RATE", 0.9);
    let duration_secs = env_u64("E2E_LOSSY_DURATION_SECS", 10);
    let default_min_validators = (N as usize).saturating_mul(2) / 3;
    let min_per_validator = env_usize("E2E_LOSSY_MIN_PER_VALIDATOR", 8);
    let min_validators = env_usize("E2E_LOSSY_MIN_VALIDATORS", default_min_validators);
    let min_total = env_usize("E2E_LOSSY_MIN_TOTAL", min_per_validator * min_validators);
    let link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(5),
        success_rate,
    };

    let handles = run_network(
        Config::test(),
        link,
        Duration::from_secs(duration_secs),
        None,
    );

    let per_validator_finalizations: Vec<usize> = handles
        .iter()
        .map(|(finalizations, _)| finalizations.lock().unwrap().len())
        .collect();
    let per_validator_fault_views: Vec<usize> = handles
        .iter()
        .map(|(_, faults)| {
            faults
                .lock()
                .unwrap()
                .values()
                .map(HashMap::len)
                .sum::<usize>()
        })
        .collect();
    println!(
        "lossy e2e summary: success_rate={success_rate:.3}, duration_secs={duration_secs}, per_validator_finalizations={per_validator_finalizations:?}, per_validator_fault_views={per_validator_fault_views:?}"
    );
    assert_sustained_progress(
        "lossy",
        &handles,
        min_per_validator,
        min_total,
        min_validators,
    );
}

#[test_log::test]
fn submitted_transfer_network_finalizes() {
    let duration_secs = env_u64("E2E_TRANSFER_DURATION_SECS", 10);
    let min_per_validator = env_usize("E2E_TRANSFER_MIN_PER_VALIDATOR", 8);
    let min_validators = env_usize("E2E_TRANSFER_MIN_VALIDATORS", N as usize);
    let min_total = env_usize("E2E_TRANSFER_MIN_TOTAL", min_per_validator * min_validators);
    let link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    let handles = run_network(
        Config::test(),
        link,
        Duration::from_secs(duration_secs),
        Some(SubmitTransfer {
            sender: 0,
            recipient: 1,
            amount: 1,
        }),
    );
    assert_sustained_progress(
        "submitted_transfer",
        &handles,
        min_per_validator,
        min_total,
        min_validators,
    );
}
