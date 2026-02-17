use commonware_codec::{Decode, Encode};
use commonware_consensus::elector::RoundRobin;
use commonware_consensus::minimmit::{
    mocks::reporter::{Config as ReporterConfig, Reporter as MockReporter},
    scheme::ed25519 as minimmit_ed25519,
    types::{Finalization, Nullification},
};
use commonware_consensus::types::View;
use commonware_cryptography::Signer;
use commonware_cryptography::certificate::{Scheme as _, mocks::Fixture};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, Handle, Metrics, Quota, Runner, deterministic};
use commonware_storage::{
    qmdb::current::unordered::fixed::Db as FixedUtxoDb, translator::EightCap,
};
use hellas_chain::config::Config;
use hellas_chain::engine::Engine;
use hellas_types::{
    Address, Coin, GENESIS_BALANCE, Transaction, genesis_object_id, output_object_id,
};
use hellas_chain::shard::AuthenticatedShardTransport;
use hellas_types::{Activity, PrivateKey, PublicKey, Scheme};
use rand::rngs::OsRng;
use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};

const NAMESPACE: &[u8] = b"hellas-e2e";
const N: u32 = 6;

type Finalizations = Arc<std::sync::Mutex<HashMap<View, Finalization<Scheme, Digest>>>>;
type Nullifications = Arc<std::sync::Mutex<HashMap<View, Nullification<Scheme>>>>;
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

fn env_f32(name: &str, default: f32) -> f32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<f32>().ok())
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
    handles: &[(Finalizations, Faults, Nullifications)],
    min_per_validator: usize,
    min_total: usize,
    min_validators_at_or_above: usize,
) {
    let per_validator_finalizations: Vec<usize> = handles
        .iter()
        .map(|(finalizations, _, _)| finalizations.lock().unwrap().len())
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

fn per_validator_nullifications(handles: &[(Finalizations, Faults, Nullifications)]) -> Vec<usize> {
    handles
        .iter()
        .map(|(_, _, nullifications)| nullifications.lock().unwrap().len())
        .collect()
}

fn run_network(
    config: Config,
    link: Link,
    duration: Duration,
    transfer: Option<SubmitTransfer>,
) -> Vec<(Finalizations, Faults, Nullifications)> {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));

    let handles: Arc<std::sync::Mutex<Vec<(Finalizations, Faults, Nullifications)>>> =
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
            handles.lock().unwrap().push((
                reporter.finalizations.clone(),
                reporter.faults.clone(),
                reporter.nullifications.clone(),
            ));

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

            let (engine, tx_mailbox, _activity_tx) = Engine::new(
                ctx,
                config,
                schemes[idx].clone(),
                blocker,
                relay.clone(),
                validator,
                reporter,
            );
            let _shard_transport = relay.start(context.clone());
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
                Transaction::transfer(&sender_key, input, Address::from(recipient_pk.clone()), transfer.amount);
            let tx_digest = Sha256::hash(&tx.encode());
            let recipient_output = output_object_id(&tx_digest, 0);
            let change_output = output_object_id(&tx_digest, 1);
            for mailbox in tx_mailboxes.clone() {
                mailbox.submit_tx(tx.clone()).await;
            }

            context.sleep(duration).await;

            let finalized_payloads = {
                let handles = handles.lock().unwrap();
                let (finalizations, _, _) = &handles[0];
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
                if coin.owner == Address::from(recipient_pk.clone()) && coin.value == transfer.amount {
                    matched_payload = Some(payload);
                    break;
                }
            }

            let payload = matched_payload
                .expect("submitted transfer was not observed in any finalized payload state");

            let expected_recipient = Coin {
                owner: Address::from(recipient_pk.clone()),
                value: transfer.amount,
            };
            let expected_change = Coin {
                owner: Address::from(sender_pk.clone()),
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

    for (_, faults, _) in &handles {
        let faults = faults.lock().unwrap();
        assert!(faults.is_empty(), "unexpected faults detected");
    }

    let per_validator_nullifications = per_validator_nullifications(&handles);
    let total_nullifications: usize = per_validator_nullifications.iter().sum();
    let max_nullifications_per_validator =
        env_usize("E2E_HEALTHY_MAX_NULLIFICATIONS_PER_VALIDATOR", 1);
    let max_total_nullifications = env_usize(
        "E2E_HEALTHY_MAX_TOTAL_NULLIFICATIONS",
        max_nullifications_per_validator * handles.len(),
    );
    println!(
        "healthy nullification summary: total_nullifications={total_nullifications}, per_validator_nullifications={per_validator_nullifications:?}, max_per_validator={max_nullifications_per_validator}, max_total={max_total_nullifications}"
    );
    assert!(
        total_nullifications <= max_total_nullifications,
        "healthy: total nullifications too high (total_nullifications={total_nullifications}, max_total={max_total_nullifications}, per-validator {per_validator_nullifications:?})"
    );
    assert!(
        per_validator_nullifications
            .iter()
            .all(|count| *count <= max_nullifications_per_validator),
        "healthy: per-validator nullifications too high (per-validator {per_validator_nullifications:?}, max_per_validator={max_nullifications_per_validator})"
    );
}

#[test_log::test]
fn lossy_network_finalizes() {
    let success_rate = env_f64("E2E_LOSSY_SUCCESS_RATE", 0.90);
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
        .map(|(finalizations, _, _)| finalizations.lock().unwrap().len())
        .collect();
    let per_validator_fault_views: Vec<usize> = handles
        .iter()
        .map(|(_, faults, _)| {
            faults
                .lock()
                .unwrap()
                .values()
                .map(HashMap::len)
                .sum::<usize>()
        })
        .collect();
    let per_validator_nullifications = per_validator_nullifications(&handles);
    let total_finalizations: usize = per_validator_finalizations.iter().sum();
    let total_nullifications: usize = per_validator_nullifications.iter().sum();
    let max_nullification_ratio = env_f32("E2E_LOSSY_MAX_NULLIFICATION_RATIO", 1.5);
    println!(
        "lossy e2e summary: success_rate={success_rate:.3}, duration_secs={duration_secs}, per_validator_finalizations={per_validator_finalizations:?}, per_validator_nullifications={per_validator_nullifications:?}, per_validator_fault_views={per_validator_fault_views:?}"
    );
    assert_sustained_progress(
        "lossy",
        &handles,
        min_per_validator,
        min_total,
        min_validators,
    );
    let max_allowed_nullifications =
        ((total_finalizations as f32) * max_nullification_ratio).ceil() as usize;
    assert!(
        total_nullifications <= max_allowed_nullifications,
        "lossy: nullifications too high (total_nullifications={total_nullifications}, total_finalizations={total_finalizations}, ratio_limit={max_nullification_ratio})"
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

#[test_log::test]
fn node_recovers_after_disconnect() {
    let link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    let config = Config::test();
    let target = 0usize;

    let runner = deterministic::Runner::timed(Duration::from_secs(120));

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

        let mut handles: Vec<(Finalizations, Faults, Nullifications)> = Vec::new();
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
            handles.push((
                reporter.finalizations.clone(),
                reporter.faults.clone(),
                reporter.nullifications.clone(),
            ));

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

            let (engine, _tx_mailbox, _activity_tx) = Engine::new(
                ctx,
                config,
                schemes[idx].clone(),
                blocker,
                relay.clone(),
                validator,
                reporter,
            );
            let _shard_transport = relay.start(context.clone());
            engine.start(vote, certificate, resolver);
        }

        // ── Phase 1: Baseline ──────────────────────────────────────────
        context.sleep(Duration::from_secs(5)).await;

        let phase1_counts: Vec<usize> = handles
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();
        println!("recovery phase 1 (baseline): finalizations={phase1_counts:?}");
        for (i, count) in phase1_counts.iter().enumerate() {
            assert!(
                *count > 0,
                "recovery phase 1: validator {i} has no finalizations"
            );
        }

        // ── Phase 2: Disconnect target node ────────────────────────────
        for (i, peer) in participants.iter().enumerate() {
            if i != target {
                oracle
                    .remove_link(participants[target].clone(), peer.clone())
                    .await
                    .unwrap();
                oracle
                    .remove_link(peer.clone(), participants[target].clone())
                    .await
                    .unwrap();
            }
        }

        let pre_disconnect_counts: Vec<usize> = handles
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();

        context.sleep(Duration::from_secs(5)).await;

        let phase2_counts: Vec<usize> = handles
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();
        let phase2_gains: Vec<usize> = phase2_counts
            .iter()
            .zip(pre_disconnect_counts.iter())
            .map(|(now, before)| now.saturating_sub(*before))
            .collect();
        println!(
            "recovery phase 2 (node {target} offline): finalizations={phase2_counts:?}, gains={phase2_gains:?}"
        );

        // Connected nodes (all except target) should have gained new finalizations.
        let connected_with_progress = phase2_gains
            .iter()
            .enumerate()
            .filter(|(i, gain)| *i != target && **gain > 0)
            .count();
        assert!(
            connected_with_progress >= 4,
            "recovery phase 2: expected at least 4 connected nodes to progress, got {connected_with_progress} (gains={phase2_gains:?})"
        );

        // ── Phase 3: Disconnect second node (should halt finalization) ─
        // With 2 of 6 offline, only 4 remain — below the supermajority
        // threshold, so no new views should finalize.
        let target2 = 3usize;
        for (i, peer) in participants.iter().enumerate() {
            // Skip self and skip target (its links were already removed in phase 2).
            if i == target2 || i == target {
                continue;
            }
            oracle
                .remove_link(participants[target2].clone(), peer.clone())
                .await
                .unwrap();
            oracle
                .remove_link(peer.clone(), participants[target2].clone())
                .await
                .unwrap();
        }

        let pre_halt_counts: Vec<usize> = handles
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();

        context.sleep(Duration::from_secs(5)).await;

        let phase3_counts: Vec<usize> = handles
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();
        let phase3_gains: Vec<usize> = phase3_counts
            .iter()
            .zip(pre_halt_counts.iter())
            .map(|(now, before)| now.saturating_sub(*before))
            .collect();
        let phase3_total_gain: usize = phase3_gains.iter().sum();
        println!(
            "recovery phase 3 (2 nodes offline, expect halt): finalizations={phase3_counts:?}, gains={phase3_gains:?}, total_gain={phase3_total_gain}"
        );

        // With only 4/6 online, finalization should have stopped (or nearly).
        // Allow a small tolerance for in-flight messages at the moment of disconnect.
        assert!(
            phase3_total_gain <= 6,
            "recovery phase 3: expected finalization to halt with 2 nodes offline, but total gain was {phase3_total_gain} (gains={phase3_gains:?})"
        );

        // ── Phase 4: Reconnect first target (restore 5/6 → resume) ────
        // Re-add bidirectional links between target and all online peers.
        // Skip target2 which is still offline.
        for (i, peer) in participants.iter().enumerate() {
            if i == target || i == target2 {
                continue;
            }
            oracle
                .add_link(participants[target].clone(), peer.clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(peer.clone(), participants[target].clone(), link.clone())
                .await
                .unwrap();
        }

        let pre_resume_counts: Vec<usize> = handles
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();

        context.sleep(Duration::from_secs(8)).await;

        let phase4_counts: Vec<usize> = handles
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();
        let phase4_gains: Vec<usize> = phase4_counts
            .iter()
            .zip(pre_resume_counts.iter())
            .map(|(now, before)| now.saturating_sub(*before))
            .collect();
        println!(
            "recovery phase 4 (5/6 restored): finalizations={phase4_counts:?}, gains={phase4_gains:?}"
        );

        // The reconnected first target should have caught up.
        assert!(
            phase4_gains[target] > 0,
            "recovery phase 4: node {target} did not recover after reconnect (gain=0, total={})",
            phase4_counts[target]
        );

        // At least 4 of the 5 online nodes should have gained new finalizations.
        let online_with_progress = phase4_gains
            .iter()
            .enumerate()
            .filter(|(i, gain)| *i != target2 && **gain > 0)
            .count();
        assert!(
            online_with_progress >= 4,
            "recovery phase 4: expected at least 4 online nodes to resume progress, got {online_with_progress} (gains={phase4_gains:?})"
        );

        // ── Phase 5: Reconnect second target, all 6 progress together ──
        // Bring all 6 nodes back online and verify they all gain
        // finalizations at the same rate (proving full sync recovery).
        // Total counts won't converge because missed views are not
        // retroactively reported, but the *rate* of new finalizations
        // should be equal across all nodes.
        for (i, peer) in participants.iter().enumerate() {
            if i == target2 || i == target {
                continue;
            }
            oracle
                .add_link(participants[target2].clone(), peer.clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(peer.clone(), participants[target2].clone(), link.clone())
                .await
                .unwrap();
        }
        // Also restore the link between the two previously-offline nodes.
        oracle
            .add_link(participants[target].clone(), participants[target2].clone(), link.clone())
            .await
            .unwrap();
        oracle
            .add_link(participants[target2].clone(), participants[target].clone(), link.clone())
            .await
            .unwrap();

        // Let all nodes settle and start progressing together.
        context.sleep(Duration::from_secs(3)).await;

        // Snapshot, wait, then check that all 6 gained equally.
        let pre_phase5: Vec<usize> = handles
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();

        context.sleep(Duration::from_secs(5)).await;

        let phase5_counts: Vec<usize> = handles
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();
        let phase5_gains: Vec<usize> = phase5_counts
            .iter()
            .zip(pre_phase5.iter())
            .map(|(now, before)| now.saturating_sub(*before))
            .collect();
        let min_gain = *phase5_gains.iter().min().unwrap();
        let max_gain = *phase5_gains.iter().max().unwrap();
        println!(
            "recovery phase 5 (all 6 back): finalizations={phase5_counts:?}, gains={phase5_gains:?}, spread={}",
            max_gain - min_gain
        );

        // Every node should have gained new finalizations.
        for (i, gain) in phase5_gains.iter().enumerate() {
            assert!(
                *gain > 0,
                "recovery phase 5: node {i} made no progress (gains={phase5_gains:?})"
            );
        }

        // All nodes should be progressing at the same rate (spread ≤ 1).
        assert!(
            max_gain - min_gain <= 1,
            "recovery phase 5: nodes progressing at different rates, spread={} (gains={phase5_gains:?})",
            max_gain - min_gain
        );
    });
}

#[test_log::test]
fn cluster_resumes_after_unclean_restart() {
    let link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    let config = Config::test();

    let runner = deterministic::Runner::timed(Duration::from_secs(120));

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
            ..
        }: Fixture<Scheme> = minimmit_ed25519::fixture(&mut context, NAMESPACE, N);

        let quota = Quota::per_second(NonZeroU32::MAX);

        // Add links between all peers.
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

        // ── Phase 1: Start initial cluster (gen1) and run until finalization
        let mut handles_gen1 = Vec::new();
        let mut tracking_gen1: Vec<(Finalizations, Faults, Nullifications)> = Vec::new();
        {
            let mut registrations = HashMap::new();
            for validator in participants.iter() {
                let control = oracle.control(validator.clone());
                let vote = control.register(0, quota).await.unwrap();
                let certificate = control.register(1, quota).await.unwrap();
                let resolver = control.register(2, quota).await.unwrap();
                let shard = control.register(3, quota).await.unwrap();
                registrations.insert(validator.clone(), (vote, certificate, resolver, shard));
            }

            for (idx, validator) in participants.iter().enumerate() {
                let ctx = context.with_label(&format!("v{idx}_gen1"));
                let blocker = oracle.control(validator.clone());

                let reporter = MockReporter::new(
                    context.clone(),
                    ReporterConfig {
                        participants: schemes[idx].participants().clone(),
                        scheme: schemes[idx].clone(),
                        elector: RoundRobin::<Sha256>::default(),
                    },
                );
                tracking_gen1.push((
                    reporter.finalizations.clone(),
                    reporter.faults.clone(),
                    reporter.nullifications.clone(),
                ));

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

                let (engine, _tx_mailbox, _activity_tx) = Engine::new(
                    ctx,
                    config,
                    schemes[idx].clone(),
                    blocker,
                    relay.clone(),
                    validator,
                    reporter,
                );
                let _shard_transport = relay.start(context.clone());
                handles_gen1.push(engine.start(vote, certificate, resolver));
            }
        }

        context.sleep(Duration::from_secs(5)).await;

        let phase1_counts: Vec<usize> = tracking_gen1
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();
        println!("restart phase 1 (baseline): finalizations={phase1_counts:?}");
        for (i, count) in phase1_counts.iter().enumerate() {
            assert!(
                *count > 0,
                "restart phase 1: validator {i} has no finalizations"
            );
        }

        // ── Phase 2: Abort all engines (simulating unclean crash) ─────────
        for handle in handles_gen1 {
            handle.abort();
        }
        // Let aborted tasks settle and resources release.
        context.sleep(Duration::from_secs(1)).await;

        // ── Phase 3: Restart all engines (gen2) with fresh network channels
        // Remove and re-add links to get fresh channel pairs.
        for v1 in participants.iter() {
            for v2 in participants.iter() {
                if v1 != v2 {
                    let _ = oracle.remove_link(v1.clone(), v2.clone()).await;
                }
            }
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

        let mut tracking_gen2: Vec<(Finalizations, Faults, Nullifications)> = Vec::new();
        {
            let mut registrations = HashMap::new();
            for validator in participants.iter() {
                let control = oracle.control(validator.clone());
                let vote = control.register(0, quota).await.unwrap();
                let certificate = control.register(1, quota).await.unwrap();
                let resolver = control.register(2, quota).await.unwrap();
                let shard = control.register(3, quota).await.unwrap();
                registrations.insert(validator.clone(), (vote, certificate, resolver, shard));
            }

            for (idx, validator) in participants.iter().enumerate() {
                let ctx = context.with_label(&format!("v{idx}_gen2"));
                let blocker = oracle.control(validator.clone());

                let reporter = MockReporter::new(
                    context.clone(),
                    ReporterConfig {
                        participants: schemes[idx].participants().clone(),
                        scheme: schemes[idx].clone(),
                        elector: RoundRobin::<Sha256>::default(),
                    },
                );
                tracking_gen2.push((
                    reporter.finalizations.clone(),
                    reporter.faults.clone(),
                    reporter.nullifications.clone(),
                ));

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

                let (engine, _tx_mailbox, _activity_tx) = Engine::new(
                    ctx,
                    config,
                    schemes[idx].clone(),
                    blocker,
                    relay.clone(),
                    validator,
                    reporter,
                );
                let _shard_transport = relay.start(context.clone());
                engine.start(vote, certificate, resolver);
            }
        }

        // ── Phase 4: Verify cluster resumes finalizing ────────────────────
        context.sleep(Duration::from_secs(15)).await;

        let phase4_counts: Vec<usize> = tracking_gen2
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();
        let total_gen2: usize = phase4_counts.iter().sum();
        println!("restart phase 4 (after restart): finalizations={phase4_counts:?}, total={total_gen2}");

        let validators_with_progress = phase4_counts.iter().filter(|c| **c > 0).count();
        assert!(
            validators_with_progress >= 5,
            "restart phase 4: expected at least 5 validators to finalize after restart, got {validators_with_progress} (counts={phase4_counts:?})"
        );
        assert!(
            total_gen2 >= 20,
            "restart phase 4: expected at least 20 total finalizations after restart, got {total_gen2} (counts={phase4_counts:?})"
        );
    });
}

/// Stops a single node while the rest of the cluster continues, then
/// restarts it.  Verifies the restarted node catches up AND can propose
/// blocks that get finalized (i.e. it doesn't just notarize others' blocks
/// but actively leads rounds).
#[test_log::test]
fn single_node_restarts_and_proposes() {
    let link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    let config = Config::test();
    let target = 0usize;

    let runner = deterministic::Runner::timed(Duration::from_secs(120));

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
            ..
        }: Fixture<Scheme> = minimmit_ed25519::fixture(&mut context, NAMESPACE, N);

        let quota = Quota::per_second(NonZeroU32::MAX);

        // Add links between all peers.
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

        // ── Phase 1: Start cluster (gen1) and run until finalization
        let mut engine_handles: Vec<Handle<()>> = Vec::new();
        let mut tracking: Vec<(Finalizations, Faults, Nullifications)> = Vec::new();
        {
            let mut registrations = HashMap::new();
            for validator in participants.iter() {
                let control = oracle.control(validator.clone());
                let vote = control.register(0, quota).await.unwrap();
                let certificate = control.register(1, quota).await.unwrap();
                let resolver = control.register(2, quota).await.unwrap();
                let shard = control.register(3, quota).await.unwrap();
                registrations.insert(validator.clone(), (vote, certificate, resolver, shard));
            }

            for (idx, validator) in participants.iter().enumerate() {
                let ctx = context.with_label(&format!("v{idx}_gen1"));
                let blocker = oracle.control(validator.clone());

                let reporter = MockReporter::new(
                    context.clone(),
                    ReporterConfig {
                        participants: schemes[idx].participants().clone(),
                        scheme: schemes[idx].clone(),
                        elector: RoundRobin::<Sha256>::default(),
                    },
                );
                tracking.push((
                    reporter.finalizations.clone(),
                    reporter.faults.clone(),
                    reporter.nullifications.clone(),
                ));

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

                let (engine, _tx_mailbox, _activity_tx) = Engine::new(
                    ctx,
                    config,
                    schemes[idx].clone(),
                    blocker,
                    relay.clone(),
                    validator,
                    reporter,
                );
                let _shard_transport = relay.start(context.clone());
                engine_handles.push(engine.start(vote, certificate, resolver));
            }
        }

        context.sleep(Duration::from_secs(5)).await;

        let phase1_counts: Vec<usize> = tracking
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();
        println!("single-restart phase 1 (baseline): finalizations={phase1_counts:?}");
        for (i, count) in phase1_counts.iter().enumerate() {
            assert!(
                *count > 0,
                "single-restart phase 1: validator {i} has no finalizations"
            );
        }

        // ── Phase 2: Abort target node (simulating unclean crash) ─────
        engine_handles[target].abort();

        // Remove target's links so the old channels become inert.
        for (i, peer) in participants.iter().enumerate() {
            if i != target {
                let _ = oracle
                    .remove_link(participants[target].clone(), peer.clone())
                    .await;
                let _ = oracle
                    .remove_link(peer.clone(), participants[target].clone())
                    .await;
            }
        }

        // Let remaining 5 nodes continue for several rounds.
        context.sleep(Duration::from_secs(5)).await;

        let phase2_counts: Vec<usize> = tracking
            .iter()
            .map(|(f, _, _)| f.lock().unwrap().len())
            .collect();
        let phase2_gains: Vec<usize> = phase2_counts
            .iter()
            .zip(phase1_counts.iter())
            .map(|(now, before)| now.saturating_sub(*before))
            .collect();
        println!(
            "single-restart phase 2 (target {target} offline): finalizations={phase2_counts:?}, gains={phase2_gains:?}"
        );

        // Connected nodes should progress (target may still observe some in-flight).
        let connected_with_progress = phase2_gains
            .iter()
            .enumerate()
            .filter(|(i, gain)| *i != target && **gain > 0)
            .count();
        assert!(
            connected_with_progress >= 4,
            "single-restart phase 2: expected at least 4 connected nodes to progress, got {connected_with_progress}"
        );

        // ── Phase 3: Restart target with fresh network channels ────────
        // Re-add links from target to all other peers.
        for (i, peer) in participants.iter().enumerate() {
            if i != target {
                oracle
                    .add_link(participants[target].clone(), peer.clone(), link.clone())
                    .await
                    .unwrap();
                oracle
                    .add_link(peer.clone(), participants[target].clone(), link.clone())
                    .await
                    .unwrap();
            }
        }

        let mut registrations = HashMap::new();
        {
            let control = oracle.control(participants[target].clone());
            let vote = control.register(0, quota).await.unwrap();
            let certificate = control.register(1, quota).await.unwrap();
            let resolver = control.register(2, quota).await.unwrap();
            let shard = control.register(3, quota).await.unwrap();
            registrations.insert(
                participants[target].clone(),
                (vote, certificate, resolver, shard),
            );
        }

        // Create a fresh reporter for the restarted node.
        let reporter_gen2 = MockReporter::new(
            context.clone(),
            ReporterConfig {
                participants: schemes[target].participants().clone(),
                scheme: schemes[target].clone(),
                elector: RoundRobin::<Sha256>::default(),
            },
        );
        let gen2_finalizations = reporter_gen2.finalizations.clone();
        let gen2_nullifications = reporter_gen2.nullifications.clone();

        let (vote, certificate, resolver, (shard_sender, shard_receiver)) = registrations
            .remove(&participants[target])
            .expect("target should be registered");
        let relay = Arc::new(AuthenticatedShardTransport::new(
            &participants[target],
            shard_sender,
            shard_receiver,
        ));
        for participant in participants.iter() {
            relay.declare(participant);
        }
        relay.finalize_validators();

        let (engine_gen2, _tx_mailbox, _activity_tx) = Engine::new(
            context.with_label(&format!("v{target}_gen2")),
            config,
            schemes[target].clone(),
            oracle.control(participants[target].clone()),
            relay.clone(),
            &participants[target],
            reporter_gen2,
        );
        let _shard_transport = relay.start(context.clone());
        let _engine_handle_gen2 = engine_gen2.start(vote, certificate, resolver);

        // ── Phase 4: Let cluster settle with restarted node ───────────
        context.sleep(Duration::from_secs(10)).await;

        let gen2_count = gen2_finalizations.lock().unwrap().len();
        println!(
            "single-restart phase 4 (after restart): gen2 finalizations={gen2_count}"
        );
        assert!(
            gen2_count > 0,
            "single-restart phase 4: restarted node has no finalizations"
        );

        // ── Phase 5: Check that the restarted node can LEAD rounds ────
        // Snapshot, wait, and verify all nodes progress at equal rates.
        // If the target can't propose, its leader slots will be nullified,
        // producing a lower finalization rate than peers.
        let pre_phase5: Vec<usize> = tracking
            .iter()
            .enumerate()
            .map(|(i, (f, _, _))| {
                if i == target {
                    gen2_finalizations.lock().unwrap().len()
                } else {
                    f.lock().unwrap().len()
                }
            })
            .collect();

        context.sleep(Duration::from_secs(8)).await;

        let phase5_counts: Vec<usize> = tracking
            .iter()
            .enumerate()
            .map(|(i, (f, _, _))| {
                if i == target {
                    gen2_finalizations.lock().unwrap().len()
                } else {
                    f.lock().unwrap().len()
                }
            })
            .collect();
        let phase5_gains: Vec<usize> = phase5_counts
            .iter()
            .zip(pre_phase5.iter())
            .map(|(now, before)| now.saturating_sub(*before))
            .collect();
        let min_gain = *phase5_gains.iter().min().unwrap();
        let max_gain = *phase5_gains.iter().max().unwrap();
        println!(
            "single-restart phase 5 (equal rate check): gains={phase5_gains:?}, spread={}",
            max_gain - min_gain
        );

        // Every node should have gained new finalizations.
        for (i, gain) in phase5_gains.iter().enumerate() {
            assert!(
                *gain > 0,
                "single-restart phase 5: node {i} made no progress (gains={phase5_gains:?})"
            );
        }

        // All nodes should progress at the same rate.  A spread >1 means
        // some leader slots are being nullified — probably the restarted
        // node failing to propose verifiable blocks.
        assert!(
            max_gain - min_gain <= 1,
            "single-restart phase 5: nodes progressing at different rates, spread={} (gains={phase5_gains:?})",
            max_gain - min_gain
        );

        // The restarted node should not have an unusual number of
        // nullifications (which would indicate its proposals are being
        // rejected).
        let gen2_nullification_count = gen2_nullifications.lock().unwrap().len();
        let total_gen2_views = gen2_count + gen2_nullification_count;
        if total_gen2_views > 0 {
            let nullification_ratio =
                gen2_nullification_count as f64 / total_gen2_views as f64;
            println!(
                "single-restart: gen2 nullification ratio={nullification_ratio:.2} ({gen2_nullification_count}/{total_gen2_views})"
            );
            // After catching up, nullification ratio should be low.
            // Allow up to 30% for the initial catch-up period.
            assert!(
                nullification_ratio < 0.30,
                "single-restart: restarted node has excessive nullifications ({nullification_ratio:.2})"
            );
        }
    });
}
