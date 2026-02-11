use commonware_consensus::elector::RoundRobin;
use commonware_consensus::minimmit::{
    mocks::reporter::{Config as ReporterConfig, Reporter as MockReporter},
    scheme::ed25519 as minimmit_ed25519,
    types::Finalization,
};
use commonware_consensus::types::View;
use commonware_cryptography::certificate::{Scheme as _, mocks::Fixture};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network};
use commonware_runtime::{Clock, Metrics, Quota, Runner, deterministic};
use hellas_chain::config::Config;
use hellas_chain::engine::Engine;
use hellas_chain::shard::AuthenticatedShardTransport;
use hellas_types::{Activity, PublicKey, Scheme};
use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};

const NAMESPACE: &[u8] = b"hellas-e2e";
const N: u32 = 6;

type Finalizations = Arc<std::sync::Mutex<HashMap<View, Finalization<Scheme, Digest>>>>;
type Faults =
    Arc<std::sync::Mutex<HashMap<PublicKey, HashMap<View, std::collections::HashSet<Activity>>>>>;

fn run_network(config: Config, link: Link, duration: Duration) -> Vec<(Finalizations, Faults)> {
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
                validator.clone(),
                shard_sender,
                shard_receiver,
            ));
            for participant in participants.iter() {
                relay.declare(participant.clone());
            }
            relay.finalize_validators();
            let _shard_transport = relay.clone().start(context.clone());

            let engine = Engine::new(
                ctx,
                config,
                schemes[idx].clone(),
                blocker,
                relay,
                validator,
                reporter,
            );
            engine.start(vote, certificate, resolver);
        }

        context.sleep(duration).await;
    });

    Arc::try_unwrap(handles_ref)
        .expect("runner finished")
        .into_inner()
        .unwrap()
}

#[test]
fn healthy_network_finalizes() {
    let link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    let handles = run_network(Config::test(), link, Duration::from_secs(3));

    let total_finalizations: usize = handles.iter().map(|(f, _)| f.lock().unwrap().len()).sum();
    assert!(
        total_finalizations > 0,
        "expected at least one finalization across all validators"
    );

    for (_, faults) in &handles {
        let faults = faults.lock().unwrap();
        assert!(faults.is_empty(), "unexpected faults detected");
    }
}

#[test]
fn lossy_network_finalizes() {
    let link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(5),
        success_rate: 0.95,
    };

    let handles = run_network(Config::test(), link, Duration::from_secs(10));

    let total_finalizations: usize = handles.iter().map(|(f, _)| f.lock().unwrap().len()).sum();
    assert!(
        total_finalizations > 0,
        "expected at least one finalization even with lossy network"
    );
}
