use commonware_consensus::minimmit::scheme::ed25519 as minimmit_ed25519;
use commonware_cryptography::certificate::mocks::Fixture;
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network};
use commonware_runtime::{Clock, Metrics, Quota, Runner, deterministic};
use hellas_chain::app::InMemoryRelay;
use hellas_chain::app::TraceReporter;
use hellas_chain::engine::Engine;
use hellas_types::Scheme;
use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};
use tracing_subscriber::EnvFilter;

const NAMESPACE: &[u8] = b"hellas";
const N: u32 = 6; // n >= 5f+1, so f=1

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    let executor = deterministic::Runner::timed(Duration::from_secs(300));
    executor.start(|mut context| async move {
        // Create simulated network
        let (network, oracle) = Network::new(
            context.with_label("network"),
            NetworkConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: None,
            },
        );
        network.start();

        // Generate validator identities and signing schemes
        let Fixture {
            participants,
            schemes,
            ..
        }: Fixture<Scheme> = minimmit_ed25519::fixture(&mut context, NAMESPACE, N);

        // Register 3 p2p channels per validator (vote, certificate, resolver)
        let quota = Quota::per_second(NonZeroU32::MAX);
        let mut registrations = HashMap::new();
        for validator in participants.iter() {
            let control = oracle.control(validator.clone());
            let vote = control.register(0, quota).await.unwrap();
            let certificate = control.register(1, quota).await.unwrap();
            let resolver = control.register(2, quota).await.unwrap();
            registrations.insert(validator.clone(), (vote, certificate, resolver));
        }

        // Link all validators with good network conditions
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 0.8,
        };

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

        // Create and start engines
        let relay = Arc::new(InMemoryRelay::new());
        for (idx, validator) in participants.iter().enumerate() {
            let ctx = context.with_label(&format!("validator_{idx}"));
            let blocker = oracle.control(validator.clone());

            let engine = Engine::new(
                ctx,
                schemes[idx].clone(),
                blocker,
                relay.clone(),
                validator,
                TraceReporter,
            );

            let (vote, certificate, resolver) = registrations
                .remove(validator)
                .expect("validator should be registered");
            engine.start(vote, certificate, resolver);
        }

        // Let consensus run — finalization progress is logged by NoopReporter
        loop {
            context.sleep(Duration::from_secs(10)).await;
        }
    });
}
