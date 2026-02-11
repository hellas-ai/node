use crate::app::{Application, InMemoryRelay, Mailbox};
use commonware_consensus::{
    elector::RoundRobin,
    minimmit,
    types::ViewDelta,
    Reporter as Rp,
};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::PoolRef, Clock, Handle, Metrics, Spawner, Storage};
use commonware_utils::NZU16;
use hellas_types::{Activity, PublicKey, Scheme, EPOCH};
use rand_core::CryptoRngCore;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

const MAILBOX_SIZE: usize = 1024;

pub struct Engine<E, B, R>
where
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = PublicKey>,
    R: Rp<Activity = Activity>,
{
    inner: minimmit::Engine<
        E,
        Scheme,
        RoundRobin<Sha256>,
        B,
        Digest,
        Mailbox,
        Mailbox,
        R,
        Sequential,
    >,
    #[allow(dead_code)]
    app_handle: Handle<()>,
}

impl<E, B, R> Engine<E, B, R>
where
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = PublicKey>,
    R: Rp<Activity = Activity>,
{
    pub fn new(
        context: E,
        scheme: Scheme,
        blocker: B,
        relay: Arc<InMemoryRelay>,
        me: &PublicKey,
        reporter: R,
    ) -> Self {
        let (app, mailbox) = Application::new(context.with_label("app"), relay, me);
        let app_handle = app.start(me.clone());

        let cfg = minimmit::Config {
            scheme,
            elector: RoundRobin::<Sha256>::default(),
            blocker,
            automaton: mailbox.clone(),
            relay: mailbox,
            reporter,
            strategy: Sequential,
            partition: me.to_string(),
            mailbox_size: MAILBOX_SIZE,
            epoch: EPOCH,
            replay_buffer: NonZeroUsize::new(1024 * 1024).unwrap(),
            write_buffer: NonZeroUsize::new(64 * 1024).unwrap(),
            buffer_pool: PoolRef::new(NZU16!(4096), NonZeroUsize::new(1024).unwrap()),
            leader_timeout: Duration::from_secs(1),
            notarization_timeout: Duration::from_secs(2),
            nullify_retry: Duration::from_millis(500),
            activity_timeout: ViewDelta::new(10),
            skip_timeout: ViewDelta::new(5),
            fetch_timeout: Duration::from_secs(5),
            fetch_concurrent: 3,
        };

        let inner = minimmit::Engine::new(context, cfg);

        Self {
            inner,
            app_handle,
        }
    }

    pub fn start(
        self,
        vote_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        certificate_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<()> {
        self.inner
            .start(vote_network, certificate_network, resolver_network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::minimmit::{
        mocks::reporter::{Config as ReporterConfig, Reporter as MockReporter},
        scheme::ed25519 as minimmit_ed25519,
        types::Finalization,
    };
    use commonware_consensus::types::View;
    use commonware_cryptography::certificate::{mocks::Fixture, Scheme as _};
    use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network};
    use commonware_runtime::{deterministic, Clock, Quota, Runner};
    use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};

    const NAMESPACE: &[u8] = b"hellas-test";
    const N: u32 = 6;

    // Extract just the Arc handles from mock reporters so we can inspect
    // them after the deterministic runner shuts down (without holding a
    // reference to the runtime context).
    type Finalizations =
        Arc<std::sync::Mutex<HashMap<View, Finalization<Scheme, Digest>>>>;
    type Faults = Arc<
        std::sync::Mutex<
            HashMap<PublicKey, HashMap<View, std::collections::HashSet<Activity>>>,
        >,
    >;

    #[test]
    fn deterministic_network_makes_progress() {
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
                registrations.insert(validator.clone(), (vote, certificate, resolver));
            }

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
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

            let relay = Arc::new(InMemoryRelay::new());
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

                let engine = Engine::new(
                    ctx,
                    schemes[idx].clone(),
                    blocker,
                    relay.clone(),
                    validator,
                    reporter,
                );

                let (vote, certificate, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine.start(vote, certificate, resolver);
            }

            context.sleep(Duration::from_secs(3)).await;
        });

        let handles = handles_ref.lock().unwrap();
        let total_finalizations: usize = handles
            .iter()
            .map(|(f, _)| f.lock().unwrap().len())
            .sum();
        assert!(
            total_finalizations > 0,
            "expected at least one finalization across all validators"
        );

        for (_, faults) in handles.iter() {
            let faults = faults.lock().unwrap();
            assert!(faults.is_empty(), "unexpected faults detected");
        }
    }
}
