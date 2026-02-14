use std::hint::black_box;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use commonware_consensus::elector::RoundRobin;
use commonware_consensus::minimmit::{
    mocks::reporter::{Config as ReporterConfig, Reporter as MockReporter},
    scheme::ed25519 as minimmit_ed25519,
};
use commonware_cryptography::certificate::{Scheme as _, mocks::Fixture};
use commonware_cryptography::Sha256;
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network};
use commonware_runtime::{Clock, Metrics, Quota, Runner, deterministic};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hellas_chain::config::Config;
use hellas_chain::engine::Engine;
use hellas_chain::shard::AuthenticatedShardTransport;
use hellas_chain::shard::perf::{encode_shards_once, recover_with_one_helper_once, wire_roundtrip_once};
use hellas_types::Scheme;

const NAMESPACE: &[u8] = b"hellas-bench";
const N: u32 = 6;

type Finalizations =
    Arc<std::sync::Mutex<HashMap<commonware_consensus::types::View, commonware_consensus::minimmit::types::Finalization<Scheme, commonware_cryptography::sha256::Digest>>>>;

/// Run a full deterministic network until at least one validator reaches
/// `target_views` finalizations. Returns the max finalization count observed.
fn run_full_sync(target_views: usize) -> usize {
    let runner = deterministic::Runner::timed(Duration::from_secs(600));

    let finalizations_list: Arc<std::sync::Mutex<Vec<Finalizations>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let finalizations_ref = finalizations_list.clone();

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
            finalizations_list
                .lock()
                .unwrap()
                .push(reporter.finalizations.clone());

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

            let (engine, _tx_mailbox) = Engine::new(
                ctx,
                Config::test(),
                schemes[idx].clone(),
                blocker,
                relay.clone(),
                validator,
                reporter,
            );
            let _shard_transport = relay.start(context.clone());
            engine.start(vote, certificate, resolver);
        }

        // Poll until at least one validator reaches the target.
        loop {
            context.sleep(Duration::from_secs(1)).await;
            let max_count = finalizations_list
                .lock()
                .unwrap()
                .iter()
                .map(|f| f.lock().unwrap().len())
                .max()
                .unwrap_or(0);
            if max_count >= target_views {
                break;
            }
        }
    });

    let list = Arc::try_unwrap(finalizations_ref)
        .expect("runner finished")
        .into_inner()
        .unwrap();
    list.iter()
        .map(|f| f.lock().unwrap().len())
        .max()
        .unwrap_or(0)
}

fn payload_of_size(size: usize) -> Vec<u8> {
    let mut payload = vec![0u8; size];
    for (idx, byte) in payload.iter_mut().enumerate() {
        *byte = (idx % 251) as u8;
    }
    payload
}

fn bench_encode_shards(c: &mut Criterion) {
    let mut group = c.benchmark_group("shard_encode");
    for size in [1_024usize, 16 * 1_024, 64 * 1_024] {
        let payload = payload_of_size(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{size}B")),
            &payload,
            |b, p| {
                b.iter(|| {
                    let shard_count = encode_shards_once(black_box(6), black_box(p.as_slice()));
                    black_box(shard_count);
                });
            },
        );
    }
    group.finish();
}

fn bench_wire_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_roundtrip");
    for size in [1_024usize, 16 * 1_024, 64 * 1_024] {
        let payload = payload_of_size(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{size}B")),
            &payload,
            |b, p| {
                b.iter(|| {
                    let ok = wire_roundtrip_once(black_box(6), black_box(p.as_slice()));
                    black_box(ok);
                });
            },
        );
    }
    group.finish();
}

fn bench_single_node_recovery(c: &mut Criterion) {
    let mut group = c.benchmark_group("recover_single_node");
    for size in [1_024usize, 16 * 1_024] {
        let payload = payload_of_size(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{size}B")),
            &payload,
            |b, p| {
                b.iter(|| {
                    let recovered =
                        recover_with_one_helper_once(black_box(6), black_box(p.as_slice()));
                    black_box(recovered);
                });
            },
        );
    }
    group.finish();
}

fn bench_full_sync(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_sync");
    group.sample_size(10);
    let target_views = 100usize;
    group.throughput(Throughput::Elements(target_views as u64));
    group.bench_function(
        BenchmarkId::from_parameter(format!("{N}v_{target_views}views")),
        |b| {
            b.iter(|| {
                let finalizations = run_full_sync(black_box(target_views));
                black_box(finalizations);
            });
        },
    );
    group.finish();
}

fn bench_sustained_finalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("sustained_finalization");
    group.sample_size(10);
    for &target_views in &[500usize, 1_000] {
        group.throughput(Throughput::Elements(target_views as u64));
        group.bench_function(
            BenchmarkId::from_parameter(format!("{N}v_{target_views}views")),
            |b| {
                b.iter(|| {
                    let finalizations = run_full_sync(black_box(target_views));
                    black_box(finalizations);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = shard_perf;
    config = Criterion::default().measurement_time(Duration::from_secs(10));
    targets = bench_encode_shards, bench_wire_roundtrip, bench_single_node_recovery, bench_full_sync, bench_sustained_finalization
);
criterion_main!(shard_perf);
