use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use hellas_chain::shard::perf::{
    encode_shards_once, recover_pipeline_once, recover_with_one_helper_once, wire_roundtrip_once,
};
use std::time::Duration;

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

fn bench_recover_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("recover_pipeline");
    group.sample_size(10);
    for (validators, size, blocks) in [(6u16, 1_024, 100), (6, 16 * 1_024, 100), (6, 64 * 1_024, 50)] {
        let payload = payload_of_size(size);
        group.throughput(Throughput::Elements(blocks as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{validators}v_{size}B_{blocks}blk")),
            &(validators, blocks, &payload),
            |b, &(v, blk, ref p)| {
                b.iter(|| {
                    let recovered =
                        recover_pipeline_once(black_box(v), black_box(blk), black_box(p.as_slice()));
                    black_box(recovered);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = shard_perf;
    config = Criterion::default().measurement_time(Duration::from_secs(10));
    targets = bench_encode_shards, bench_wire_roundtrip, bench_single_node_recovery, bench_recover_pipeline
);
criterion_main!(shard_perf);
