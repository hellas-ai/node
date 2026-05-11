//! Kernel apply benchmarks.
//!
//! Workloads come from the Quint ITF trace fixtures under
//! `models/traces/`. Each fixture is a deterministic op sequence that
//! the abstract model believes the kernel must accept; benching them
//! gives throughput numbers tied to the spec rather than to a synthetic
//! shape. The conversion from `lastInput` to `(Context, Op)` and the
//! kernel construction parameters (keys, ids, payouts, terms) are shared
//! with `tests/itf.rs` via `#[path]` so a fixture replayed here exercises
//! the same kernel paths as the equivalent test replay.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_methods)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]

#[path = "../tests/support/mod.rs"]
mod support;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hellas_kernel::{Context, Tx};
use support::{
    FAKE_VERIFIER,
    itf::{State, context_for, op_for},
    l1::{TraceState, initial_state},
};

// Fixtures baked in at compile time so the bench is hermetic. Each entry
// corresponds to a `run` declaration in `models/l1.qnt`.
const FIXTURES: &[(&str, &str)] = &[
    (
        "basic",
        include_str!("../models/traces/l1_basicTraceTest.itf.json"),
    ),
    (
        "mutual_timeout",
        include_str!("../models/traces/l1_mutualTimeoutTraceTest.itf.json"),
    ),
    (
        "violation",
        include_str!("../models/traces/l1_violationTraceTest.itf.json"),
    ),
    (
        "both_edges_timeout",
        include_str!("../models/traces/l1_bothEdgesTimeoutTraceTest.itf.json"),
    ),
    (
        "mixed_proofs",
        include_str!("../models/traces/l1_mixedProofsTraceTest.itf.json"),
    ),
    (
        "height_accumulation",
        include_str!("../models/traces/l1_heightAccumulationTraceTest.itf.json"),
    ),
];

/// Parses an ITF fixture into a flat `(Context, Op)` sequence — one
/// entry per kernel-visible step. `tick`/`idle`/`init` produce no kernel
/// work and are dropped, so the resulting length is exactly the number of
/// `apply` calls the bench will measure.
fn workload(json: &str) -> Vec<(Context, Tx)> {
    let trace: itf::Trace<State> =
        itf::trace_from_str(json).expect("ITF fixture parses against the shared schema");

    trace
        .states
        .iter()
        .filter_map(|state| {
            op_for(&state.value.last_input).map(|op| (context_for(&state.value.last_input), op))
        })
        .collect()
}

fn apply(c: &mut Criterion) {
    let workloads: Vec<(&'static str, Vec<(Context, Tx)>)> = FIXTURES
        .iter()
        .map(|(name, json)| (*name, workload(json)))
        .collect();

    let mut group = c.benchmark_group("itf_replay");

    for (name, ops) in &workloads {
        group.throughput(Throughput::Elements(ops.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), ops, |b, ops| {
            b.iter(|| {
                let mut state: TraceState = initial_state();
                for (ctx, op) in ops {
                    let event = state
                        .apply(*ctx, &FAKE_VERIFIER, op)
                        .expect("model fixture rejected by kernel");
                    core::hint::black_box(event.kind());
                }
                core::hint::black_box(state);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, apply);
criterion_main!(benches);
