#[macro_use]
extern crate tracing;

mod app;
pub mod config;
pub mod engine;
mod execution;
pub mod object;
pub mod shard;

pub use app::{AppMailbox, TraceReporter};

use commonware_parallel::Rayon;
use std::num::NonZeroUsize;
use std::sync::LazyLock;

/// Global erasure-coding thread pool, created once on first access.
///
/// Thread count is set at build time via `CODING_THREADS`.
/// When unset, defaults to [`std::thread::available_parallelism`].
static CODING_POOL: LazyLock<Rayon> = LazyLock::new(|| {
    const OVERRIDE: Option<&str> = option_env!("CODING_THREADS");
    let num_threads = match OVERRIDE {
        Some(s) => s
            .parse::<NonZeroUsize>()
            .expect("CODING_THREADS must be a positive integer"),
        None => std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN),
    };
    Rayon::new(num_threads).expect("failed to create rayon thread pool")
});

/// Returns a handle to the shared coding thread pool.
///
/// Cheap to call — clones an `Arc` reference to the singleton pool.
pub(crate) fn coding_strategy() -> Rayon {
    CODING_POOL.clone()
}
