//! Pluggable clock. `std::time::Instant::now` is forbidden in this
//! crate — it panics on `wasm32-unknown-unknown`. All time flows
//! through `Clock`.

use std::sync::OnceLock;
use web_time::Instant;

pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> Instant;
    fn now_monotonic_ns(&self) -> u64;
}

/// Default clock — uses `web_time::Instant`, which is `std::time::Instant`
/// on native and `performance.now()` on wasm32-unknown-unknown.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultClock;

static EPOCH: OnceLock<Instant> = OnceLock::new();

fn epoch() -> Instant {
    *EPOCH.get_or_init(Instant::now)
}

impl Clock for DefaultClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn now_monotonic_ns(&self) -> u64 {
        Instant::now()
            .duration_since(epoch())
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}
