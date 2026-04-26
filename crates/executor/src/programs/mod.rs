//! Bound-program cache + admission state machine, and the per-bound-program
//! [`ExecutionContext`] that wraps a [`catgrad::runtime::BoundProgram`]
//! together with its prefix-snapshot and exact-replay caches.
//!
//! [`Cache`] is the executor's two-level cache + admission machinery: load
//! [`crate::inputs::Bundle`] (slow, single-flight, queued via the load
//! queue) → bind a [`catgrad::runtime::Program`] against those inputs (fast
//! CPU work, single-flight, cached). Every cache lookup produces an
//! [`ExecutionContext`] ready to drive a quote and stream tokens.

mod cache;
mod context;

pub(crate) use cache::Cache;
pub(crate) use context::{ExecutionContext, ExecutionStart};
