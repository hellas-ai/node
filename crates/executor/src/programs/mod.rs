//! Bound-program cache + admission state machine, and the per-bound-program
//! [`ExecutionContext`] that wraps a [`hellas_runtime::graph::BoundProgram`]
//! together with its run-time caches.
//!
//! [`Cache`] is the executor's two-level cache + admission machinery: load
//! [`crate::inputs::Bundle`] (slow, single-flight, queued via the load
//! queue) → bind a [`hellas_runtime::graph::Program`] against those inputs (fast
//! CPU work, single-flight, cached). Every cache lookup produces an
//! [`ExecutionContext`] ready to drive a quote and stream tokens.
//!
//! # Commitment-keyed caches
//!
//! Each [`ExecutionContext`] owns an exact-replay cache keyed by the
//! request *commitment* — a [`Cid<TextExecution>`] computed from
//! `(program, parameter tensor CIDs, prompt tokens, policy)`. Two
//! requests with the same commitment hash are byte-identical asks; the
//! cache returns the previously-streamed output tokens without touching
//! the model.
//!
//! [`Cid<TextExecution>`]: hellas_runtime::cid::Cid

mod cache;
mod context;

pub(crate) use cache::Cache;
pub(crate) use context::{ExecutionContext, ExecutionStart};
