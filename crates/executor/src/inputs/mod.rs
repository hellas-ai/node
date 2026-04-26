//! Loading and lifecycle for [`catgrad::runtime::Inputs`] — the
//! pre-loaded tensor bundles supplied to [`catgrad::runtime::Inputs::bind`]
//! to produce a runnable bound program.
//!
//! This module owns:
//! - [`HuggingFaceLocator`]: the cache key (`model_id` + `revision` +
//!   `dtype`). For now the only resolution source is HuggingFace; future
//!   sources (iroh-blobs by `Cid<InputsManifest>`, local paths, ...) would
//!   live alongside as sibling locator types.
//! - [`Bundle`]: the loaded [`Inputs`] plus any load-time metadata.
//! - [`load_bundle`] / [`is_cached_locally`]: HF cache lookup + tensor
//!   materialization.
//! - [`State`]: the per-locator status state machine, and the
//!   bound-program registry hung off each `Ready` entry. Programs bound
//!   against the same `Inputs` share an entry; the registry is what
//!   [`crate::programs::Cache`] queries on every quote.
//!
//! [`Inputs`]: catgrad::runtime::Inputs

mod bundle;
mod loader;
mod locator;
mod state;

pub(crate) use bundle::Bundle;
pub(crate) use loader::{Loaded, is_cached_locally, load_bundle};
pub(crate) use locator::HuggingFaceLocator;
pub(crate) use state::{CacheProgramOutcome, State, Status};

use thiserror::Error;

/// Outcome of an `ensure_*` admission against [`State`]. Drives whether the
/// caller can proceed (`Ready`), must wait for a load already in progress
/// (`InFlight`), has just enqueued a new load (`Queued`), or has hit a
/// terminal failure (`Failed`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EnsureDisposition {
    Ready,
    Queued,
    InFlight,
    Failed(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum Error {
    #[error("inputs not ready")]
    NotReady,
    #[error("inputs failed: {0}")]
    Failed(String),
    #[error("unknown locator")]
    UnknownKey,
}
