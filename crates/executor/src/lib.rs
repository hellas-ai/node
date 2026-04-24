#[macro_use]
extern crate tracing;

mod backend;
mod executor;
mod runner;
mod state;
mod weights;
mod worker;

pub use executor::{Executor, ExecutorHandle};
pub use hellas_rpc::pb::hellas::execute_server::ExecuteServer;

// Migration re-exports: these types moved to `hellas-rpc` but serve-side callers
// still import them from `hellas_executor::*`. Follow-up: update call sites and
// drop these re-exports.
pub use hellas_rpc::error::{BackendInitError, ExecutorError, StateError};
pub use hellas_rpc::model::{ModelAssets, ModelAssetsError};
pub use hellas_rpc::policy::{DownloadPolicy, ExecutePattern, ExecutePolicy};
pub use hellas_rpc::{DEFAULT_EXECUTION_QUEUE_CAPACITY, error, model, policy};

pub(crate) const DEFAULT_MAX_SEQ: u32 = 16;
