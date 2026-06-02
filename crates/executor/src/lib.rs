#[macro_use]
extern crate tracing;

mod artifacts;
mod backend;
mod executor;
mod fetch;
mod metrics;
mod state;
mod worker;

pub use artifacts::ArtifactStoreConfig;
pub use executor::{Executor, ExecutorHandle, ExecutorSpawnConfig};
pub use fetch::FetchCallerPolicy;
pub use hellas_rpc::services::courtesy::CourtesyServer;
pub use hellas_rpc::services::execute::ExecuteServer;
pub use hellas_rpc::services::fetch::FetchServer;
pub use hellas_rpc::services::symbolic::SymbolicServer;
pub use metrics::ExecutorMetrics;

pub(crate) const DEFAULT_MAX_SEQ: u32 = 16;
