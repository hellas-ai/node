#[macro_use]
extern crate tracing;

mod artifacts;
mod backend;
mod executor;
mod metrics;
mod state;
mod worker;

pub use artifacts::ArtifactStoreConfig;
pub use executor::{Executor, ExecutorHandle};
pub use hellas_rpc::services::courtesy::CourtesyServer;
pub use hellas_rpc::services::execute::ExecuteServer;
pub use hellas_rpc::services::opaque::OpaqueServer;
pub use hellas_rpc::services::symbolic::SymbolicServer;
pub use metrics::ExecutorMetrics;

pub(crate) const DEFAULT_MAX_SEQ: u32 = 16;
