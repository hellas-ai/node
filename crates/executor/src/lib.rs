#[macro_use]
extern crate tracing;

mod artifacts;
mod backend;
mod executor;
mod inputs;
mod metrics;
mod programs;
mod runner;
mod state;
mod worker;

pub use executor::{Executor, ExecutorHandle};
pub use hellas_pb::hellas::courtesy_server::CourtesyServer;
pub use hellas_pb::hellas::execute_server::ExecuteServer;
pub use metrics::ExecutorMetrics;

pub(crate) const DEFAULT_MAX_SEQ: u32 = 16;
