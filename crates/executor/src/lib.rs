#[macro_use]
extern crate tracing;

mod backend;
mod error;
mod executor;
pub mod model;
pub mod policy;
mod runner;
mod state;
mod weights;
mod worker;

pub use error::ExecutorError;
pub use executor::{DEFAULT_EXECUTION_QUEUE_CAPACITY, Executor, ExecutorHandle};
pub use hellas_rpc::pb::hellas::execute_server::ExecuteServer;
pub use model::ModelAssets;
pub use policy::{DownloadPolicy, ExecutePolicy};

pub(crate) const DEFAULT_MAX_SEQ: u32 = 16;
