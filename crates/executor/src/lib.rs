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
pub use executor::{Executor, ExecutorHandle, DEFAULT_EXECUTION_QUEUE_CAPACITY};
pub use hellas_rpc::pb::hellas::execute_server::ExecuteServer;
pub use model::ModelAssets;
pub use policy::{DownloadPolicy, ExecutePolicy};

pub(crate) const DEFAULT_MAX_SEQ: u32 = 16;
