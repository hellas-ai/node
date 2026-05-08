pub type CliResult<T = ()> = anyhow::Result<T>;

pub mod artifact;
pub mod gateway;
pub mod identity;
pub mod llm;
pub mod monitor;
pub mod opaque;
pub mod rpc;
#[cfg(feature = "hellas-executor")]
pub mod serve;
