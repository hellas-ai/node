pub type CliResult<T = ()> = anyhow::Result<T>;

pub mod gateway;
pub mod llm;
pub mod rpc;
pub mod monitor;
#[cfg(feature = "serve")]
pub mod serve;
