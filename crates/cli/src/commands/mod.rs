pub type CliResult<T = ()> = anyhow::Result<T>;

pub mod gateway;
pub mod llm;
pub mod monitor;
pub mod rpc;
#[cfg(feature = "serve")]
pub mod serve;
