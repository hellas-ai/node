pub type CliResult<T = ()> = anyhow::Result<T>;

pub mod artifact;
pub(crate) mod discovery;
pub mod fetch;
pub mod gateway;
pub mod identity;
pub mod llm;
pub mod monitor;
pub(crate) mod openai_responses_stream;
pub mod rpc;
#[cfg(feature = "hellas-executor")]
pub mod serve;
