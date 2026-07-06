pub type CliResult<T = ()> = anyhow::Result<T>;

use std::time::Duration;

pub mod artifact;
#[cfg(feature = "chain")]
pub mod chain;
pub(crate) mod codex_auth;
pub(crate) mod discovery;
pub mod fetch;
#[cfg(feature = "evaluate")]
pub mod gateway;
pub mod identity;
#[cfg(feature = "evaluate")]
pub mod llm;
pub mod monitor;
#[cfg(feature = "node")]
pub(crate) mod openai_responses_stream;
pub mod rpc;
#[cfg(feature = "node")]
pub mod serve;

pub(crate) fn http_client(request_timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(request_timeout)
        .build()
        .expect("HTTP client configuration is valid")
}
