pub type CliResult<T = ()> = anyhow::Result<T>;

pub(crate) mod common;
pub mod execute;
pub mod health;
pub mod monitor;
#[cfg(feature = "discovery")]
mod quote_stream;
#[cfg(feature = "serve")]
pub mod serve;
