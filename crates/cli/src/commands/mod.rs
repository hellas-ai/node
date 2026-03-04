pub type CliResult<T = ()> = anyhow::Result<T>;

pub(crate) mod common;
pub mod execute;
pub mod health;
#[cfg(feature = "discovery")]
mod quote_stream;
#[cfg(feature = "serve")]
pub mod serve;
