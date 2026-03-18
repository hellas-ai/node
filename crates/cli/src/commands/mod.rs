pub type CliResult<T = ()> = anyhow::Result<T>;

pub mod execute;
pub mod gateway;
pub mod health;
pub mod monitor;
#[cfg(feature = "serve")]
pub mod serve;
