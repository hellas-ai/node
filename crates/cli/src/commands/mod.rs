pub type CliResult<T = ()> = anyhow::Result<T>;

pub mod execute;
pub mod health;
#[cfg(feature = "serve")]
pub mod serve;
