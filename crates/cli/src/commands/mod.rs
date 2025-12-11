pub type CliResult<T = ()> = anyhow::Result<T>;

pub mod execute;
pub mod health;
pub mod serve;
