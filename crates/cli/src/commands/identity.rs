use crate::commands::CliResult;
use tonic_iroh_transport::iroh::SecretKey;

pub fn show_node_id(secret_key: &SecretKey) -> CliResult<()> {
    println!("{}", secret_key.public());
    Ok(())
}
