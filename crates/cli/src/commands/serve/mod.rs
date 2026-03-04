use crate::commands::CliResult;
use anyhow::Context;
use hellas_executor::{DownloadPolicy, ExecutePolicy};
use tokio::time::{timeout, Duration};
use tracing::warn;

mod node;
mod peer_tracker;

pub async fn run(
    port: Option<u16>,
    download_policy: DownloadPolicy,
    execute_policy: ExecutePolicy,
) -> CliResult<()> {
    let node = node::spawn_node(port, download_policy, execute_policy)
        .await
        .context("failed to start node server")?;

    println!("Node Address: {}", node.node_id());

    println!("RPC server running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for shutdown signal")?;

    println!("Shutting down RPC server...");
    match timeout(Duration::from_secs(5), node.shutdown()).await {
        Ok(result) => result.context("failed to shut down RPC server")?,
        Err(_) => {
            warn!("graceful shutdown timed out; forcing shutdown");
            // At this point, drop will signal shutdown; exit to avoid hanging
            std::process::exit(0);
        }
    }

    Ok(())
}
