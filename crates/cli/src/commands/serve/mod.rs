use crate::commands::CliResult;
use anyhow::Context;
use tokio::time::{timeout, Duration};
use tracing::warn;

mod node;

pub async fn run(enable_discovery: bool) -> CliResult<()> {
    let node = node::spawn_node(enable_discovery)
        .await
        .context("failed to start node server")?;

    println!("Node Address: {}", node.node_id());
    if !enable_discovery {
        warn!("discovery disabled; clients must pass a node id or start the server with `serve --discovery`");
    }

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
