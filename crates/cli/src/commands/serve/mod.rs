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
    let node = node::spawn_node(port, download_policy.clone(), execute_policy.clone())
        .await
        .context("failed to start node server")?;

    eprintln!("Node Address: {}", node.node_id());
    println!(
        "Policies: download={} execute={}",
        download_policy, execute_policy
    );
    if matches!(download_policy, DownloadPolicy::Skip)
        && matches!(execute_policy, ExecutePolicy::Skip)
    {
        println!(
            "Node is running in deny-by-default mode. Pass explicit policies to allow remote downloads or execution."
        );
    } else {
        warn!(
            %download_policy,
            %execute_policy,
            "node is permitting remote downloads and/or execution; only run this on trusted networks"
        );
        eprintln!(
            "warning: current policies allow remote peers to trigger downloads and/or execution"
        );
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
