use crate::commands::CliResult;
use anyhow::Context;
use hellas_executor::{DownloadPolicy, ExecutePolicy};
use std::collections::HashSet;
use tokio::time::{Duration, timeout};
use tracing::warn;

mod node;
mod peer_tracker;

pub async fn run(
    port: Option<u16>,
    download_policy: DownloadPolicy,
    execute_policy: ExecutePolicy,
    queue_size: usize,
    preload_weights: Vec<String>,
    metrics_port: Option<u16>,
) -> CliResult<()> {
    if let Some(metrics_port) = metrics_port {
        let registry = std::sync::Arc::new(prometheus_client::registry::Registry::default());
        crate::metrics::spawn_metrics_server(metrics_port, registry);
    }

    let preload_weights = dedupe_preload_weights(preload_weights);
    let node = node::spawn_node(
        port,
        download_policy.clone(),
        execute_policy.clone(),
        queue_size,
        preload_weights.clone(),
    )
    .await
    .context("failed to start node server")?;

    let node_id = node.node_id();
    let add_url = format!("https://explorer.hellas.ai/executors/add/{node_id}");
    eprintln!("Node ID:      {node_id}");
    eprintln!("Explorer:     {add_url}");
    print_qr(&add_url);
    println!(
        "Policies: download={} execute={} queue_size={}",
        download_policy, execute_policy, queue_size
    );
    if !preload_weights.is_empty() {
        println!("Preloaded weights: {}", preload_weights.join(", "));
    }
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

/// Print a QR code to stderr using Unicode half-block characters.
fn print_qr(data: &str) {
    use qrcode::QrCode;
    let Ok(code) = QrCode::new(data.as_bytes()) else {
        return;
    };
    let width = code.width();
    let modules = code.into_colors();
    // Two rows per character using upper/lower half blocks.
    // ██ = both dark, ▀ = top dark, ▄ = bottom dark, ' ' = both light.
    for y in (0..width).step_by(2) {
        eprint!("  ");
        for x in 0..width {
            let top = modules[y * width + x] == qrcode::Color::Dark;
            let bottom = if y + 1 < width {
                modules[(y + 1) * width + x] == qrcode::Color::Dark
            } else {
                false
            };
            eprint!(
                "{}",
                match (top, bottom) {
                    (true, true) => "█",
                    (true, false) => "▀",
                    (false, true) => "▄",
                    (false, false) => " ",
                }
            );
        }
        eprintln!();
    }
}

fn dedupe_preload_weights(mut models: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    models.retain(|model| {
        let trimmed = model.trim();
        !trimmed.is_empty() && seen.insert(trimmed.to_string())
    });
    models
        .into_iter()
        .map(|model| model.trim().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_preload_weights_preserves_first_occurrence() {
        let models = dedupe_preload_weights(vec![
            "foo/bar".to_string(),
            "baz/qux".to_string(),
            "foo/bar".to_string(),
            "baz/qux@rev".to_string(),
        ]);
        assert_eq!(models, vec!["foo/bar", "baz/qux", "baz/qux@rev"]);
    }

    #[test]
    fn dedupe_preload_weights_trims_and_drops_empty_entries() {
        let models = dedupe_preload_weights(vec![
            " foo/bar ".to_string(),
            "".to_string(),
            "   ".to_string(),
            "baz/qux@rev".to_string(),
        ]);
        assert_eq!(models, vec!["foo/bar", "baz/qux@rev"]);
    }
}
