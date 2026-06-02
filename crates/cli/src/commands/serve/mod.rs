use crate::commands::CliResult;
use anyhow::Context;
use catgrad::prelude::Dtype;
use hellas_core::{ProducerSigningKey, PublicKey};
use hellas_executor::ExecutorMetrics;
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use iroh::SecretKey;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use tracing::warn;

mod node;
mod node_handler;

pub struct ServeOptions {
    pub port: Option<u16>,
    pub download_policy: DownloadPolicy,
    pub execute_policy: ExecutePolicy,
    pub queue_size: usize,
    pub preload_models: Vec<String>,
    pub artifact_store_path: Option<PathBuf>,
    pub metrics_port: Option<u16>,
    pub graffiti: String,
    pub dtype: Vec<Dtype>,
    pub trusted_caller_public_keys: Vec<PublicKey>,
    pub secret_key: SecretKey,
    pub producer_key: ProducerSigningKey,
}

pub async fn run(options: ServeOptions) -> CliResult<()> {
    let preload_models = dedupe_preload_models(options.preload_models);
    let artifact_store_path = options
        .artifact_store_path
        .map(Ok)
        .unwrap_or_else(crate::identity::default_artifact_store_path)?;
    let build = option_env!("GIT_REV").unwrap_or("unknown").to_string();
    let graffiti = {
        let mut buf = [0u8; 16];
        let src = options.graffiti.as_bytes();
        let len = src.len().min(16);
        buf[..len].copy_from_slice(&src[..len]);
        buf.to_vec()
    };
    let trusted_caller_public_keys = if options.trusted_caller_public_keys.is_empty() {
        vec![options.producer_key.public_key()]
    } else {
        options.trusted_caller_public_keys
    };
    // Counters live in the executor and are mutated inline; cloning the
    // counter handles into a registry just adds a scrape view on the same
    // underlying state.
    let metrics = Arc::new(ExecutorMetrics::default());
    let node = node::spawn_node(node::NodeConfig {
        port: options.port,
        execute_policy: options.execute_policy.clone(),
        queue_size: options.queue_size,
        preload_models: preload_models.clone(),
        build,
        graffiti,
        supported_dtypes: options.dtype,
        trusted_caller_public_keys,
        artifact_store_path,
        secret_key: options.secret_key,
        producer_key: options.producer_key,
        metrics: metrics.clone(),
    })
    .await
    .context("failed to start node server")?;

    if let Some(metrics_port) = options.metrics_port {
        let mut registry = prometheus_client::registry::Registry::default();
        metrics.register_with(&mut registry);
        let bundle = crate::metrics::MetricsBundle::new(Arc::new(registry));
        #[cfg(feature = "otel")]
        let bundle = bundle.with_iroh(node.iroh_metrics());
        crate::metrics::spawn_metrics_server(metrics_port, bundle);
    }

    let node_id = node.node_id();
    let add_url = format!("https://explorer.hellas.ai/executors/add/{node_id}");

    eprintln!("Node ID:      {node_id}");
    print_qr(&add_url);
    eprintln!("Explorer:     {add_url}");

    if !preload_models.is_empty() {
        info!("Loaded model metadata: {}", preload_models.join(", "));
    }

    if matches!(options.download_policy, DownloadPolicy::Skip)
        && matches!(options.execute_policy, ExecutePolicy::Skip)
    {
        warn!(
            "Node is running in deny-by-default mode. Pass explicit policies to allow remote downloads or execution."
        );
    } else {
        warn!(
            download_policy = %options.download_policy,
            execute_policy = %options.execute_policy,
            "node is permitting remote downloads and/or execution; only run this on trusted networks"
        );
        warn!("warning: current policies allow remote peers to trigger downloads and/or execution");
    }

    println!("RPC server running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for shutdown signal")?;

    println!("Shutting down...");
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

fn dedupe_preload_models(mut models: Vec<String>) -> Vec<String> {
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
    fn dedupe_preload_models_preserves_first_occurrence() {
        let models = dedupe_preload_models(vec![
            "foo/bar".to_string(),
            "baz/qux".to_string(),
            "foo/bar".to_string(),
            "baz/qux@rev".to_string(),
        ]);
        assert_eq!(models, vec!["foo/bar", "baz/qux", "baz/qux@rev"]);
    }

    #[test]
    fn dedupe_preload_models_trims_and_drops_empty_entries() {
        let models = dedupe_preload_models(vec![
            " foo/bar ".to_string(),
            "".to_string(),
            "   ".to_string(),
            "baz/qux@rev".to_string(),
        ]);
        assert_eq!(models, vec!["foo/bar", "baz/qux@rev"]);
    }
}
