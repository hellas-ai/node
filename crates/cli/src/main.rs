#[macro_use]
extern crate tracing;

use clap::{Parser, Subcommand};
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use tonic_iroh_transport::iroh::EndpointId;

mod commands;
mod execution;
mod text_output;

#[derive(Parser)]
#[command(name = "hellas")]
#[command(version)]
#[command(about = "Hellas node CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[cfg(feature = "serve")]
    /// Run the RPC server
    Serve {
        /// Port to listen on (auto-selects if not specified or if in use)
        #[arg(long)]
        port: Option<u16>,
        /// Download policy: 'skip' (default, cache-only, never download),
        /// 'eager' (download freely),
        /// or 'allow(pattern,...)' (download only matching HF models)
        #[arg(long = "download-policy", default_value = "skip")]
        download_policy: hellas_executor::DownloadPolicy,
        /// Execute policy: 'skip' (default, refuse all executions),
        /// 'eager' (execute any graph),
        /// or 'allow(hf/pattern,...,graph/pattern,...)' (execute only matching)
        #[arg(long = "execute-policy", default_value = "skip")]
        execute_policy: hellas_executor::ExecutePolicy,
        /// Maximum number of queued executions waiting behind the active worker
        #[arg(
            long = "queue-size",
            default_value_t = hellas_executor::DEFAULT_EXECUTION_QUEUE_CAPACITY
        )]
        queue_size: usize,
        /// Preload model weights on startup. Repeat or use commas: --preload foo/bar --preload baz/qux@rev
        #[arg(long = "preload", value_delimiter = ',')]
        preload_weights: Vec<String>,
    },
    /// Run HTTP gateway exposing OpenAI/Anthropic/plain APIs over Hellas network
    Gateway {
        /// Host interface to bind
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port to listen on
        #[arg(long, default_value_t = 8080)]
        port: u16,
        /// Direct target node id (omit to use discovery)
        #[arg(long)]
        node_id: Option<EndpointId>,
        /// Run locally with the catgrad backend instead of the Hellas network
        #[arg(long = "local", default_value_t = false, conflicts_with = "node_id")]
        local: bool,
        /// Run remotely and verify that the response matches a local catgrad execution
        #[arg(
            long = "verify-local",
            default_value_t = false,
            conflicts_with_all = ["local", "verify"]
        )]
        verify_local: bool,
        /// Verify the primary remote node against a second remote node
        #[arg(
            long = "verify",
            conflicts_with_all = ["local", "verify_local"],
            requires = "node_id"
        )]
        verify: Option<EndpointId>,
        /// Maximum number of queued local executions when `--local` is set
        #[arg(
            long = "queue-size",
            default_value_t = hellas_executor::DEFAULT_EXECUTION_QUEUE_CAPACITY
        )]
        queue_size: usize,
        /// Max execution retries on failure (discovery mode)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Fallback max new tokens when request omits max_tokens
        #[arg(long = "default-max-tokens", default_value_t = 128)]
        default_max_tokens: u32,
        /// Override request model and force this HuggingFace model id, optionally with @revision
        #[arg(long = "force-model")]
        force_model: Option<String>,
    },
    /// Check health of a remote node
    Health {
        /// Node ID to check
        node_id: EndpointId,
    },
    /// Execute a job remotely or locally
    Execute {
        /// Node ID to execute on remotely (omit to auto-discover)
        node_id: Option<EndpointId>,
        /// HuggingFace model id used to fetch weights, optionally with @revision
        #[arg(
            short = 'm',
            long = "model",
            default_value = "HuggingFaceTB/SmolLM2-135M-Instruct"
        )]
        model: String,
        /// Prompt to execute (required)
        #[arg(short = 'p', long = "prompt")]
        prompt: String,
        /// Maximum number of new tokens to generate
        #[arg(long = "max-seq", default_value_t = 16)]
        max_seq: u32,
        /// Max execution retries on failure (discovery path only)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Number of accepted backup quotes to pre-fetch
        #[arg(long = "backup-quotes", default_value_t = 2)]
        backup_quotes: usize,
        /// Run locally with the catgrad backend instead of the Hellas network
        #[arg(long = "local", default_value_t = false, conflicts_with_all = ["verify_local", "node_id"])]
        local: bool,
        /// Run remotely and locally, then verify that both outputs match
        #[arg(
            long = "verify-local",
            default_value_t = false,
            conflicts_with = "local"
        )]
        verify_local: bool,
    },
    /// Discover peers and log network events
    Monitor {
        /// Stop monitoring after N seconds (default: run until Ctrl+C)
        #[arg(long = "timeout-secs")]
        timeout_secs: Option<u64>,
        /// Disable peer interrogation RPCs (health + known peers)
        #[arg(long = "no-interrogate", default_value_t = false)]
        no_interrogate: bool,
    },
}

/// Initialise the tracing subscriber.
///
/// When `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set (and non-empty), an
/// OpenTelemetry OTLP layer is added that exports traces over HTTP/protobuf.
///
/// Supported environment variables (all standard OTEL):
///   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT  — collector URL (e.g. https://jaeger.lsd-ag.ch/v1/traces)
///   OTEL_SERVICE_NAME                    — service name  (default: hellas-node)
///   OTEL_TRACES_SAMPLER_ARG             — sample rate 0.0–1.0 (default: 1.0)
///   OTEL_EXPORTER_OTLP_HEADERS          — extra headers as k=v,k=v
///                                          (use for CF-Access-Client-Id / CF-Access-Client-Secret)
fn init_tracing() -> Option<opentelemetry_sdk::trace::SdkTracerProvider> {
    use tracing_subscriber::prelude::*;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"))
        .add_directive("netlink_packet_route=error".parse().unwrap());

    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);

    let (otel_layer, provider) = init_otlp_layer();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    provider
}

fn init_otlp_layer<S>() -> (
    Option<tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>>,
    Option<opentelemetry_sdk::trace::SdkTracerProvider>,
)
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let endpoint = match std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return (None, None),
    };

    let service_name = std::env::var("OTEL_SERVICE_NAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "hellas-node".to_string());

    let sample_rate: f64 = std::env::var("OTEL_TRACES_SAMPLER_ARG")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|r: &f64| (0.0..=1.0).contains(r))
        .unwrap_or(1.0);

    let headers: std::collections::HashMap<String, String> =
        std::env::var("OTEL_EXPORTER_OTLP_HEADERS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .filter_map(|pair| {
                        let (k, v) = pair.split_once('=')?;
                        Some((k.trim().to_string(), v.trim().to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();

    let mut http = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(&endpoint);

    if !headers.is_empty() {
        http = http.with_headers(headers);
    }

    let exporter = match http.build() {
        Ok(e) => e,
        Err(err) => {
            eprintln!("warning: failed to build OTLP exporter: {err}");
            return (None, None);
        }
    };

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(
            sample_rate,
        ))
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(service_name.clone())
                .build(),
        )
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());
    let tracer = provider.tracer(service_name.clone());

    eprintln!("otlp: enabled endpoint={endpoint} service={service_name} sample_rate={sample_rate}");

    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    (Some(layer), Some(provider))
}

#[tokio::main]
async fn main() {
    let tracer_provider = init_tracing();

    let cli = Cli::parse();
    let result = match cli.command {
        #[cfg(feature = "serve")]
        Commands::Serve {
            port,
            download_policy,
            execute_policy,
            queue_size,
            preload_weights,
        } => {
            commands::serve::run(
                port,
                download_policy,
                execute_policy,
                queue_size,
                preload_weights,
            )
            .await
        }
        Commands::Gateway {
            host,
            port,
            node_id,
            local,
            verify_local,
            verify,
            queue_size,
            retries,
            default_max_tokens,
            force_model,
        } => {
            commands::gateway::run(commands::gateway::GatewayOptions {
                host,
                port,
                node_id,
                local,
                verify_local,
                verify,
                queue_size,
                retries,
                default_max_tokens,
                force_model,
            })
            .await
        }
        Commands::Health { node_id } => commands::health::run(node_id).await,
        Commands::Execute {
            node_id,
            model,
            prompt,
            max_seq,
            retries,
            backup_quotes,
            local,
            verify_local,
        } => {
            commands::execute::run(commands::execute::ExecuteOptions {
                node_id,
                model,
                prompt,
                max_seq,
                retries,
                backup_quotes,
                local,
                verify_local,
            })
            .await
        }
        Commands::Monitor {
            timeout_secs,
            no_interrogate,
        } => commands::monitor::run(timeout_secs, !no_interrogate).await,
    };

    if let Some(provider) = tracer_provider {
        if let Err(err) = provider.shutdown() {
            eprintln!("warning: failed to flush traces: {err}");
        }
    }

    if let Err(err) = result {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_accepts_local_mode() {
        let cli = Cli::try_parse_from(["hellas", "execute", "--local", "-p", "hello"]).unwrap();
        match cli.command {
            Commands::Execute {
                node_id,
                local,
                verify_local,
                ..
            } => {
                assert!(node_id.is_none());
                assert!(local);
                assert!(!verify_local);
            }
            _ => panic!("expected execute command"),
        }
    }

    #[test]
    fn execute_rejects_local_with_node_id() {
        let result = Cli::try_parse_from([
            "hellas",
            "execute",
            "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
            "--local",
            "-p",
            "hello",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn execute_rejects_conflicting_local_modes() {
        let result = Cli::try_parse_from([
            "hellas",
            "execute",
            "--local",
            "--verify-local",
            "-p",
            "hello",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn gateway_accepts_local_mode() {
        let cli = Cli::try_parse_from(["hellas", "gateway", "--local"]).unwrap();
        match cli.command {
            Commands::Gateway { node_id, local, .. } => {
                assert!(node_id.is_none());
                assert!(local);
            }
            _ => panic!("expected gateway command"),
        }
    }

    #[test]
    fn gateway_rejects_local_with_node_id() {
        let result = Cli::try_parse_from([
            "hellas",
            "gateway",
            "--local",
            "--node-id",
            "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
        ]);

        assert!(result.is_err());
    }
}
