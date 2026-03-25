#[macro_use]
extern crate tracing;

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use tonic_iroh_transport::iroh::EndpointId;

mod commands;
mod execution;
mod metrics;
mod text_output;
mod tracing_config;

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
        /// Prometheus metrics port (e.g. 9090)
        #[arg(long = "metrics-port")]
        metrics_port: Option<u16>,
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
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',', requires = "node_id")]
        node_addrs: Vec<SocketAddr>,
        /// Run locally with the catgrad backend instead of the Hellas network
        #[arg(long = "local", default_value_t = false, conflicts_with_all = ["node_id", "node_addrs"])]
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
        /// Prometheus metrics port (e.g. 9090)
        #[arg(long = "metrics-port")]
        metrics_port: Option<u16>,
    },
    /// Query a remote node via RPC
    Rpc {
        /// Node ID to check
        node_id: EndpointId,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',')]
        node_addrs: Vec<SocketAddr>,
    },
    /// Run LLM inference remotely or locally
    Llm {
        /// Node ID to run on remotely (omit to auto-discover)
        node_id: Option<EndpointId>,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',', requires = "node_id")]
        node_addrs: Vec<SocketAddr>,
        /// HuggingFace model id used to fetch weights, optionally with @revision
        #[arg(
            short = 'm',
            long = "model",
            default_value = "Qwen/Qwen3-0.6B"
        )]
        model: String,
        /// Prompt to send (required)
        #[arg(short = 'p', long = "prompt")]
        prompt: String,
        /// Maximum number of new tokens to generate
        #[arg(long = "max-seq", default_value_t = 16)]
        max_seq: u32,
        /// Max execution retries on failure (discovery path only)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Run locally with the catgrad backend instead of the Hellas network
        #[arg(long = "local", default_value_t = false, conflicts_with_all = ["verify_local", "node_id", "node_addrs"])]
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

#[tokio::main]
async fn main() {
    let tracer_provider = tracing_config::init_tracing();

    let cli = Cli::parse();
    let result = match cli.command {
        #[cfg(feature = "serve")]
        Commands::Serve {
            port,
            download_policy,
            execute_policy,
            queue_size,
            preload_weights,
            metrics_port,
        } => {
            commands::serve::run(
                port,
                download_policy,
                execute_policy,
                queue_size,
                preload_weights,
                metrics_port,
            )
            .await
        }
        Commands::Gateway {
            host,
            port,
            node_id,
            node_addrs,
            local,
            verify_local,
            verify,
            queue_size,
            retries,
            default_max_tokens,
            force_model,
            metrics_port,
        } => {
            commands::gateway::run(commands::gateway::GatewayOptions {
                host,
                port,
                node_id,
                node_addrs,
                local,
                verify_local,
                verify,
                queue_size,
                retries,
                default_max_tokens,
                force_model,
                metrics_port,
            })
            .await
        }
        Commands::Rpc {
            node_id,
            node_addrs,
        } => commands::rpc::run(node_id, node_addrs).await,
        Commands::Llm {
            node_id,
            node_addrs,
            model,
            prompt,
            max_seq,
            retries,
            local,
            verify_local,
        } => {
            commands::llm::run(commands::llm::ExecuteOptions {
                node_id,
                node_addrs,
                model,
                prompt,
                max_seq,
                retries,
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
    fn llm_accepts_local_mode() {
        let cli = Cli::try_parse_from(["hellas", "llm", "--local", "-p", "hello"]).unwrap();
        match cli.command {
            Commands::Llm {
                node_id,
                node_addrs,
                local,
                verify_local,
                ..
            } => {
                assert!(node_id.is_none());
                assert!(node_addrs.is_empty());
                assert!(local);
                assert!(!verify_local);
            }
            _ => panic!("expected llm command"),
        }
    }

    #[test]
    fn llm_rejects_local_with_node_id() {
        let result = Cli::try_parse_from([
            "hellas",
            "llm",
            "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
            "--local",
            "-p",
            "hello",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn llm_rejects_conflicting_local_modes() {
        let result = Cli::try_parse_from([
            "hellas",
            "llm",
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
            Commands::Gateway {
                node_id,
                node_addrs,
                local,
                ..
            } => {
                assert!(node_id.is_none());
                assert!(node_addrs.is_empty());
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

    #[test]
    fn llm_rejects_node_addr_without_node_id() {
        let result = Cli::try_parse_from([
            "hellas",
            "llm",
            "--node-addr",
            "127.0.0.1:31145",
            "-p",
            "hello",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn gateway_rejects_node_addr_without_node_id() {
        let result = Cli::try_parse_from(["hellas", "gateway", "--node-addr", "127.0.0.1:31145"]);

        assert!(result.is_err());
    }
}
