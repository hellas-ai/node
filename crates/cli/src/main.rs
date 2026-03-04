#[macro_use]
extern crate tracing;

use clap::{Parser, Subcommand};
use tonic_iroh_transport::iroh::EndpointId;

mod commands;

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
        /// Download policy: 'eager' (default, download freely),
        /// 'skip' (cache-only, never download),
        /// or 'allow(pattern,...)' (download only matching HF models)
        #[arg(long = "download-policy", default_value = "eager")]
        download_policy: hellas_executor::DownloadPolicy,
        /// Execute policy: 'eager' (default, execute any graph),
        /// 'skip' (refuse all executions),
        /// or 'allow(hf/pattern,...,graph/pattern,...)' (execute only matching)
        #[arg(long = "execute-policy", default_value = "eager")]
        execute_policy: hellas_executor::ExecutePolicy,
    },
    /// Check health of a remote node
    Health {
        /// Node ID to check
        node_id: EndpointId,
    },
    /// Execute a job on a remote node
    Execute {
        /// Node ID to execute on (omit to auto-discover)
        node_id: Option<EndpointId>,
        /// HuggingFace model id used to fetch weights (e.g. HuggingFaceTB/SmolLM2-135M-Instruct)
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
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"))
                .add_directive("netlink_packet_route=error".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    let result = match cli.command {
        #[cfg(feature = "serve")]
        Commands::Serve {
            port,
            download_policy,
            execute_policy,
        } => commands::serve::run(port, download_policy, execute_policy).await,
        Commands::Health { node_id } => commands::health::run(node_id).await,
        Commands::Execute {
            node_id,
            model,
            prompt,
            max_seq,
            retries,
            backup_quotes,
        } => commands::execute::run(node_id, model, prompt, max_seq, retries, backup_quotes).await,
        Commands::Monitor {
            timeout_secs,
            no_interrogate,
        } => commands::monitor::run(timeout_secs, !no_interrogate).await,
    };

    if let Err(err) = result {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
