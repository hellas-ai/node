#[macro_use]
extern crate tracing;

use clap::{Parser, Subcommand};
use tonic_iroh_transport::iroh::EndpointId;

mod bootstrap_peers;
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
        /// Enable discovery (LAN mDNS + internet discovery via pkarr/DNS + DHT).
        #[arg(long, default_value_t = false)]
        discovery: bool,
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
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    let result = match cli.command {
        #[cfg(feature = "serve")]
        Commands::Serve { discovery } => commands::serve::run(discovery).await,
        Commands::Health { node_id } => commands::health::run(node_id).await,
        Commands::Execute {
            node_id,
            model,
            prompt,
            max_seq,
        } => commands::execute::run(node_id, model, prompt, max_seq).await,
    };

    if let Err(err) = result {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
