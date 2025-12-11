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
    /// Run the RPC server
    Serve,
    /// Check health of a remote node
    Health {
        /// Node ID to check
        node_id: EndpointId,
    },
    /// Execute a job on a remote node
    Execute {
        /// Node ID to execute on
        node_id: EndpointId,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,hellas=info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Serve => commands::serve::run().await,
        Commands::Health { node_id } => commands::health::run(node_id).await,
        Commands::Execute { node_id } => commands::execute::run(node_id).await,
    }
}
