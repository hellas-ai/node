use clap::{Parser, Subcommand};
use commonware_codec::Encode;
use commonware_cryptography::certificate::Scheme as _;
use commonware_cryptography::{Signer, ed25519};
use commonware_p2p::{Manager, authenticated::lookup};
use commonware_runtime::{Metrics, Quota, Runner, tokio};
use hellas_chain::TraceReporter;
use hellas_chain::config::{Config, ConfigError, NodeConfig, PeerEntry, encode_private_key};
use hellas_chain::engine::Engine;
use hellas_chain::shard::AuthenticatedShardTransport;
use hellas_types::Scheme;
use std::io;
use std::{net::SocketAddr, num::NonZeroU32, path::PathBuf, sync::Arc};
use thiserror::Error;
use tracing_subscriber::EnvFilter;

const NAMESPACE: &[u8] = b"hellas";
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
const CHANNEL_BACKLOG: usize = 1024;

#[derive(Debug, Error)]
enum ValidatorError {
    #[error("invalid setup args: {0}")]
    InvalidSetup(String),
    #[error("failed to serialize config")]
    SerializeConfig(#[from] toml::ser::Error),
    #[error("failed to parse log directive")]
    InvalidLogDirective(#[from] tracing_subscriber::filter::ParseError),
    #[error("failed to read config file")]
    ReadConfig(#[from] io::Error),
    #[error("failed to parse config file")]
    ParseConfig(#[from] toml::de::Error),
    #[error("invalid node configuration")]
    Config(#[from] ConfigError),
    #[error("invalid listen address")]
    InvalidListenAddress(#[from] std::net::AddrParseError),
    #[error("failed to build consensus scheme: {0}")]
    Scheme(String),
    #[error("storage directory is not valid UTF-8: {0}")]
    NonUtf8StorageDirectory(PathBuf),
}

#[derive(Parser)]
#[command(name = "validator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a TOML config for a single validator node
    Setup {
        /// Total number of validators in the network
        #[arg(long)]
        validators: u32,
        /// This node's index (0-based)
        #[arg(long)]
        node: u32,
        /// Starting port number (node i listens on start_port + i)
        #[arg(long, default_value = "3000")]
        start_port: u16,
        /// Deterministic seed for key generation (required for multi-node local setup)
        #[arg(long)]
        seed: Option<u64>,
    },
    /// Run a validator node
    Run {
        /// Path to the TOML config file
        #[arg(long)]
        config: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Setup {
            validators,
            node,
            start_port,
            seed,
        } => setup(validators, node, start_port, seed),
        Command::Run { config } => run(config),
    };

    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn setup(
    validators: u32,
    node: u32,
    start_port: u16,
    seed: Option<u64>,
) -> Result<(), ValidatorError> {
    if validators == 0 {
        return Err(ValidatorError::InvalidSetup(
            "need at least one validator".to_string(),
        ));
    }
    if node >= validators {
        return Err(ValidatorError::InvalidSetup(
            "node index must be less than validators".to_string(),
        ));
    }

    let keys: Vec<ed25519::PrivateKey> = (0..validators)
        .map(|i| match seed {
            Some(s) => ed25519::PrivateKey::from_seed(s + i as u64),
            None => {
                eprintln!("warning: generating random keys without --seed; configs will not be reproducible");
                ed25519::PrivateKey::from_seed(i as u64)
            }
        })
        .collect();

    let my_key = &keys[node as usize];
    let peers: Vec<PeerEntry> = keys
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != node as usize)
        .map(|(i, k)| PeerEntry {
            public_key: hex::encode(k.public_key().encode()),
            address: format!("127.0.0.1:{}", start_port + i as u16),
        })
        .collect();

    let config = NodeConfig {
        private_key: encode_private_key(my_key),
        listen_port: start_port + node as u16,
        peers,
    };

    let rendered = toml::to_string_pretty(&config)?;
    println!("{rendered}");
    Ok(())
}

fn run(config_path: PathBuf) -> Result<(), ValidatorError> {
    let log_directive = "info".parse()?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(log_directive))
        .init();

    let config_str = std::fs::read_to_string(&config_path)?;
    let node_config: NodeConfig = toml::from_str(&config_str)?;

    let private_key = node_config.decode_private_key()?;
    let me = private_key.public_key();
    let participants = node_config.participants()?;
    let peer_map = node_config.peer_address_map()?;

    let listen_addr: SocketAddr = format!("0.0.0.0:{}", node_config.listen_port).parse()?;

    // Build consensus scheme
    let scheme = match Scheme::signer(NAMESPACE, participants, private_key.clone()) {
        Some(scheme) => scheme,
        None => {
            return Err(ValidatorError::Scheme(
                "own key not found in participants".to_string(),
            ));
        }
    };

    // Configure tokio runtime
    let storage_dir = node_config.storage_directory()?;
    let storage_dir_utf8 = storage_dir
        .to_str()
        .ok_or_else(|| ValidatorError::NonUtf8StorageDirectory(storage_dir.clone()))?;
    let runtime_cfg = tokio::Config::new().with_storage_directory(storage_dir_utf8);
    let runner = tokio::Runner::new(runtime_cfg);

    runner.start(|context| async move {
        // Create lookup-based p2p network
        let p2p_cfg = lookup::Config::local(private_key, NAMESPACE, listen_addr, MAX_MESSAGE_SIZE);
        let (mut network, mut oracle) =
            lookup::Network::new(context.with_label("network"), p2p_cfg);

        // Register all validators with the oracle
        oracle.update(0, peer_map).await;

        // Register consensus and shard channels.
        let quota = Quota::per_second(NonZeroU32::MAX);
        let vote = network.register(0, quota, CHANNEL_BACKLOG);
        let certificate = network.register(1, quota, CHANNEL_BACKLOG);
        let resolver = network.register(2, quota, CHANNEL_BACKLOG);
        let (shard_sender, shard_receiver) = network.register(3, quota, CHANNEL_BACKLOG);

        // Start networking
        let _network_handle = network.start();

        let relay = Arc::new(AuthenticatedShardTransport::new(
            &me,
            shard_sender,
            shard_receiver,
        ));
        for participant in scheme.participants() {
            relay.declare(participant);
        }
        relay.finalize_validators();
        let _shard_transport_handle = relay.clone().start(context.clone());

        // Create engine
        let (engine, _tx_mailbox) = Engine::new(
            context,
            Config::mainnet(),
            scheme,
            oracle,
            relay,
            &me,
            TraceReporter,
        );

        let _engine_handle = engine.start(vote, certificate, resolver);

        // Block forever — consensus runs in background tasks
        std::future::pending::<()>().await;
    });
    Ok(())
}
