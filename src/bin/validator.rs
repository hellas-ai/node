use clap::{Parser, Subcommand};
use commonware_codec::Encode;
use commonware_cryptography::{Signer, ed25519};
use commonware_p2p::{Manager, authenticated::lookup};
use commonware_runtime::{Metrics, Quota, Runner, tokio};
use hellas_chain::app::TraceReporter;
use hellas_chain::config::{Config, NodeConfig, PeerEntry, encode_private_key};
use hellas_chain::engine::Engine;
use hellas_chain::shard::AuthenticatedShardTransport;
use hellas_types::Scheme;
use std::{net::SocketAddr, num::NonZeroU32, path::PathBuf, sync::Arc};
use tracing_subscriber::EnvFilter;

const NAMESPACE: &[u8] = b"hellas";
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
const CHANNEL_BACKLOG: usize = 1024;

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

    match cli.command {
        Command::Setup {
            validators,
            node,
            start_port,
            seed,
        } => setup(validators, node, start_port, seed),
        Command::Run { config } => run(config),
    }
}

fn setup(validators: u32, node: u32, start_port: u16, seed: Option<u64>) {
    assert!(node < validators, "node index must be less than validators");
    assert!(validators >= 1, "need at least one validator");

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

    println!("{}", toml::to_string_pretty(&config).unwrap());
}

fn run(config_path: PathBuf) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    let config_str = std::fs::read_to_string(&config_path).expect("failed to read config file");
    let node_config: NodeConfig = toml::from_str(&config_str).expect("failed to parse config");

    let private_key = node_config.decode_private_key();
    let me = private_key.public_key();
    let participants = node_config.participants();
    let peer_map = node_config.peer_address_map();

    let listen_addr: SocketAddr = format!("0.0.0.0:{}", node_config.listen_port)
        .parse()
        .unwrap();

    // Build consensus scheme
    let scheme = Scheme::signer(NAMESPACE, participants.clone(), private_key.clone())
        .expect("own key not found in participants");

    // Configure tokio runtime
    let storage_dir = node_config.storage_directory();
    let runtime_cfg = tokio::Config::new()
        .with_storage_directory(storage_dir.to_str().expect("non-UTF-8 data directory"));
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
            me.clone(),
            shard_sender,
            shard_receiver,
        ));
        for participant in participants.iter() {
            relay.declare(participant.clone());
        }
        relay.finalize_validators();
        let _shard_transport_handle = relay.clone().start(context.clone());

        // Create engine
        let engine = Engine::new(
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
}
