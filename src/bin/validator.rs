use clap::{Parser, Subcommand};
use commonware_broadcast::buffered;
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    marshal::{
        self,
        core::Actor as MarshalActor,
        resolver::p2p as marshal_resolver,
        standard::{Deferred, Standard},
    },
    simplex::{self, config::ForwardingPolicy, elector::RoundRobin},
    types::{Epoch, FixedEpocher, ViewDelta},
};
use commonware_cryptography::bls12381::dkg::feldman_desmedt::deal;
use commonware_cryptography::certificate::{ConstantProvider, Scheme as _};
use commonware_cryptography::{Digestible as _, Signer, ed25519};
use commonware_glue::stateful::{
    Config as StatefulConfig, Stateful as StatefulActor, SyncPlan,
    db::{SyncEngineConfig, p2p::standard as qmdb_resolver},
};
use commonware_p2p::{AddressableManager, authenticated::lookup};
use commonware_parallel::Sequential;
use commonware_runtime::{Metrics, Quota, Runner, Spawner, Supervisor as _, tokio};
use commonware_storage::{
    archive::{Archive as _, Identifier as ArchiveIdentifier, immutable},
    mmr,
};
use commonware_utils::{N3f1, NZU64, NZUsize, ordered::Set};
use futures::FutureExt;
use hellas_chain::client::RemoteLightClient;
use hellas_chain::config::{
    Config, ConfigError, GenesisEntry, NodeConfig, PeerEntry, encode_private_key,
    encode_threshold_polynomial, encode_threshold_share,
};
use hellas_chain::rpc::LocalLightClient;
use hellas_chain::{
    ActivityReporter, Application, ApplicationConfig, Indexer, LightClient as _, Mempool, UtxoDb,
    spawn_light_client_server, utxo_db_config,
};
use hellas_kernel::domain::{
    Address, Digest, PublicKey, Scheme, ThresholdPolynomial, ThresholdShare, ThresholdVariant,
    UserPublicKey,
};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig as _};
use p256::ecdsa::SigningKey as UserSigningKey;
use prometheus_client::metrics::gauge::Gauge;
use rand::{
    RngCore, SeedableRng,
    rngs::{OsRng, StdRng},
};
use std::io;
use std::sync::atomic::AtomicI64;
use std::time::{Duration, Instant};
use std::{
    net::SocketAddr,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
};
use thiserror::Error;
use tracing::{error, info, warn};

const NAMESPACE: &[u8] = b"hellas";
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
const CHANNEL_BACKLOG: usize = 1024;
const DEFAULT_OTLP_SERVICE_NAME: &str = "hellas-validator";
const DEFAULT_OTLP_SAMPLE_RATE: f64 = 1.0;
const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";
const OTLP_SERVICE_NAME_ENV: &str = "OTEL_SERVICE_NAME";
const OTLP_SAMPLE_RATE_ENV: &str = "OTEL_TRACES_SAMPLER_ARG";
const OTLP_HEADERS_ENV: &str = "OTEL_EXPORTER_OTLP_HEADERS";
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

fn random_private_key() -> ed25519::PrivateKey {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    ed25519::PrivateKey::decode(raw.as_slice())
        .expect("decoding 32 random bytes as an ed25519 private key should always succeed")
}

fn deal_threshold_shares(
    seed: Option<u64>,
    participants: Set<PublicKey>,
) -> Result<
    (
        ThresholdPolynomial,
        commonware_utils::ordered::Map<PublicKey, ThresholdShare>,
    ),
    ValidatorError,
> {
    let dealt = match seed {
        Some(seed) => {
            let mut rng = StdRng::seed_from_u64(seed ^ 0x4845_4c4c_4153_424c);
            deal::<ThresholdVariant, _, N3f1>(&mut rng, Default::default(), participants)
        }
        None => {
            let mut rng = OsRng;
            deal::<ThresholdVariant, _, N3f1>(&mut rng, Default::default(), participants)
        }
    }
    .map_err(|e| ValidatorError::InvalidSetup(format!("failed to deal threshold shares: {e}")))?;

    let (output, shares) = dealt;
    Ok((output.public().clone(), shares))
}

fn random_user_private_key() -> UserSigningKey {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    UserSigningKey::from_slice(&raw)
        .expect("decoding 32 random bytes as a secp256r1 private key should succeed")
}

fn wallet_address_from_signing_key(key: &UserSigningKey) -> Address {
    Address::from(UserPublicKey::from(key.verifying_key().to_owned()))
}

#[derive(Debug, Error)]
enum ValidatorError {
    #[error("invalid setup args: {0}")]
    InvalidSetup(String),
    #[error("failed to serialize config")]
    SerializeConfig(#[from] toml::ser::Error),
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
    #[error("failed to replay owner index: {0}")]
    OwnerIndex(String),
    #[error("failed to bind RPC server at {addr}: {source}")]
    RpcBind { addr: SocketAddr, source: io::Error },
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
    Config {
        /// Total number of validators in the network
        #[arg(short = 'n', long)]
        validators: u32,
        /// This node's index (0-based)
        #[arg(short = 'i', long, default_value = "0")]
        node: u32,
        /// Starting port number (node i listens on start_port + i)
        #[arg(long, default_value = "3000")]
        start_port: u16,
        /// Deterministic seed for key generation (required for multi-node local setup)
        #[arg(long)]
        seed: Option<u64>,
        /// Comma-separated list of addresses for each validator (one per validator,
        /// in index order). When omitted, all peers default to 127.0.0.1.
        #[arg(long, value_delimiter = ',')]
        addresses: Option<Vec<String>>,
        /// WebSocket gRPC bind address (e.g. [::]:31130). Baked into the TOML.
        #[arg(long)]
        ws_bind: Option<String>,
        /// Explorer WebSocket URL for pushing activity events and serving queries
        #[arg(long)]
        ws_push: Option<String>,
        /// Prometheus metrics port (defaults to 9090 + node index)
        #[arg(long)]
        metrics_port: Option<u16>,
        /// Genesis allocation as address:balance. May be repeated.
        #[arg(long = "genesis-allocation")]
        genesis_allocations: Vec<String>,
    },
    /// Run a validator node
    Run {
        /// Path to the TOML config file
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate a TOML config without running the node
    CheckConfig {
        #[arg(long)]
        config: PathBuf,
    },
    /// Query a running validator via RPC
    Query {
        /// RPC endpoint (e.g. http://127.0.0.1:9000)
        #[arg(long)]
        rpc: String,
        #[command(subcommand)]
        query: QueryCommand,
    },
    /// Manage wallet keys
    Wallet {
        #[command(subcommand)]
        wallet: WalletCommand,
    },
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Generate a new keypair and save to disk
    Create,
    /// Display the address for the stored key
    View,
}

#[derive(Subcommand)]
enum QueryCommand {
    /// Get the latest finalized block
    LatestBlock,
    /// Get the current state root
    StateRoot,
    /// Get a Merkle inclusion proof for an object
    Proof {
        /// Hex-encoded 32-byte object ID
        #[arg(long)]
        object_id: String,
    },
    /// Get the finalization certificate for a payload
    Finalization {
        /// Hex-encoded 32-byte payload digest
        #[arg(long)]
        payload: String,
    },
    /// Look up a coin by object ID in the latest finalized state
    Coin {
        /// Hex-encoded 32-byte object ID
        #[arg(long)]
        object_id: String,
    },
    /// Submit a transfer transaction
    Transfer {
        /// Hex-encoded 32-byte secp256r1 private key (sender)
        #[arg(long)]
        key: String,
        /// Hex-encoded 32-byte object ID of the input coin
        #[arg(long)]
        input: String,
        /// Base58-encoded secp256r1 public key of the recipient
        #[arg(long)]
        recipient: String,
        /// Amount to transfer
        #[arg(long)]
        amount: u64,
        /// WebAuthn origin embedded in clientDataJSON
        #[arg(long, default_value = "https://wallet.hellas.ai")]
        origin: String,
    },
    /// Submit a merge-coin transaction
    MergeCoin {
        /// Hex-encoded 32-byte secp256r1 private key (owner)
        #[arg(long)]
        key: String,
        /// Comma-separated hex-encoded 32-byte object IDs to merge
        #[arg(long, value_delimiter = ',')]
        inputs: Vec<String>,
        /// WebAuthn origin embedded in clientDataJSON
        #[arg(long, default_value = "https://wallet.hellas.ai")]
        origin: String,
    },
    /// Subscribe to consensus activity events
    Activity,
    /// List all known validators
    Validators,
    /// List coins owned by an address
    CoinsByOwner {
        /// Base58-encoded secp256r1 public key address
        #[arg(long)]
        owner: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Config {
            validators,
            node,
            start_port,
            seed,
            addresses,
            ws_bind,
            ws_push,
            metrics_port,
            genesis_allocations,
        } => setup(SetupArgs {
            validators,
            node,
            start_port,
            seed,
            addresses,
            ws_bind,
            ws_push,
            metrics_port,
            genesis_allocations,
        }),
        Command::Run { config } => run(config),
        Command::CheckConfig { config } => check_config(config),
        Command::Query { rpc, query } => do_query(rpc, query),
        Command::Wallet { wallet } => do_wallet(wallet),
    };

    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn wallet_key_path() -> Result<PathBuf, ValidatorError> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| ValidatorError::InvalidSetup("cannot determine data directory".into()))?;
    Ok(base.join("hellas").join("wallet.key"))
}

fn do_wallet(cmd: WalletCommand) -> Result<(), ValidatorError> {
    let path = wallet_key_path()?;
    match cmd {
        WalletCommand::Create => {
            if path.exists() {
                return Err(ValidatorError::InvalidSetup(format!(
                    "wallet already exists at {}; remove it first to create a new one",
                    path.display()
                )));
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    ValidatorError::InvalidSetup(format!("failed to create directory: {e}"))
                })?;
            }
            let key = random_user_private_key();
            let addr = wallet_address_from_signing_key(&key);
            let hex_key = hex::encode(key.to_bytes());
            std::fs::write(&path, &hex_key).map_err(|e| {
                ValidatorError::InvalidSetup(format!("failed to write wallet key: {e}"))
            })?;
            println!("address: {addr}");
            println!("saved to: {}", path.display());
            Ok(())
        }
        WalletCommand::View => {
            let hex_key = std::fs::read_to_string(&path).map_err(|e| {
                ValidatorError::InvalidSetup(format!(
                    "failed to read wallet key from {}: {e}",
                    path.display()
                ))
            })?;
            let key = parse_hex_private_key(hex_key.trim())?;
            let addr = wallet_address_from_signing_key(&key);
            println!("address: {addr}");
            Ok(())
        }
    }
}

struct SetupArgs {
    validators: u32,
    node: u32,
    start_port: u16,
    seed: Option<u64>,
    addresses: Option<Vec<String>>,
    ws_bind: Option<String>,
    ws_push: Option<String>,
    metrics_port: Option<u16>,
    genesis_allocations: Vec<String>,
}

fn setup(args: SetupArgs) -> Result<(), ValidatorError> {
    let SetupArgs {
        validators,
        node,
        start_port,
        seed,
        addresses,
        ws_bind,
        ws_push,
        metrics_port,
        genesis_allocations,
    } = args;

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
    if let Some(ref addrs) = addresses
        && addrs.len() != validators as usize
    {
        return Err(ValidatorError::InvalidSetup(format!(
            "--addresses must have exactly {validators} entries (one per validator), got {}",
            addrs.len(),
        )));
    }

    if seed.is_none() {
        eprintln!(
            "warning: generating cryptographically random keys without --seed; configs will not be reproducible"
        );
    }
    let keys: Vec<ed25519::PrivateKey> = (0..validators)
        .map(|i| match seed {
            Some(s) => ed25519::PrivateKey::from_seed(s + i as u64),
            None => random_private_key(),
        })
        .collect();
    let threshold_participants = Set::try_from(
        keys.iter()
            .map(|key| key.public_key())
            .collect::<Vec<PublicKey>>(),
    )
    .map_err(|_| {
        ValidatorError::InvalidSetup("generated duplicate validator identity keys".to_string())
    })?;
    let (threshold_polynomial, threshold_shares) =
        deal_threshold_shares(seed, threshold_participants)?;

    let my_key = &keys[node as usize];
    let my_public_key = my_key.public_key();
    let my_threshold_share = threshold_shares.get_value(&my_public_key).ok_or_else(|| {
        ValidatorError::InvalidSetup("missing threshold share for generated validator".to_string())
    })?;
    let peers: Vec<PeerEntry> = keys
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != node as usize)
        .map(|(i, k)| {
            let host = addresses
                .as_ref()
                .map(|a| a[i].as_str())
                .unwrap_or("127.0.0.1");
            PeerEntry {
                public_key: hex::encode(k.public_key().encode()),
                address: format!("{}:{}", host, start_port + i as u16),
            }
        })
        .collect();
    let genesis_allocations = genesis_allocations
        .iter()
        .map(|raw| parse_genesis_allocation(raw))
        .collect::<Result<Vec<_>, _>>()?;

    let config = NodeConfig {
        private_key: encode_private_key(my_key),
        threshold_share: encode_threshold_share(my_threshold_share),
        threshold_polynomial: encode_threshold_polynomial(&threshold_polynomial),
        listen_port: start_port + node as u16,
        metrics_port: Some(metrics_port.unwrap_or(9090 + node as u16)),
        ws_bind,
        explorer_url: ws_push,
        genesis_allocations,
        peers,
    };
    config.genesis_allocations()?;

    let rendered = toml::to_string_pretty(&config)?;
    println!("{rendered}");
    Ok(())
}

fn parse_genesis_allocation(raw: &str) -> Result<GenesisEntry, ValidatorError> {
    let (address, balance) = raw.rsplit_once(':').ok_or_else(|| {
        ValidatorError::InvalidSetup(
            "genesis allocation must have the form address:balance".to_string(),
        )
    })?;
    let address = address.parse::<Address>().map_err(|err| {
        ValidatorError::InvalidSetup(format!("invalid genesis allocation address: {err}"))
    })?;
    let balance = balance.parse::<u64>().map_err(|err| {
        ValidatorError::InvalidSetup(format!("invalid genesis allocation balance: {err}"))
    })?;
    Ok(GenesisEntry {
        address: address.to_string(),
        balance,
    })
}

fn parse_hex_private_key(hex_str: &str) -> Result<UserSigningKey, ValidatorError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| ValidatorError::InvalidSetup(format!("bad hex for key: {e}")))?;
    UserSigningKey::from_slice(bytes.as_slice()).map_err(|_| {
        ValidatorError::InvalidSetup("key must be a valid secp256r1 private key".into())
    })
}

fn do_query(rpc: String, query: QueryCommand) -> Result<(), ValidatorError> {
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| ValidatorError::InvalidSetup(format!("failed to start runtime: {err}")))?;
    runtime.block_on(async move {
        let client = RemoteLightClient::connect(rpc)
            .await
            .map_err(|err| ValidatorError::InvalidSetup(format!("failed to connect: {err}")))?;
        match query {
            QueryCommand::LatestBlock => {
                match client.get_latest_block().await.map_err(query_error)? {
                    Some(block) => {
                        println!("height {}", block.height);
                        println!("payload {}", hex::encode(block.payload));
                        println!("state_root {}", hex::encode(block.state_root));
                        println!("finalization {}", hex::encode(block.finalization));
                    }
                    None => println!("none"),
                }
                Ok(())
            }
            QueryCommand::StateRoot => {
                match client.get_state_root().await.map_err(query_error)? {
                    Some(root) => println!("{}", hex::encode(root)),
                    None => println!("none"),
                }
                Ok(())
            }
            QueryCommand::Coin { object_id } => {
                let object_id = parse_hex_digest(&object_id, "object_id")?;
                let Some(latest) = client.get_latest_block().await.map_err(query_error)? else {
                    println!("none");
                    return Ok(());
                };
                match client
                    .get_coin(latest.payload, object_id)
                    .await
                    .map_err(query_error)?
                {
                    Some(coin) => println!("{} {}", coin.owner, coin.value),
                    None => println!("none"),
                }
                Ok(())
            }
            QueryCommand::Validators => {
                for validator in client.get_validators().await.map_err(query_error)? {
                    println!("{validator}");
                }
                Ok(())
            }
            QueryCommand::CoinsByOwner { owner } => {
                let owner = owner.parse::<Address>().map_err(|err| {
                    ValidatorError::InvalidSetup(format!("invalid owner address: {err}"))
                })?;
                match client
                    .get_coins_by_owner(owner)
                    .await
                    .map_err(query_error)?
                {
                    Some(owner_coins) => {
                        println!("height {}", owner_coins.snapshot.height);
                        println!("payload {}", hex::encode(owner_coins.snapshot.payload));
                        println!(
                            "state_root {}",
                            hex::encode(owner_coins.snapshot.state_root)
                        );
                        println!(
                            "finalization {}",
                            hex::encode(owner_coins.snapshot.finalization)
                        );
                        for (object_id, value) in owner_coins.coins {
                            println!("{} {}", hex::encode(object_id), value);
                        }
                    }
                    None => println!("none"),
                }
                Ok(())
            }
            QueryCommand::Proof { .. }
            | QueryCommand::Finalization { .. }
            | QueryCommand::Transfer { .. }
            | QueryCommand::MergeCoin { .. }
            | QueryCommand::Activity => Err(ValidatorError::InvalidSetup(
                "query command is not implemented".to_string(),
            )),
        }
    })
}

fn parse_hex_digest(raw: &str, field: &'static str) -> Result<Digest, ValidatorError> {
    let bytes = hex::decode(raw)
        .map_err(|err| ValidatorError::InvalidSetup(format!("bad hex for {field}: {err}")))?;
    let len = bytes.len();
    let raw: [u8; 32] = bytes.try_into().map_err(|_| {
        ValidatorError::InvalidSetup(format!("{field} must be 32 bytes, got {len}"))
    })?;
    Ok(Digest::from(raw))
}

fn query_error(err: impl std::fmt::Display) -> ValidatorError {
    ValidatorError::InvalidSetup(format!("query failed: {err}"))
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn otlp_sample_rate() -> f64 {
    let Some(raw) = env_non_empty(OTLP_SAMPLE_RATE_ENV) else {
        return DEFAULT_OTLP_SAMPLE_RATE;
    };
    match raw.parse::<f64>() {
        Ok(value) if (0.0..=1.0).contains(&value) => value,
        _ => {
            eprintln!(
                "warning: invalid OTLP sample rate `{raw}` in {OTLP_SAMPLE_RATE_ENV}; expected a value in [0.0, 1.0], using {}",
                DEFAULT_OTLP_SAMPLE_RATE,
            );
            DEFAULT_OTLP_SAMPLE_RATE
        }
    }
}

/// Initialise the tracing subscriber.
///
/// When `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set (and non-empty), an
/// OpenTelemetry OTLP layer is added that exports traces over HTTP/protobuf.
///
/// Supported environment variables:
///   RUST_LOG                             — log filter (default: info)
///   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT   — collector URL
///   OTEL_SERVICE_NAME                    — service name (default: hellas-validator)
///   OTEL_TRACES_SAMPLER_ARG             — sample rate 0.0–1.0 (default: 1.0)
///   OTEL_EXPORTER_OTLP_HEADERS          — extra headers as k=v,k=v
fn init_telemetry() -> Option<opentelemetry_sdk::trace::SdkTracerProvider> {
    use tracing_subscriber::prelude::*;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_line_number(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .compact();

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
    let endpoint = match env_non_empty(OTLP_ENDPOINT_ENV) {
        Some(v) => v,
        None => return (None, None),
    };

    let service_name = env_non_empty(OTLP_SERVICE_NAME_ENV)
        .unwrap_or_else(|| DEFAULT_OTLP_SERVICE_NAME.to_string());

    let sample_rate = otlp_sample_rate();

    let headers: std::collections::HashMap<String, String> = env_non_empty(OTLP_HEADERS_ENV)
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

fn spawn_metrics_server(context: tokio::Context, addr: SocketAddr) {
    use axum::{Router, routing::get};

    context.child("metrics").spawn(move |context| async move {
        let listener = ::tokio::net::TcpListener::bind(addr)
            .await
            .expect("failed to bind metrics server");
        let metrics_context = std::sync::Arc::new(context);

        let app = Router::new().route(
            "/metrics",
            get({
                let metrics_context = metrics_context.clone();
                move || {
                    let metrics_context = metrics_context.clone();
                    async move {
                        axum::http::Response::builder()
                            .status(axum::http::StatusCode::OK)
                            .header(
                                axum::http::header::CONTENT_TYPE,
                                "text/plain; version=0.0.4",
                            )
                            .body(axum::body::Body::from(metrics_context.encode()))
                            .expect("failed to create response")
                    }
                }
            }),
        );

        axum::serve(listener, app.into_make_service())
            .await
            .expect("could not serve metrics");
    });
}

async fn wait_for_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use ::tokio::signal::unix::{SignalKind, signal};
        use futures::future::Either;

        let ctrl_c = ::tokio::signal::ctrl_c();
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                let sigterm_wait = sigterm.recv();
                futures::pin_mut!(ctrl_c);
                futures::pin_mut!(sigterm_wait);
                match futures::future::select(ctrl_c, sigterm_wait).await {
                    Either::Left((res, _)) => {
                        if let Err(err) = res {
                            warn!(?err, "failed waiting for SIGINT");
                        }
                        "sigint"
                    }
                    Either::Right((_res, _)) => "sigterm",
                }
            }
            Err(err) => {
                warn!(
                    ?err,
                    "failed to install SIGTERM handler, falling back to SIGINT only"
                );
                if let Err(wait_err) = ctrl_c.await {
                    warn!(?wait_err, "failed waiting for SIGINT");
                }
                "sigint"
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(err) = ::tokio::signal::ctrl_c().await {
            warn!(?err, "failed waiting for shutdown signal");
        }
        "ctrl_c"
    }
}

#[derive(Clone, Copy)]
enum ShutdownTrigger {
    Signal(&'static str),
    NetworkExited,
    EngineExited,
    RpcExited,
}

async fn graceful_stop(context: tokio::Context, monitor_second_signal: bool) {
    if monitor_second_signal {
        let stop = context.stop(0, Some(SHUTDOWN_TIMEOUT));
        let second_signal = wait_for_shutdown_signal();
        futures::pin_mut!(stop);
        futures::pin_mut!(second_signal);
        match futures::future::select(stop, second_signal).await {
            futures::future::Either::Left((stop_result, _)) => {
                if let Err(err) = stop_result {
                    warn!(?err, "runtime stop failed or timed out");
                }
            }
            futures::future::Either::Right((second, _)) => {
                eprintln!("received second shutdown signal ({second}), forcing exit");
                std::process::exit(1);
            }
        }
        return;
    }

    if let Err(err) = context.stop(0, Some(SHUTDOWN_TIMEOUT)).await {
        warn!(?err, "runtime stop failed or timed out");
    }
}

type Finalization = commonware_consensus::simplex::types::Finalization<
    Scheme,
    commonware_cryptography::sha256::Digest,
>;
type FinalizationStore =
    immutable::Archive<tokio::Context, commonware_cryptography::sha256::Digest, Finalization>;
type BlockStore = immutable::Archive<
    tokio::Context,
    commonware_cryptography::sha256::Digest,
    hellas_chain::HellasBlock,
>;

async fn init_finalization_store(
    context: tokio::Context,
    partition_prefix: &str,
    config: &Config,
) -> FinalizationStore {
    let page_cache = config.page_cache(&context);
    immutable::Archive::init(
        context,
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-finalizations-by-height-metadata"),
            freezer_table_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-table"
            ),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-key"
            ),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!(
                "{partition_prefix}-finalizations-by-height-freezer-value"
            ),
            freezer_value_target_size: 65536,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition_prefix}-finalizations-by-height-ordinal"),
            items_per_section: NZU64!(256),
            codec_config: Scheme::certificate_codec_config_unbounded(),
            replay_buffer: NonZeroUsize::new(config.replay_buffer).unwrap_or(NonZeroUsize::MIN),
            freezer_key_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            freezer_value_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            ordinal_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
        },
    )
    .await
    .expect("failed to initialize finalizations archive")
}

async fn init_block_store(
    context: tokio::Context,
    partition_prefix: &str,
    config: &Config,
) -> BlockStore {
    let page_cache = config.page_cache(&context);
    immutable::Archive::init(
        context,
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-finalized-blocks-metadata"),
            freezer_table_partition: format!("{partition_prefix}-finalized-blocks-freezer-table"),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!("{partition_prefix}-finalized-blocks-freezer-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{partition_prefix}-finalized-blocks-freezer-value"),
            freezer_value_target_size: 65536,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition_prefix}-finalized-blocks-ordinal"),
            items_per_section: NZU64!(256),
            codec_config: (),
            replay_buffer: NonZeroUsize::new(config.replay_buffer).unwrap_or(NonZeroUsize::MIN),
            freezer_key_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            freezer_value_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            ordinal_write_buffer: NonZeroUsize::new(config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
        },
    )
    .await
    .expect("failed to initialize finalized blocks archive")
}

async fn replay_owner_index(
    indexer: &Indexer,
    finalized_blocks: &BlockStore,
) -> Result<(), ValidatorError> {
    for (start, end) in finalized_blocks.ranges() {
        for height in start..=end {
            let block = finalized_blocks
                .get(ArchiveIdentifier::Index(height))
                .await
                .map_err(|err| {
                    ValidatorError::OwnerIndex(format!(
                        "failed to load finalized block at height {height}: {err}"
                    ))
                })?;
            let Some(block) = block else {
                continue;
            };
            indexer.apply_finalized(&block).map_err(|err| {
                ValidatorError::OwnerIndex(format!(
                    "failed to index finalized block at height {height}: {err}"
                ))
            })?;
        }
    }
    Ok(())
}

/// Run all `NodeConfig` validations the runtime would perform at startup.
/// Used by `validator check-config` and by `nix build` via runCommand.
fn check_config(config_path: PathBuf) -> Result<(), ValidatorError> {
    let config_str = std::fs::read_to_string(&config_path)?;
    let node_config: NodeConfig = toml::from_str(&config_str)?;
    node_config.decode_private_key()?;
    node_config.decode_threshold_share()?;
    node_config.decode_threshold_polynomial()?;
    node_config.participants()?;
    node_config.peer_address_map()?;
    node_config.genesis_allocations()?;
    if let Some(ws_bind) = &node_config.ws_bind {
        ws_bind.parse::<SocketAddr>().map_err(|err| {
            ValidatorError::InvalidSetup(format!("invalid ws_bind address: {err}"))
        })?;
    }
    println!("ok");
    Ok(())
}

fn run(config_path: PathBuf) -> Result<(), ValidatorError> {
    let config_str = std::fs::read_to_string(&config_path)?;
    let mut node_config: NodeConfig = toml::from_str(&config_str)?;

    // Prefer systemd-supplied credentials; otherwise keys come from the TOML — fine for dev/test,
    // never for production. eprintln! because tracing isn't initialized yet at this point.
    if !node_config.load_credentials()? {
        eprintln!(
            "WARNING: CREDENTIALS_DIRECTORY not set; using key material from {}. \
             Production must supply keys via systemd LoadCredential.",
            config_path.display(),
        );
    }

    let private_key = node_config.decode_private_key()?;
    let me = private_key.public_key();
    let threshold_share = node_config.decode_threshold_share()?;
    let threshold_polynomial = node_config.decode_threshold_polynomial()?;
    let genesis_allocations = node_config.genesis_allocations()?;

    let git_rev = option_env!("GIT_REV").unwrap_or("unknown");

    let participants = node_config.participants()?;
    let peer_map = node_config.peer_address_map()?;

    let listen_addr: SocketAddr = format!("0.0.0.0:{}", node_config.listen_port).parse()?;

    // Build consensus scheme
    let scheme = match Scheme::signer(
        NAMESPACE,
        participants,
        threshold_polynomial,
        threshold_share,
    ) {
        Some(scheme) => scheme,
        None => {
            return Err(ValidatorError::Scheme(
                "threshold share does not match configured participants".to_string(),
            ));
        }
    };
    let validator_names = scheme
        .participants()
        .iter()
        .map(|public_key| hex::encode(public_key.encode()))
        .collect::<Vec<_>>();

    // Configure tokio runtime
    let storage_dir = node_config.storage_directory()?;
    let storage_dir_utf8 = storage_dir
        .to_str()
        .ok_or_else(|| ValidatorError::NonUtf8StorageDirectory(storage_dir.clone()))?;
    let metrics_addr = node_config
        .metrics_port
        .map(|metrics_port| format!("0.0.0.0:{metrics_port}").parse())
        .transpose()?;
    let ws_bind_addr = node_config
        .ws_bind
        .as_ref()
        .map(|addr| {
            addr.parse::<SocketAddr>().map_err(|err| {
                ValidatorError::InvalidSetup(format!("invalid ws_bind address: {err}"))
            })
        })
        .transpose()?;
    let runtime_cfg = tokio::Config::new()
        .with_storage_directory(storage_dir_utf8)
        .with_tcp_nodelay(Some(true));
    let runner = tokio::Runner::new(runtime_cfg);

    runner.start(move |context| async move {
        let tracer_provider = init_telemetry();

        if let Some(addr) = metrics_addr {
            spawn_metrics_server(context.child("telemetry"), addr);
        }

        info!(
            git_rev,
            version = env!("CARGO_PKG_VERSION"),
            "hellas validator starting",
        );
        if let Some(metrics_port) = node_config.metrics_port {
            info!(metrics_port, "prometheus metrics server started");
        }

        // Create lookup-based p2p network
        let p2p_cfg = lookup::Config::local(private_key, NAMESPACE, listen_addr, MAX_MESSAGE_SIZE);
        let (mut network, mut oracle) = lookup::Network::new(context.child("network"), p2p_cfg);

        // Register all validators with the oracle, then allow address refreshes
        // without introducing a new peer-set epoch.
        oracle.track(0, peer_map.clone());
        oracle.overwrite(peer_map);

        // Register consensus, marshal resolver, and block broadcast channels.
        let quota = Quota::per_second(NonZeroU32::MAX);
        let vote = network.register(0, quota, CHANNEL_BACKLOG);
        let certificate = network.register(1, quota, CHANNEL_BACKLOG);
        let consensus_resolver = network.register(2, quota, CHANNEL_BACKLOG);
        let marshal_resolver_network = network.register(3, quota, CHANNEL_BACKLOG);
        let broadcast_blocks = network.register(4, quota, CHANNEL_BACKLOG);
        let qmdb_resolver_network = network.register(5, quota, CHANNEL_BACKLOG);

        // Publish process uptime as a prometheus gauge, updated every second.
        let uptime_gauge: Gauge<i64, AtomicI64> = Gauge::default();
        let _uptime_registration = context.child("process").register(
            "uptime_seconds",
            "seconds since the validator process started",
            uptime_gauge.clone(),
        );
        let boot = Instant::now();
        ::tokio::spawn(async move {
            let mut tick = ::tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                uptime_gauge.set(boot.elapsed().as_secs() as i64);
            }
        });

        let chain_config = Config::mainnet();
        let partition_prefix = format!("hellas_{me}");
        let page_cache = chain_config.page_cache(&context);
        let finalizations_by_height = init_finalization_store(
            context.child("finalizations_by_height"),
            &partition_prefix,
            &chain_config,
        )
        .await;
        let finalized_blocks = init_block_store(
            context.child("finalized_blocks"),
            &partition_prefix,
            &chain_config,
        )
        .await;

        let mailbox_size =
            NonZeroUsize::new(chain_config.mailbox_size).unwrap_or(NonZeroUsize::MIN);
        let fetch_concurrent =
            NonZeroUsize::new(chain_config.fetch_concurrent).unwrap_or(NonZeroUsize::MIN);
        let max_pending_acks = NZUsize!(1);
        let mempool = Mempool::default();
        let genesis_leader = scheme
            .participants()
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| me.clone());
        let application = Application::new(
            context.child("app"),
            genesis_leader,
            genesis_allocations.clone(),
            &partition_prefix,
            ApplicationConfig {
                page_cache_size: chain_config.page_cache_size,
                page_cache_count: chain_config.page_cache_count,
            },
        )
        .await;
        let owner_index = application.indexer();
        if let Err(err) = replay_owner_index(&owner_index, &finalized_blocks).await {
            error!(?err, "owner index replay failed");
            panic!("{err}");
        }
        let owner_index_cursor = owner_index.cursor();
        info!(
            height = owner_index_cursor.height,
            payload = ?owner_index_cursor.payload,
            "owner index replayed",
        );
        let genesis_block = application.genesis_block();
        let stateful_startup_context = context.child("stateful_startup");
        let plan = SyncPlan::<_, Scheme, Standard<hellas_chain::HellasBlock>>::init(
            &stateful_startup_context,
            partition_prefix.clone(),
        )
        .await;
        let sync_floor = plan.floor().cloned();

        let epocher = FixedEpocher::new(NonZeroU64::new(u64::MAX).unwrap());
        let marshal_config = marshal::Config {
            provider: ConstantProvider::new(scheme.clone()),
            epocher: epocher.clone(),
            start: plan.marshal_start(genesis_block.clone()),
            partition_prefix: partition_prefix.clone(),
            mailbox_size,
            view_retention_timeout: ViewDelta::new(chain_config.activity_timeout),
            prunable_items_per_section: NZU64!(256),
            page_cache: page_cache.clone(),
            replay_buffer: NonZeroUsize::new(chain_config.replay_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            key_write_buffer: NonZeroUsize::new(chain_config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            value_write_buffer: NonZeroUsize::new(chain_config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            block_codec_config: (),
            max_repair: NonZeroUsize::new(chain_config.max_repair).unwrap_or(NonZeroUsize::MIN),
            max_pending_acks,
            strategy: Sequential,
        };
        let (marshal_actor, marshal_mailbox, _last_height) =
            MarshalActor::<_, Standard<hellas_chain::HellasBlock>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal_config,
            )
            .await;

        let broadcast_config = buffered::Config {
            public_key: me.clone(),
            mailbox_size,
            deque_size: chain_config.broadcast_cache_per_peer,
            priority: false,
            codec_config: (),
            peer_provider: oracle.clone(),
        };
        let (broadcast_engine, buffer) =
            buffered::Engine::new(context.child("broadcast"), broadcast_config);
        let broadcast_handle = broadcast_engine.start(broadcast_blocks);

        let resolver_cfg = marshal_resolver::Config {
            public_key: me.clone(),
            peer_provider: oracle.clone(),
            blocker: oracle.clone(),
            mailbox_size,
            initial: Duration::from_secs(1),
            timeout: chain_config.fetch_timeout,
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = marshal_resolver::init(
            context.child("marshal_resolver"),
            resolver_cfg,
            marshal_resolver_network,
        );

        let (qmdb_resolver_actor, qmdb_sync_resolver) =
            qmdb_resolver::Actor::<_, PublicKey, _, _, mmr::Family, UtxoDb<_>>::new(
                context.child("qmdb_resolver"),
                qmdb_resolver::Config {
                    peer_provider: oracle.clone(),
                    blocker: oracle.clone(),
                    database: None,
                    mailbox_size,
                    me: Some(me.clone()),
                    initial: Duration::from_secs(1),
                    timeout: chain_config.fetch_timeout,
                    fetch_retry_timeout: Duration::from_millis(100),
                    max_serve_ops: NZU64!(64),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
        let qmdb_resolver_handle = qmdb_resolver_actor.start(qmdb_resolver_network);

        let db_config = utxo_db_config(
            &context,
            &partition_prefix,
            chain_config.page_cache_size,
            chain_config.page_cache_count,
        );
        let (stateful_actor, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config,
                input_provider: mempool.clone(),
                marshal: marshal_mailbox.clone(),
                max_pending_acks,
                mailbox_size,
                plan,
                resolvers: qmdb_sync_resolver.clone(),
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(64),
                    apply_batch_size: 1024,
                    max_outstanding_requests: 8,
                    update_channel_size: NZUsize!(256),
                    max_retained_roots: 8,
                },
            },
        );

        let deferred = Deferred::new(
            context.child("deferred"),
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            epocher,
        );
        let (activity_tx, _) = ::tokio::sync::broadcast::channel(1024);
        let simplex_config = simplex::Config {
            scheme,
            elector: RoundRobin::<commonware_cryptography::Sha256>::default(),
            blocker: oracle.clone(),
            automaton: deferred.clone(),
            relay: deferred,
            reporter: ActivityReporter::new(marshal_mailbox.clone(), activity_tx.clone()),
            strategy: Sequential,
            partition: format!("{partition_prefix}-simplex"),
            mailbox_size,
            epoch: Epoch::zero(),
            floor: sync_floor.map_or_else(
                || simplex::config::Floor::Genesis(genesis_block.digest()),
                simplex::config::Floor::Finalized,
            ),
            replay_buffer: NonZeroUsize::new(chain_config.replay_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            write_buffer: NonZeroUsize::new(chain_config.write_buffer).unwrap_or(NonZeroUsize::MIN),
            page_cache,
            leader_timeout: chain_config.leader_timeout,
            certification_timeout: chain_config.certification_timeout,
            timeout_retry: chain_config.nullify_retry,
            activity_timeout: ViewDelta::new(chain_config.activity_timeout),
            skip_timeout: ViewDelta::new(chain_config.skip_timeout),
            fetch_timeout: chain_config.fetch_timeout,
            fetch_concurrent,
            forwarding: ForwardingPolicy::Disabled,
        };
        let simplex_engine = simplex::Engine::new(context.child("simplex"), simplex_config);

        let marshal_handle = marshal_actor.start(stateful_mailbox.clone(), buffer, resolver);
        let stateful_handle = stateful_actor.start();
        let engine_handle = simplex_engine.start(vote, certificate, consensus_resolver);

        let databases = stateful_mailbox.subscribe_databases().await;
        let startup_root = databases.read().await.root();
        info!(?startup_root, "application startup barrier passed");
        let rpc_handle = if let Some(addr) = ws_bind_addr {
            let light_client = LocalLightClient::new(
                databases.clone(),
                owner_index.clone(),
                mempool.clone(),
                marshal_mailbox.clone(),
                validator_names.clone(),
            );
            Some(
                spawn_light_client_server(addr, light_client, activity_tx.clone())
                    .await
                    .unwrap_or_else(|source| {
                        panic!("{}", ValidatorError::RpcBind { addr, source })
                    }),
            )
        } else {
            None
        };

        if let Some(explorer_url) = &node_config.explorer_url {
            warn!(
                %explorer_url,
                "explorer_url is not implemented",
            );
        }

        // Start networking only after the app + consensus engine are initialized.
        let network_handle = network.start();

        let signal_waiter = wait_for_shutdown_signal()
            .map(ShutdownTrigger::Signal)
            .boxed();
        let network_waiter = network_handle
            .map(|_| ShutdownTrigger::NetworkExited)
            .boxed();
        let engine_waiter = engine_handle.map(|_| ShutdownTrigger::EngineExited).boxed();
        let marshal_waiter = marshal_handle
            .map(|_| ShutdownTrigger::EngineExited)
            .boxed();
        let broadcast_waiter = broadcast_handle
            .map(|_| ShutdownTrigger::EngineExited)
            .boxed();
        let stateful_waiter = stateful_handle
            .map(|_| ShutdownTrigger::EngineExited)
            .boxed();
        let qmdb_resolver_waiter = qmdb_resolver_handle
            .map(|_| ShutdownTrigger::EngineExited)
            .boxed();
        let rpc_waiter =
            rpc_handle.map(|handle| handle.map(|_| ShutdownTrigger::RpcExited).boxed());

        let mut waiters = vec![
            signal_waiter,
            network_waiter,
            engine_waiter,
            marshal_waiter,
            broadcast_waiter,
            stateful_waiter,
            qmdb_resolver_waiter,
        ];
        if let Some(rpc_waiter) = rpc_waiter {
            waiters.push(rpc_waiter);
        }

        let (trigger, _, _) = futures::future::select_all(waiters).await;

        let signal_triggered = matches!(trigger, ShutdownTrigger::Signal(_));
        match trigger {
            ShutdownTrigger::Signal(signal) => {
                info!(signal, "received shutdown signal");
            }
            ShutdownTrigger::NetworkExited => {
                warn!("network task exited unexpectedly; triggering shutdown");
            }
            ShutdownTrigger::EngineExited => {
                warn!("engine task exited unexpectedly; triggering shutdown");
            }
            ShutdownTrigger::RpcExited => {
                warn!("RPC task exited unexpectedly; triggering shutdown");
            }
        }

        graceful_stop(context, signal_triggered).await;

        if let Some(provider) = tracer_provider
            && let Err(err) = provider.shutdown()
        {
            warn!(?err, "failed to flush OTLP traces on shutdown");
        }

        // Any non-signal trigger means a sibling actor died unexpectedly. Exit non-zero so
        // systemd's `Restart=on-failure` kicks in instead of treating us as a clean shutdown.
        if !signal_triggered {
            std::process::exit(1);
        }
    });
    Ok(())
}
