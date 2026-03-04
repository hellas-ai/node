use base64ct::{Base64UrlUnpadded, Encoding};
use clap::{Parser, Subcommand};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::certificate::Scheme as _;
use commonware_cryptography::{Signer, ed25519};
use commonware_p2p::{AddressableManager, authenticated::lookup};
use commonware_runtime::{Clock, Metrics, Quota, Runner, Spawner, tokio};
use futures::FutureExt;
use hellas_chain::TraceReporter;
use hellas_chain::config::{Config, ConfigError, NodeConfig, PeerEntry, encode_private_key};
use hellas_chain::engine::Engine;
use hellas_chain::shard::AuthenticatedShardTransport;
use hellas_types::Scheme;
use p256::ecdsa::SigningKey as UserSigningKey;
use p256::ecdsa::signature::Signer as _;
use prometheus_client::metrics::gauge::Gauge;
use rand::RngCore;
use sha2::{Digest as _, Sha256 as Sha2};
use std::io;
use std::sync::atomic::AtomicI64;
use std::time::{Duration, Instant};
use std::{net::SocketAddr, num::NonZeroU32, path::PathBuf, sync::Arc};
use thiserror::Error;
use tracing::{info, warn};

const NAMESPACE: &[u8] = b"hellas";
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
const CHANNEL_BACKLOG: usize = 1024;
const SHARD_CHANNEL_BACKLOG: usize = 4096;
const DEFAULT_OTLP_SERVICE_NAME: &str = "hellas-validator";
const DEFAULT_OTLP_SAMPLE_RATE: f64 = 1.0;
const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";
const OTLP_SERVICE_NAME_ENV: &str = "OTEL_SERVICE_NAME";
const OTLP_SAMPLE_RATE_ENV: &str = "OTEL_TRACES_SAMPLER_ARG";
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

fn random_private_key() -> ed25519::PrivateKey {
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    ed25519::PrivateKey::decode(raw.as_slice())
        .expect("decoding 32 random bytes as an ed25519 private key should always succeed")
}

fn random_user_private_key() -> UserSigningKey {
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    UserSigningKey::from_slice(&raw)
        .expect("decoding 32 random bytes as a secp256r1 private key should succeed")
}

fn wallet_address_from_signing_key(key: &UserSigningKey) -> hellas_types::Address {
    hellas_types::Address::from(hellas_types::UserPublicKey::from(
        key.verifying_key().to_owned(),
    ))
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha2::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn mock_webauthn_sign(
    key: &UserSigningKey,
    challenge: &commonware_cryptography::sha256::Digest,
    origin: &str,
) -> Result<hellas_types::WebAuthnSignature, ValidatorError> {
    let challenge_b64 = Base64UrlUnpadded::encode_string(&challenge.to_vec());
    let client_data_json = format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        hellas_types::WEBAUTHN_TYPE_GET,
        challenge_b64,
        origin
    )
    .into_bytes();

    let rp_id_hash = hellas_types::rp_id_hash_from_origin(origin).ok_or_else(|| {
        ValidatorError::InvalidSetup(format!("invalid WebAuthn origin for signing: {origin}"))
    })?;

    let mut authenticator_data = Vec::with_capacity(hellas_types::MIN_AUTHENTICATOR_DATA_LEN);
    authenticator_data.extend_from_slice(&rp_id_hash);
    authenticator_data.push(0x05); // UP | UV
    authenticator_data.extend_from_slice(&0u32.to_be_bytes());

    let client_hash = sha256_bytes(&client_data_json);
    let mut msg = Vec::with_capacity(authenticator_data.len() + client_hash.len());
    msg.extend_from_slice(&authenticator_data);
    msg.extend_from_slice(&client_hash);

    let signed: p256::ecdsa::Signature = key.sign(&msg);
    let normalized = signed.normalize_s().unwrap_or(signed);
    let signature = hellas_types::UserSignature::decode(normalized.to_bytes().as_ref())
        .map_err(|e| ValidatorError::InvalidSetup(format!("invalid signature bytes: {e}")))?;

    Ok(hellas_types::WebAuthnSignature {
        signature,
        authenticator_data,
        client_data_json,
    })
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
        /// Explorer WebSocket URL for pushing activity events and serving queries
        #[arg(long)]
        ws_push: Option<String>,
        /// Minimum time (ms) the leader waits before emitting a proposal
        #[arg(long)]
        min_propose_ms: Option<u64>,
    },
    /// Run a validator node
    Run {
        /// Path to the TOML config file
        #[arg(long)]
        config: PathBuf,
        /// Enable structured JSON logs on stderr.
        ///
        /// A value is accepted for backward CLI compatibility but not used.
        #[arg(long)]
        log_json: Option<PathBuf>,
        /// WebSocket gRPC bind address (e.g. [::]:31130)
        #[arg(long)]
        ws_bind: Option<String>,
        /// Explorer WebSocket URL for pushing activity events and serving queries
        #[arg(long)]
        ws_push: Option<String>,
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
            ws_push,
            min_propose_ms,
        } => setup(
            validators,
            node,
            start_port,
            seed,
            addresses,
            ws_push,
            min_propose_ms,
        ),
        Command::Run {
            config,
            log_json,
            ws_bind,
            ws_push,
        } => run(config, log_json, ws_bind, ws_push),
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

fn setup(
    validators: u32,
    node: u32,
    start_port: u16,
    seed: Option<u64>,
    addresses: Option<Vec<String>>,
    ws_push: Option<String>,
    min_propose_ms: Option<u64>,
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
    if let Some(ref addrs) = addresses {
        if addrs.len() != validators as usize {
            return Err(ValidatorError::InvalidSetup(format!(
                "--addresses must have exactly {validators} entries (one per validator), got {}",
                addrs.len(),
            )));
        }
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

    let my_key = &keys[node as usize];
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

    let config = NodeConfig {
        private_key: encode_private_key(my_key),
        listen_port: start_port + node as u16,
        metrics_port: Some(9090 + node as u16),
        ws_bind: None,
        explorer_url: ws_push,
        min_propose_ms,
        genesis_allocations: Vec::new(),
        peers,
    };

    let rendered = toml::to_string_pretty(&config)?;
    println!("{rendered}");
    Ok(())
}

fn parse_hex_digest(
    hex_str: &str,
    field: &str,
) -> Result<commonware_cryptography::sha256::Digest, ValidatorError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| ValidatorError::InvalidSetup(format!("bad hex for {field}: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ValidatorError::InvalidSetup(format!("{field} must be 32 bytes")))?;
    Ok(commonware_cryptography::sha256::Digest::from(arr))
}

fn parse_hex_private_key(hex_str: &str) -> Result<UserSigningKey, ValidatorError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| ValidatorError::InvalidSetup(format!("bad hex for key: {e}")))?;
    UserSigningKey::from_slice(bytes.as_slice()).map_err(|_| {
        ValidatorError::InvalidSetup("key must be a valid secp256r1 private key".into())
    })
}

fn do_query(rpc: String, query: QueryCommand) -> Result<(), ValidatorError> {
    let rt = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ValidatorError::InvalidSetup(format!("failed to create runtime: {e}")))?;
    rt.block_on(async {
        let client = hellas_rpc::client::RemoteLightClient::connect(rpc)
            .await
            .map_err(|e| ValidatorError::InvalidSetup(format!("failed to connect: {e}")))?;

        use hellas_types::rpc::LightClient;
        match query {
            QueryCommand::LatestBlock => {
                let block = client
                    .get_latest_block()
                    .await
                    .map_err(|e| ValidatorError::InvalidSetup(e.to_string()))?;
                match block {
                    Some(b) => {
                        println!("height:     {}", b.height);
                        println!("payload:    {}", hex::encode(b.payload));
                        println!("state_root: {}", hex::encode(b.state_root));
                    }
                    None => println!("no block persisted yet"),
                }
            }
            QueryCommand::StateRoot => {
                let root = client
                    .get_state_root()
                    .await
                    .map_err(|e| ValidatorError::InvalidSetup(e.to_string()))?;
                match root {
                    Some(r) => println!("{}", hex::encode(r)),
                    None => println!("no state root available"),
                }
            }
            QueryCommand::Proof { object_id } => {
                let digest = parse_hex_digest(&object_id, "object_id")?;
                let proof = client
                    .get_proof(digest)
                    .await
                    .map_err(|e| ValidatorError::InvalidSetup(e.to_string()))?;
                match proof {
                    Some(p) => println!("{}", hex::encode(p)),
                    None => println!("no proof found"),
                }
            }
            QueryCommand::Finalization { payload } => {
                let digest = parse_hex_digest(&payload, "payload")?;
                let cert = client
                    .get_finalization(digest)
                    .await
                    .map_err(|e| ValidatorError::InvalidSetup(e.to_string()))?;
                match cert {
                    Some(c) => println!("{}", hex::encode(c)),
                    None => println!("no finalization certificate found"),
                }
            }
            QueryCommand::Coin { object_id } => {
                let digest = parse_hex_digest(&object_id, "object_id")?;
                let block = client
                    .get_latest_block()
                    .await
                    .map_err(|e| ValidatorError::InvalidSetup(e.to_string()))?;
                let Some(block) = block else {
                    println!("no block finalized yet");
                    return Ok(());
                };
                let coin = client
                    .get_coin(block.payload, digest)
                    .await
                    .map_err(|e| ValidatorError::InvalidSetup(e.to_string()))?;
                match coin {
                    Some(c) => {
                        println!("owner: {}", c.owner);
                        println!("value: {}", c.value);
                    }
                    None => println!("coin not found"),
                }
            }
            QueryCommand::Transfer {
                key,
                input,
                recipient,
                amount,
                origin,
            } => {
                let private_key = parse_hex_private_key(&key)?;
                let input_digest = parse_hex_digest(&input, "input")?;
                let recipient_addr: hellas_types::Address = recipient.parse()
                    .map_err(|e: hellas_types::AddressError| ValidatorError::InvalidSetup(format!("bad recipient: {e}")))?;
                let challenge = hellas_types::transfer_challenge(&input_digest, &recipient_addr, amount);
                let signature = mock_webauthn_sign(&private_key, &challenge, &origin)?;
                let tx = hellas_types::Transaction::Transfer {
                    input: input_digest,
                    recipient: recipient_addr,
                    amount,
                    signature,
                };
                client
                    .submit_tx(tx)
                    .await
                    .map_err(|e| ValidatorError::InvalidSetup(e.to_string()))?;
                println!("transaction submitted");
            }
            QueryCommand::MergeCoin { key, inputs, origin } => {
                let private_key = parse_hex_private_key(&key)?;
                let mut input_digests: Vec<commonware_cryptography::sha256::Digest> = inputs
                    .iter()
                    .enumerate()
                    .map(|(i, hex_str)| parse_hex_digest(hex_str, &format!("inputs[{i}]")))
                    .collect::<Result<_, _>>()?;
                input_digests.sort();
                let challenge = hellas_types::merge_challenge(&input_digests);
                let signature = mock_webauthn_sign(&private_key, &challenge, &origin)?;
                let tx = hellas_types::Transaction::MergeCoin {
                    inputs: input_digests,
                    signature,
                };
                client
                    .submit_tx(tx)
                    .await
                    .map_err(|e| ValidatorError::InvalidSetup(e.to_string()))?;
                println!("transaction submitted");
            }
            QueryCommand::Validators => {
                let validators = client
                    .get_validators()
                    .await
                    .map_err(|e| ValidatorError::InvalidSetup(e.to_string()))?;
                for v in &validators {
                    println!("{v}");
                }
            }
            QueryCommand::Activity => {
                use hellas_rpc::pb::hellas::{ActivityEvent, activity_event::Event};
                let mut stream = client
                    .subscribe_activity()
                    .await
                    .map_err(|e| ValidatorError::InvalidSetup(e.to_string()))?;
                while let Some(event) = stream
                    .message::<ActivityEvent>()
                    .await
                    .map_err(|e| ValidatorError::InvalidSetup(e.to_string()))?
                {
                    let Some(inner) = event.event else { continue };
                    match inner {
                        Event::Notarize(e) => {
                            let p = e.proposal.unwrap_or_default();
                            println!(
                                "notarize: epoch={} view={} signer={}",
                                p.epoch, p.view, e.signer
                            );
                        }
                        Event::MNotarization(e) => {
                            let p = e.proposal.unwrap_or_default();
                            println!(
                                "m-notarization: epoch={} view={} signers={:?}",
                                p.epoch, p.view, e.signers
                            );
                        }
                        Event::Nullify(e) => {
                            println!(
                                "nullify: epoch={} view={} signer={}",
                                e.epoch, e.view, e.signer
                            );
                        }
                        Event::Nullification(e) => {
                            println!(
                                "nullification: epoch={} view={} signers={:?}",
                                e.epoch, e.view, e.signers
                            );
                        }
                        Event::Finalization(e) => {
                            let p = e.proposal.unwrap_or_default();
                            println!(
                                "finalization: epoch={} view={} signers={:?}",
                                p.epoch, p.view, e.signers
                            );
                        }
                        Event::ConflictingNotarize(e) => {
                            let f = e.first.and_then(|n| n.proposal).unwrap_or_default();
                            let s = e.second.and_then(|n| n.proposal).unwrap_or_default();
                            println!(
                                "conflicting-notarize: first=(epoch={} view={}) second=(epoch={} view={})",
                                f.epoch, f.view, s.epoch, s.view
                            );
                        }
                    }
                }
                println!("activity stream ended");
            }
        }
        Ok(())
    })
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

fn otlp_config_from_env() -> Option<tokio::tracing::Config> {
    let endpoint = env_non_empty(OTLP_ENDPOINT_ENV)?;
    let name = env_non_empty(OTLP_SERVICE_NAME_ENV)
        .unwrap_or_else(|| DEFAULT_OTLP_SERVICE_NAME.to_string());
    Some(tokio::tracing::Config {
        endpoint,
        name,
        rate: otlp_sample_rate(),
    })
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
    ShardTransportExited,
    EngineExited,
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

/// Open a WebSocket to `url` and serve LightClient RPCs via ws-mux.
///
/// The relay DO acts as ws-mux client and calls the validator's LightClient
/// RPCs (including `subscribe_activity` for the event stream).
async fn serve_relay(
    url: &str,
    svc: impl ws_mux::ServiceDispatch + Clone,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures::StreamExt;

    let (ws_stream, _) = tokio_tungstenite::connect_async(url).await?;
    let (write, read) = ws_stream.split();
    let sink = ws_mux::NativeWsSink::new(write);
    let recv = ws_mux::NativeWsRecv::new(read);

    ws_mux::serve(svc, recv, sink).await?;
    Ok(())
}

fn run(
    config_path: PathBuf,
    log_json: Option<PathBuf>,
    ws_bind: Option<String>,
    ws_push: Option<String>,
) -> Result<(), ValidatorError> {
    let config_str = std::fs::read_to_string(&config_path)?;
    let mut node_config: NodeConfig = toml::from_str(&config_str)?;
    if ws_bind.is_some() {
        node_config.ws_bind = ws_bind;
    }
    if ws_push.is_some() {
        node_config.explorer_url = ws_push;
    }

    let private_key = node_config.decode_private_key()?;
    let me = private_key.public_key();
    let genesis_allocations = node_config.genesis_allocations()?;
    if let Some(path) = log_json.as_ref() {
        eprintln!(
            "warning: --log-json file output ({}) is ignored by commonware_runtime::tokio::telemetry::init; enabling JSON logs on stderr instead",
            path.display(),
        );
    }
    let telemetry_json = log_json.is_some();
    let telemetry_traces = otlp_config_from_env();
    let otlp_info = telemetry_traces
        .as_ref()
        .map(|cfg| (cfg.endpoint.clone(), cfg.name.clone(), cfg.rate));

    let git_rev = option_env!("GIT_REV").unwrap_or("unknown");

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
    let metrics_addr = node_config
        .metrics_port
        .map(|metrics_port| format!("0.0.0.0:{metrics_port}").parse())
        .transpose()?;
    let runtime_cfg = tokio::Config::new()
        .with_storage_directory(storage_dir_utf8)
        .with_tcp_nodelay(Some(true));
    let runner = tokio::Runner::new(runtime_cfg);

    runner.start(move |context| async move {
        commonware_runtime::tokio::telemetry::init(
            context.with_label("telemetry"),
            commonware_runtime::tokio::telemetry::Logging {
                level: tracing::Level::INFO,
                json: telemetry_json,
            },
            metrics_addr,
            telemetry_traces,
        );
        info!(
            git_rev,
            version = env!("CARGO_PKG_VERSION"),
            "hellas validator starting",
        );
        if let Some(metrics_port) = node_config.metrics_port {
            info!(metrics_port, "prometheus metrics server started");
        }
        if let Some((endpoint, service_name, sample_rate)) = otlp_info.as_ref() {
            info!(
                otlp_endpoint = %endpoint,
                otlp_service_name = %service_name,
                otlp_sample_rate = sample_rate,
                "OTLP trace export enabled",
            );
        }

        // Create lookup-based p2p network
        let p2p_cfg = lookup::Config::local(private_key, NAMESPACE, listen_addr, MAX_MESSAGE_SIZE);
        let (mut network, mut oracle) =
            lookup::Network::new(context.with_label("network"), p2p_cfg);

        // Register all validators with the oracle, then allow address refreshes
        // without introducing a new peer-set epoch.
        oracle.track(0, peer_map.clone()).await;
        oracle.overwrite(peer_map).await;

        // Register consensus and shard channels.
        let quota = Quota::per_second(NonZeroU32::MAX);
        let vote = network.register(0, quota, CHANNEL_BACKLOG);
        let certificate = network.register(1, quota, CHANNEL_BACKLOG);
        let resolver = network.register(2, quota, CHANNEL_BACKLOG);
        let (shard_sender, shard_receiver) = network.register(3, quota, SHARD_CHANNEL_BACKLOG);

        // Publish process uptime as a prometheus gauge, updated every second.
        let uptime_gauge: Gauge<i64, AtomicI64> = Gauge::default();
        context.with_label("process").register(
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

        let relay = Arc::new(AuthenticatedShardTransport::new(
            &me,
            shard_sender,
            shard_receiver,
        ));
        for participant in scheme.participants() {
            relay.declare(participant);
        }
        relay.finalize_validators();

        // Extract validator names before scheme is moved into the engine.
        let validators: Vec<String> = scheme
            .participants()
            .iter()
            .map(|pk| hex::encode(&pk.encode()[..8]))
            .collect();

        // Create engine first so the application can subscribe to shard ingress
        // before the transport starts dispatching inbound shard messages.
        let mut chain_config = Config::mainnet();
        if let Some(ms) = node_config.min_propose_ms {
            chain_config.min_propose_delay = Duration::from_millis(ms);
            info!(min_propose_ms = ms, "proposal throttle enabled");
        }
        let (engine, tx_mailbox, activity_tx) = Engine::new(
            context.clone(),
            chain_config,
            scheme,
            oracle,
            relay.clone(),
            &me,
            genesis_allocations.clone(),
            TraceReporter,
        );
        let light_client = hellas_chain::rpc::LocalLightClient::new(tx_mailbox, validators);

        // Start light-client gRPC server over WebSocket (if configured)
        if let Some(ws_bind) = &node_config.ws_bind {
            let addr: SocketAddr = ws_bind.parse().expect("ws_bind address should be valid");
            let svc = hellas_chain::rpc::LightClientGrpcServer::new(
                light_client.clone(),
                activity_tx.clone(),
            )
            .into_service();
            let listener = ::tokio::net::TcpListener::bind(addr)
                .await
                .expect("failed to bind WebSocket listener");
            let incoming = hellas_rpc::ws::ws_incoming(listener);
            context.clone().spawn(|_| async move {
                tonic::transport::Server::builder()
                    .add_service(svc)
                    .serve_with_incoming(incoming)
                    .await
                    .unwrap();
            });
            info!(%addr, "light client WebSocket gRPC server started");
        }

        // Connect to explorer relay DO (if configured).
        // Single outbound WebSocket: the validator serves LightClient RPCs
        // (including subscribe_activity) and the relay DO acts as ws-mux client.
        if let Some(explorer_url) = &node_config.explorer_url {
            let validator_name = hex::encode(&me.encode()[..8]);
            let relay_url = format!("{explorer_url}/relay/{validator_name}");
            let relay_svc = hellas_rpc::mux::MuxServiceDispatch::new(
                hellas_chain::rpc::LightClientGrpcServer::new(light_client, activity_tx)
                    .into_service(),
            );
            context.clone().spawn(|ctx| async move {
                loop {
                    match serve_relay(&relay_url, relay_svc.clone()).await {
                        Ok(()) => info!("relay connection closed normally"),
                        Err(e) => warn!(%e, "relay connection failed"),
                    }
                    ctx.sleep(Duration::from_secs(5)).await;
                }
            });

            info!(%explorer_url, "relay connection started");
        }

        let shard_transport_handle = relay.start(context.clone());

        // Start networking only after the app + shard transport are initialized.
        let network_handle = network.start();

        let engine_handle = engine.start(vote, certificate, resolver);

        let signal_waiter = wait_for_shutdown_signal()
            .map(ShutdownTrigger::Signal)
            .boxed();
        let network_waiter = network_handle
            .map(|_| ShutdownTrigger::NetworkExited)
            .boxed();
        let shard_waiter = shard_transport_handle
            .map(|_| ShutdownTrigger::ShardTransportExited)
            .boxed();
        let engine_waiter = engine_handle.map(|_| ShutdownTrigger::EngineExited).boxed();

        let (trigger, _, _) = futures::future::select_all(vec![
            signal_waiter,
            network_waiter,
            shard_waiter,
            engine_waiter,
        ])
        .await;

        let monitor_second_signal = matches!(trigger, ShutdownTrigger::Signal(_));
        match trigger {
            ShutdownTrigger::Signal(signal) => {
                info!(signal, "received shutdown signal");
            }
            ShutdownTrigger::NetworkExited => {
                warn!("network task exited unexpectedly; triggering shutdown");
            }
            ShutdownTrigger::ShardTransportExited => {
                warn!("shard transport task exited unexpectedly; triggering shutdown");
            }
            ShutdownTrigger::EngineExited => {
                warn!("engine task exited unexpectedly; triggering shutdown");
            }
        }

        graceful_stop(context, monitor_second_signal).await;
    });
    Ok(())
}
