use clap::{Parser, Subcommand};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::certificate::Scheme as _;
use commonware_cryptography::{Signer, ed25519};
use commonware_p2p::{AddressableManager, authenticated::lookup};
use commonware_runtime::{Metrics, Quota, Runner, Spawner, tokio};
use futures::FutureExt;
use hellas_chain::TraceReporter;
use hellas_chain::config::{Config, ConfigError, NodeConfig, PeerEntry, encode_private_key};
use hellas_chain::engine::Engine;
use hellas_chain::shard::AuthenticatedShardTransport;
use hellas_types::Scheme;
use opentelemetry::{KeyValue, global, trace::TracerProvider as _};
use opentelemetry_otlp::{ExporterBuildError, SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    trace::{BatchSpanProcessor, Sampler, SdkTracerProvider, Tracer},
};
use rand::RngCore;
use std::io;
use std::time::Duration;
use std::{net::SocketAddr, num::NonZeroU32, path::PathBuf, sync::Arc};
use thiserror::Error;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

const NAMESPACE: &[u8] = b"hellas";
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
const CHANNEL_BACKLOG: usize = 1024;
const SHARD_CHANNEL_BACKLOG: usize = 4096;
const DEFAULT_OTLP_SERVICE_NAME: &str = "hellas-validator";
const DEFAULT_OTLP_SAMPLE_RATE: f64 = 1.0;
const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";
const OTLP_SERVICE_NAME_ENV: &str = "OTEL_SERVICE_NAME";
const OTLP_SAMPLE_RATE_ENV: &str = "OTEL_TRACES_SAMPLER_ARG";
const OTLP_EXPORT_TIMEOUT: Duration = Duration::from_secs(15);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

fn random_private_key() -> ed25519::PrivateKey {
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    ed25519::PrivateKey::decode(raw.as_slice())
        .expect("decoding 32 random bytes as an ed25519 private key should always succeed")
}

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
    #[error("failed to initialize OTLP trace exporter: {0}")]
    TraceExport(String),
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
        .map(|(i, k)| PeerEntry {
            public_key: hex::encode(k.public_key().encode()),
            address: format!("127.0.0.1:{}", start_port + i as u16),
        })
        .collect();

    let config = NodeConfig {
        private_key: encode_private_key(my_key),
        listen_port: start_port + node as u16,
        metrics_port: Some(9090 + node as u16),
        peers,
    };

    let rendered = toml::to_string_pretty(&config)?;
    println!("{rendered}");
    Ok(())
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

fn local_hostname() -> Option<String> {
    env_non_empty("HOSTNAME").or_else(|| {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .and_then(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
    })
}

fn build_otlp_tracer(
    cfg: tokio::tracing::Config,
    validator_pubkey: &str,
) -> Result<(Tracer, SdkTracerProvider), ExporterBuildError> {
    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(cfg.endpoint.clone())
        .with_timeout(OTLP_EXPORT_TIMEOUT)
        .build()?;
    let batch_processor = BatchSpanProcessor::builder(exporter).build();

    let mut attributes = Vec::with_capacity(4);
    attributes.push(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")));
    attributes.push(KeyValue::new(
        "hellas.validator.public_key",
        validator_pubkey.to_string(),
    ));
    attributes.push(KeyValue::new(
        "service.instance.id",
        format!(
            "validator-{}",
            &validator_pubkey[..validator_pubkey.len().min(16)]
        ),
    ));
    if let Some(hostname) = local_hostname() {
        attributes.push(KeyValue::new("host.name", hostname));
    }

    let resource = Resource::builder_empty()
        .with_service_name(cfg.name.clone())
        .with_attributes(attributes)
        .build();

    let tracer_provider = SdkTracerProvider::builder()
        .with_span_processor(batch_processor)
        .with_resource(resource)
        .with_sampler(Sampler::TraceIdRatioBased(cfg.rate))
        .build();
    let tracer = tracer_provider.tracer(cfg.name);
    Ok((tracer, tracer_provider))
}

fn init_tracing(validator_pubkey: &str) -> Result<Option<SdkTracerProvider>, ValidatorError> {
    let log_directive = "info".parse()?;
    let env_filter = EnvFilter::from_default_env().add_directive(log_directive);
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(io::stderr);

    if let Some(otlp_cfg) = otlp_config_from_env() {
        let endpoint = otlp_cfg.endpoint.clone();
        let service_name = otlp_cfg.name.clone();
        let sample_rate = otlp_cfg.rate;
        let (tracer, tracer_provider) = build_otlp_tracer(otlp_cfg, validator_pubkey)
            .map_err(|err| ValidatorError::TraceExport(err.to_string()))?;
        global::set_tracer_provider(tracer_provider.clone());
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .init();
        info!(
            otlp_endpoint = %endpoint,
            otlp_service_name = %service_name,
            otlp_sample_rate = sample_rate,
            "OTLP trace export enabled",
        );
        return Ok(Some(tracer_provider));
    }

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();
    Ok(None)
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

fn run(config_path: PathBuf) -> Result<(), ValidatorError> {
    let config_str = std::fs::read_to_string(&config_path)?;
    let node_config: NodeConfig = toml::from_str(&config_str)?;

    let private_key = node_config.decode_private_key()?;
    let me = private_key.public_key();
    let validator_pubkey = hex::encode(me.encode());
    let tracer_provider = init_tracing(&validator_pubkey)?;
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

        // Start metrics server (if configured)
        if let Some(metrics_port) = node_config.metrics_port {
            let metrics_addr: SocketAddr = format!("0.0.0.0:{metrics_port}")
                .parse()
                .expect("metrics address should be valid");
            commonware_runtime::tokio::telemetry::serve_metrics(
                context.with_label("metrics"),
                metrics_addr,
            );
            info!(metrics_port, "prometheus metrics server started");
        }

        let relay = Arc::new(AuthenticatedShardTransport::new(
            &me,
            shard_sender,
            shard_receiver,
        ));
        for participant in scheme.participants() {
            relay.declare(participant);
        }
        relay.finalize_validators();

        // Create engine first so the application can subscribe to shard ingress
        // before the transport starts dispatching inbound shard messages.
        let (engine, _tx_mailbox) = Engine::new(
            context.clone(),
            Config::mainnet(),
            scheme,
            oracle,
            relay.clone(),
            &me,
            TraceReporter,
        );
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
    if let Some(provider) = tracer_provider
        && let Err(err) = provider.shutdown()
    {
        eprintln!("failed to flush OTLP traces on shutdown: {err:?}");
    }
    Ok(())
}
