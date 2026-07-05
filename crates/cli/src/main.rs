#[macro_use]
extern crate tracing;

use catgrad::prelude::Dtype;
use clap::{Parser, Subcommand, ValueEnum};
use iroh::EndpointId;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

mod commands;
mod execution;
mod identity;
mod metrics;
mod tracing_config;

/// `clap` value parser for `--dtype`. Accepts model floating-point dtypes.
/// Rejects `u32`, which is the catgrad token-tensor dtype, never a model dtype.
fn parse_model_dtype(s: &str) -> Result<Dtype, String> {
    let dtype = Dtype::from_str(s)?;
    match dtype {
        Dtype::F32 | Dtype::F16 | Dtype::BF16 | Dtype::F8 => Ok(dtype),
        Dtype::U32 => Err("model dtype must be f32, f16, bf16, or f8".to_string()),
    }
}

fn parse_public_key_hex(s: &str) -> Result<hellas_core::PublicKey, String> {
    let bytes = parse_hex_array::<{ hellas_core::PublicKey::LEN }>(s)?;
    Ok(hellas_core::PublicKey::from_compressed_sec1(bytes))
}

fn parse_hex_array<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, s.len()));
    }
    let mut out = [0u8; N];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        *byte = u8::from_str_radix(&s[start..start + 2], 16)
            .map_err(|err| format!("invalid hex at byte {idx}: {err}"))?;
    }
    Ok(out)
}

fn parse_json_object(s: &str) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(serde_json::Value::Object(object)) => Ok(object),
        Ok(_) => Err("expected a JSON object".to_string()),
        Err(err) => Err(format!("invalid JSON object: {err}")),
    }
}

/// Default dtype per build configuration. CUDA / Metal builds assume modern
/// hardware (Ampere+, M2+) where `bf16` matches the dtype most current models
/// are trained at and gives a real perf/VRAM win. CPU / unspecified-backend
/// builds default to `f32` because CPUs typically emulate bf16 via f32 anyway,
/// and `f32` is the safest broadly-correct choice. Used for `serve --dtype`
/// and `gateway --dtype`.
#[cfg(any(feature = "candle-cuda", feature = "candle-metal"))]
const DEFAULT_DTYPE_STR: &str = "bf16";
#[cfg(not(any(feature = "candle-cuda", feature = "candle-metal")))]
const DEFAULT_DTYPE_STR: &str = "f32";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum GatewayResponsesBackend {
    Hellas,
    Proxy,
    Fetch,
}

impl From<GatewayResponsesBackend> for commands::gateway::ResponsesBackend {
    fn from(value: GatewayResponsesBackend) -> Self {
        match value {
            GatewayResponsesBackend::Hellas => Self::Hellas,
            GatewayResponsesBackend::Proxy => Self::Proxy,
            GatewayResponsesBackend::Fetch => Self::Fetch,
        }
    }
}

/// Default `--dtype` preference list for `llm`, resolved at dispatch.
///
/// - **Network mode** (no `--local` / `--verify-local`): `[bf16, f32, f16]`
///   regardless of build. The remote executor decides what it can run; the
///   CLI's local hardware capability is irrelevant to the wire request.
/// - **Local-ish mode on a cuda/metal build**: same `[bf16, f32, f16]`.
///   The operator opted into a GPU-backend feature, so the build assumes
///   Ampere+/M2+ where bf16 is natively supported. If the GPU lacks bf16
///   the weight load will fail loudly at first attempt — that's a build /
///   hardware mismatch the operator should fix, not something we paper over.
/// - **Local-ish mode on a cpu / unspecified build**: `[f32, f16]`. Skips
///   bf16 because CPU bf16 throughput is rarely a win and we want a default
///   that loads on every backend, including GPUs without native bf16
///   support in non-standard builds.
fn default_llm_dtypes(is_local_mode: bool) -> Vec<Dtype> {
    let cuda_or_metal = cfg!(any(feature = "candle-cuda", feature = "candle-metal"));
    if is_local_mode && !cuda_or_metal {
        vec![Dtype::F32, Dtype::F16]
    } else {
        vec![Dtype::BF16, Dtype::F32, Dtype::F16]
    }
}

#[derive(Parser)]
#[command(name = "hellas")]
#[command(version)]
#[command(about = "Hellas node CLI")]
struct Cli {
    /// Path to node identity file (default: $HOME/.hellas/identity)
    #[arg(long = "identity", global = true)]
    identity: Option<PathBuf>,

    /// Path to producer signing key (default: $HOME/.hellas/signing-key.secp256k1)
    #[arg(long = "producer-key-path", global = true)]
    producer_key_path: Option<PathBuf>,

    /// Also append tracing output to this file.
    #[arg(long = "log-file", global = true)]
    log_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Print the node ID (hex public key) derived from the identity file
    ShowNodeId,
}

#[derive(Subcommand)]
enum ProducerKeyCommand {
    /// Print the producer public key and derived producer id
    Show,
}

#[derive(Subcommand)]
enum CodexAuthCommand {
    /// Sign in to Codex with device-code OAuth and store credentials locally
    Login {
        /// Codex auth store path (default: $HOME/.hellas/codex-auth.json)
        #[arg(long = "auth-path")]
        auth_path: Option<PathBuf>,
    },
    /// Import credentials from an existing Codex CLI auth file
    Import {
        /// Codex auth store path (default: $HOME/.hellas/codex-auth.json)
        #[arg(long = "auth-path")]
        auth_path: Option<PathBuf>,
        /// Source auth file (default: $HOME/.codex/auth.json)
        #[arg(long = "from")]
        source_path: Option<PathBuf>,
    },
    /// Show whether local Codex credentials are configured
    Status {
        /// Codex auth store path (default: $HOME/.hellas/codex-auth.json)
        #[arg(long = "auth-path")]
        auth_path: Option<PathBuf>,
    },
}

// Parsed once at startup and immediately destructured; boxing the large
// variants would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Commands {
    #[cfg(feature = "hellas-executor")]
    /// Run the RPC server
    Serve {
        /// Port to listen on (auto-selects if not specified or if in use)
        #[arg(long)]
        port: Option<u16>,
        /// Execute policy: 'skip' (default, refuse all executions),
        /// 'eager' (execute any graph),
        /// or 'allow(hf/pattern,...,graph/pattern,...)' (execute only matching)
        #[arg(long = "execute-policy", default_value = "skip")]
        execute_policy: hellas_rpc::policy::ExecutePolicy,
        /// Maximum number of queued executions waiting behind the active worker
        #[arg(
            long = "queue-size",
            default_value_t = hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY
        )]
        queue_size: usize,
        /// Load model metadata on startup. Repeat or use commas: --preload foo/bar --preload baz/qux@rev
        #[arg(long = "preload", value_delimiter = ',')]
        preload_models: Vec<String>,
        /// Persistent canonical artifact blob store path (default: $HOME/.hellas/artifacts)
        #[arg(long = "artifact-store-path")]
        artifact_store_path: Option<PathBuf>,
        /// Prometheus metrics port (e.g. 9090)
        #[arg(long = "metrics-port")]
        metrics_port: Option<u16>,
        /// Operator graffiti tag (up to 16 bytes, padded/truncated)
        #[arg(long = "graffiti", default_value = "")]
        graffiti: String,
        /// Dtypes this executor will accept, comma-separated. The first entry
        /// is the executor's preferred dtype (used when the server constructs
        /// a program itself, e.g. for `QuotePromptRequest`). Other entries are
        /// also accepted on a per-request basis. Each accepted dtype loads its
        /// own bundle of weights, so listing more dtypes costs more VRAM.
        /// Defaults to `f32`.
        #[arg(
            long = "dtype",
            default_value = DEFAULT_DTYPE_STR,
            value_delimiter = ',',
            value_parser = parse_model_dtype
        )]
        dtype: Vec<Dtype>,
        /// Unified Fetch configuration file: routes (provider upstreams,
        /// protocols, capabilities) and caller access policy. No file means
        /// this node serves no Fetch routes.
        #[arg(long = "fetch-config")]
        fetch_config_file: Option<PathBuf>,
        /// Maximum number of Fetch provider streams running at once.
        #[arg(
            long = "fetch-max-in-flight",
            default_value_t = hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT
        )]
        fetch_max_in_flight: usize,
        /// Maximum number of Fetch executions waiting behind active provider streams.
        #[arg(
            long = "fetch-queue-size",
            default_value_t = hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY
        )]
        fetch_queue_size: usize,
    },
    /// Run HTTP gateway exposing OpenAI/Anthropic/plain APIs over Hellas network
    Gateway {
        /// Host interface to bind
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port to listen on. Omit to try 8080 with fallback to an OS-assigned port.
        #[arg(long)]
        port: Option<u16>,
        /// Direct target node id (omit to use discovery)
        #[arg(long)]
        node_id: Option<EndpointId>,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',', requires = "node_id")]
        node_addrs: Vec<SocketAddr>,
        /// Run locally with the catgrad backend instead of the Hellas network
        #[cfg(feature = "hellas-executor")]
        #[arg(long = "local", default_value_t = false, conflicts_with_all = ["node_id", "node_addrs"])]
        local: bool,
        /// Run remotely and verify that the response matches a local catgrad execution
        #[cfg(feature = "hellas-executor")]
        #[arg(
            long = "verify-local",
            default_value_t = false,
            conflicts_with_all = ["local", "verify"]
        )]
        verify_local: bool,
        /// Verify the primary remote node against a second remote node
        #[cfg_attr(
            feature = "hellas-executor",
            arg(
                long = "verify",
                conflicts_with_all = ["local", "verify_local"],
                requires = "node_id"
            )
        )]
        #[cfg_attr(
            not(feature = "hellas-executor"),
            arg(long = "verify", requires = "node_id")
        )]
        verify: Option<EndpointId>,
        /// Maximum number of queued local executions when `--local` is set
        #[cfg(feature = "hellas-executor")]
        #[arg(
            long = "queue-size",
            default_value_t = hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY
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
        /// Dtype the local executor (when `--local` or `--verify-local`) runs at,
        /// and the dtype the client builds the quote program at: f32, f16, or bf16
        #[arg(long = "dtype", default_value = DEFAULT_DTYPE_STR, value_parser = parse_model_dtype)]
        dtype: Dtype,
        /// Backend for /v1/responses.
        #[arg(long = "responses-backend", value_enum, default_value_t = GatewayResponsesBackend::Hellas)]
        responses_backend: GatewayResponsesBackend,
        /// Upstream endpoint used when --responses-backend=proxy.
        #[arg(
            long = "responses-proxy-url",
            default_value = "https://api.openai.com/v1/responses"
        )]
        responses_proxy_url: String,
        /// Environment variable holding the bearer token for --responses-backend=proxy.
        #[arg(long = "responses-proxy-api-key-env", default_value = "OPENAI_API_KEY")]
        responses_proxy_api_key_env: String,
        /// Fetch route service used when --responses-backend=fetch.
        #[arg(long = "responses-fetch-route-service", default_value = "codex")]
        responses_fetch_route_service: String,
        /// Fetch route method used when --responses-backend=fetch.
        #[arg(long = "responses-fetch-route-method", default_value = "responses")]
        responses_fetch_route_method: String,
        /// JSON object merged into OpenAI Responses requests before signing
        /// and sending them through Fetch.
        #[arg(long = "responses-fetch-request-overrides", value_parser = parse_json_object)]
        responses_fetch_request_overrides: Option<serde_json::Map<String, serde_json::Value>>,
        /// Producer public keys trusted to sign Fetch output when
        /// --responses-backend=fetch. Repeat or comma-separate compressed
        /// secp256k1 keys as hex (see `producer-key show`). Defaults to this
        /// gateway's own producer key.
        #[arg(long = "trusted-producer-public-key", value_delimiter = ',', value_parser = parse_public_key_hex)]
        trusted_producer_public_keys: Vec<hellas_core::PublicKey>,
        /// Wrap a child command with the gateway as its OpenAI/Anthropic backend.
        #[arg(long = "wrap")]
        wrap: Option<String>,
        /// Trailing args forwarded verbatim to the wrapped command (after `--`).
        #[arg(last = true, allow_hyphen_values = true, requires = "wrap")]
        wrap_args: Vec<String>,
    },
    /// Query a remote node via RPC
    Rpc {
        /// Node ID to check
        node_id: EndpointId,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',')]
        node_addrs: Vec<SocketAddr>,
    },
    /// Store or fetch canonical artifact bytes on a provider
    Artifact {
        #[command(subcommand)]
        command: commands::artifact::ArtifactCommand,
    },
    /// Query or run Hellas chain components
    #[cfg(feature = "chain")]
    Chain {
        #[command(subcommand)]
        command: commands::chain::ChainCommand,
    },
    /// Run LLM inference remotely or locally
    Llm {
        /// Node ID to run on remotely (omit to auto-discover)
        node_id: Option<EndpointId>,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',', requires = "node_id")]
        node_addrs: Vec<SocketAddr>,
        /// HuggingFace model id used to fetch weights, optionally with @revision
        #[arg(short = 'm', long = "model", default_value = "Qwen/Qwen3-0.6B")]
        model: String,
        /// Prompt to send (required)
        #[arg(short = 'p', long = "prompt")]
        prompt: String,
        /// Pass the prompt through unchanged instead of applying the model chat template
        #[arg(long = "raw", default_value_t = false)]
        raw: bool,
        /// Maximum number of new tokens to generate
        #[arg(long = "max-seq", default_value_t = 16)]
        max_seq: u32,
        /// Max execution retries on failure (discovery path only)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Run locally with the catgrad backend instead of the Hellas network
        #[cfg(feature = "hellas-executor")]
        #[arg(long = "local", default_value_t = false, conflicts_with_all = ["verify_local", "node_id", "node_addrs"])]
        local: bool,
        /// Run remotely and locally, then verify that both outputs match
        #[cfg(feature = "hellas-executor")]
        #[arg(
            long = "verify-local",
            default_value_t = false,
            conflicts_with = "local"
        )]
        verify_local: bool,
        /// Comma-separated preference list (each one of `f32`, `f16`,
        /// `bf16`). The client builds the quote program at the first entry,
        /// then on a remote `DtypeNotSupported` rejection retries at the
        /// next. For `--local` / `--verify-local` the embedded executor's
        /// `supported_dtypes` is the full list. If omitted the default
        /// depends on the build and mode (cuda/metal builds and any network
        /// mode prefer `bf16,f32,f16`; cpu builds in local-ish mode prefer
        /// `f32,f16` to stay safe on hardware without bf16/f16 support).
        #[arg(long = "dtype", value_delimiter = ',', value_parser = parse_model_dtype)]
        dtype: Vec<Dtype>,
    },
    /// Run trust-based fetch JSON work
    Fetch {
        /// Node ID to run on remotely (omit to auto-discover)
        node_id: Option<EndpointId>,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',', requires = "node_id")]
        node_addrs: Vec<SocketAddr>,
        /// Fetch service label. The protocol records it but does not interpret it.
        #[arg(long)]
        service: String,
        /// Fetch method label. The protocol records it but does not interpret it.
        #[arg(long)]
        method: String,
        /// Exact UTF-8 JSON payload bytes.
        #[arg(
            long,
            conflicts_with = "payload_file",
            required_unless_present = "payload_file"
        )]
        payload: Option<String>,
        /// Read exact UTF-8 JSON payload bytes from a file.
        #[arg(long = "payload-file")]
        payload_file: Option<PathBuf>,
        /// Max execution retries on failure (discovery path only)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Producer public keys trusted to sign Fetch output. Repeat or
        /// comma-separate compressed secp256k1 keys as hex (see
        /// `producer-key show`). Defaults to this node's own producer key.
        #[arg(long = "trusted-producer-public-key", value_delimiter = ',', value_parser = parse_public_key_hex)]
        trusted_producer_public_keys: Vec<hellas_core::PublicKey>,
    },
    /// Inspect the local identity file
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Inspect the local producer signing key
    ProducerKey {
        #[command(subcommand)]
        command: ProducerKeyCommand,
    },
    /// Manage Codex OAuth credentials
    CodexAuth {
        #[command(subcommand)]
        command: CodexAuthCommand,
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
    // Parse the CLI first so we can honour the global `--log-file`
    // flag in the subscriber setup. clap's parser is cheap; doing it
    // before tracing init means very early subscriber-internal failures
    // (which print to stderr regardless) are the only thing that
    // bypasses the requested log file.
    let cli = Cli::parse();
    let tracer_provider = tracing_config::init_tracing(cli.log_file.as_deref());
    let producer_key_path = cli.producer_key_path.clone();

    if let Commands::ProducerKey {
        command: ProducerKeyCommand::Show,
    } = &cli.command
    {
        let result = identity::load_existing_producer_key(producer_key_path.as_deref())
            .and_then(|key| commands::identity::show_producer_key(&key));
        tracer_provider.shutdown();
        if let Err(err) = result {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
        return;
    }

    if let Commands::CodexAuth { command } = &cli.command {
        let result = match command {
            CodexAuthCommand::Login { auth_path } => {
                commands::codex_auth::login(auth_path.as_deref()).await
            }
            CodexAuthCommand::Import {
                auth_path,
                source_path,
            } => {
                commands::codex_auth::import_codex_cli(auth_path.as_deref(), source_path.as_deref())
            }
            CodexAuthCommand::Status { auth_path } => {
                commands::codex_auth::status(auth_path.as_deref())
            }
        };
        tracer_provider.shutdown();
        if let Err(err) = result {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
        return;
    }

    // show-node-id is a read-only query; never create an identity file as a
    // side effect of it (would race with a running service's own creator).
    let load_identity = match &cli.command {
        Commands::Identity {
            command: IdentityCommand::ShowNodeId,
        } => identity::load_existing,
        _ => identity::load_or_create,
    };
    let secret_key = match load_identity(cli.identity.as_deref()) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
    };

    let result = match cli.command {
        #[cfg(feature = "hellas-executor")]
        Commands::Serve {
            port,
            execute_policy,
            queue_size,
            preload_models,
            artifact_store_path,
            metrics_port,
            graffiti,
            dtype,
            fetch_config_file,
            fetch_max_in_flight,
            fetch_queue_size,
        } => {
            let producer_key =
                match identity::load_or_create_producer_key(producer_key_path.as_deref()) {
                    Ok(key) => key,
                    Err(err) => {
                        eprintln!("error: {err:#}");
                        std::process::exit(1);
                    }
                };
            commands::serve::run(commands::serve::ServeOptions {
                port,
                execute_policy,
                queue_size,
                preload_models,
                artifact_store_path,
                metrics_port,
                graffiti,
                dtype,
                fetch_config_file,
                fetch_max_in_flight,
                fetch_queue_size,
                secret_key,
                producer_key,
            })
            .await
        }
        Commands::Gateway {
            host,
            port,
            node_id,
            node_addrs,
            #[cfg(feature = "hellas-executor")]
            local,
            #[cfg(feature = "hellas-executor")]
            verify_local,
            verify,
            #[cfg(feature = "hellas-executor")]
            queue_size,
            retries,
            default_max_tokens,
            force_model,
            metrics_port,
            dtype,
            responses_backend,
            responses_proxy_url,
            responses_proxy_api_key_env,
            responses_fetch_route_service,
            responses_fetch_route_method,
            responses_fetch_request_overrides,
            trusted_producer_public_keys,
            wrap,
            wrap_args,
        } => {
            commands::gateway::run(commands::gateway::GatewayOptions {
                host,
                port,
                node_id,
                node_addrs,
                #[cfg(feature = "hellas-executor")]
                local,
                #[cfg(feature = "hellas-executor")]
                verify_local,
                verify,
                #[cfg(feature = "hellas-executor")]
                queue_size,
                retries,
                default_max_tokens,
                force_model,
                metrics_port,
                dtype,
                responses_backend: responses_backend.into(),
                responses_proxy_url,
                responses_proxy_api_key_env,
                responses_fetch_route_service,
                responses_fetch_route_method,
                responses_fetch_request_overrides: responses_fetch_request_overrides
                    .unwrap_or_default(),
                trusted_producer_public_keys,
                producer_key_path: producer_key_path.clone(),
                secret_key,
                wrap,
                wrap_args,
            })
            .await
        }
        Commands::Rpc {
            node_id,
            node_addrs,
        } => commands::rpc::run(node_id, node_addrs, secret_key).await,
        Commands::Artifact { command } => commands::artifact::run(command, secret_key).await,
        #[cfg(feature = "chain")]
        Commands::Chain { command } => commands::chain::run(command).await,
        Commands::Llm {
            node_id,
            node_addrs,
            model,
            prompt,
            raw,
            max_seq,
            retries,
            #[cfg(feature = "hellas-executor")]
            local,
            #[cfg(feature = "hellas-executor")]
            verify_local,
            dtype,
        } => {
            #[cfg(feature = "hellas-executor")]
            let is_local_mode = local || verify_local;
            #[cfg(not(feature = "hellas-executor"))]
            let is_local_mode = false;
            let dtype = if dtype.is_empty() {
                default_llm_dtypes(is_local_mode)
            } else {
                dtype
            };
            commands::llm::run(
                commands::llm::ExecuteOptions {
                    node_id,
                    node_addrs,
                    model,
                    prompt,
                    raw,
                    max_seq,
                    retries,
                    #[cfg(feature = "hellas-executor")]
                    local,
                    #[cfg(feature = "hellas-executor")]
                    verify_local,
                    dtype,
                    producer_key_path: producer_key_path.clone(),
                },
                secret_key,
            )
            .await
        }
        Commands::Fetch {
            node_id,
            node_addrs,
            service,
            method,
            payload,
            payload_file,
            retries,
            trusted_producer_public_keys,
        } => {
            let payload = match (payload, payload_file) {
                (Some(payload), None) => Ok(payload.into_bytes()),
                (None, Some(path)) => tokio::fs::read(&path).await.map_err(|err| {
                    anyhow::anyhow!("failed to read --payload-file {}: {err}", path.display())
                }),
                (None, None) => unreachable!("clap requires --payload or --payload-file"),
                (Some(_), Some(_)) => unreachable!("clap rejects both payload sources"),
            };
            match payload {
                Ok(payload) => {
                    commands::fetch::run(
                        commands::fetch::ExecuteOptions {
                            node_id,
                            node_addrs,
                            service,
                            method,
                            payload,
                            retries,
                            producer_key_path: producer_key_path.clone(),
                            trusted_producer_public_keys,
                        },
                        secret_key,
                    )
                    .await
                }
                Err(err) => Err(err),
            }
        }
        Commands::Identity { command } => match command {
            IdentityCommand::ShowNodeId => commands::identity::show_node_id(&secret_key),
        },
        Commands::ProducerKey { .. } => unreachable!("producer-key handled before identity load"),
        Commands::CodexAuth { .. } => unreachable!("codex-auth handled before identity load"),
        Commands::Monitor {
            timeout_secs,
            no_interrogate,
        } => commands::monitor::run(timeout_secs, !no_interrogate, secret_key).await,
    };

    tracer_provider.shutdown();

    if let Err(err) = result {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn llm_accepts_local_mode() {
        let cli = Cli::try_parse_from(["hellas", "llm", "--local", "-p", "hello"]).unwrap();
        match cli.command {
            Commands::Llm {
                node_id,
                node_addrs,
                local,
                verify_local,
                raw,
                ..
            } => {
                assert!(node_id.is_none());
                assert!(node_addrs.is_empty());
                assert!(local);
                assert!(!verify_local);
                assert!(!raw);
            }
            _ => panic!("expected llm command"),
        }
    }

    #[test]
    fn llm_accepts_raw_mode() {
        let cli = Cli::try_parse_from(["hellas", "llm", "--raw", "-p", "hello"]).unwrap();
        match cli.command {
            Commands::Llm { raw, .. } => assert!(raw),
            _ => panic!("expected llm command"),
        }
    }

    #[cfg(feature = "hellas-executor")]
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

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn llm_rejects_conflicting_local_modes() {
        let result =
            Cli::try_parse_from(["hellas", "llm", "--local", "--verify-local", "-p", "hello"]);

        assert!(result.is_err());
    }

    #[cfg(feature = "hellas-executor")]
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

    #[cfg(feature = "hellas-executor")]
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

    #[test]
    fn fetch_accepts_payload() {
        let cli = Cli::try_parse_from([
            "hellas",
            "fetch",
            "--service",
            "echo",
            "--method",
            "run",
            "--payload",
            r#"{"x":1}"#,
        ])
        .unwrap();
        match cli.command {
            Commands::Fetch {
                service,
                method,
                payload,
                ..
            } => {
                assert_eq!(service, "echo");
                assert_eq!(method, "run");
                assert_eq!(payload.as_deref(), Some(r#"{"x":1}"#));
            }
            _ => panic!("expected fetch command"),
        }
    }

    #[test]
    fn fetch_rejects_node_addr_without_node_id() {
        let result = Cli::try_parse_from([
            "hellas",
            "fetch",
            "--service",
            "echo",
            "--method",
            "run",
            "--payload",
            r#"{"x":1}"#,
            "--node-addr",
            "127.0.0.1:31145",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn fetch_rejects_missing_payload() {
        let result =
            Cli::try_parse_from(["hellas", "fetch", "--service", "echo", "--method", "run"]);

        assert!(result.is_err());
    }

    #[test]
    fn artifact_put_accepts_provider_and_path() {
        let cli = Cli::try_parse_from([
            "hellas",
            "artifact",
            "put",
            "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
            "--node-addr",
            "127.0.0.1:31145",
            "/tmp/artifact.cbor",
        ])
        .unwrap();
        match cli.command {
            Commands::Artifact {
                command:
                    commands::artifact::ArtifactCommand::Put {
                        node_id: _,
                        node_addrs,
                        path,
                    },
            } => {
                assert_eq!(node_addrs.len(), 1);
                assert_eq!(path, std::path::Path::new("/tmp/artifact.cbor"));
            }
            _ => panic!("expected artifact put command"),
        }
    }

    #[test]
    fn artifact_get_accepts_digest_and_output() {
        let digest = "00".repeat(32);
        let cli = Cli::try_parse_from([
            "hellas",
            "artifact",
            "get",
            "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
            &digest,
            "--output",
            "/tmp/artifact.cbor",
        ])
        .unwrap();
        match cli.command {
            Commands::Artifact {
                command:
                    commands::artifact::ArtifactCommand::Get {
                        node_id: _,
                        node_addrs,
                        digest: parsed_digest,
                        output,
                    },
            } => {
                assert!(node_addrs.is_empty());
                assert_eq!(parsed_digest, digest);
                assert_eq!(output, std::path::Path::new("/tmp/artifact.cbor"));
            }
            _ => panic!("expected artifact get command"),
        }
    }

    /// On CPU-only builds the default is `f32`; on CUDA/Metal builds it is
    /// `bf16`. See [`DEFAULT_DTYPE_STR`]. Used for `serve` / `gateway`,
    /// which still take a single dtype.
    #[cfg(feature = "hellas-executor")]
    fn expected_default_dtype() -> Dtype {
        parse_model_dtype(DEFAULT_DTYPE_STR).unwrap()
    }

    #[test]
    fn llm_dtype_omitted_yields_empty_vec_for_runtime_resolution() {
        // Clap parses no `--dtype` as an empty `Vec<Dtype>`; main resolves
        // the per-mode default via [`default_llm_dtypes`].
        let cli = Cli::try_parse_from(["hellas", "llm", "-p", "hi"]).unwrap();
        match cli.command {
            Commands::Llm { dtype, .. } => assert!(dtype.is_empty()),
            _ => panic!("expected llm command"),
        }
    }

    #[test]
    fn llm_accepts_single_dtype() {
        let cli = Cli::try_parse_from(["hellas", "llm", "--dtype", "f16", "-p", "hi"]).unwrap();
        match cli.command {
            Commands::Llm { dtype, .. } => assert_eq!(dtype, vec![Dtype::F16]),
            _ => panic!("expected llm command"),
        }
    }

    #[test]
    fn llm_accepts_dtype_preference_list() {
        let cli =
            Cli::try_parse_from(["hellas", "llm", "--dtype", "bf16,f32,f16", "-p", "hi"]).unwrap();
        match cli.command {
            Commands::Llm { dtype, .. } => {
                assert_eq!(dtype, vec![Dtype::BF16, Dtype::F32, Dtype::F16]);
            }
            _ => panic!("expected llm command"),
        }
    }

    #[test]
    fn default_llm_dtypes_local_cpu_skips_bf16() {
        let cuda_or_metal = cfg!(any(feature = "candle-cuda", feature = "candle-metal"));
        let prefs = default_llm_dtypes(/* is_local_mode = */ true);
        if cuda_or_metal {
            assert_eq!(prefs, vec![Dtype::BF16, Dtype::F32, Dtype::F16]);
        } else {
            assert_eq!(prefs, vec![Dtype::F32, Dtype::F16]);
        }
    }

    #[test]
    fn default_llm_dtypes_network_uses_bf16_first() {
        let prefs = default_llm_dtypes(/* is_local_mode = */ false);
        assert_eq!(prefs, vec![Dtype::BF16, Dtype::F32, Dtype::F16]);
    }

    #[test]
    fn gateway_accepts_dtype_bf16() {
        let cli = Cli::try_parse_from(["hellas", "gateway", "--dtype", "bf16"]).unwrap();
        match cli.command {
            Commands::Gateway { dtype, .. } => assert_eq!(dtype, Dtype::BF16),
            _ => panic!("expected gateway command"),
        }
    }

    #[test]
    fn gateway_wrap_forwards_trailing_args() {
        let cli = Cli::try_parse_from([
            "hellas",
            "gateway",
            "--wrap",
            "pi",
            "--",
            "-p",
            "--no-session",
            "say hello",
        ])
        .unwrap();
        match cli.command {
            Commands::Gateway {
                wrap, wrap_args, ..
            } => {
                assert_eq!(wrap.as_deref(), Some("pi"));
                assert_eq!(wrap_args, vec!["-p", "--no-session", "say hello"]);
            }
            _ => panic!("expected gateway command"),
        }
    }

    #[test]
    fn gateway_wrap_args_require_wrap() {
        let result = Cli::try_parse_from(["hellas", "gateway", "--", "-p", "hi"]);
        assert!(result.is_err(), "trailing args without --wrap should error");
    }

    #[test]
    fn gateway_accepts_responses_fetch_backend() {
        let cli = Cli::try_parse_from([
            "hellas",
            "gateway",
            "--responses-backend",
            "fetch",
            "--responses-fetch-route-service",
            "codex",
            "--responses-fetch-route-method",
            "responses",
            "--responses-fetch-request-overrides",
            r#"{"store":false}"#,
        ])
        .unwrap();
        match cli.command {
            Commands::Gateway {
                responses_backend,
                responses_fetch_route_service,
                responses_fetch_route_method,
                responses_fetch_request_overrides,
                ..
            } => {
                assert_eq!(responses_backend, GatewayResponsesBackend::Fetch);
                assert_eq!(responses_fetch_route_service, "codex");
                assert_eq!(responses_fetch_route_method, "responses");
                assert_eq!(responses_fetch_request_overrides.unwrap()["store"], false);
            }
            _ => panic!("expected gateway command"),
        }
    }

    #[test]
    fn producer_key_show_accepts_global_key_path() {
        let cli = Cli::try_parse_from([
            "hellas",
            "--producer-key-path",
            "/tmp/hellas-producer-key",
            "producer-key",
            "show",
        ])
        .unwrap();
        assert_eq!(
            cli.producer_key_path.as_deref(),
            Some(std::path::Path::new("/tmp/hellas-producer-key"))
        );
        match cli.command {
            Commands::ProducerKey {
                command: ProducerKeyCommand::Show,
            } => {}
            _ => panic!("expected producer-key show command"),
        }
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn serve_accepts_artifact_store_path() {
        let cli = Cli::try_parse_from([
            "hellas",
            "serve",
            "--artifact-store-path",
            "/tmp/hellas-artifacts",
        ])
        .unwrap();
        match cli.command {
            Commands::Serve {
                artifact_store_path,
                ..
            } => assert_eq!(
                artifact_store_path.as_deref(),
                Some(std::path::Path::new("/tmp/hellas-artifacts"))
            ),
            _ => panic!("expected serve command"),
        }
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn serve_accepts_dtype_f16() {
        let cli = Cli::try_parse_from(["hellas", "serve", "--dtype", "f16"]).unwrap();
        match cli.command {
            Commands::Serve { dtype, .. } => assert_eq!(dtype, vec![Dtype::F16]),
            _ => panic!("expected serve command"),
        }
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn serve_accepts_fetch_config() {
        let cli = Cli::try_parse_from([
            "hellas",
            "serve",
            "--fetch-max-in-flight",
            "3",
            "--fetch-queue-size",
            "0",
            "--fetch-config",
            "/tmp/fetch-config.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Serve {
                fetch_max_in_flight,
                fetch_queue_size,
                fetch_config_file,
                ..
            } => {
                assert_eq!(fetch_max_in_flight, 3);
                assert_eq!(fetch_queue_size, 0);
                assert_eq!(
                    fetch_config_file.as_deref(),
                    Some(std::path::Path::new("/tmp/fetch-config.json"))
                );
            }
            _ => panic!("expected serve command"),
        }
    }

    #[test]
    fn codex_auth_status_accepts_auth_path() {
        let cli = Cli::try_parse_from([
            "hellas",
            "codex-auth",
            "status",
            "--auth-path",
            "/tmp/codex-auth.json",
        ])
        .unwrap();
        match cli.command {
            Commands::CodexAuth {
                command: CodexAuthCommand::Status { auth_path },
            } => assert_eq!(
                auth_path.as_deref(),
                Some(std::path::Path::new("/tmp/codex-auth.json"))
            ),
            _ => panic!("expected codex-auth status command"),
        }
    }

    #[test]
    fn codex_auth_import_accepts_paths() {
        let cli = Cli::try_parse_from([
            "hellas",
            "codex-auth",
            "import",
            "--auth-path",
            "/tmp/hellas-codex-auth.json",
            "--from",
            "/tmp/codex-auth.json",
        ])
        .unwrap();
        match cli.command {
            Commands::CodexAuth {
                command:
                    CodexAuthCommand::Import {
                        auth_path,
                        source_path,
                    },
            } => {
                assert_eq!(
                    auth_path.as_deref(),
                    Some(std::path::Path::new("/tmp/hellas-codex-auth.json"))
                );
                assert_eq!(
                    source_path.as_deref(),
                    Some(std::path::Path::new("/tmp/codex-auth.json"))
                );
            }
            _ => panic!("expected codex-auth import command"),
        }
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn serve_accepts_multi_dtype() {
        let cli = Cli::try_parse_from(["hellas", "serve", "--dtype", "f32,f16,bf16"]).unwrap();
        match cli.command {
            Commands::Serve { dtype, .. } => {
                assert_eq!(dtype, vec![Dtype::F32, Dtype::F16, Dtype::BF16]);
            }
            _ => panic!("expected serve command"),
        }
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn serve_dtype_defaults_to_build_default() {
        let cli = Cli::try_parse_from(["hellas", "serve"]).unwrap();
        match cli.command {
            Commands::Serve { dtype, .. } => {
                assert_eq!(dtype, vec![expected_default_dtype()]);
            }
            _ => panic!("expected serve command"),
        }
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn serve_rejects_dtype_u32_in_list() {
        let result = Cli::try_parse_from(["hellas", "serve", "--dtype", "f32,u32"]);
        assert!(result.is_err());
    }

    #[test]
    fn llm_rejects_dtype_u32() {
        let result = Cli::try_parse_from(["hellas", "llm", "--dtype", "u32", "-p", "hi"]);
        assert!(result.is_err());
    }
}
