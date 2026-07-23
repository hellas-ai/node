#[macro_use]
extern crate tracing;

#[cfg(feature = "gateway")]
use clap::ValueEnum;
use clap::{Parser, Subcommand};
#[cfg(any(feature = "node", feature = "gateway"))]
use hellas_rpc::Dtype;
use iroh::EndpointId;
use std::net::SocketAddr;
use std::path::PathBuf;

mod commands;
mod identity;
#[cfg(feature = "node")]
mod metrics;
#[cfg(feature = "node")]
mod platform_hardening;
mod tracing_config;

#[cfg(any(feature = "node", feature = "gateway"))]
/// `clap` value parser for `--dtype`. Accepts model floating-point dtypes.
/// Rejects `u32`, which is the tensor token-index dtype, never a model dtype.
fn parse_model_dtype(s: &str) -> Result<Dtype, String> {
    let dtype: Dtype = s
        .parse()
        .map_err(|err: hellas_rpc::ParseDtypeError| err.to_string())?;
    if dtype.is_model_dtype() {
        Ok(dtype)
    } else {
        Err("model dtype must be f32, f16, bf16, or f8".to_string())
    }
}

fn parse_public_key_hex(s: &str) -> Result<hellas_rpc::PublicKey, String> {
    let bytes = parse_hex_array::<33>(s)?;
    Ok(hellas_rpc::PublicKey::Secp256k1(bytes))
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

fn parse_content_id_hex(s: &str) -> Result<hellas_rpc::ContentId, String> {
    parse_hex_array::<32>(s).map(hellas_rpc::ContentId::from_bytes)
}

fn parse_assurance(s: &str) -> Result<hellas_rpc::Assurance, String> {
    match s {
        "producer-signed" => Ok(hellas_rpc::Assurance::ProducerSigned),
        "apple-app-attest" => Ok(hellas_rpc::Assurance::AppleAppAttest),
        _ => Err("assurance must be producer-signed or apple-app-attest".to_string()),
    }
}

#[cfg(feature = "node")]
fn validate_serve_assurance(
    software_root: bool,
    assurance: hellas_rpc::Assurance,
    root_kind: Option<hellas_rpc::RootKind>,
) -> Result<(), String> {
    if assurance == hellas_rpc::Assurance::AppleAppAttest
        && (software_root
            || root_kind.is_some_and(|kind| kind != hellas_rpc::RootKind::SecureEnclave))
    {
        Err(
            "Apple App Attest assurance requires a Secure Enclave root; \
             --software-root cannot be used"
                .to_owned(),
        )
    } else {
        Ok(())
    }
}

#[cfg(feature = "gateway")]
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
#[cfg(all(
    any(feature = "node", feature = "gateway"),
    any(feature = "candle-cuda", feature = "candle-metal")
))]
const DEFAULT_DTYPE_STR: &str = "bf16";
#[cfg(all(
    any(feature = "node", feature = "gateway"),
    not(any(feature = "candle-cuda", feature = "candle-metal"))
))]
const DEFAULT_DTYPE_STR: &str = "f32";

#[cfg(feature = "gateway")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum GatewayResponsesBackend {
    Hellas,
    Proxy,
    Fetch,
}

#[cfg(feature = "gateway")]
impl From<GatewayResponsesBackend> for hellas_gateway::ResponsesBackend {
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
#[cfg(feature = "evaluate")]
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
    /// Path to the versioned provider identity (default: $HOME/.hellas/identity)
    #[arg(long = "identity", global = true)]
    identity: Option<PathBuf>,

    /// Choose the software platform root when creating an identity.
    #[arg(long = "software-root", global = true)]
    software_root: bool,

    /// Assurance requested from and served by execution providers.
    #[arg(
        long,
        global = true,
        default_value = "producer-signed",
        value_parser = parse_assurance
    )]
    assurance: hellas_rpc::Assurance,

    /// Out-of-band ContentId pin for the remote provider's canonical enrollment bundle.
    #[arg(long = "provider-genesis", global = true, value_parser = parse_content_id_hex)]
    provider_genesis: Option<hellas_rpc::ContentId>,

    /// Apple App Attest application CDhashes trusted for confidential open.
    /// Repeat the flag or pass a comma-separated list of 32-byte hex values.
    #[arg(
        long = "apple-app-attest-cdhashes",
        global = true,
        value_delimiter = ',',
        value_parser = parse_hex_array::<32>
    )]
    apple_app_attest_cdhashes: Vec<[u8; 32]>,

    /// Apple App Attest application identity in <teamID>.<bundleID> form.
    #[arg(long = "apple-app-attest-app-id", global = true)]
    apple_app_attest_app_id: Option<String>,

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
    #[cfg(feature = "node")]
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
    #[cfg(feature = "gateway")]
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
        #[cfg(feature = "evaluate")]
        #[arg(long = "local", default_value_t = false, conflicts_with_all = ["node_id", "node_addrs"])]
        local: bool,
        /// Run remotely and verify that the response matches a local catgrad execution
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "verify-local",
            default_value_t = false,
            conflicts_with_all = ["local", "verify"]
        )]
        verify_local: bool,
        /// Verify the primary remote node against a second remote node
        #[cfg_attr(
            feature = "evaluate",
            arg(
                long = "verify",
                conflicts_with_all = ["local", "verify_local"],
                requires = "node_id"
            )
        )]
        #[cfg_attr(not(feature = "evaluate"), arg(long = "verify", requires = "node_id"))]
        verify: Option<EndpointId>,
        /// Maximum number of queued local executions when `--local` is set
        #[cfg(feature = "evaluate")]
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
        /// Fetch ProgramManifest ContentId expected from the provider route.
        #[arg(long = "responses-fetch-execution-environment", value_parser = parse_content_id_hex, required_if_eq("responses_backend", "fetch"))]
        responses_fetch_execution_environment: Option<hellas_rpc::ContentId>,
        /// JSON object merged into OpenAI Responses requests before signing
        /// and sending them through Fetch.
        #[arg(long = "responses-fetch-request-overrides", value_parser = parse_json_object)]
        responses_fetch_request_overrides: Option<serde_json::Map<String, serde_json::Value>>,
        /// Producer public keys trusted to sign Fetch output when
        /// --responses-backend=fetch. Repeat or comma-separate compressed
        /// secp256k1 keys as hex (see `producer-key show`). Defaults to this
        /// gateway's own producer key.
        #[arg(long = "trusted-producer-public-key", value_delimiter = ',', value_parser = parse_public_key_hex)]
        trusted_producer_public_keys: Vec<hellas_rpc::PublicKey>,
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
    #[cfg(feature = "evaluate")]
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
        /// Allow the provider to retain prompt- and token-bearing artifacts.
        #[arg(long = "retain", default_value_t = true, action = clap::ArgAction::Set)]
        retain: bool,
        /// Maximum number of new tokens to generate
        #[arg(long = "max-seq", default_value_t = 16)]
        max_seq: u32,
        /// Max execution retries on failure (discovery path only)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Run locally with the catgrad backend instead of the Hellas network
        #[cfg(feature = "evaluate")]
        #[arg(long = "local", default_value_t = false, conflicts_with_all = ["verify_local", "node_id", "node_addrs"])]
        local: bool,
        /// Run remotely and locally, then verify that both outputs match
        #[cfg(feature = "evaluate")]
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
        /// Fetch ProgramManifest ContentId expected from the provider route.
        #[arg(long = "execution-environment", value_parser = parse_content_id_hex)]
        execution_environment: hellas_rpc::ContentId,
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
        /// Allow the provider to retain the signed input/output transcript.
        #[arg(long = "retain", default_value_t = true, action = clap::ArgAction::Set)]
        retain: bool,
        /// Producer public keys trusted to sign Fetch output. Repeat or
        /// comma-separate compressed secp256k1 keys as hex (see
        /// `producer-key show`). Defaults to this node's own producer key.
        #[arg(long = "trusted-producer-public-key", value_delimiter = ',', value_parser = parse_public_key_hex)]
        trusted_producer_public_keys: Vec<hellas_rpc::PublicKey>,
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
    #[cfg(feature = "node")]
    if matches!(&cli.command, Commands::Serve { .. })
        && let Err(error) = validate_serve_assurance(cli.software_root, cli.assurance, None)
    {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
    #[cfg(feature = "node")]
    if matches!(&cli.command, Commands::Serve { .. })
        && let Err(err) = platform_hardening::harden_provider_process()
    {
        eprintln!("error: failed to harden provider process: {err}");
        std::process::exit(1);
    }
    let tracer_provider = if command_owns_tracing(&cli.command) {
        tracing_config::TracerGuard::noop()
    } else {
        tracing_config::init_tracing(cli.log_file.as_deref())
    };
    let assurance = cli.assurance;
    let expected_provider_genesis = cli.provider_genesis;
    let apple_app_attest_cdhashes = cli.apple_app_attest_cdhashes;
    let apple_app_attest_app_id = cli.apple_app_attest_app_id;

    if let Commands::ProducerKey {
        command: ProducerKeyCommand::Show,
    } = &cli.command
    {
        let result = identity::load_existing(cli.identity.as_deref())
            .and_then(|identity| commands::identity::show_producer_key(&identity.producer_key));
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
    let read_only = matches!(
        &cli.command,
        Commands::Identity {
            command: IdentityCommand::ShowNodeId,
        }
    );
    let local_identity = match if read_only {
        identity::load_existing(cli.identity.as_deref())
    } else {
        identity::load_or_create(cli.identity.as_deref(), cli.software_root)
    } {
        Ok(identity) => identity,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
    };
    let secret_key = local_identity.transport_key.clone();
    #[cfg(feature = "node")]
    if matches!(&cli.command, Commands::Serve { .. })
        && let Err(error) = validate_serve_assurance(
            cli.software_root,
            assurance,
            Some(local_identity.genesis.statement.root_kind),
        )
    {
        eprintln!("error: {error}");
        std::process::exit(1);
    }

    let result = match cli.command {
        #[cfg(feature = "node")]
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
                open_identity: local_identity.open_identity(),
                producer_key: local_identity.producer_key,
                provider_genesis: local_identity.enrollment.canonical_bytes(),
                assurance,
            })
            .await
        }
        #[cfg(feature = "gateway")]
        Commands::Gateway {
            host,
            port,
            node_id,
            node_addrs,
            #[cfg(feature = "evaluate")]
            local,
            #[cfg(feature = "evaluate")]
            verify_local,
            verify,
            #[cfg(feature = "evaluate")]
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
            responses_fetch_execution_environment,
            responses_fetch_request_overrides,
            trusted_producer_public_keys,
            wrap,
            wrap_args,
        } => {
            async {
                let provider_trust = identity::provider_trust(
                    expected_provider_genesis,
                    assurance,
                    apple_app_attest_app_id.clone(),
                    apple_app_attest_cdhashes.clone(),
                )?;
                hellas_gateway::run(hellas_gateway::GatewayOptions {
                    host,
                    port,
                    node_id,
                    node_addrs,
                    #[cfg(feature = "evaluate")]
                    local,
                    #[cfg(feature = "evaluate")]
                    verify_local,
                    verify,
                    #[cfg(feature = "evaluate")]
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
                    responses_fetch_execution_environment,
                    responses_fetch_request_overrides: responses_fetch_request_overrides
                        .unwrap_or_default(),
                    trusted_producer_public_keys,
                    provider_trust,
                    producer_key: local_identity.producer_key,
                    #[cfg(feature = "evaluate")]
                    provider_genesis: local_identity.enrollment.canonical_bytes(),
                    assurance,
                    secret_key,
                    wrap,
                    wrap_args,
                })
                .await
            }
            .await
        }
        Commands::Rpc {
            node_id,
            node_addrs,
        } => commands::rpc::run(node_id, node_addrs, secret_key).await,
        Commands::Artifact { command } => commands::artifact::run(command, secret_key).await,
        #[cfg(feature = "chain")]
        Commands::Chain { command } => commands::chain::run(command).await,
        #[cfg(feature = "evaluate")]
        Commands::Llm {
            node_id,
            node_addrs,
            model,
            prompt,
            raw,
            retain,
            max_seq,
            retries,
            local,
            verify_local,
            dtype,
        } => {
            let is_local_mode = local || verify_local;
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
                    retain,
                    max_seq,
                    retries,
                    local,
                    verify_local,
                    dtype,
                    producer_key: local_identity.producer_key,
                    provider_genesis: local_identity.enrollment.canonical_bytes(),
                    expected_provider_genesis,
                    apple_app_attest_app_id: apple_app_attest_app_id.clone(),
                    apple_app_attest_cdhashes: apple_app_attest_cdhashes.clone(),
                    assurance,
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
            execution_environment,
            payload,
            payload_file,
            retries,
            retain,
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
                            execution_environment,
                            payload,
                            retries,
                            retain,
                            producer_key: local_identity.producer_key,
                            trusted_producer_public_keys,
                            expected_provider_genesis,
                            apple_app_attest_app_id,
                            apple_app_attest_cdhashes,
                            assurance,
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

fn command_owns_tracing(command: &Commands) -> bool {
    match command {
        #[cfg(feature = "chain")]
        Commands::Chain { command } => commands::chain::command_owns_tracing(command),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "evaluate")]
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

    #[cfg(feature = "evaluate")]
    #[test]
    fn llm_accepts_raw_mode() {
        let cli = Cli::try_parse_from(["hellas", "llm", "--raw", "-p", "hello"]).unwrap();
        match cli.command {
            Commands::Llm { raw, .. } => assert!(raw),
            _ => panic!("expected llm command"),
        }
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn llm_retention_defaults_on_and_can_be_disabled() {
        let default = Cli::try_parse_from(["hellas", "llm", "-p", "hello"]).unwrap();
        assert!(matches!(
            default.command,
            Commands::Llm { retain: true, .. }
        ));

        let disabled =
            Cli::try_parse_from(["hellas", "llm", "--retain=false", "-p", "hello"]).unwrap();
        assert!(matches!(
            disabled.command,
            Commands::Llm { retain: false, .. }
        ));
    }

    #[cfg(feature = "evaluate")]
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

    #[cfg(feature = "evaluate")]
    #[test]
    fn llm_rejects_conflicting_local_modes() {
        let result =
            Cli::try_parse_from(["hellas", "llm", "--local", "--verify-local", "-p", "hello"]);

        assert!(result.is_err());
    }

    #[cfg(feature = "evaluate")]
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

    #[cfg(feature = "evaluate")]
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

    #[cfg(feature = "evaluate")]
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

    #[cfg(feature = "evaluate")]
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
            "--execution-environment",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "--payload",
            r#"{"x":1}"#,
            "--assurance",
            "apple-app-attest",
        ])
        .unwrap();
        assert_eq!(cli.assurance, hellas_rpc::Assurance::AppleAppAttest);
        match cli.command {
            Commands::Fetch {
                service,
                method,
                payload,
                retain,
                ..
            } => {
                assert_eq!(service, "echo");
                assert_eq!(method, "run");
                assert_eq!(payload.as_deref(), Some(r#"{"x":1}"#));
                assert!(retain);
            }
            _ => panic!("expected fetch command"),
        }
    }

    #[test]
    fn requester_accepts_provider_pin_and_apple_cdhash_allowlist() {
        let cli = Cli::try_parse_from([
            "hellas",
            "fetch",
            "--service",
            "echo",
            "--method",
            "run",
            "--execution-environment",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "--payload",
            r#"{"x":1}"#,
            "--provider-genesis",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "--apple-app-attest-app-id",
            "2F53L9ZR3N.ai.hellas.app",
            "--apple-app-attest-cdhashes",
            "2222222222222222222222222222222222222222222222222222222222222222,3333333333333333333333333333333333333333333333333333333333333333",
        ])
        .unwrap();
        assert_eq!(
            cli.provider_genesis,
            Some(hellas_rpc::ContentId::from_bytes([0x11; 32]))
        );
        assert_eq!(
            cli.apple_app_attest_app_id.as_deref(),
            Some("2F53L9ZR3N.ai.hellas.app")
        );
        assert_eq!(cli.apple_app_attest_cdhashes, vec![[0x22; 32], [0x33; 32]]);
    }

    #[cfg(feature = "node")]
    #[test]
    fn serve_rejects_software_root_with_apple_assurance() {
        assert!(
            validate_serve_assurance(true, hellas_rpc::Assurance::AppleAppAttest, None).is_err()
        );
        assert!(
            validate_serve_assurance(
                false,
                hellas_rpc::Assurance::AppleAppAttest,
                Some(hellas_rpc::RootKind::Software),
            )
            .is_err()
        );
        assert!(
            validate_serve_assurance(
                false,
                hellas_rpc::Assurance::AppleAppAttest,
                Some(hellas_rpc::RootKind::SecureEnclave),
            )
            .is_ok()
        );
    }

    #[test]
    fn fetch_retention_can_be_disabled() {
        let cli = Cli::try_parse_from([
            "hellas",
            "fetch",
            "--service",
            "echo",
            "--method",
            "run",
            "--execution-environment",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "--payload",
            r#"{"x":1}"#,
            "--retain=false",
        ])
        .unwrap();
        assert!(matches!(cli.command, Commands::Fetch { retain: false, .. }));
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
    #[cfg(feature = "node")]
    fn expected_default_dtype() -> Dtype {
        parse_model_dtype(DEFAULT_DTYPE_STR).unwrap()
    }

    #[cfg(feature = "evaluate")]
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

    #[cfg(feature = "evaluate")]
    #[test]
    fn llm_accepts_single_dtype() {
        let cli = Cli::try_parse_from(["hellas", "llm", "--dtype", "f16", "-p", "hi"]).unwrap();
        match cli.command {
            Commands::Llm { dtype, .. } => assert_eq!(dtype, vec![Dtype::F16]),
            _ => panic!("expected llm command"),
        }
    }

    #[cfg(feature = "evaluate")]
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

    #[cfg(feature = "evaluate")]
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

    #[cfg(feature = "evaluate")]
    #[test]
    fn default_llm_dtypes_network_uses_bf16_first() {
        let prefs = default_llm_dtypes(/* is_local_mode = */ false);
        assert_eq!(prefs, vec![Dtype::BF16, Dtype::F32, Dtype::F16]);
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn gateway_accepts_dtype_bf16() {
        let cli = Cli::try_parse_from(["hellas", "gateway", "--dtype", "bf16"]).unwrap();
        match cli.command {
            Commands::Gateway { dtype, .. } => assert_eq!(dtype, Dtype::BF16),
            _ => panic!("expected gateway command"),
        }
    }

    #[cfg(feature = "evaluate")]
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

    #[cfg(feature = "evaluate")]
    #[test]
    fn gateway_wrap_args_require_wrap() {
        let result = Cli::try_parse_from(["hellas", "gateway", "--", "-p", "hi"]);
        assert!(result.is_err(), "trailing args without --wrap should error");
    }

    #[cfg(feature = "evaluate")]
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
            "--responses-fetch-execution-environment",
            "0909090909090909090909090909090909090909090909090909090909090909",
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
    fn producer_key_show_accepts_global_identity_path() {
        let cli = Cli::try_parse_from([
            "hellas",
            "--identity",
            "/tmp/hellas-identity",
            "producer-key",
            "show",
        ])
        .unwrap();
        assert_eq!(
            cli.identity.as_deref(),
            Some(std::path::Path::new("/tmp/hellas-identity"))
        );
        match cli.command {
            Commands::ProducerKey {
                command: ProducerKeyCommand::Show,
            } => {}
            _ => panic!("expected producer-key show command"),
        }
    }

    #[cfg(feature = "node")]
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

    #[cfg(feature = "node")]
    #[test]
    fn serve_accepts_dtype_f16() {
        let cli = Cli::try_parse_from(["hellas", "serve", "--dtype", "f16"]).unwrap();
        match cli.command {
            Commands::Serve { dtype, .. } => assert_eq!(dtype, vec![Dtype::F16]),
            _ => panic!("expected serve command"),
        }
    }

    #[cfg(feature = "node")]
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

    #[cfg(feature = "node")]
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

    #[cfg(feature = "node")]
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

    #[cfg(feature = "node")]
    #[test]
    fn serve_rejects_dtype_u32_in_list() {
        let result = Cli::try_parse_from(["hellas", "serve", "--dtype", "f32,u32"]);
        assert!(result.is_err());
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn llm_rejects_dtype_u32() {
        let result = Cli::try_parse_from(["hellas", "llm", "--dtype", "u32", "-p", "hi"]);
        assert!(result.is_err());
    }
}
