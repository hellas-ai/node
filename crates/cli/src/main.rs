#[macro_use]
extern crate tracing;

#[cfg(feature = "gateway")]
use clap::ValueEnum;
use clap::{Args, Parser, Subcommand};
use iroh::EndpointId;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
#[cfg(feature = "evaluate")]
use std::time::Duration;

mod commands;
mod identity;
#[cfg(feature = "node")]
mod metrics;
#[cfg(feature = "node")]
mod platform_hardening;
mod tracing_config;

#[cfg(feature = "node")]
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
    s.parse()
        .map_err(|error| format!("invalid ContentId: {error}"))
}

fn parse_fetch_environment(s: &str) -> Result<hellas_rpc::ContentId, String> {
    match s {
        "codex-responses" => Ok(hellas_rpc::FetchEnvironment::CodexResponses.manifest_id()),
        "openai-responses" => Ok(hellas_rpc::FetchEnvironment::OpenAiResponses.manifest_id()),
        content_id => parse_content_id_hex(content_id),
    }
}

#[cfg(feature = "node")]
fn parse_positive_usize(s: &str) -> Result<usize, String> {
    usize::try_from(parse_positive_u64(s)?)
        .map_err(|_| "invalid positive integer: number too large to fit in target type".to_string())
}

#[cfg(feature = "node")]
fn parse_positive_u64(s: &str) -> Result<u64, String> {
    let value = s
        .parse::<u64>()
        .map_err(|error| format!("invalid positive integer: {error}"))?;
    (value > 0)
        .then_some(value)
        .ok_or_else(|| "value must be greater than zero".to_string())
}

#[cfg(feature = "evaluate")]
fn parse_gpu_generation_capacity(s: &str) -> Result<u64, String> {
    let value = parse_positive_u64(s)?;
    (value <= hellas_executor::MAX_GPU_GENERATION_CAPACITY)
        .then_some(value)
        .ok_or_else(|| {
            format!(
                "value must not exceed {}",
                hellas_executor::MAX_GPU_GENERATION_CAPACITY
            )
        })
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

/// Loads the identity this command runs under, creating one only where
/// creating one is what the operator asked for.
///
/// Identity queries read the file and create nothing as a side effect: doing
/// so could race with a running service's own creator. Two other commands read
/// an existing identity because they settle paid work:
/// a `serve` that was handed a work configuration, and the `provision`
/// that stakes the bond such a node offers. Both sign with the stored
/// identity's key, so the key must be one an operator already made —
/// `identity init` is where it comes from. Minting one here would give
/// the node a settlement party nobody has funded and no bond names, and
/// the first symptom would be a channel that cannot be opened.
///
/// # Errors
///
/// Whatever the identity file's own loader says, which names the file it
/// could not read.
fn load_command_identity(
    command: &Commands,
    path: Option<&Path>,
    software_root: bool,
) -> anyhow::Result<identity::LocalIdentity> {
    #[cfg(feature = "node")]
    let settles_paid_work = matches!(
        command,
        Commands::Serve {
            work_config_file: Some(_),
            ..
        } | Commands::Provision { .. }
            | Commands::PaidWork { .. }
    );
    #[cfg(not(feature = "node"))]
    let settles_paid_work = false;
    let read_only = settles_paid_work
        || matches!(
            command,
            Commands::Identity {
                command: IdentityCommand::ShowNodeId | IdentityCommand::ShowEnrollmentId,
            }
        );
    if read_only {
        identity::load_existing(path)
    } else {
        identity::load_or_create(path, software_root)
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

/// The trust anchor this gateway's remote routes are built from, or
/// `None` for a gateway that has none to build.
///
/// Every non-local Hellas route dials either a direct node or discovery, and
/// Fetch always dials remotely. Their trust anchor is required before the
/// gateway binds; local Hellas execution and a proxy-only gateway need none.
#[cfg(feature = "gateway")]
fn gateway_provider_trust(
    local: bool,
    responses_backend: GatewayResponsesBackend,
    expected_genesis: Option<hellas_rpc::ContentId>,
    assurance: hellas_rpc::Assurance,
    apple_app_attest_app_id: Option<String>,
    apple_app_attest_cdhashes: Vec<[u8; 32]>,
) -> anyhow::Result<Option<hellas_client::ProviderTrustAnchor>> {
    let dials_provider = (responses_backend == GatewayResponsesBackend::Hellas && !local)
        || responses_backend == GatewayResponsesBackend::Fetch;
    if !dials_provider && expected_genesis.is_none() {
        return Ok(None);
    }
    identity::provider_trust(
        expected_genesis,
        assurance,
        apple_app_attest_app_id,
        apple_app_attest_cdhashes,
    )
    .map(Some)
}

/// Caller-selected trust policy for commands that execute on a remote provider.
#[derive(Args)]
struct RemoteTrustArgs {
    /// Assurance required for remote execution.
    #[arg(long, default_value = "producer-signed", value_parser = parse_assurance)]
    assurance: hellas_rpc::Assurance,

    /// Out-of-band ContentId pin for the remote node's canonical enrollment
    /// bundle. This is a hash asserted by the caller, not a document learned
    /// from the node being checked.
    #[arg(
        long = "provider",
        value_name = "CONTENT_ID",
        value_parser = parse_content_id_hex
    )]
    provider_genesis: Option<hellas_rpc::ContentId>,

    /// Apple App Attest application CDhashes trusted for confidential open.
    /// Repeat the flag or pass a comma-separated list of 32-byte hex values.
    #[arg(
        long = "apple-app-attest-cdhashes",
        value_delimiter = ',',
        value_parser = parse_hex_array::<32>
    )]
    apple_app_attest_cdhashes: Vec<[u8; 32]>,

    /// Apple App Attest application identity in <teamID>.<bundleID> form.
    #[arg(long = "apple-app-attest-app-id")]
    apple_app_attest_app_id: Option<String>,
}

/// One canonical causal-LM route and its untrusted text-presentation boundary.
#[cfg(feature = "llm")]
#[derive(Args)]
struct CausalLmArgs {
    /// Canonical causal-LM environment root. Without --manifest-id, these
    /// local file bytes are the trust anchor and determine the exact manifest.
    #[arg(long = "environment", value_name = "FILE")]
    environment: PathBuf,

    /// Optional caller-selected manifest ContentId for --environment. When
    /// supplied, the file must derive exactly this ID before any route starts.
    #[arg(
        long = "manifest-id",
        value_name = "CONTENT_ID",
        value_parser = parse_content_id_hex
    )]
    manifest_id: Option<hellas_rpc::ContentId>,

    /// Presentation-only model label. It defaults to the derived manifest ID
    /// and never enters the manifest, quote, or trusted executor input.
    #[arg(long = "model", value_name = "NAME")]
    model: Option<String>,

    /// Local files that satisfy exact program/static content references.
    /// Repeat for multiple objects; used only by local execution legs.
    #[cfg(feature = "evaluate")]
    #[arg(
        long = "content",
        value_name = "PATH",
        requires = "causal_lm_local_mode"
    )]
    content_paths: Vec<PathBuf>,

    /// Directory trees to adopt as local content. No network fetch or
    /// compilation occurs; used only by local execution legs.
    #[cfg(feature = "evaluate")]
    #[arg(
        long = "content-root",
        value_name = "DIR",
        requires = "causal_lm_local_mode"
    )]
    content_roots: Vec<PathBuf>,

    /// Fast-resume content index (default: Hellas store state).
    #[cfg(feature = "evaluate")]
    #[arg(
        long = "content-index",
        value_name = "FILE",
        requires = "causal_lm_local_mode"
    )]
    content_index: Option<PathBuf>,

    /// Tokenizer JSON used only for local text presentation. It is not part of
    /// the Hellas execution guarantee.
    #[arg(long = "tokenizer", value_name = "PATH")]
    tokenizer: PathBuf,

    /// Caller-selected stop token ID. Repeat or comma-separate. No stop tokens
    /// are inferred from the tokenizer or causal-LM environment.
    #[arg(long = "stop-token", value_delimiter = ',')]
    stop_token_ids: Vec<u32>,
}

#[derive(Parser)]
#[command(name = "hellas")]
#[command(version)]
#[command(about = "Hellas node CLI")]
struct Cli {
    /// Path to the versioned local identity for commands that use one
    /// (default: $HOME/.hellas/identity).
    #[arg(long = "identity", global = true)]
    identity: Option<PathBuf>,

    /// Choose the software platform root when a command creates an identity.
    #[arg(long = "software-root", global = true)]
    software_root: bool,

    /// Also append tracing output to this file.
    #[arg(long = "log-file", global = true)]
    log_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Create the local identity file if it does not exist
    Init,
    /// Print the node ID (hex public key) derived from the identity file
    ShowNodeId,
    /// Print the ContentId of the canonical enrollment bundle
    ShowEnrollmentId,
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
        /// Assurance offered by this provider.
        #[arg(long, default_value = "producer-signed", value_parser = parse_assurance)]
        assurance: hellas_rpc::Assurance,
        /// Port to listen on. Omit it to let the OS select an available port.
        #[arg(long)]
        port: Option<u16>,
        /// Evaluate policy: 'none' (default), 'any', or
        /// 'only(EXECUTION_ENVIRONMENT_ID_GLOB,...)'.
        #[arg(long = "execute-policy", default_value = "none")]
        execute_policy: hellas_rpc::policy::ExecutePolicy,
        /// Maximum number of queued executions waiting behind the active worker
        #[arg(
            long = "queue-size",
            default_value_t = hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY
        )]
        queue_size: usize,
        /// Local files that may satisfy content references in submitted
        /// canonical causal-LM environments. Repeat for programs/assets.
        #[cfg(feature = "evaluate")]
        #[arg(long = "content", value_name = "PATH")]
        content_paths: Vec<PathBuf>,
        /// Directory tree to adopt into the local content store. Repeat for
        /// HuggingFace/Xet cache roots; no remote fetch is performed.
        #[cfg(feature = "evaluate")]
        #[arg(long = "content-root", value_name = "DIR")]
        content_roots: Vec<PathBuf>,
        /// Fast-resume index for local content (default: under the artifact
        /// store directory).
        #[cfg(feature = "evaluate")]
        #[arg(long = "content-index", value_name = "FILE")]
        content_index: Option<PathBuf>,
        /// Maximum distinct Catena programs retained in one GPU session.
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-session-programs", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_PROGRAMS, value_parser = parse_positive_usize)]
        gpu_session_programs: usize,
        /// Maximum aggregate static asset bytes retained in one GPU session.
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-session-asset-bytes", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_ASSET_BYTES, value_parser = parse_positive_u64)]
        gpu_session_asset_bytes: u64,
        /// Maximum prompt-plus-output capacity of one GPU generation (at most
        /// 524288 so retained token output fits the artifact transport).
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-max-generation-capacity", default_value_t = hellas_executor::DEFAULT_GPU_MAX_GENERATION_CAPACITY, value_parser = parse_gpu_generation_capacity)]
        gpu_max_generation_capacity: u64,
        /// Maximum non-asset device bytes owned or allocated by one GPU generation.
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-max-generation-device-bytes", default_value_t = hellas_executor::DEFAULT_GPU_MAX_GENERATION_DEVICE_BYTES, value_parser = parse_positive_u64)]
        gpu_max_generation_device_bytes: u64,
        /// Maximum seconds spent loading and compiling one Catena program.
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-compile-timeout-secs", default_value_t = hellas_executor::DEFAULT_GPU_COMPILE_TIMEOUT_SECS, value_parser = parse_positive_u64)]
        gpu_compile_timeout_secs: u64,
        /// Maximum seconds for one GPU control operation or full generation.
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-execution-timeout-secs", default_value_t = hellas_executor::DEFAULT_GPU_EXECUTION_TIMEOUT_SECS, value_parser = parse_positive_u64)]
        gpu_execution_timeout_secs: u64,
        /// Maximum distinct retained Evaluate executions. Zero disables new
        /// retained completions. The value is persisted per artifact-store
        /// root; stop every sharing process before changing it.
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "evaluate-retained-execution-capacity",
            default_value_t = hellas_executor::DEFAULT_EVALUATE_RETAINED_EXECUTION_CAPACITY
        )]
        evaluate_retained_execution_capacity: usize,
        /// Persistent canonical artifact blob store path (default: $HOME/.hellas/artifacts)
        #[arg(long = "artifact-store-path")]
        artifact_store_path: Option<PathBuf>,
        /// Paid-work configuration. Its presence serves WorkSetup and Work;
        /// Work remains retryably not ready until the configured state mounts.
        #[arg(long = "work-config")]
        work_config_file: Option<PathBuf>,
        /// Prometheus metrics port (e.g. 9090)
        #[arg(long = "metrics-port")]
        metrics_port: Option<u16>,
        /// Operator graffiti tag (up to 16 bytes, padded/truncated)
        #[arg(long = "graffiti", default_value = "")]
        graffiti: String,
        /// Fetch configuration file: sealed upstream destinations and
        /// credentials, route capabilities, and caller access policy. No file
        /// means this node serves no Fetch routes.
        #[arg(long = "fetch-config")]
        fetch_config_file: Option<PathBuf>,
        /// Maximum number of Fetch provider streams running at once.
        #[arg(
            long = "fetch-max-in-flight",
            default_value_t = hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT,
            value_parser = parse_positive_usize
        )]
        fetch_max_in_flight: usize,
        /// Maximum number of Fetch executions waiting behind active provider streams.
        #[arg(
            long = "fetch-queue-size",
            default_value_t = hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY
        )]
        fetch_queue_size: usize,
        /// Maximum distinct retained Fetch inputs across completed transcripts
        /// and indeterminate running markers. Zero disables new retention. The
        /// value is persisted per store root; stop every process sharing that
        /// root before changing it or removing its capacity metadata.
        #[arg(
            long = "fetch-retained-transcript-capacity",
            default_value_t = hellas_rpc::DEFAULT_FETCH_RETAINED_TRANSCRIPT_CAPACITY
        )]
        fetch_retained_transcript_capacity: usize,
        /// Maximum retained Fetch replays with a live, not-yet-drained consumer.
        #[arg(
            long = "fetch-replay-max-in-flight",
            default_value_t = hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
            value_parser = parse_positive_usize
        )]
        fetch_replay_max_in_flight: usize,
    },
    #[cfg(feature = "gateway")]
    /// Run HTTP gateway exposing OpenAI/Anthropic/plain APIs over Hellas network
    ///
    /// The gateway's routes reach an executor, so it binds loopback only
    /// and every route requires a credential drawn fresh at startup and
    /// printed once to your terminal. Send it as
    /// `Authorization: Bearer <token>`; a restart draws a new one. Hellas
    /// routes use the one operator-selected causal-LM environment below. Text
    /// tokenization and decoding are a separate, unattested presentation
    /// concern configured explicitly by `--tokenizer`.
    #[cfg_attr(
        feature = "evaluate",
        command(group(
            clap::ArgGroup::new("causal_lm_local_mode")
                .args(["local", "verify_local"])
        ))
    )]
    #[cfg_attr(
        feature = "evaluate",
        command(group(
            clap::ArgGroup::new("causal_lm_local_content")
                .args(["content_paths", "content_roots"])
                .multiple(true)
        ))
    )]
    Gateway {
        #[command(flatten)]
        remote_trust: RemoteTrustArgs,
        #[command(flatten)]
        causal_lm: CausalLmArgs,
        /// Host interface to bind. Must resolve to a loopback address;
        /// anything else is refused, because these routes reach an
        /// executor.
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
        /// Run locally with Catena instead of the Hellas network
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "local",
            default_value_t = false,
            conflicts_with_all = ["node_id", "node_addrs"],
            requires = "causal_lm_local_content"
        )]
        local: bool,
        /// Run remotely and verify that the response matches local Catena execution
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "verify-local",
            default_value_t = false,
            conflicts_with_all = ["local", "verify"],
            requires = "causal_lm_local_content"
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
        #[arg(
            long = "default-max-tokens",
            default_value_t = 128,
            value_parser = clap::value_parser!(u32).range(1..)
        )]
        default_max_tokens: u32,
        /// Prometheus metrics port (e.g. 9090)
        #[arg(long = "metrics-port")]
        metrics_port: Option<u16>,
        /// Backend used only for /v1/responses; other gateway APIs are unchanged.
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
        /// Built-in Fetch environment alias (`codex-responses` or
        /// `openai-responses`) or exact ProgramManifest ContentId expected from
        /// the provider route.
        #[arg(
            long = "responses-fetch-execution-environment",
            required_if_eq("responses_backend", "fetch"),
            value_parser = parse_fetch_environment
        )]
        responses_fetch_execution_environment: Option<hellas_rpc::ContentId>,
        /// JSON object merged into OpenAI Responses requests before signing
        /// and sending them through Fetch.
        #[arg(long = "responses-fetch-request-overrides", value_parser = parse_json_object)]
        responses_fetch_request_overrides: Option<serde_json::Map<String, serde_json::Value>>,
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
    /// Fetch canonical artifact bytes from a node
    Artifact {
        #[command(subcommand)]
        command: commands::artifact::ArtifactCommand,
    },
    /// Inspect or run the durable paid-work client path.
    #[cfg(feature = "node")]
    PaidWork {
        #[command(subcommand)]
        command: commands::paid_work::PaidWorkCommand,
    },
    /// Inspect and fill the content store
    Store {
        #[command(subcommand)]
        command: commands::store::StoreCommand,
    },
    /// Build or inspect canonical causal-LM environments.
    Environment {
        #[command(subcommand)]
        command: commands::environment::EnvironmentCommand,
    },
    /// Query or run Hellas chain components
    #[cfg(feature = "chain")]
    Chain {
        #[command(subcommand)]
        command: commands::chain::ChainCommand,
    },
    #[cfg(feature = "llm")]
    /// Run token-native Catena inference remotely, or locally when built with `evaluate`
    #[cfg_attr(
        feature = "evaluate",
        command(group(
            clap::ArgGroup::new("causal_lm_local_mode").args(["local", "verify_local"])
        ))
    )]
    #[cfg_attr(
        feature = "evaluate",
        command(group(
            clap::ArgGroup::new("causal_lm_local_content")
                .args(["content_paths", "content_roots"])
                .multiple(true)
        ))
    )]
    Llm {
        #[command(flatten)]
        remote_trust: RemoteTrustArgs,
        #[command(flatten)]
        causal_lm: CausalLmArgs,
        /// Node ID to run on remotely (omit to auto-discover)
        node_id: Option<EndpointId>,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',', requires = "node_id")]
        node_addrs: Vec<SocketAddr>,
        /// Prompt to send (required)
        #[arg(short = 'p', long = "prompt")]
        prompt: String,
        /// Publish prompt- and token-bearing artifacts through Courtesy.
        #[arg(long = "retain", action = clap::ArgAction::SetTrue)]
        retain: bool,
        /// Maximum number of new tokens to generate
        #[arg(
            long = "max-new-tokens",
            default_value_t = 16,
            value_parser = clap::value_parser!(u32).range(1..)
        )]
        max_new_tokens: u32,
        /// Max execution retries on failure (discovery path only)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Run locally with Catena instead of the Hellas network
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "local",
            default_value_t = false,
            conflicts_with_all = ["verify_local", "node_id", "node_addrs"],
            requires = "causal_lm_local_content"
        )]
        local: bool,
        /// Run remotely and locally, then verify that both outputs match
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "verify-local",
            default_value_t = false,
            conflicts_with = "local",
            requires = "causal_lm_local_content"
        )]
        verify_local: bool,
    },
    /// Run a signed, manifest-pinned Fetch request
    ///
    /// The selected Fetch contract strictly structures the upstream request
    /// and destructures its adversarial response into signed output. A
    /// platform-backed assurance authenticates the app; producer-signed does not.
    Fetch {
        #[command(flatten)]
        remote_trust: RemoteTrustArgs,
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
        /// Built-in Fetch environment alias (`codex-responses` or
        /// `openai-responses`) or exact ProgramManifest ContentId. This pins
        /// the exact request structuring and response destructuring contract.
        #[arg(long = "execution-environment", value_parser = parse_fetch_environment)]
        execution_environment: hellas_rpc::ContentId,
        /// Exact UTF-8 JSON request input signed by this caller.
        #[arg(
            long,
            conflicts_with = "payload_file",
            required_unless_present = "payload_file"
        )]
        payload: Option<String>,
        /// Read exact UTF-8 JSON request input from a file.
        #[arg(long = "payload-file")]
        payload_file: Option<PathBuf>,
        /// Max execution retries on failure (discovery path only)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Publish the signed input/output transcript through Courtesy.
        #[arg(long = "retain", action = clap::ArgAction::SetTrue)]
        retain: bool,
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
    #[cfg(feature = "node")]
    /// Run the bootstrap measurement and write the artifact `serve` reads
    ///
    /// §4's floor is a measured policy, so a node with no artifact
    /// countersigns no paid channel. This is the run that produces one.
    /// It countersigns nothing itself, records raw samples rather than
    /// summaries, and writes `assumed` — by name, on the terminal — for
    /// every term this deployment cannot observe. Pin the digest it
    /// prints in the configuration's `artifact.digest`.
    Measure {
        /// The paid-work configuration this run measures under
        #[arg(long = "work-config")]
        work_config: PathBuf,
        /// Journal root the workload runs on. Use the one the node will
        /// serve from: the disk being measured has to be the disk the
        /// duties run on.
        #[arg(long = "journal-root")]
        journal_root: PathBuf,
        /// The machine, as you name it. It is recorded in the artifact,
        /// because a measurement is a statement about a machine.
        #[arg(long = "machine")]
        machine: String,
        /// What you write down for every term no run here can observe.
        /// A term that is neither measured nor named in this file stops
        /// the run.
        #[arg(long = "assume")]
        assume: PathBuf,
        /// Where the artifact is written
        #[arg(long = "out")]
        out: PathBuf,
    },
    #[cfg(feature = "node")]
    /// Make one of this provider's bond offers, so its client has something to
    /// answer
    ///
    /// A node serves `WorkSetup` from the setup journals under its work
    /// root and creates none, so a fresh provider offers nothing however
    /// well it is configured. This signs one bond and journals it, and
    /// returns only once the runner's own replay of that journal finds
    /// it. A root may hold several offers only when their configured routes,
    /// bonds, and every staked coin are pairwise disjoint.
    Provision {
        /// The paid-work configuration this offer is made under
        #[arg(long = "work-config")]
        work_config: PathBuf,
        /// The client this bond names as taker, hex-encoded
        #[arg(long = "client")]
        client: String,
        /// A coin this provider stakes, hex-encoded. Repeat it for each
        /// coin; the stake is the provider's alone, so none of these is
        /// the client's.
        #[arg(long = "stake-coin", required = true)]
        stake_coin: Vec<String>,
        /// Height the bond expires at, which is also the admission
        /// horizon of the channel it insures
        #[arg(long = "bond-timeout")]
        bond_timeout: u64,
        /// What the bond's timeout returns to this provider. Consensus
        /// requires it to be the staked edge's close value exactly, and
        /// refuses the open otherwise.
        #[arg(long = "timeout-payout")]
        timeout_payout: u64,
        /// The largest job price this bond covers
        #[arg(long = "max-job-price")]
        max_job_price: u64,
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

fn validate_identity_options(
    command: &Commands,
    identity: Option<&Path>,
    software_root: bool,
) -> Result<(), String> {
    let identity_free = match command {
        Commands::Store { .. } => Some("store"),
        Commands::Environment { .. } => Some("environment"),
        #[cfg(feature = "chain")]
        Commands::Chain { .. } => Some("chain"),
        Commands::CodexAuth { .. } => Some("codex-auth"),
        #[cfg(feature = "node")]
        Commands::Measure { .. } => Some("measure"),
        _ => None,
    };
    if let Some(name) = identity_free
        && (identity.is_some() || software_root)
    {
        let options = match (identity.is_some(), software_root) {
            (true, true) => "--identity and --software-root",
            (true, false) => "--identity",
            (false, true) => "--software-root",
            (false, false) => unreachable!("an identity option was present"),
        };
        return Err(format!(
            "{options} cannot be used with `{name}`; that command does not use a Hellas identity"
        ));
    }

    let reads_existing_identity = match command {
        Commands::Identity {
            command: IdentityCommand::ShowNodeId | IdentityCommand::ShowEnrollmentId,
        }
        | Commands::ProducerKey { .. } => true,
        #[cfg(feature = "node")]
        Commands::Serve {
            work_config_file: Some(_),
            ..
        }
        | Commands::Provision { .. } => true,
        #[cfg(feature = "node")]
        Commands::PaidWork { .. } => true,
        _ => false,
    };
    if software_root && reads_existing_identity {
        return Err(
            "--software-root only selects the root when creating an identity; this command reads an existing identity"
                .to_string(),
        );
    }
    Ok(())
}

fn main() {
    // SafeRuntime launches the current executable as a worker child. This
    // must run before Tokio creates worker threads and before clap, tracing,
    // or any stdout-producing command so the child speaks only Catena's worker
    // protocol on stdout.
    #[cfg(feature = "evaluate")]
    match catena_lang::safe_gpu::run_worker_if_requested() {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("error: failed to start Catena GPU worker: {error}");
            std::process::exit(1);
        }
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: failed to start async runtime: {error}");
            std::process::exit(1);
        }
    };
    runtime.block_on(async_main());
}

async fn async_main() {
    // Parse the CLI first so we can honour the global `--log-file`
    // flag in the subscriber setup. clap's parser is cheap; doing it
    // before tracing init means very early subscriber-internal failures
    // (which print to stderr regardless) are the only thing that
    // bypasses the requested log file.
    let cli = Cli::parse();
    if let Err(error) =
        validate_identity_options(&cli.command, cli.identity.as_deref(), cli.software_root)
    {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
    #[cfg(feature = "node")]
    if let Commands::Serve { assurance, .. } = &cli.command
        && let Err(error) = validate_serve_assurance(cli.software_root, *assurance, None)
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

    // Chain commands carry their own authentication material and transport.
    // Running them must not create an unrelated provider identity as a side
    // effect; in particular, validator config generation runs in a pure Nix
    // build where there is deliberately no writable home directory.
    let command = match cli.command {
        Commands::Store { command } => {
            let result = commands::store::run(command).await;
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        Commands::Environment { command } => {
            let result = commands::environment::run(command).await;
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        command => command,
    };

    #[cfg(feature = "chain")]
    let command = match command {
        Commands::Chain { command } => {
            let result = commands::chain::run(command).await;
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        command => command,
    };

    // A bootstrap run signs nothing, dials nothing, and countersigns
    // nothing: it writes to a journal directory of its own and hashes
    // two files. Loading — or worse, creating — a settlement identity
    // for it would make the measurement depend on a key it never uses,
    // and would make an operator with an unreadable identity file
    // unable to measure the machine that would fix it.
    #[cfg(feature = "node")]
    let command = match command {
        Commands::Measure {
            work_config,
            journal_root,
            machine,
            assume,
            out,
        } => {
            let result = commands::serve::run_probe(commands::serve::ProbeOptions {
                work_config,
                journal_root,
                machine,
                assume,
                out,
            });
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        command => command,
    };

    // Before anything binds, and before any other startup work: a
    // command that cannot have an identity has nothing further to do.
    let local_identity =
        match load_command_identity(&command, cli.identity.as_deref(), cli.software_root) {
            Ok(identity) => identity,
            Err(err) => {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
        };
    let secret_key = local_identity.transport_key.clone();
    #[cfg(feature = "node")]
    if let Commands::Serve { assurance, .. } = &command
        && let Err(error) = validate_serve_assurance(
            cli.software_root,
            *assurance,
            Some(local_identity.genesis.statement.root_kind),
        )
    {
        eprintln!("error: {error}");
        std::process::exit(1);
    }

    let result = match command {
        #[cfg(feature = "node")]
        Commands::Serve {
            assurance,
            port,
            execute_policy,
            queue_size,
            #[cfg(feature = "evaluate")]
            content_paths,
            #[cfg(feature = "evaluate")]
            content_roots,
            #[cfg(feature = "evaluate")]
            content_index,
            #[cfg(feature = "evaluate")]
            gpu_session_programs,
            #[cfg(feature = "evaluate")]
            gpu_session_asset_bytes,
            #[cfg(feature = "evaluate")]
            gpu_max_generation_capacity,
            #[cfg(feature = "evaluate")]
            gpu_max_generation_device_bytes,
            #[cfg(feature = "evaluate")]
            gpu_compile_timeout_secs,
            #[cfg(feature = "evaluate")]
            gpu_execution_timeout_secs,
            #[cfg(feature = "evaluate")]
            evaluate_retained_execution_capacity,
            artifact_store_path,
            work_config_file,
            metrics_port,
            graffiti,
            fetch_config_file,
            fetch_max_in_flight,
            fetch_queue_size,
            fetch_retained_transcript_capacity,
            fetch_replay_max_in_flight,
        } => {
            // Loaded before anything binds: a work configuration that
            // will not load is a node that would advertise two paid
            // ALPNs and then have nothing to mount behind them.
            match work_config_file
                .as_deref()
                .map(commands::serve::load_work_config)
                .transpose()
            {
                Err(error) => Err(error),
                Ok(work_config) => {
                    async {
                        // The key every settlement this node signs is signed
                        // with, taken from the identity loaded above and
                        // never made here.
                        let settlement_key = identity::settlement_signer(&local_identity);
                        let open_identity = local_identity.open_identity();
                        #[cfg(feature = "evaluate")]
                        let gpu_config = hellas_executor::GpuConfig::new(
                            gpu_session_programs,
                            gpu_session_asset_bytes,
                            gpu_max_generation_capacity,
                            gpu_max_generation_device_bytes,
                            Duration::from_secs(gpu_compile_timeout_secs),
                            Duration::from_secs(gpu_execution_timeout_secs),
                        )
                        .map_err(anyhow::Error::msg)?;
                        commands::serve::run(commands::serve::ServeOptions {
                            port,
                            execute_policy,
                            queue_size,
                            #[cfg(feature = "evaluate")]
                            content_paths,
                            #[cfg(feature = "evaluate")]
                            content_roots,
                            #[cfg(feature = "evaluate")]
                            content_index,
                            #[cfg(feature = "evaluate")]
                            gpu_config,
                            #[cfg(feature = "evaluate")]
                            evaluate_retained_execution_capacity,
                            artifact_store_path,
                            work_config,
                            metrics_port,
                            graffiti,
                            fetch_config_file,
                            fetch_max_in_flight,
                            fetch_queue_size,
                            fetch_retained_transcript_capacity,
                            fetch_replay_max_in_flight,
                            secret_key,
                            producer_key: local_identity.producer_key,
                            settlement_key,
                            provider_genesis: local_identity.enrollment.canonical_bytes(),
                            open_identity,
                            assurance,
                        })
                        .await
                    }
                    .await
                }
            }
        }
        #[cfg(feature = "node")]
        Commands::Provision {
            work_config,
            client,
            stake_coin,
            bond_timeout,
            timeout_payout,
            max_job_price,
        } => match commands::serve::load_work_config(&work_config) {
            Err(error) => Err(error),
            Ok(work_config) => {
                commands::serve::run_provision(commands::serve::ProvisionOptions {
                    work_config,
                    // The bond is staked by the party this node already
                    // settles as, taken from the identity loaded above
                    // and never made here.
                    settlement_key: identity::settlement_signer(&local_identity),
                    client,
                    stake_coins: stake_coin,
                    bond_timeout,
                    timeout_payout,
                    max_job_price,
                })
                .await
            }
        },
        #[cfg(feature = "gateway")]
        Commands::Gateway {
            remote_trust,
            causal_lm,
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
            metrics_port,
            responses_backend,
            responses_proxy_url,
            responses_proxy_api_key_env,
            responses_fetch_route_service,
            responses_fetch_route_method,
            responses_fetch_execution_environment,
            responses_fetch_request_overrides,
            wrap,
            wrap_args,
        } => {
            async {
                let CausalLmArgs {
                    environment,
                    manifest_id,
                    model,
                    #[cfg(feature = "evaluate")]
                    content_paths,
                    #[cfg(feature = "evaluate")]
                    content_roots,
                    #[cfg(feature = "evaluate")]
                    content_index,
                    tokenizer,
                    stop_token_ids,
                } = causal_lm;
                let assurance = remote_trust.assurance;
                let loaded_environment =
                    commands::llm::load_environment(&environment, manifest_id)?;
                let model_name = model
                    .unwrap_or_else(|| loaded_environment.execution().manifest_id().to_string());
                #[cfg(feature = "evaluate")]
                let local_content_store = commands::llm::local_content_store(
                    local || verify_local,
                    &environment,
                    &loaded_environment,
                    content_paths,
                    content_roots,
                    content_index,
                )?;
                #[cfg(not(feature = "evaluate"))]
                let local = false;
                let provider_trust = gateway_provider_trust(
                    local,
                    responses_backend,
                    remote_trust.provider_genesis,
                    assurance,
                    remote_trust.apple_app_attest_app_id,
                    remote_trust.apple_app_attest_cdhashes,
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
                    model_name,
                    causal_lm: loaded_environment.into_execution(),
                    #[cfg(feature = "evaluate")]
                    local_content_store,
                    tokenizer,
                    stop_token_ids,
                    metrics_port,
                    responses_backend: responses_backend.into(),
                    responses_proxy_url,
                    responses_proxy_api_key_env,
                    responses_fetch_route_service,
                    responses_fetch_route_method,
                    responses_fetch_execution_environment,
                    responses_fetch_request_overrides: responses_fetch_request_overrides
                        .unwrap_or_default(),
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
        #[cfg(feature = "node")]
        Commands::PaidWork { command } => {
            commands::paid_work::run(
                command,
                secret_key,
                identity::settlement_signer(&local_identity),
            )
            .await
        }
        #[cfg(feature = "chain")]
        Commands::Chain { .. } => unreachable!("chain commands handled before identity load"),
        Commands::Store { .. } => unreachable!("store commands handled before identity load"),
        Commands::Environment { .. } => {
            unreachable!("environment commands handled before identity load")
        }
        #[cfg(feature = "llm")]
        Commands::Llm {
            remote_trust,
            causal_lm,
            node_id,
            node_addrs,
            prompt,
            retain,
            max_new_tokens,
            retries,
            #[cfg(feature = "evaluate")]
            local,
            #[cfg(feature = "evaluate")]
            verify_local,
        } => {
            async {
                let CausalLmArgs {
                    environment,
                    manifest_id,
                    model,
                    #[cfg(feature = "evaluate")]
                    content_paths,
                    #[cfg(feature = "evaluate")]
                    content_roots,
                    #[cfg(feature = "evaluate")]
                    content_index,
                    tokenizer,
                    stop_token_ids,
                } = causal_lm;
                let loaded_environment =
                    commands::llm::load_environment(&environment, manifest_id)?;
                let model_name = model
                    .unwrap_or_else(|| loaded_environment.execution().manifest_id().to_string());
                #[cfg(feature = "evaluate")]
                let local_content_store = commands::llm::local_content_store(
                    local || verify_local,
                    &environment,
                    &loaded_environment,
                    content_paths,
                    content_roots,
                    content_index,
                )?;
                commands::llm::run(
                    commands::llm::ExecuteOptions {
                        node_id,
                        node_addrs,
                        model_name,
                        causal_lm: loaded_environment.into_execution(),
                        #[cfg(feature = "evaluate")]
                        local_content_store,
                        tokenizer,
                        stop_token_ids,
                        prompt,
                        retain,
                        max_new_tokens,
                        retries,
                        #[cfg(feature = "evaluate")]
                        local,
                        #[cfg(feature = "evaluate")]
                        verify_local,
                        producer_key: local_identity.producer_key,
                        #[cfg(feature = "evaluate")]
                        provider_genesis: local_identity.enrollment.canonical_bytes(),
                        expected_provider_genesis: remote_trust.provider_genesis,
                        apple_app_attest_app_id: remote_trust.apple_app_attest_app_id,
                        apple_app_attest_cdhashes: remote_trust.apple_app_attest_cdhashes,
                        assurance: remote_trust.assurance,
                    },
                    secret_key,
                )
                .await
            }
            .await
        }
        Commands::Fetch {
            remote_trust,
            node_id,
            node_addrs,
            service,
            method,
            execution_environment,
            payload,
            payload_file,
            retries,
            retain,
        } => {
            let payload = match (payload, payload_file) {
                (Some(payload), None) => Ok(payload.into_bytes()),
                (None, Some(path)) => commands::fetch::load_payload_file(&path),
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
                            expected_provider_genesis: remote_trust.provider_genesis,
                            apple_app_attest_app_id: remote_trust.apple_app_attest_app_id,
                            apple_app_attest_cdhashes: remote_trust.apple_app_attest_cdhashes,
                            assurance: remote_trust.assurance,
                        },
                        secret_key,
                    )
                    .await
                }
                Err(err) => Err(err),
            }
        }
        Commands::Identity { command } => match command {
            IdentityCommand::Init => Ok(()),
            IdentityCommand::ShowNodeId => commands::identity::show_node_id(&secret_key),
            IdentityCommand::ShowEnrollmentId => {
                commands::identity::show_enrollment_id(&local_identity.enrollment)
            }
        },
        Commands::ProducerKey { .. } => unreachable!("producer-key handled before identity load"),
        Commands::CodexAuth { .. } => unreachable!("codex-auth handled before identity load"),
        #[cfg(feature = "node")]
        Commands::Measure { .. } => unreachable!("measure handled before identity load"),
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

    #[cfg(feature = "llm")]
    const TEST_ENVIRONMENT: &str = "/path/to/model.environment";
    #[cfg(feature = "llm")]
    const TEST_MANIFEST_ID: &str =
        "4444444444444444444444444444444444444444444444444444444444444444";
    #[cfg(feature = "llm")]
    const TEST_TOKENIZER: &str = "/path/to/tokenizer.json";
    #[cfg(feature = "evaluate")]
    const TEST_CONTENT: &str = "/path/to/model.hex";
    const TEST_PROVIDER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const TEST_APP_ID: &str = "2F53L9ZR3N.ai.hellas.app";
    const TEST_CDHASHES: &str = "2222222222222222222222222222222222222222222222222222222222222222,3333333333333333333333333333333333333333333333333333333333333333";
    const TEST_REMOTE_TRUST_ARGS: &[&str] = &[
        "--provider",
        TEST_PROVIDER,
        "--assurance",
        "apple-app-attest",
        "--apple-app-attest-app-id",
        TEST_APP_ID,
        "--apple-app-attest-cdhashes",
        TEST_CDHASHES,
    ];

    fn assert_test_remote_trust(remote_trust: &RemoteTrustArgs) {
        assert_eq!(
            remote_trust.provider_genesis,
            Some(hellas_rpc::ContentId::from_bytes([0x11; 32]))
        );
        assert_eq!(
            remote_trust.assurance,
            hellas_rpc::Assurance::AppleAppAttest
        );
        assert_eq!(
            remote_trust.apple_app_attest_app_id.as_deref(),
            Some(TEST_APP_ID)
        );
        assert_eq!(
            remote_trust.apple_app_attest_cdhashes,
            vec![[0x22; 32], [0x33; 32]]
        );
    }

    fn fetch_environment_cases() -> [(&'static str, hellas_rpc::ContentId); 3] {
        [
            (
                "codex-responses",
                hellas_rpc::FetchEnvironment::CodexResponses.manifest_id(),
            ),
            (
                "openai-responses",
                hellas_rpc::FetchEnvironment::OpenAiResponses.manifest_id(),
            ),
            (
                "0909090909090909090909090909090909090909090909090909090909090909",
                hellas_rpc::ContentId::from_bytes([9; 32]),
            ),
        ]
    }

    #[cfg(feature = "llm")]
    fn parse_llm(args: &[&str]) -> Result<Cli, clap::Error> {
        #[cfg(feature = "evaluate")]
        let local = args.contains(&"--local") || args.contains(&"--verify-local");
        #[cfg(feature = "evaluate")]
        let local_content: &[&str] = if local {
            &["--content", TEST_CONTENT]
        } else {
            &[]
        };
        #[cfg(not(feature = "evaluate"))]
        let local_content: &[&str] = &[];
        Cli::try_parse_from(
            [
                "hellas",
                "llm",
                "--environment",
                TEST_ENVIRONMENT,
                "--tokenizer",
                TEST_TOKENIZER,
            ]
            .into_iter()
            .chain(local_content.iter().copied())
            .chain(args.iter().copied()),
        )
    }

    #[cfg(feature = "gateway")]
    fn parse_gateway(args: &[&str]) -> Result<Cli, clap::Error> {
        #[cfg(feature = "evaluate")]
        let local = args.contains(&"--local") || args.contains(&"--verify-local");
        #[cfg(feature = "evaluate")]
        let local_content: &[&str] = if local {
            &["--content", TEST_CONTENT]
        } else {
            &[]
        };
        #[cfg(not(feature = "evaluate"))]
        let local_content: &[&str] = &[];
        Cli::try_parse_from(
            [
                "hellas",
                "gateway",
                "--environment",
                TEST_ENVIRONMENT,
                "--tokenizer",
                TEST_TOKENIZER,
            ]
            .into_iter()
            .chain(local_content.iter().copied())
            .chain(args.iter().copied()),
        )
    }

    #[cfg(feature = "llm")]
    fn causal_lm_args(command: Commands) -> CausalLmArgs {
        match command {
            Commands::Llm { causal_lm, .. } => causal_lm,
            #[cfg(feature = "gateway")]
            Commands::Gateway { causal_lm, .. } => causal_lm,
            _ => panic!("expected causal-LM command"),
        }
    }

    #[test]
    fn identity_init_has_an_explicit_dispatch_command() {
        let cli = Cli::try_parse_from(["hellas", "identity", "init"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Identity {
                command: IdentityCommand::Init,
            }
        ));
    }

    #[test]
    fn identity_free_commands_reject_global_identity_options() {
        for args in [
            vec![
                "hellas",
                "--identity",
                "unused.identity",
                "environment",
                "inspect",
                "--environment",
                "model.environment",
            ],
            vec![
                "hellas",
                "environment",
                "inspect",
                "--environment",
                "model.environment",
                "--software-root",
            ],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(
                validate_identity_options(
                    &cli.command,
                    cli.identity.as_deref(),
                    cli.software_root,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn identity_queries_reject_a_root_selection_they_cannot_use() {
        let cli =
            Cli::try_parse_from(["hellas", "identity", "show-node-id", "--software-root"]).unwrap();
        assert!(
            validate_identity_options(&cli.command, cli.identity.as_deref(), cli.software_root,)
                .is_err()
        );
    }

    #[test]
    fn identity_enrollment_id_has_an_explicit_dispatch_command() {
        let cli = Cli::try_parse_from(["hellas", "identity", "show-enrollment-id"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Identity {
                command: IdentityCommand::ShowEnrollmentId,
            }
        ));
    }

    #[test]
    fn remote_trust_flags_are_rejected_by_irrelevant_commands() {
        let commands: &[&[&str]] = &[
            &["hellas", "store", "status"],
            &[
                "hellas",
                "environment",
                "inspect",
                "--environment",
                "model.environment",
            ],
            &["hellas", "identity", "init"],
        ];
        for command in commands {
            for flag in TEST_REMOTE_TRUST_ARGS.chunks_exact(2) {
                assert!(
                    Cli::try_parse_from(command.iter().copied().chain(flag.iter().copied()))
                        .is_err(),
                    "{} accepted {}",
                    command.join(" "),
                    flag[0]
                );
            }
        }
    }

    #[cfg(feature = "node")]
    #[test]
    fn serve_accepts_only_its_command_local_assurance() {
        let cli =
            Cli::try_parse_from(["hellas", "serve", "--assurance", "apple-app-attest"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Serve {
                assurance: hellas_rpc::Assurance::AppleAppAttest,
                ..
            }
        ));

        for flag in TEST_REMOTE_TRUST_ARGS.chunks_exact(2) {
            if flag[0] == "--assurance" {
                continue;
            }
            assert!(
                Cli::try_parse_from(["hellas", "serve"].into_iter().chain(flag.iter().copied()))
                    .is_err(),
                "serve accepted requester-only {}",
                flag[0]
            );
        }
    }

    #[cfg(feature = "llm")]
    #[test]
    fn llm_accepts_remote_trust_policy() {
        let mut args = TEST_REMOTE_TRUST_ARGS.to_vec();
        args.extend(["-p", "hello"]);
        assert!(parse_llm(&args).is_ok());
    }

    #[cfg(feature = "llm")]
    #[test]
    fn llm_accepts_an_optional_strict_environment_pin() {
        let pinned = causal_lm_args(
            parse_llm(&["--manifest-id", TEST_MANIFEST_ID, "-p", "hello"])
                .unwrap()
                .command,
        );
        assert_eq!(
            pinned.manifest_id,
            Some(hellas_rpc::ContentId::from_bytes([0x44; 32]))
        );

        let derived = causal_lm_args(parse_llm(&["-p", "hello"]).unwrap().command);
        assert!(derived.manifest_id.is_none());
        assert!(parse_llm(&["--manifest-id", "not-a-content-id", "-p", "hello"]).is_err());
    }

    #[cfg(feature = "gateway")]
    #[test]
    fn gateway_accepts_remote_trust_policy() {
        assert!(parse_gateway(TEST_REMOTE_TRUST_ARGS).is_ok());
    }

    #[cfg(feature = "gateway")]
    #[test]
    fn gateway_accepts_the_optional_environment_pin() {
        let pinned = causal_lm_args(
            parse_gateway(&["--manifest-id", TEST_MANIFEST_ID])
                .unwrap()
                .command,
        );
        assert_eq!(
            pinned.manifest_id,
            Some(hellas_rpc::ContentId::from_bytes([0x44; 32]))
        );
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn llm_accepts_local_mode() {
        let cli = parse_llm(&["--local", "-p", "hello"]).unwrap();
        match cli.command {
            Commands::Llm {
                causal_lm,
                node_id,
                node_addrs,
                local,
                verify_local,
                ..
            } => {
                assert!(node_id.is_none());
                assert!(node_addrs.is_empty());
                assert!(local);
                assert!(!verify_local);
                assert_eq!(causal_lm.environment, PathBuf::from(TEST_ENVIRONMENT));
                assert!(causal_lm.manifest_id.is_none());
                assert_eq!(causal_lm.content_paths, vec![PathBuf::from(TEST_CONTENT)]);
                assert_eq!(causal_lm.tokenizer, PathBuf::from(TEST_TOKENIZER));
                assert!(causal_lm.stop_token_ids.is_empty());
            }
            _ => panic!("expected llm command"),
        }
    }

    #[cfg(feature = "llm")]
    #[test]
    fn llm_requires_explicit_environment_and_tokenizer() {
        assert!(Cli::try_parse_from(["hellas", "llm", "-p", "hello"]).is_err());
        assert!(
            Cli::try_parse_from([
                "hellas",
                "llm",
                "--environment",
                TEST_ENVIRONMENT,
                "-p",
                "hello",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "hellas",
                "llm",
                "--tokenizer",
                TEST_TOKENIZER,
                "-p",
                "hello",
            ])
            .is_err()
        );
    }

    #[cfg(feature = "gateway")]
    #[test]
    fn gateway_requires_explicit_environment_and_tokenizer() {
        assert!(Cli::try_parse_from(["hellas", "gateway"]).is_err());
        assert!(
            Cli::try_parse_from(["hellas", "gateway", "--environment", TEST_ENVIRONMENT,]).is_err()
        );
        assert!(Cli::try_parse_from(["hellas", "gateway", "--tokenizer", TEST_TOKENIZER]).is_err());
    }

    #[cfg(feature = "llm")]
    #[test]
    fn package_flags_are_not_accepted_as_compatibility_aliases() {
        assert!(
            parse_llm(&["--package", "old-package", "-p", "hello"]).is_err(),
            "the removed package selector was accepted"
        );
        assert!(
            parse_llm(&[
                "--package-id",
                "0808080808080808080808080808080808080808080808080808080808080808",
                "-p",
                "hello",
            ])
            .is_err(),
            "the removed package identity was accepted"
        );
    }

    #[cfg(feature = "llm")]
    #[test]
    fn llm_model_is_only_an_optional_label() {
        let args = causal_lm_args(
            parse_llm(&["--model", "friendly-name", "-p", "hello"])
                .unwrap()
                .command,
        );
        assert_eq!(args.model.as_deref(), Some("friendly-name"));
        let args = causal_lm_args(parse_llm(&["-p", "hello"]).unwrap().command);
        assert!(args.model.is_none());
    }

    #[cfg(feature = "gateway")]
    #[test]
    fn gateway_model_is_only_an_optional_api_label() {
        let args = causal_lm_args(parse_gateway(&["--model", "api-label"]).unwrap().command);
        assert_eq!(args.model.as_deref(), Some("api-label"));
        let args = causal_lm_args(parse_gateway(&[]).unwrap().command);
        assert!(args.model.is_none());
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn local_content_flags_are_scoped_to_local_modes() {
        assert!(parse_llm(&["--content", TEST_CONTENT, "-p", "hello"]).is_err());
        assert!(parse_llm(&["--content-root", "/content", "-p", "hello"]).is_err());
        assert!(parse_gateway(&["--content", TEST_CONTENT]).is_err());
        assert!(parse_gateway(&["--content-index", "/state/index.bin"]).is_err());
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn local_modes_accept_repeatable_content_and_roots() {
        let cli = Cli::try_parse_from([
            "hellas",
            "llm",
            "--environment",
            TEST_ENVIRONMENT,
            "--tokenizer",
            TEST_TOKENIZER,
            "--local",
            "--content",
            "/content/program.hex",
            "--content",
            "/content/weights.bin",
            "--content-root",
            "/content/cache",
            "--content-index",
            "/state/index.bin",
            "-p",
            "hello",
        ])
        .unwrap();
        let args = causal_lm_args(cli.command);
        assert_eq!(
            args.content_paths,
            ["/content/program.hex", "/content/weights.bin"].map(PathBuf::from)
        );
        assert_eq!(args.content_roots, vec![PathBuf::from("/content/cache")]);
        assert_eq!(args.content_index, Some(PathBuf::from("/state/index.bin")));
    }

    #[cfg(feature = "llm")]
    #[test]
    fn llm_retention_defaults_off_and_can_be_enabled() {
        let default = parse_llm(&["-p", "hello"]).unwrap();
        assert!(matches!(
            default.command,
            Commands::Llm { retain: false, .. }
        ));

        let enabled = parse_llm(&["--retain", "-p", "hello"]).unwrap();
        assert!(matches!(
            enabled.command,
            Commands::Llm { retain: true, .. }
        ));
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn llm_rejects_local_with_node_id() {
        let result = parse_llm(&[
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
        let result = parse_llm(&["--local", "--verify-local", "-p", "hello"]);

        assert!(result.is_err());
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn gateway_local_modes_require_and_accept_explicit_content() {
        let cli = parse_gateway(&["--local"]).unwrap();
        match cli.command {
            Commands::Gateway {
                causal_lm,
                node_id,
                node_addrs,
                local,
                ..
            } => {
                assert!(node_id.is_none());
                assert!(node_addrs.is_empty());
                assert!(local);
                assert_eq!(causal_lm.content_paths, vec![PathBuf::from(TEST_CONTENT)]);
            }
            _ => panic!("expected gateway command"),
        }

        assert!(
            Cli::try_parse_from([
                "hellas",
                "gateway",
                "--environment",
                TEST_ENVIRONMENT,
                "--tokenizer",
                TEST_TOKENIZER,
                "--local",
            ])
            .is_err(),
            "a local route without explicit content was accepted"
        );
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn gateway_rejects_local_with_node_id() {
        let result = parse_gateway(&[
            "--local",
            "--node-id",
            "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
        ]);

        assert!(result.is_err());
    }

    /// The anchor `hellas gateway <args>` would run with.
    #[cfg(feature = "gateway")]
    fn gateway_trust(args: &[&str]) -> anyhow::Result<Option<hellas_client::ProviderTrustAnchor>> {
        let cli = parse_gateway(args).expect("valid gateway arguments");
        let Commands::Gateway {
            remote_trust,
            responses_backend,
            #[cfg(feature = "evaluate")]
            local,
            ..
        } = cli.command
        else {
            panic!("expected gateway command");
        };
        #[cfg(not(feature = "evaluate"))]
        let local = false;
        gateway_provider_trust(
            local,
            responses_backend,
            remote_trust.provider_genesis,
            remote_trust.assurance,
            remote_trust.apple_app_attest_app_id,
            remote_trust.apple_app_attest_cdhashes,
        )
    }

    #[cfg(feature = "gateway")]
    #[test]
    fn gateway_demands_a_provider_anchor_exactly_where_it_dials_one() {
        const NODE: &str = "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550";
        const SHADOW: &str = "edfadcefb3917925de1111087f11925542c97e14ab00cf42b9447f7567a25b62";
        const PROVIDER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
        const ENVIRONMENT: &str =
            "0909090909090909090909090909090909090909090909090909090909090909";

        // Local and proxy-only modes do not dial a Hellas provider.
        #[cfg(feature = "evaluate")]
        assert!(gateway_trust(&["--local"]).unwrap().is_none());
        assert!(
            gateway_trust(&["--responses-backend", "proxy"])
                .unwrap()
                .is_none()
        );

        // Names one: `--provider` is required, and its absence is refused
        // by the flag that would supply it.
        for dialling in [
            vec![],
            vec!["--node-id", NODE],
            vec!["--node-id", NODE, "--verify", SHADOW],
            vec![
                "--responses-backend",
                "fetch",
                "--responses-fetch-execution-environment",
                ENVIRONMENT,
            ],
        ] {
            let refusal = gateway_trust(&dialling).unwrap_err().to_string();
            assert!(refusal.contains("--provider <content-id>"), "{refusal}");
        }

        #[cfg(feature = "evaluate")]
        {
            let refusal = gateway_trust(&["--verify-local"]).unwrap_err().to_string();
            assert!(refusal.contains("--provider <content-id>"), "{refusal}");
        }

        // Named with its pin: the anchor carries the provider it pins.
        let anchor = gateway_trust(&["--node-id", NODE, "--provider", PROVIDER])
            .unwrap()
            .expect("a dialling gateway carries an anchor");
        assert_eq!(
            anchor.expected_genesis,
            hellas_rpc::ContentId::from_bytes([0x11; 32])
        );
        // A discovery gateway given one keeps the routes it always had.
        assert!(gateway_trust(&["--provider", PROVIDER]).unwrap().is_some());
    }

    #[cfg(feature = "llm")]
    #[test]
    fn llm_rejects_node_addr_without_node_id() {
        let result = parse_llm(&["--node-addr", "127.0.0.1:31145", "-p", "hello"]);

        assert!(result.is_err());
    }

    #[cfg(feature = "gateway")]
    #[test]
    fn gateway_rejects_node_addr_without_node_id() {
        let result = parse_gateway(&["--node-addr", "127.0.0.1:31145"]);

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
        match cli.command {
            Commands::Fetch {
                remote_trust,
                service,
                method,
                payload,
                retain,
                ..
            } => {
                assert_eq!(
                    remote_trust.assurance,
                    hellas_rpc::Assurance::AppleAppAttest
                );
                assert_eq!(service, "echo");
                assert_eq!(method, "run");
                assert_eq!(payload.as_deref(), Some(r#"{"x":1}"#));
                assert!(!retain);
            }
            _ => panic!("expected fetch command"),
        }
    }

    #[test]
    fn direct_fetch_accepts_builtin_environment_aliases_and_exact_id() {
        for (spelling, expected) in fetch_environment_cases() {
            let cli = Cli::try_parse_from([
                "hellas",
                "fetch",
                "--service",
                "echo",
                "--method",
                "run",
                "--execution-environment",
                spelling,
                "--payload",
                r#"{"x":1}"#,
            ])
            .unwrap();
            let Commands::Fetch {
                execution_environment,
                ..
            } = cli.command
            else {
                panic!("expected fetch command");
            };
            assert_eq!(execution_environment, expected);
        }
    }

    #[test]
    fn fetch_output_signer_is_derived_from_the_pinned_provider() {
        let result = Cli::try_parse_from([
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
            "--trusted-producer-public-key",
            "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn fetch_accepts_remote_trust_policy() {
        let cli = Cli::try_parse_from(
            [
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
            ]
            .into_iter()
            .chain(TEST_REMOTE_TRUST_ARGS.iter().copied()),
        )
        .unwrap();
        let Commands::Fetch { remote_trust, .. } = cli.command else {
            panic!("expected fetch command");
        };
        assert_test_remote_trust(&remote_trust);
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
    fn fetch_retention_defaults_off_and_can_be_enabled() {
        let base = [
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
        ];
        let default = Cli::try_parse_from(base).unwrap();
        assert!(matches!(
            default.command,
            Commands::Fetch { retain: false, .. }
        ));

        let enabled = Cli::try_parse_from(base.into_iter().chain(["--retain"])).unwrap();
        assert!(matches!(
            enabled.command,
            Commands::Fetch { retain: true, .. }
        ));
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
            "--execution-environment",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "--payload",
            r#"{"x":1}"#,
            "--node-addr",
            "127.0.0.1:31145",
        ]);

        let error = result
            .err()
            .expect("node address must be rejected")
            .to_string();
        assert!(error.contains("<NODE_ID>"), "{error}");
    }

    #[test]
    fn fetch_rejects_missing_payload() {
        let result = Cli::try_parse_from([
            "hellas",
            "fetch",
            "--service",
            "echo",
            "--method",
            "run",
            "--execution-environment",
            "0909090909090909090909090909090909090909090909090909090909090909",
        ]);

        let error = result
            .err()
            .expect("missing payload must be rejected")
            .to_string();
        assert!(error.contains("--payload"), "{error}");
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
                assert_eq!(parsed_digest, hellas_rpc::Digest::ZERO);
                assert_eq!(output, std::path::Path::new("/tmp/artifact.cbor"));
            }
            _ => panic!("expected artifact get command"),
        }
    }

    #[cfg(feature = "llm")]
    #[test]
    fn llm_accepts_explicit_stop_tokens_without_inference() {
        let cli = parse_llm(&[
            "--stop-token",
            "1,2",
            "--stop-token",
            "3",
            "--max-new-tokens",
            "32",
            "-p",
            "hi",
        ])
        .unwrap();
        match cli.command {
            Commands::Llm {
                causal_lm: CausalLmArgs { stop_token_ids, .. },
                max_new_tokens,
                ..
            } => {
                assert_eq!(stop_token_ids, vec![1, 2, 3]);
                assert_eq!(max_new_tokens, 32);
            }
            _ => panic!("expected llm command"),
        }
    }

    #[cfg(feature = "llm")]
    #[test]
    fn llm_rejects_an_explicit_zero_output_limit() {
        assert!(parse_llm(&["--max-new-tokens", "0", "-p", "hi"]).is_err());
    }

    #[cfg(feature = "gateway")]
    #[test]
    fn gateway_accepts_explicit_stop_tokens() {
        let cli = parse_gateway(&["--stop-token", "1,2", "--stop-token", "3"]).unwrap();
        assert_eq!(causal_lm_args(cli.command).stop_token_ids, vec![1, 2, 3]);
    }

    #[cfg(feature = "gateway")]
    #[test]
    fn gateway_rejects_a_zero_default_output_limit() {
        assert!(parse_gateway(&["--default-max-tokens", "0"]).is_err());
    }

    #[cfg(feature = "gateway")]
    #[test]
    fn gateway_wrap_forwards_trailing_args() {
        let cli =
            parse_gateway(&["--wrap", "pi", "--", "-p", "--no-session", "say hello"]).unwrap();
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

    #[cfg(feature = "gateway")]
    #[test]
    fn gateway_wrap_args_require_wrap() {
        let result = parse_gateway(&["--", "-p", "hi"]);
        assert!(result.is_err(), "trailing args without --wrap should error");
    }

    #[cfg(feature = "gateway")]
    #[test]
    fn gateway_fetch_backend_accepts_builtin_environment_aliases_and_exact_id() {
        for (spelling, expected) in fetch_environment_cases() {
            let cli = parse_gateway(&[
                "--responses-backend",
                "fetch",
                "--responses-fetch-route-service",
                "codex",
                "--responses-fetch-route-method",
                "responses",
                "--responses-fetch-execution-environment",
                spelling,
                "--responses-fetch-request-overrides",
                r#"{"store":false}"#,
            ])
            .unwrap();
            match cli.command {
                Commands::Gateway {
                    responses_backend,
                    responses_fetch_route_service,
                    responses_fetch_route_method,
                    responses_fetch_execution_environment,
                    responses_fetch_request_overrides,
                    ..
                } => {
                    assert_eq!(responses_backend, GatewayResponsesBackend::Fetch);
                    assert_eq!(responses_fetch_route_service, "codex");
                    assert_eq!(responses_fetch_route_method, "responses");
                    assert_eq!(responses_fetch_execution_environment, Some(expected));
                    assert_eq!(responses_fetch_request_overrides.unwrap()["store"], false);
                }
                _ => panic!("expected gateway command"),
            }
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

    #[cfg(all(feature = "node", feature = "evaluate"))]
    #[test]
    fn serve_accepts_gpu_resource_envelope() {
        let cli = Cli::try_parse_from([
            "hellas",
            "serve",
            "--gpu-session-programs",
            "3",
            "--gpu-session-asset-bytes",
            "5",
            "--gpu-max-generation-capacity",
            "7",
            "--gpu-max-generation-device-bytes",
            "11",
            "--gpu-compile-timeout-secs",
            "13",
            "--gpu-execution-timeout-secs",
            "17",
        ])
        .unwrap();
        match cli.command {
            Commands::Serve {
                gpu_session_programs,
                gpu_session_asset_bytes,
                gpu_max_generation_capacity,
                gpu_max_generation_device_bytes,
                gpu_compile_timeout_secs,
                gpu_execution_timeout_secs,
                ..
            } => {
                assert_eq!(gpu_session_programs, 3);
                assert_eq!(gpu_session_asset_bytes, 5);
                assert_eq!(gpu_max_generation_capacity, 7);
                assert_eq!(gpu_max_generation_device_bytes, 11);
                assert_eq!(gpu_compile_timeout_secs, 13);
                assert_eq!(gpu_execution_timeout_secs, 17);
            }
            _ => panic!("expected serve command"),
        }
    }

    #[cfg(all(feature = "node", feature = "evaluate"))]
    #[test]
    fn serve_rejects_a_generation_capacity_above_the_transport_bound() {
        let over_limit = (hellas_executor::MAX_GPU_GENERATION_CAPACITY + 1).to_string();
        assert!(
            Cli::try_parse_from([
                "hellas",
                "serve",
                "--gpu-max-generation-capacity",
                &over_limit,
            ])
            .is_err()
        );
    }

    #[cfg(feature = "node")]
    #[test]
    fn serve_accepts_work_config() {
        let cli =
            Cli::try_parse_from(["hellas", "serve", "--work-config", "/tmp/work.json"]).unwrap();
        match cli.command {
            Commands::Serve {
                work_config_file, ..
            } => assert_eq!(
                work_config_file.as_deref(),
                Some(std::path::Path::new("/tmp/work.json"))
            ),
            _ => panic!("expected serve command"),
        }
    }

    /// An offer names every term of the bond it stakes, and the coins it
    /// stakes them with come one flag at a time.
    #[cfg(feature = "node")]
    #[test]
    fn provision_accepts_the_terms_of_one_bond() {
        let cli = Cli::try_parse_from([
            "hellas",
            "provision",
            "--work-config",
            "/tmp/work.json",
            "--client",
            "02aa",
            "--stake-coin",
            "a1",
            "--stake-coin",
            "a2",
            "--bond-timeout",
            "500",
            "--timeout-payout",
            "64",
            "--max-job-price",
            "40",
        ])
        .unwrap();
        match cli.command {
            Commands::Provision {
                work_config,
                client,
                stake_coin,
                bond_timeout,
                timeout_payout,
                max_job_price,
            } => {
                assert_eq!(work_config, PathBuf::from("/tmp/work.json"));
                assert_eq!(client, "02aa");
                assert_eq!(stake_coin, vec!["a1".to_string(), "a2".to_string()]);
                assert_eq!(bond_timeout, 500);
                assert_eq!(timeout_payout, 64);
                assert_eq!(max_job_price, 40);
            }
            _ => panic!("expected provision command"),
        }
    }

    /// A bond funded by no coin is not one, so the stake is required
    /// rather than defaulted to an empty list.
    #[cfg(feature = "node")]
    #[test]
    fn provision_rejects_an_offer_with_nothing_staked() {
        assert!(
            Cli::try_parse_from([
                "hellas",
                "provision",
                "--work-config",
                "/tmp/work.json",
                "--client",
                "02aa",
                "--bond-timeout",
                "500",
                "--timeout-payout",
                "64",
                "--max-job-price",
                "40",
            ])
            .is_err(),
            "an offer staking nothing was accepted",
        );
    }

    /// The bond an offer stakes is settled with the key an operator
    /// already made, exactly as a paid `serve` is: the same refusal, and
    /// the same file named by it.
    #[cfg(feature = "node")]
    #[test]
    fn provisioning_an_offer_loads_a_stored_settlement_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        let provision = Cli::try_parse_from([
            "hellas",
            "provision",
            "--work-config",
            "/tmp/work.json",
            "--client",
            "02aa",
            "--stake-coin",
            "a1",
            "--bond-timeout",
            "500",
            "--timeout-payout",
            "64",
            "--max-job-price",
            "40",
        ])
        .unwrap();

        let Err(error) = load_command_identity(&provision.command, Some(&path), true) else {
            panic!("a bond is staked with a key an operator already made");
        };
        assert!(
            format!("{error:#}").contains(&path.display().to_string()),
            "the refusal does not name the identity file: {error:#}",
        );
        assert!(!path.exists(), "no identity was created by the refusal");
    }

    /// A node asked to serve paid work loads its settlement identity
    /// before anything binds, and a missing one is a startup failure
    /// naming the file.
    ///
    /// The whole point is what it does *not* do: the same `serve`
    /// without a work configuration creates the file, so the refusal
    /// below is this rule and not a loader that always refuses. A node
    /// that minted its own settlement key would advertise two paid ALPNs
    /// as a party nobody has funded — and would say nothing about it.
    #[cfg(feature = "node")]
    #[test]
    fn serving_paid_work_loads_a_stored_settlement_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        let paid =
            Cli::try_parse_from(["hellas", "serve", "--work-config", "/tmp/work.json"]).unwrap();
        let unpaid = Cli::try_parse_from(["hellas", "serve"]).unwrap();

        let Err(error) = load_command_identity(&paid.command, Some(&path), true) else {
            panic!("paid work is settled with a key an operator already made");
        };
        assert!(
            format!("{error:#}").contains(&path.display().to_string()),
            "the refusal does not name the identity file: {error:#}",
        );
        assert!(!path.exists(), "no identity was created by the refusal");

        // The key is the identity's own, and the identity is the one on
        // disk: created here by a `serve` that was asked for no paid
        // work, and read back by the paid one that would not create it.
        let created = load_command_identity(&unpaid.command, Some(&path), true)
            .expect("a serve with no paid work still creates its transport identity");
        let loaded = load_command_identity(&paid.command, Some(&path), true)
            .expect("the stored identity is what paid work settles with");
        assert_eq!(
            identity::settlement_signer(&loaded).party_key(),
            identity::settlement_signer(&created).party_key(),
        );
        assert_eq!(
            &identity::settlement_signer(&loaded).party_key().to_bytes()[..],
            loaded.producer_key.public_key().bytes(),
            "the settlement party is the producer identity, not a second key",
        );
    }

    /// An identity file that is there and is not one is the same
    /// startup failure, and names the same file.
    #[cfg(feature = "node")]
    #[test]
    fn an_unreadable_settlement_identity_is_a_startup_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        std::fs::write(&path, b"not an identity").unwrap();
        let paid =
            Cli::try_parse_from(["hellas", "serve", "--work-config", "/tmp/work.json"]).unwrap();

        let Err(error) = load_command_identity(&paid.command, Some(&path), true) else {
            panic!("an identity file that is not one is not a key to settle with");
        };

        assert!(
            format!("{error:#}").contains(&path.display().to_string()),
            "the refusal does not name the identity file: {error:#}",
        );
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
            "--fetch-retained-transcript-capacity",
            "0",
            "--fetch-replay-max-in-flight",
            "2",
            "--fetch-config",
            "/tmp/fetch-config.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Serve {
                fetch_max_in_flight,
                fetch_queue_size,
                fetch_retained_transcript_capacity,
                fetch_replay_max_in_flight,
                fetch_config_file,
                ..
            } => {
                assert_eq!(fetch_max_in_flight, 3);
                assert_eq!(fetch_queue_size, 0);
                assert_eq!(fetch_retained_transcript_capacity, 0);
                assert_eq!(fetch_replay_max_in_flight, 2);
                assert_eq!(
                    fetch_config_file.as_deref(),
                    Some(std::path::Path::new("/tmp/fetch-config.json"))
                );
            }
            _ => panic!("expected serve command"),
        }
    }

    #[cfg(feature = "node")]
    #[test]
    fn serve_rejects_zero_fetch_concurrency() {
        assert!(
            Cli::try_parse_from(["hellas", "serve", "--fetch-replay-max-in-flight", "0",]).is_err()
        );
        assert!(Cli::try_parse_from(["hellas", "serve", "--fetch-max-in-flight", "0"]).is_err());
    }

    #[cfg(feature = "node")]
    #[test]
    fn serve_uses_bounded_fetch_defaults() {
        let cli = Cli::try_parse_from(["hellas", "serve"]).unwrap();
        let Commands::Serve {
            fetch_retained_transcript_capacity,
            #[cfg(feature = "evaluate")]
            evaluate_retained_execution_capacity,
            fetch_replay_max_in_flight,
            ..
        } = cli.command
        else {
            panic!("expected serve command");
        };
        assert_eq!(
            fetch_retained_transcript_capacity,
            hellas_rpc::DEFAULT_FETCH_RETAINED_TRANSCRIPT_CAPACITY
        );
        #[cfg(feature = "evaluate")]
        assert_eq!(
            evaluate_retained_execution_capacity,
            hellas_executor::DEFAULT_EVALUATE_RETAINED_EXECUTION_CAPACITY
        );
        assert_eq!(
            fetch_replay_max_in_flight,
            hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT
        );
    }

    #[cfg(all(feature = "node", feature = "evaluate"))]
    #[test]
    fn serve_accepts_and_defaults_evaluate_retention_capacity() {
        let configured = Cli::try_parse_from([
            "hellas",
            "serve",
            "--evaluate-retained-execution-capacity",
            "0",
        ])
        .unwrap();
        let Commands::Serve {
            evaluate_retained_execution_capacity,
            ..
        } = configured.command
        else {
            panic!("expected serve command");
        };
        assert_eq!(evaluate_retained_execution_capacity, 0);

        let defaulted = Cli::try_parse_from(["hellas", "serve"]).unwrap();
        let Commands::Serve {
            evaluate_retained_execution_capacity,
            ..
        } = defaulted.command
        else {
            panic!("expected serve command");
        };
        assert_eq!(
            evaluate_retained_execution_capacity,
            hellas_executor::DEFAULT_EVALUATE_RETAINED_EXECUTION_CAPACITY
        );
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

    #[test]
    fn content_id_parser_round_trips_xet_text_encoding() {
        let displayed = "87d327b23e941d6932610a282834a2d7d5edd761fe0a1b948e5f0d7ca73392ca";
        assert_eq!(
            parse_content_id_hex(displayed).unwrap().to_string(),
            displayed
        );
    }
}
