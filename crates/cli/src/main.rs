#[macro_use]
extern crate tracing;

#[cfg(feature = "gateway")]
use clap::ValueEnum;
use clap::{Parser, Subcommand};
use iroh::EndpointId;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

mod commands;
mod identity;
#[cfg(feature = "node")]
mod metrics;
#[cfg(feature = "node")]
mod platform_hardening;
mod tracing_config;

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

/// Loads the identity this command runs under, creating one only where
/// creating one is what the operator asked for.
///
/// Three commands read the file and never write it. `show-node-id` is a
/// query, and creating an identity as a side effect of one would race
/// with a running service's own creator. The other two settle paid work:
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
    );
    #[cfg(not(feature = "node"))]
    let settles_paid_work = false;
    let read_only = settles_paid_work
        || matches!(
            command,
            Commands::Identity {
                command: IdentityCommand::ShowNodeId,
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

#[derive(Parser)]
#[command(name = "hellas")]
#[command(version)]
#[command(about = "Hellas node CLI")]
struct Cli {
    /// Path to the versioned local identity (default: $HOME/.hellas/identity)
    #[arg(long = "identity", global = true)]
    identity: Option<PathBuf>,

    /// Choose the software platform root when creating an identity.
    #[arg(long = "software-root", global = true)]
    software_root: bool,

    /// Assurance required for remote execution and offered when serving.
    #[arg(
        long,
        global = true,
        default_value = "producer-signed",
        value_parser = parse_assurance
    )]
    assurance: hellas_rpc::Assurance,

    /// Out-of-band ContentId pin for the remote node's canonical enrollment
    /// bundle. This is a hash asserted by the caller, not a document learned
    /// from the node being checked.
    #[arg(
        long = "provider",
        global = true,
        value_name = "CONTENT_ID",
        value_parser = parse_content_id_hex
    )]
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
    /// Create the local identity file if it does not exist
    Init,
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
        /// Execute policy: 'skip' (default), 'eager', or
        /// 'allow(package/pattern,...,id/pattern,...)'.
        #[arg(long = "execute-policy", default_value = "skip")]
        execute_policy: hellas_rpc::policy::ExecutePolicy,
        /// Maximum number of queued executions waiting behind the active worker
        #[arg(
            long = "queue-size",
            default_value_t = hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY
        )]
        queue_size: usize,
        /// Catena execution package to fetch, verify, compile, and serve,
        /// written NAME=PATH. Repeat for multiple local aliases. Peer requests
        /// can only select aliases loaded here; they never resolve paths.
        #[cfg(feature = "evaluate")]
        #[arg(long = "package", value_name = "NAME=PATH")]
        packages: Vec<commands::package::PackageArg>,
        /// Directory for materialized Catena package objects
        /// (default: $HOME/.hellas/packages).
        #[cfg(feature = "evaluate")]
        #[arg(long = "package-cache")]
        package_cache: Option<PathBuf>,
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
    ///
    /// The gateway's routes reach an executor, so it binds loopback only
    /// and every route requires a credential drawn fresh at startup and
    /// printed once to your terminal. Send it as
    /// `Authorization: Bearer <token>`; a restart draws a new one. Hellas
    /// routes use the one operator-selected Catena package below. Text
    /// tokenization and decoding are a separate, unattested presentation
    /// concern configured explicitly by `--tokenizer`.
    Gateway {
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
        #[arg(long = "local", default_value_t = false, conflicts_with_all = ["node_id", "node_addrs"])]
        local: bool,
        /// Run remotely and verify that the response matches local Catena execution
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
        #[arg(
            long = "default-max-tokens",
            default_value_t = 128,
            value_parser = clap::value_parser!(u32).range(1..)
        )]
        default_max_tokens: u32,
        /// Fixed Catena package alias used by Hellas-backed routes. Use NAME
        /// with --package-id for remote execution, or NAME=PATH when a local
        /// or verification leg must materialize and identify the package.
        /// Request-body model strings cannot select files.
        #[cfg_attr(
            feature = "evaluate",
            arg(
                long = "package",
                value_name = "NAME[=PATH]",
                help = "Fixed Catena package route: NAME for remote-only, or NAME=PATH when a local verification leg must materialize it"
            )
        )]
        #[cfg_attr(
            not(feature = "evaluate"),
            arg(
                long = "package",
                value_name = "NAME",
                help = "Peer-local Catena package alias used only for routing; --package-id supplies the trusted identity"
            )
        )]
        package: commands::package::PackageArg,
        /// Exact Catena execution-package ID expected from a remote executor.
        /// Local and verify-local gateways derive it from the verified package.
        #[cfg_attr(
            feature = "evaluate",
            arg(
                long = "package-id",
                value_name = "64_HEX",
                required_unless_present_any = ["local", "verify_local"],
                conflicts_with_all = ["local", "verify_local"],
                help = "Exact Catena execution-package ID expected from a remote executor; local modes derive it from the verified package"
            )
        )]
        #[cfg_attr(
            not(feature = "evaluate"),
            arg(
                long = "package-id",
                value_name = "64_HEX",
                required = true,
                help = "Exact Catena execution-package ID expected from the remote executor"
            )
        )]
        package_id: Option<hellas_rpc::ExecutionPackageId>,
        /// Directory for locally materialized Catena package objects
        /// (default: $HOME/.hellas/packages; unused for remote-only routes).
        #[cfg(feature = "evaluate")]
        #[arg(long = "package-cache")]
        package_cache: Option<PathBuf>,
        /// Tokenizer JSON used only for local text presentation. It is not
        /// part of the Hellas execution guarantee.
        #[arg(long = "tokenizer", value_name = "PATH")]
        tokenizer: PathBuf,
        /// Caller-selected stop token ID. Repeat or comma-separate. No stop
        /// tokens are inferred from the tokenizer or Catena package.
        #[arg(long = "stop-token", value_delimiter = ',')]
        stop_token_ids: Vec<u32>,
        /// Prometheus metrics port (e.g. 9090)
        #[arg(long = "metrics-port")]
        metrics_port: Option<u16>,
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
        #[arg(
            long = "responses-fetch-execution-environment",
            required_if_eq("responses_backend", "fetch")
        )]
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
    /// Fetch canonical artifact bytes from a node
    Artifact {
        #[command(subcommand)]
        command: commands::artifact::ArtifactCommand,
    },
    /// Inspect and fill the content store
    Store {
        #[command(subcommand)]
        command: commands::store::StoreCommand,
    },
    /// Query or run Hellas chain components
    #[cfg(feature = "chain")]
    Chain {
        #[command(subcommand)]
        command: commands::chain::ChainCommand,
    },
    #[cfg(feature = "llm")]
    /// Run token-native Catena inference remotely, or locally when built with `evaluate`
    Llm {
        /// Node ID to run on remotely (omit to auto-discover)
        node_id: Option<EndpointId>,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',', requires = "node_id")]
        node_addrs: Vec<SocketAddr>,
        /// Catena package alias sent to the executor. Use NAME with an exact
        /// --package-id for remote execution, or NAME=PATH when `--local` or
        /// `--verify-local` materializes and identifies it on this machine.
        #[cfg_attr(
            feature = "evaluate",
            arg(long = "package", value_name = "NAME[=PATH]")
        )]
        #[cfg_attr(
            not(feature = "evaluate"),
            arg(
                long = "package",
                value_name = "NAME",
                help = "Peer-local package alias used only for routing; --package-id supplies the trusted identity"
            )
        )]
        package: commands::package::PackageArg,
        /// Exact Catena execution-package ID expected from a remote executor.
        /// Omit for local and verify-local runs, which derive it from the
        /// locally verified package.
        #[cfg_attr(
            feature = "evaluate",
            arg(
                long = "package-id",
                value_name = "64_HEX",
                required_unless_present_any = ["local", "verify_local"],
                conflicts_with_all = ["local", "verify_local"]
            )
        )]
        #[cfg_attr(
            not(feature = "evaluate"),
            arg(
                long = "package-id",
                value_name = "64_HEX",
                required = true,
                help = "Exact Catena execution-package ID expected from the remote node"
            )
        )]
        package_id: Option<hellas_rpc::ExecutionPackageId>,
        /// Directory for locally materialized Catena package objects
        /// (default: $HOME/.hellas/packages).
        #[cfg(feature = "evaluate")]
        #[arg(long = "package-cache")]
        package_cache: Option<PathBuf>,
        /// Tokenizer JSON used only for local text presentation. It is not
        /// part of the Hellas execution guarantee.
        #[arg(long = "tokenizer", value_name = "PATH")]
        tokenizer: PathBuf,
        /// Caller-selected stop token ID. Repeat or comma-separate. No stop
        /// tokens are inferred from the tokenizer or Catena package.
        #[arg(long = "stop-token", value_delimiter = ',')]
        stop_token_ids: Vec<u32>,
        /// Prompt to send (required)
        #[arg(short = 'p', long = "prompt")]
        prompt: String,
        /// Allow the provider to retain prompt- and token-bearing artifacts.
        #[arg(long = "retain", default_value_t = true, action = clap::ArgAction::Set)]
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
    },
    #[cfg(feature = "evaluate")]
    /// Inspect owner-selected Catena execution packages
    Package {
        #[command(subcommand)]
        command: commands::package::PackageCommand,
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
        #[arg(long = "execution-environment")]
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
        command => command,
    };

    #[cfg(feature = "evaluate")]
    let command = match command {
        Commands::Package { command } => {
            let result = commands::package::run(command).await;
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
    if matches!(&command, Commands::Serve { .. })
        && let Err(error) = validate_serve_assurance(
            cli.software_root,
            assurance,
            Some(local_identity.genesis.statement.root_kind),
        )
    {
        eprintln!("error: {error}");
        std::process::exit(1);
    }

    let result = match command {
        #[cfg(feature = "node")]
        Commands::Serve {
            port,
            execute_policy,
            queue_size,
            #[cfg(feature = "evaluate")]
            packages,
            #[cfg(feature = "evaluate")]
            package_cache,
            artifact_store_path,
            work_config_file,
            metrics_port,
            graffiti,
            fetch_config_file,
            fetch_max_in_flight,
            fetch_queue_size,
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
                    // The key every settlement this node signs is signed
                    // with, taken from the identity loaded above and
                    // never made here.
                    let settlement_key = identity::settlement_signer(&local_identity);
                    commands::serve::run(commands::serve::ServeOptions {
                        port,
                        execute_policy,
                        queue_size,
                        #[cfg(feature = "evaluate")]
                        packages,
                        #[cfg(feature = "evaluate")]
                        package_cache,
                        artifact_store_path,
                        work_config,
                        metrics_port,
                        graffiti,
                        fetch_config_file,
                        fetch_max_in_flight,
                        fetch_queue_size,
                        secret_key,
                        producer_key: local_identity.producer_key,
                        settlement_key,
                        provider_genesis: local_identity.enrollment.canonical_bytes(),
                        assurance,
                    })
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
            package,
            package_id,
            #[cfg(feature = "evaluate")]
            package_cache,
            tokenizer,
            stop_token_ids,
            metrics_port,
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
                let package_name = package.name().to_string();
                #[cfg(feature = "evaluate")]
                let local_package = if local || verify_local {
                    let package_cache = package_cache
                        .map(Ok)
                        .unwrap_or_else(identity::default_package_cache_path)?;
                    Some(package.into_source(&package_cache)?)
                } else {
                    package.require_remote_alias().map_err(anyhow::Error::msg)?;
                    if package_cache.is_some() {
                        anyhow::bail!(
                            "--package-cache is only used with --local or --verify-local"
                        );
                    }
                    None
                };
                #[cfg(not(feature = "evaluate"))]
                package.require_remote_alias().map_err(anyhow::Error::msg)?;
                #[cfg(not(feature = "evaluate"))]
                let local = false;
                let provider_trust = gateway_provider_trust(
                    local,
                    responses_backend,
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
                    package_name,
                    execution_package: package_id,
                    #[cfg(feature = "evaluate")]
                    local_package,
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
        Commands::Chain { .. } => unreachable!("chain commands handled before identity load"),
        Commands::Store { .. } => unreachable!("store commands handled before identity load"),
        #[cfg(feature = "evaluate")]
        Commands::Package { .. } => {
            unreachable!("package commands handled before identity load")
        }
        #[cfg(feature = "llm")]
        Commands::Llm {
            node_id,
            node_addrs,
            package,
            package_id,
            #[cfg(feature = "evaluate")]
            package_cache,
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
        } => {
            async {
                let package_name = package.name().to_string();
                #[cfg(feature = "evaluate")]
                let local_package = if local || verify_local {
                    let package_cache = package_cache
                        .map(Ok)
                        .unwrap_or_else(identity::default_package_cache_path)?;
                    Some(package.into_source(&package_cache)?)
                } else {
                    package.require_remote_alias().map_err(anyhow::Error::msg)?;
                    if package_cache.is_some() {
                        anyhow::bail!(
                            "--package-cache is only used with --local or --verify-local"
                        );
                    }
                    None
                };
                #[cfg(not(feature = "evaluate"))]
                package.require_remote_alias().map_err(anyhow::Error::msg)?;
                commands::llm::run(
                    commands::llm::ExecuteOptions {
                        node_id,
                        node_addrs,
                        package_name,
                        execution_package: package_id,
                        #[cfg(feature = "evaluate")]
                        local_package,
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
                        expected_provider_genesis,
                        apple_app_attest_app_id: apple_app_attest_app_id.clone(),
                        apple_app_attest_cdhashes: apple_app_attest_cdhashes.clone(),
                        assurance,
                    },
                    secret_key,
                )
                .await
            }
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
            IdentityCommand::Init => Ok(()),
            IdentityCommand::ShowNodeId => commands::identity::show_node_id(&secret_key),
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
    const TEST_PACKAGE: &str = "smollm2-135m";
    #[cfg(feature = "llm")]
    const TEST_PACKAGE_ID: &str =
        "0808080808080808080808080808080808080808080808080808080808080808";
    #[cfg(feature = "evaluate")]
    const TEST_LOCAL_PACKAGE: &str = "smollm2-135m=/path/to/catena-package";
    #[cfg(feature = "llm")]
    const TEST_TOKENIZER: &str = "/path/to/tokenizer.json";

    #[cfg(feature = "llm")]
    fn parse_llm(args: &[&str]) -> Result<Cli, clap::Error> {
        parse_llm_with_package(TEST_PACKAGE, args)
    }

    #[cfg(feature = "llm")]
    fn parse_llm_with_package(package: &str, args: &[&str]) -> Result<Cli, clap::Error> {
        #[cfg(feature = "evaluate")]
        let local = args.contains(&"--local") || args.contains(&"--verify-local");
        #[cfg(not(feature = "evaluate"))]
        let local = false;
        let package_id: &[&str] = if local {
            &[]
        } else {
            &["--package-id", TEST_PACKAGE_ID]
        };
        Cli::try_parse_from(
            [
                "hellas",
                "llm",
                "--package",
                package,
                "--tokenizer",
                TEST_TOKENIZER,
            ]
            .into_iter()
            .chain(package_id.iter().copied())
            .chain(args.iter().copied()),
        )
    }

    #[cfg(feature = "gateway")]
    fn parse_gateway(args: &[&str]) -> Result<Cli, clap::Error> {
        parse_gateway_with_package(TEST_PACKAGE, args)
    }

    #[cfg(feature = "gateway")]
    fn parse_gateway_with_package(package: &str, args: &[&str]) -> Result<Cli, clap::Error> {
        #[cfg(feature = "evaluate")]
        let local = args.contains(&"--local") || args.contains(&"--verify-local");
        #[cfg(not(feature = "evaluate"))]
        let local = false;
        let package_id: &[&str] = if local {
            &[]
        } else {
            &["--package-id", TEST_PACKAGE_ID]
        };
        Cli::try_parse_from(
            [
                "hellas",
                "gateway",
                "--package",
                package,
                "--tokenizer",
                TEST_TOKENIZER,
            ]
            .into_iter()
            .chain(package_id.iter().copied())
            .chain(args.iter().copied()),
        )
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

    #[cfg(feature = "evaluate")]
    #[test]
    fn llm_accepts_local_mode() {
        let cli = parse_llm_with_package(TEST_LOCAL_PACKAGE, &["--local", "-p", "hello"]).unwrap();
        match cli.command {
            Commands::Llm {
                node_id,
                node_addrs,
                local,
                verify_local,
                package,
                tokenizer,
                stop_token_ids,
                ..
            } => {
                assert!(node_id.is_none());
                assert!(node_addrs.is_empty());
                assert!(local);
                assert!(!verify_local);
                assert_eq!(package.name(), "smollm2-135m");
                assert_eq!(
                    package.package_dir(),
                    Some(Path::new("/path/to/catena-package"))
                );
                assert_eq!(tokenizer, PathBuf::from(TEST_TOKENIZER));
                assert!(stop_token_ids.is_empty());
            }
            _ => panic!("expected llm command"),
        }
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn package_id_accepts_an_owner_selected_manifest() {
        let cli = Cli::try_parse_from(["hellas", "package", "id", "--package", TEST_LOCAL_PACKAGE])
            .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Package {
                command: commands::package::PackageCommand::Id { .. },
            }
        ));
    }

    #[cfg(feature = "llm")]
    #[test]
    fn llm_requires_explicit_package_and_tokenizer() {
        assert!(Cli::try_parse_from(["hellas", "llm", "-p", "hello"]).is_err());
        assert!(
            Cli::try_parse_from(["hellas", "llm", "--package", TEST_PACKAGE, "-p", "hello",])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "hellas",
                "llm",
                "--package",
                TEST_PACKAGE,
                "--tokenizer",
                TEST_TOKENIZER,
                "-p",
                "hello",
            ])
            .is_err(),
            "a remote alias without an exact package pin must be rejected"
        );
    }

    #[cfg(feature = "gateway")]
    #[test]
    fn gateway_requires_explicit_package_and_tokenizer() {
        assert!(Cli::try_parse_from(["hellas", "gateway"]).is_err());
        assert!(Cli::try_parse_from(["hellas", "gateway", "--package", TEST_PACKAGE]).is_err());
        assert!(
            Cli::try_parse_from([
                "hellas",
                "gateway",
                "--package",
                TEST_PACKAGE,
                "--tokenizer",
                TEST_TOKENIZER,
            ])
            .is_err(),
            "a remote gateway alias without an exact package pin must be rejected"
        );
    }

    #[cfg(feature = "llm")]
    #[test]
    fn llm_retention_defaults_on_and_can_be_disabled() {
        let default = parse_llm(&["-p", "hello"]).unwrap();
        assert!(matches!(
            default.command,
            Commands::Llm { retain: true, .. }
        ));

        let disabled = parse_llm(&["--retain=false", "-p", "hello"]).unwrap();
        assert!(matches!(
            disabled.command,
            Commands::Llm { retain: false, .. }
        ));
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn llm_rejects_local_with_node_id() {
        let result = parse_llm_with_package(
            TEST_LOCAL_PACKAGE,
            &[
                "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
                "--local",
                "-p",
                "hello",
            ],
        );

        assert!(result.is_err());
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn llm_rejects_conflicting_local_modes() {
        let result = parse_llm_with_package(
            TEST_LOCAL_PACKAGE,
            &["--local", "--verify-local", "-p", "hello"],
        );

        assert!(result.is_err());
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn gateway_local_modes_derive_the_package_id() {
        let cli = parse_gateway_with_package(TEST_LOCAL_PACKAGE, &["--local"]).unwrap();
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

        for mode in ["--local", "--verify-local"] {
            assert!(
                parse_gateway_with_package(
                    TEST_LOCAL_PACKAGE,
                    &[mode, "--package-id", TEST_PACKAGE_ID],
                )
                .is_err(),
                "{mode} must conflict with an explicit --package-id",
            );
        }
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn gateway_rejects_local_with_node_id() {
        let result = parse_gateway_with_package(
            TEST_LOCAL_PACKAGE,
            &[
                "--local",
                "--node-id",
                "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
            ],
        );

        assert!(result.is_err());
    }

    /// The anchor `hellas gateway <args>` would run with.
    #[cfg(feature = "gateway")]
    fn gateway_trust(args: &[&str]) -> anyhow::Result<Option<hellas_client::ProviderTrustAnchor>> {
        let cli = parse_gateway(args).expect("valid gateway arguments");
        let Commands::Gateway {
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
            cli.provider_genesis,
            cli.assurance,
            cli.apple_app_attest_app_id,
            cli.apple_app_attest_cdhashes,
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
            "--provider",
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
                stop_token_ids,
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
        match cli.command {
            Commands::Gateway { stop_token_ids, .. } => {
                assert_eq!(stop_token_ids, vec![1, 2, 3]);
            }
            _ => panic!("expected gateway command"),
        }
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
    fn gateway_accepts_responses_fetch_backend() {
        let cli = parse_gateway(&[
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
}
