use crate::commands::CliResult;
use anyhow::{Context, bail};
#[cfg(feature = "evaluate")]
use commonware_runtime::Runner as _;
#[cfg(feature = "evaluate")]
use hellas_executor::ArtifactStoreConfig;
#[cfg(feature = "evaluate")]
use hellas_executor::GpuConfig;
use hellas_executor::{
    CallerAccess, ExecutorMetrics, FetchAccessPolicy, FetchRoute, FetchRouteEntry, FetchRouteGrant,
    FetchRoutePolicy, FetchRouteRegistry, RequestRateLimit, SpendLimit,
};
use hellas_kernel::Secp256k1Signer;
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::{Assurance, FetchEnvironment, ProducerId, ProducerSigningKey};
use iroh::SecretKey;
use serde::Deserialize;
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::time::{Duration, timeout};
use tracing::warn;

mod codex_provider;
mod codex_responses;
mod node;
mod node_handler;
mod openai_provider;
pub mod probe;
pub mod provision;
mod responses_fetch;
mod responses_projector;
pub mod work_config;

pub use probe::{ProbeOptions, run_probe};
pub use provision::{ProvisionOptions, run_provision};
pub use work_config::{WorkConfig, load_work_config};

pub struct ServeOptions {
    pub port: Option<u16>,
    pub execute_policy: ExecutePolicy,
    pub queue_size: usize,
    #[cfg(feature = "evaluate")]
    pub content_paths: Vec<PathBuf>,
    #[cfg(feature = "evaluate")]
    pub content_roots: Vec<PathBuf>,
    #[cfg(feature = "evaluate")]
    pub content_index: Option<PathBuf>,
    #[cfg(feature = "evaluate")]
    pub gpu_config: GpuConfig,
    #[cfg(feature = "evaluate")]
    pub evaluate_retained_execution_capacity: usize,
    pub artifact_store_path: Option<PathBuf>,
    /// The loaded paid-work configuration, not the path it came from.
    /// Its presence is still what serves the two work ALPNs; what is new
    /// is that the node holds the chain cross-check, the validator
    /// fan-out, the journal root, and the policies it would mount a
    /// channel with.
    pub work_config: Option<WorkConfig>,
    pub metrics_port: Option<u16>,
    pub graffiti: String,
    pub fetch_config_file: Option<PathBuf>,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_size: usize,
    pub fetch_retained_transcript_capacity: usize,
    pub fetch_replay_max_in_flight: usize,
    pub secret_key: SecretKey,
    pub producer_key: ProducerSigningKey,
    /// The settlement key both paid endpoints are built over, read from
    /// the stored identity before this node binds anything.
    ///
    /// A `SetupEndpoint` and a `CloseEndpoint` each take one of these
    /// and a journal, and neither the transport key nor the producer key
    /// above is one — so without it a node that had loaded its whole
    /// paid-work configuration still had nothing to sign a settlement
    /// with.
    pub settlement_key: Secp256k1Signer,
    pub provider_genesis: Vec<u8>,
    pub open_identity: Arc<crate::identity::OpenIdentity>,
    pub assurance: Assurance,
}

pub async fn run(options: ServeOptions) -> CliResult<()> {
    let artifact_store_path = options
        .artifact_store_path
        .clone()
        .map(Ok)
        .unwrap_or_else(crate::identity::default_artifact_store_path)?;
    #[cfg(feature = "evaluate")]
    {
        let storage_path = artifact_store_path.join("evaluate");
        // Claim and narrow the configured root before either the content index
        // or Commonware's Evaluate child is opened. The retained descriptor
        // coordinates cooperating runtimes that resolve the same stable path;
        // its ancestors remain an operator-trusted boundary.
        let artifact_store_root = ArtifactStoreConfig::lock_root(
            &artifact_store_path,
            options.evaluate_retained_execution_capacity,
        )
        .map_err(anyhow::Error::msg)?;
        // Not needless, whatever clippy sees: the `#[cfg(not(evaluate))]`
        // call below is the other arm, and without this `return` the
        // block's value becomes the function's under one cfg and not the
        // other. Clippy cannot see across the cfg split.
        #[expect(
            clippy::needless_return,
            reason = "the cfg-gated arm below is the alternative"
        )]
        return tokio::task::spawn_blocking(move || {
            commonware_runtime::tokio::Runner::new(
                commonware_runtime::tokio::Config::new().with_storage_directory(storage_path),
            )
            .start(move |context| {
                run_with_store(
                    options,
                    artifact_store_path,
                    ArtifactStoreConfig::new(context).with_locked_root(artifact_store_root),
                )
            })
        })
        .await
        .context("artifact storage runtime failed")?;
    }
    #[cfg(not(feature = "evaluate"))]
    run_with_store(options, artifact_store_path).await
}

async fn run_with_store(
    options: ServeOptions,
    artifact_store_path: PathBuf,
    #[cfg(feature = "evaluate")] artifact_store: ArtifactStoreConfig,
) -> CliResult<()> {
    #[cfg(feature = "evaluate")]
    let content_index = options
        .content_index
        .clone()
        .unwrap_or_else(|| artifact_store_path.join("content-index.bin"));
    #[cfg(feature = "evaluate")]
    let content_store = crate::commands::environment::index_content(
        &options.content_paths,
        &options.content_roots,
        &content_index,
    )?;

    // What the operator configured, said back once, and then which of
    // §4's four evidence cases this node started in, in words. The
    // second line is the one that matters: §4 disables setup and new
    // work on missing, changed or `assumed` evidence and never disables
    // recovery, so a node that admits no paid work still serves its
    // journals and still answers a contest. That is why an artifact that
    // is absent or is not the pinned one is a warning here and not a
    // startup refusal.
    let mut work_runner = None;
    if let Some(work) = options.work_config.as_ref() {
        // A configured route is a promise about durable state, so verify all
        // of them before the endpoint binds or advertises WorkSetup. This is
        // intentionally later than parsing: provisioning shares the parser
        // and is the command that may create the journal named here.
        work_config::validate_work_routes(work)?;
        info!(
            network = %work.chain.network,
            validators = work.validators.len(),
            journal_root = %work.journal_root.display(),
            routes = work.routes.len(),
            poll_ms = work.poll.as_millis(),
            response_alarm_margin_blocks = work.response_alarm_margin_blocks,
            // Said back because it is the party the chain will see: an
            // operator who funded a different one has configured a node
            // that can settle nothing, and this is where they find out.
            settlement_party = %hex::encode(options.settlement_key.party_key().to_bytes()),
            "loaded the paid-work configuration",
        );
        let duties = work_config::load_paid_work_duties(work)?;
        if duties.admits_paid_work() {
            info!("{}", duties.summary());
        } else {
            warn!("{}", duties.summary());
        }
        // The whole of what the clock is built from, decided here and
        // carried there. The admission in particular is §4's answer and
        // not a flag the runner re-derives.
        work_runner = Some(node::WorkRunnerConfig {
            network: work.chain.network,
            threshold_identity: work.chain.threshold_identity.clone(),
            journal_root: work.journal_root.clone(),
            routes: work.routes.clone(),
            validators: work.validators.clone(),
            poll: work.poll,
            settlement_key: options.settlement_key.clone(),
            admission: duties.payment_admission(),
        });
    }

    let build = option_env!("GIT_REV").unwrap_or("unknown").to_string();
    let graffiti = {
        let mut buf = [0u8; 16];
        let src = options.graffiti.as_bytes();
        let len = src.len().min(16);
        buf[..len].copy_from_slice(&src[..len]);
        buf.to_vec()
    };
    let (fetch_routes, fetch_access_policy) = match options.fetch_config_file.as_deref() {
        // The config file is the single source of fetch truth: routes,
        // capabilities, and caller access, cross-validated at load. No file
        // means this node serves no fetch routes and admits no fetch callers.
        Some(path) => load_fetch_config(path)?,
        None => (FetchRouteRegistry::default(), FetchAccessPolicy::new([])),
    };
    // Counters live in the executor and are mutated inline; cloning the
    // counter handles into a registry just adds a scrape view on the same
    // underlying state.
    let metrics = Arc::new(ExecutorMetrics::default());
    let node = node::spawn_node(node::NodeConfig {
        port: options.port,
        execute_policy: options.execute_policy.clone(),
        queue_size: options.queue_size,
        #[cfg(feature = "evaluate")]
        content_store,
        #[cfg(feature = "evaluate")]
        gpu_config: options.gpu_config,
        build,
        graffiti,
        fetch_access_policy,
        artifact_store_path,
        fetch_routes,
        fetch_max_in_flight: options.fetch_max_in_flight,
        fetch_queue_size: options.fetch_queue_size,
        fetch_retained_transcript_capacity: options.fetch_retained_transcript_capacity,
        fetch_replay_max_in_flight: options.fetch_replay_max_in_flight,
        work: work_runner,
        secret_key: options.secret_key,
        producer_key: options.producer_key,
        provider_genesis: options.provider_genesis,
        open_identity: options.open_identity,
        assurance: options.assurance,
        metrics: metrics.clone(),
        #[cfg(feature = "evaluate")]
        artifact_store,
    })
    .await
    .context("failed to start node server")?;

    if let Some(metrics_port) = options.metrics_port {
        let mut registry = prometheus_client::registry::Registry::default();
        metrics.register_with(&mut registry);
        let bundle = crate::metrics::MetricsBundle::new(Arc::new(registry));
        #[cfg(feature = "otel")]
        let bundle = bundle.with_iroh(node.iroh_metrics());
        crate::metrics::spawn_metrics_server(metrics_port, bundle);
    }

    let node_id = node.node_id();
    let add_url = format!("https://explorer.hellas.ai/executors/add/{node_id}");

    eprintln!("Node ID:      {node_id}");
    print_qr(&add_url);
    eprintln!("Explorer:     {add_url}");

    println!("RPC server running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for shutdown signal")?;

    println!("Shutting down...");
    match timeout(Duration::from_secs(5), node.shutdown()).await {
        Ok(result) => result.context("failed to shut down RPC server")?,
        Err(_) => {
            warn!("graceful shutdown timed out; forcing shutdown");
            // At this point, drop will signal shutdown; exit to avoid hanging
            std::process::exit(0);
        }
    }

    Ok(())
}

/// Load the unified fetch configuration: the route table (sealed destinations,
/// credentials, capabilities) and the caller access policy, cross-validated so
/// a caller grant naming an undefined route is a load error rather than a
/// silent dead entry.
fn load_fetch_config(path: &std::path::Path) -> CliResult<(FetchRouteRegistry, FetchAccessPolicy)> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let file: FetchConfigFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let mut registry = FetchRouteRegistry::new();
    for route in file.routes {
        if route.service.trim().is_empty() || route.method.trim().is_empty() {
            bail!("fetch config route service and method must be non-empty");
        }
        let entry = route
            .destination
            .into_entry(route.capabilities.into_policy()?)?;
        info!(
            service = %route.service,
            method = %route.method,
            execution_environment = %entry.execution_environment(),
            "loaded sealed Fetch route",
        );
        registry
            .register(FetchRoute::new(route.service, route.method), entry)
            .map_err(|err| anyhow::anyhow!("invalid fetch config: {err}"))?;
    }

    let mut caller_ids = HashSet::new();
    let mut callers = Vec::with_capacity(file.callers.len());
    for caller in file.callers {
        let caller = caller.into_access()?;
        let caller_id = ProducerId::from_public_key(&caller.public_key);
        if !caller_ids.insert(caller_id) {
            bail!("fetch config defines the same caller public_key more than once");
        }
        callers.push(caller);
    }
    for caller in &callers {
        if let hellas_executor::RouteSet::Explicit(routes) = &caller.routes {
            for route in routes.keys() {
                if registry.entry(route).is_none() {
                    bail!(
                        "fetch config grants caller access to undefined route {}/{}",
                        route.service,
                        route.method
                    );
                }
            }
        }
    }
    Ok((registry, FetchAccessPolicy::new(callers)))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchConfigFile {
    #[serde(default)]
    routes: Vec<FetchConfigRoute>,
    #[serde(default)]
    callers: Vec<FetchPolicyCaller>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchConfigRoute {
    service: String,
    method: String,
    /// One sealed, compiled destination plus provider-local credentials. This
    /// one selection constructs both the HTTP driver and the projector whose
    /// manifest is quoted; a URL or separate identity cannot be supplied.
    destination: FetchDestination,
    #[serde(default)]
    capabilities: FetchPolicyLimits,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum FetchDestination {
    /// Official Codex Responses, authenticated by the local Codex OAuth store.
    CodexResponses {
        #[serde(default)]
        auth_path: Option<PathBuf>,
    },
    /// Official OpenAI Responses, authenticated by an API key held in a local
    /// environment variable.
    OpenaiResponses {
        #[serde(default = "default_openai_api_key_env")]
        api_key_env: String,
    },
}

fn default_openai_api_key_env() -> String {
    "OPENAI_API_KEY".to_string()
}

impl FetchDestination {
    fn into_entry(self, capabilities: FetchRoutePolicy) -> CliResult<FetchRouteEntry> {
        let (environment, provider): (FetchEnvironment, Arc<dyn hellas_executor::FetchProvider>) =
            match self {
                Self::CodexResponses { auth_path } => (
                    FetchEnvironment::CodexResponses,
                    Arc::new(codex_provider::CodexResponsesFetchProvider::new(
                        auth_path.as_deref(),
                    )?),
                ),
                Self::OpenaiResponses { api_key_env } => (
                    FetchEnvironment::OpenAiResponses,
                    Arc::new(openai_provider::OpenAiResponsesFetchProvider::new(
                        &api_key_env,
                    )?),
                ),
            };
        let adaptor_factory = Arc::new(responses_projector::ResponsesFetchAdaptorFactory::new(
            environment,
        ));
        Ok(FetchRouteEntry::new(
            provider,
            adaptor_factory,
            capabilities,
        )?)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchPolicyCaller {
    public_key: String,
    routes: Vec<FetchPolicyRoute>,
    #[serde(default)]
    request_rate: Option<FetchPolicyRate>,
    #[serde(default)]
    spend: Option<FetchPolicySpend>,
}

impl FetchPolicyCaller {
    fn into_access(self) -> CliResult<CallerAccess> {
        let public_key = crate::parse_public_key_hex(&self.public_key)
            .map_err(|err| anyhow::anyhow!("invalid fetch policy public_key: {err}"))?;
        let mut seen_routes = HashSet::new();
        let mut routes = Vec::with_capacity(self.routes.len());
        for route in self.routes {
            let grant = route.into_grant()?;
            if !seen_routes.insert(grant.route.clone()) {
                bail!(
                    "fetch config grants caller duplicate route {}/{}",
                    grant.route.service,
                    grant.route.method
                );
            }
            routes.push(grant);
        }
        let mut access = CallerAccess::explicit(public_key, routes);
        access.request_rate = self
            .request_rate
            .map(FetchPolicyRate::into_limit)
            .transpose()?;
        access.spend = self.spend.map(FetchPolicySpend::into_limit).transpose()?;
        Ok(access)
    }
}

/// Model/output limits — the same shape serves as a route-wide capability
/// (on `routes`) and as a per-caller grant (on `callers`); admission
/// validates against their intersection.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchPolicyLimits {
    #[serde(default)]
    models: Vec<String>,
    #[serde(default, alias = "max_output_units")]
    max_output_tokens: Option<u64>,
}

impl FetchPolicyLimits {
    fn into_policy(self) -> CliResult<FetchRoutePolicy> {
        let allowed_models = if self.models.is_empty() {
            None
        } else {
            let mut models = BTreeSet::new();
            for model in self.models {
                let model = model.trim();
                if model.is_empty() {
                    bail!("fetch config model names must be non-empty");
                }
                models.insert(model.to_string());
            }
            Some(models)
        };
        Ok(FetchRoutePolicy {
            allowed_models,
            max_output_units: self.max_output_tokens,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchPolicyRoute {
    service: String,
    method: String,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default, alias = "max_output_units")]
    max_output_tokens: Option<u64>,
}

impl FetchPolicyRoute {
    fn into_grant(self) -> CliResult<FetchRouteGrant> {
        if self.service.trim().is_empty() || self.method.trim().is_empty() {
            bail!("fetch config route service and method must be non-empty");
        }
        Ok(FetchRouteGrant {
            route: FetchRoute::new(self.service, self.method),
            policy: FetchPolicyLimits {
                models: self.models,
                max_output_tokens: self.max_output_tokens,
            }
            .into_policy()?,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchPolicyRate {
    capacity: f64,
    refill_per_sec: f64,
}

impl FetchPolicyRate {
    fn into_limit(self) -> CliResult<RequestRateLimit> {
        if !self.capacity.is_finite() || self.capacity <= 0.0 {
            bail!("fetch policy request_rate.capacity must be finite and greater than zero");
        }
        if !self.refill_per_sec.is_finite() || self.refill_per_sec < 0.0 {
            bail!("fetch policy request_rate.refill_per_sec must be finite and non-negative");
        }
        Ok(RequestRateLimit {
            capacity: self.capacity,
            refill_per_sec: self.refill_per_sec,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchPolicySpend {
    max_units: u64,
    window_seconds: u64,
}

impl FetchPolicySpend {
    fn into_limit(self) -> CliResult<SpendLimit> {
        if self.max_units == 0 {
            bail!("fetch policy spend.max_units must be greater than zero");
        }
        if self.window_seconds == 0 {
            bail!("fetch policy spend.window_seconds must be greater than zero");
        }
        Ok(SpendLimit {
            max_units: self.max_units,
            window: Duration::from_secs(self.window_seconds),
        })
    }
}

/// Print a QR code to stderr using Unicode half-block characters.
fn print_qr(data: &str) {
    use qrcode::QrCode;
    let Ok(code) = QrCode::new(data.as_bytes()) else {
        return;
    };
    let width = code.width();
    let modules = code.into_colors();
    // Two rows per character using upper/lower half blocks.
    // ██ = both dark, ▀ = top dark, ▄ = bottom dark, ' ' = both light.
    for y in (0..width).step_by(2) {
        eprint!("  ");
        for x in 0..width {
            let top = modules[y * width + x] == qrcode::Color::Dark;
            let bottom = if y + 1 < width {
                modules[(y + 1) * width + x] == qrcode::Color::Dark
            } else {
                false
            };
            eprint!(
                "{}",
                match (top, bottom) {
                    (true, true) => "█",
                    (true, false) => "▀",
                    (false, true) => "▄",
                    (false, false) => " ",
                }
            );
        }
        eprintln!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_executor::{FetchAccessError, FetchRequestView};
    use hellas_rpc::{Digest, FetchEnvironment, InputCommitment, ProducerSigningKey};

    fn public_key_hex(byte: u8) -> String {
        let key = ProducerSigningKey::from_secret_bytes([byte; 32])
            .unwrap()
            .public_key();
        key.bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn write_config(dir: &tempfile::TempDir, config: serde_json::Value) -> PathBuf {
        let path = dir.path().join("fetch-config.json");
        fs::write(&path, config.to_string()).unwrap();
        path
    }

    fn codex_route(capabilities: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "service": "codex",
            "method": "responses",
            // Keep this fixture independent of the process-global HOME.
            "destination": {
                "type": "codex-responses",
                "auth_path": "target/hellas-test-codex-auth.json"
            },
            "capabilities": capabilities,
        })
    }

    fn authenticated_codex_route(
        dir: &tempfile::TempDir,
        capabilities: serde_json::Value,
    ) -> serde_json::Value {
        let auth_path = dir.path().join("codex-auth.json");
        let auth = crate::commands::codex_auth::CodexAuthStore::new(Some(&auth_path)).unwrap();
        auth.save(&crate::commands::codex_auth::CodexAuthState::new(
            crate::commands::codex_auth::test_tokens_with_account_id(
                "test-access",
                "test-refresh",
                "test-account",
            ),
            None,
        ))
        .unwrap();
        let mut route = codex_route(capabilities);
        route["destination"]["auth_path"] = serde_json::json!(auth_path);
        route
    }

    #[test]
    fn load_fetch_config_parses_routes_limits_and_quotas() {
        let dir = tempfile::tempdir().unwrap();
        let public_key = public_key_hex(1);
        let path = write_config(
            &dir,
            serde_json::json!({
                "routes": [authenticated_codex_route(&dir, serde_json::json!({}))],
                "callers": [{
                    "public_key": public_key,
                    "routes": [{
                        "service": "codex",
                        "method": "responses",
                        "models": ["gpt-5.5-codex"],
                        "max_output_tokens": 32
                    }],
                    "request_rate": { "capacity": 2.0, "refill_per_sec": 1.0 },
                    "spend": { "max_units": 64, "window_seconds": 60 }
                }]
            }),
        );
        let caller = ProducerSigningKey::from_secret_bytes([1; 32])
            .unwrap()
            .public_key();
        let (registry, mut policy) = load_fetch_config(&path).unwrap();

        let route = FetchRoute::new("codex", "responses");
        let entry = registry.entry(&route).unwrap();
        assert_eq!(
            entry.execution_environment(),
            FetchEnvironment::CodexResponses.manifest_id()
        );
        let capabilities = entry.capabilities.clone();
        policy
            .authorize_admission(
                &caller,
                &FetchRequestView {
                    service: "codex".to_string(),
                    method: "responses".to_string(),
                    model: Some("gpt-5.5-codex".to_string()),
                    max_output_units: Some(32),
                },
                1_000,
                "r1".to_string(),
                InputCommitment::from_digest(Digest::from_bytes([1; 32])),
                &capabilities,
            )
            .unwrap();
        let denied = policy
            .authorize_admission(
                &caller,
                &FetchRequestView {
                    service: "codex".to_string(),
                    method: "responses".to_string(),
                    model: Some("other".to_string()),
                    max_output_units: Some(1),
                },
                1_000,
                "r2".to_string(),
                InputCommitment::from_digest(Digest::from_bytes([2; 32])),
                &capabilities,
            )
            .unwrap_err();
        assert!(matches!(denied, FetchAccessError::Denied(_)));
    }

    #[test]
    fn load_fetch_config_parses_route_capabilities() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            &dir,
            serde_json::json!({
                "routes": [authenticated_codex_route(&dir, serde_json::json!({
                    "models": ["gpt-5.5-codex"],
                    "max_output_tokens": 4096
                }))],
            }),
        );

        let (registry, _) = load_fetch_config(&path).unwrap();

        let capabilities = &registry
            .entry(&FetchRoute::new("codex", "responses"))
            .unwrap()
            .capabilities;
        assert_eq!(capabilities.max_output_units, Some(4096));
        assert!(
            capabilities
                .allowed_models
                .as_ref()
                .unwrap()
                .contains("gpt-5.5-codex")
        );
    }

    #[test]
    fn load_fetch_config_rejects_grant_for_undefined_route() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            &dir,
            serde_json::json!({
                "routes": [authenticated_codex_route(&dir, serde_json::json!({}))],
                "callers": [{
                    "public_key": public_key_hex(1),
                    "routes": [{ "service": "openai", "method": "responses" }]
                }]
            }),
        );

        let err = load_fetch_config(&path).unwrap_err();

        assert!(err.to_string().contains("undefined route openai/responses"));
    }

    #[test]
    fn load_fetch_config_rejects_duplicate_route() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            &dir,
            serde_json::json!({
                "routes": [
                    authenticated_codex_route(&dir, serde_json::json!({})),
                    authenticated_codex_route(&dir, serde_json::json!({})),
                ],
            }),
        );

        let err = load_fetch_config(&path).unwrap_err();

        assert!(err.to_string().contains("registered twice"));
    }

    #[test]
    fn load_fetch_config_rejects_duplicate_callers_and_caller_routes() {
        let dir = tempfile::tempdir().unwrap();
        let caller = serde_json::json!({
            "public_key": public_key_hex(1),
            "routes": [{ "service": "codex", "method": "responses" }]
        });
        let duplicate_callers = write_config(
            &dir,
            serde_json::json!({
                "routes": [authenticated_codex_route(&dir, serde_json::json!({}))],
                "callers": [caller.clone(), caller]
            }),
        );
        let error = load_fetch_config(&duplicate_callers).unwrap_err();
        assert!(error.to_string().contains("more than once"), "{error:#}");

        let duplicate_routes = write_config(
            &dir,
            serde_json::json!({
                "routes": [authenticated_codex_route(&dir, serde_json::json!({}))],
                "callers": [{
                    "public_key": public_key_hex(1),
                    "routes": [
                        { "service": "codex", "method": "responses" },
                        { "service": "codex", "method": "responses" }
                    ]
                }]
            }),
        );
        let error = load_fetch_config(&duplicate_routes).unwrap_err();
        assert!(error.to_string().contains("duplicate route"), "{error:#}");
    }

    #[test]
    fn load_fetch_config_rejects_operator_claimed_trusted_identity() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = codex_route(serde_json::json!({}));
        route["adaptor"] = serde_json::json!("codex-0.0.1");
        let path = write_config(&dir, serde_json::json!({ "routes": [route] }));
        let err = load_fetch_config(&path).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field `adaptor`"));

        let mut route = codex_route(serde_json::json!({}));
        route["environment"] = serde_json::json!({
            "program": "01",
            "config": "02",
            "build": "03"
        });
        let path = write_config(&dir, serde_json::json!({ "routes": [route] }));
        let err = load_fetch_config(&path).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field `environment`"));
    }

    #[test]
    fn load_fetch_config_rejects_operator_selected_destination() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = codex_route(serde_json::json!({}));
        route["destination"]["base_url"] = serde_json::json!("https://example.invalid/codex");
        let path = write_config(&dir, serde_json::json!({ "routes": [route] }));
        let error = load_fetch_config(&path).unwrap_err();

        assert!(format!("{error:#}").contains("unknown field `base_url`"));
    }

    #[test]
    fn config_has_two_sealed_destination_variants_and_no_url_field() {
        let codex: FetchDestination = serde_json::from_value(serde_json::json!({
            "type": "codex-responses",
            "auth_path": "target/codex-auth.json"
        }))
        .unwrap();
        assert!(matches!(codex, FetchDestination::CodexResponses { .. }));

        let openai: FetchDestination = serde_json::from_value(serde_json::json!({
            "type": "openai-responses",
            "api_key_env": "HELLAS_TEST_OPENAI_KEY"
        }))
        .unwrap();
        assert!(matches!(
            openai,
            FetchDestination::OpenaiResponses { ref api_key_env }
                if api_key_env == "HELLAS_TEST_OPENAI_KEY"
        ));

        let error = serde_json::from_value::<FetchDestination>(serde_json::json!({
            "type": "openai-responses",
            "url": "https://example.invalid/v1/responses"
        }))
        .unwrap_err();
        assert!(error.to_string().contains("unknown field `url`"));
    }

    #[test]
    fn fetch_config_rejects_unknown_policy_fields_at_every_level() {
        type Mutation = (&'static str, fn(&mut serde_json::Value));

        let base = serde_json::json!({
            "routes": [codex_route(serde_json::json!({}))],
            "callers": [{
                "public_key": public_key_hex(1),
                "routes": [{ "service": "codex", "method": "responses" }],
                "request_rate": { "capacity": 2.0, "refill_per_sec": 1.0 },
                "spend": { "max_units": 64, "window_seconds": 60 }
            }]
        });
        let mutations: &[Mutation] = &[
            ("modles", |value| {
                value["routes"][0]["capabilities"]["modles"] = serde_json::json!(["gpt"]);
            }),
            ("route_typo", |value| {
                value["callers"][0]["routes"][0]["route_typo"] = serde_json::json!(true);
            }),
            ("caller_typo", |value| {
                value["callers"][0]["caller_typo"] = serde_json::json!(true);
            }),
            ("rate_typo", |value| {
                value["callers"][0]["request_rate"]["rate_typo"] = serde_json::json!(1);
            }),
            ("spend_typo", |value| {
                value["callers"][0]["spend"]["spend_typo"] = serde_json::json!(1);
            }),
        ];

        for (field, mutate) in mutations {
            let mut value = base.clone();
            mutate(&mut value);
            let error = serde_json::from_value::<FetchConfigFile>(value).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("unknown field `{field}`")),
                "unexpected error for {field}: {error}"
            );
        }
    }
}
