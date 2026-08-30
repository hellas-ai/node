use crate::commands::CliResult;
use anyhow::{Context, bail};
#[cfg(feature = "evaluate")]
use commonware_runtime::Runner as _;
#[cfg(feature = "evaluate")]
use hellas_executor::ArtifactStoreConfig;
use hellas_executor::{
    CallerAccess, ExecutorMetrics, FetchAccessPolicy, FetchProjectorFactory, FetchProvider,
    FetchRoute, FetchRouteEntry, FetchRouteGrant, FetchRoutePolicy, FetchRouteRegistry,
    RequestRateLimit, SpendLimit,
};
use hellas_kernel::Secp256k1Signer;
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::{Assurance, ContentId, FetchProgramManifest, ProducerSigningKey, ProgramManifest};
use iroh::SecretKey;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::time::{Duration, timeout};
use tracing::warn;

mod codex_provider;
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

pub(crate) const DEFAULT_CODEX_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";

pub struct ServeOptions {
    pub port: Option<u16>,
    pub execute_policy: ExecutePolicy,
    pub queue_size: usize,
    #[cfg(feature = "evaluate")]
    pub packages: Vec<crate::commands::package::PackageArg>,
    #[cfg(feature = "evaluate")]
    pub package_cache: Option<PathBuf>,
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
                    ArtifactStoreConfig::new(context),
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
    let package_cache = options
        .package_cache
        .clone()
        .map(Ok)
        .unwrap_or_else(crate::identity::default_package_cache_path)?;
    #[cfg(feature = "evaluate")]
    let packages = crate::commands::package::package_sources(options.packages, package_cache)?;

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
        packages,
        build,
        graffiti,
        fetch_access_policy,
        artifact_store_path,
        fetch_routes,
        fetch_max_in_flight: options.fetch_max_in_flight,
        fetch_queue_size: options.fetch_queue_size,
        work: work_runner,
        secret_key: options.secret_key,
        producer_key: options.producer_key,
        provider_genesis: options.provider_genesis,
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

/// Load the unified fetch configuration: the route table (providers,
/// protocols, capabilities) and the caller access policy, cross-validated so
/// a caller grant naming an undefined route is a load error rather than a
/// silent dead entry.
fn load_fetch_config(path: &std::path::Path) -> CliResult<(FetchRouteRegistry, FetchAccessPolicy)> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let file: FetchConfigFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let mut registry = FetchRouteRegistry::new();
    let responses_projector: Arc<dyn FetchProjectorFactory> =
        Arc::new(responses_projector::ResponsesFetchProjectorFactory);
    for route in file.routes {
        if route.service.trim().is_empty() || route.method.trim().is_empty() {
            bail!("fetch config route service and method must be non-empty");
        }
        let projector_factory = match route.protocol {
            FetchRouteProtocol::OpenaiResponses => responses_projector.clone(),
        };
        registry
            .register(
                FetchRoute::new(route.service, route.method),
                FetchRouteEntry {
                    execution_environment: ProgramManifest::Fetch(FetchProgramManifest {
                        program: parse_content_id(&route.manifest.program)?,
                        config: parse_content_id(&route.manifest.config)?,
                        build: parse_content_id(&route.manifest.build)?,
                    })
                    .content_id(),
                    provider: route.upstream.into_provider()?,
                    projector_factory,
                    capabilities: route.capabilities.into_policy()?,
                },
            )
            .map_err(|err| anyhow::anyhow!("invalid fetch config: {err}"))?;
    }

    let callers = file
        .callers
        .into_iter()
        .map(FetchPolicyCaller::into_access)
        .collect::<CliResult<Vec<_>>>()?;
    for caller in &callers {
        if let hellas_executor::RouteSet::Explicit(routes) = &caller.routes {
            for route in routes.keys() {
                if !registry.contains(route) {
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
struct FetchConfigFile {
    #[serde(default)]
    routes: Vec<FetchConfigRoute>,
    #[serde(default)]
    callers: Vec<FetchPolicyCaller>,
}

#[derive(Debug, Deserialize)]
struct FetchConfigRoute {
    service: String,
    method: String,
    /// The wire contract this route speaks; selects the output projector and
    /// event canonicalizer. Explicit because it is consensus-relevant.
    protocol: FetchRouteProtocol,
    manifest: FetchManifest,
    upstream: FetchUpstream,
    #[serde(default)]
    capabilities: FetchPolicyLimits,
}

#[derive(Debug, Deserialize)]
struct FetchManifest {
    program: String,
    config: String,
    build: String,
}

fn parse_content_id(raw: &str) -> CliResult<ContentId> {
    raw.parse()
        .with_context(|| format!("invalid ContentId {raw:?}"))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum FetchRouteProtocol {
    OpenaiResponses,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum FetchUpstream {
    /// Any OpenAI-Responses-compatible HTTP endpoint with bearer auth from
    /// an environment variable.
    OpenaiCompatible {
        url: String,
        #[serde(default = "default_openai_api_key_env")]
        api_key_env: String,
    },
    CodexOauth {
        #[serde(default)]
        base_url: Option<String>,
        #[serde(default)]
        auth_path: Option<PathBuf>,
    },
}

fn default_openai_api_key_env() -> String {
    "OPENAI_API_KEY".to_string()
}

impl FetchUpstream {
    fn into_provider(self) -> CliResult<Arc<dyn FetchProvider>> {
        Ok(match self {
            Self::OpenaiCompatible { url, api_key_env } => Arc::new(
                openai_provider::OpenAiResponsesFetchProvider::new(&url, &api_key_env)?,
            ),
            Self::CodexOauth {
                base_url,
                auth_path,
            } => Arc::new(codex_provider::CodexResponsesFetchProvider::new(
                base_url.as_deref().unwrap_or(DEFAULT_CODEX_BASE_URL),
                auth_path.as_deref(),
            )?),
        })
    }
}

#[derive(Debug, Deserialize)]
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
        let routes = self
            .routes
            .into_iter()
            .map(FetchPolicyRoute::into_grant)
            .collect::<CliResult<Vec<_>>>()?;
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
struct FetchPolicyRoute {
    service: String,
    method: String,
    #[serde(flatten)]
    limits: FetchPolicyLimits,
}

impl FetchPolicyRoute {
    fn into_grant(self) -> CliResult<FetchRouteGrant> {
        if self.service.trim().is_empty() || self.method.trim().is_empty() {
            bail!("fetch config route service and method must be non-empty");
        }
        Ok(FetchRouteGrant {
            route: FetchRoute::new(self.service, self.method),
            policy: self.limits.into_policy()?,
        })
    }
}

#[derive(Debug, Deserialize)]
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
    use hellas_rpc::ProducerSigningKey;

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
            "protocol": "openai-responses",
            "manifest": {
                "program": "0101010101010101010101010101010101010101010101010101010101010101",
                "config": "0202020202020202020202020202020202020202020202020202020202020202",
                "build": "0303030303030303030303030303030303030303030303030303030303030303"
            },
            // Keep this fixture independent of the process-global HOME.
            "upstream": { "type": "codex-oauth", "auth_path": "/tmp/hellas-test-codex-auth.json" },
            "capabilities": capabilities,
        })
    }

    #[test]
    fn load_fetch_config_parses_routes_limits_and_quotas() {
        let dir = tempfile::tempdir().unwrap();
        let public_key = public_key_hex(1);
        let path = write_config(
            &dir,
            serde_json::json!({
                "routes": [codex_route(serde_json::json!({}))],
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
        let capabilities = registry.entry(&route).unwrap().capabilities.clone();
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
                "routes": [codex_route(serde_json::json!({
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
                "routes": [codex_route(serde_json::json!({}))],
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
                    codex_route(serde_json::json!({})),
                    codex_route(serde_json::json!({})),
                ],
            }),
        );

        let err = load_fetch_config(&path).unwrap_err();

        assert!(err.to_string().contains("registered twice"));
    }
}
