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
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::{
    Assurance, ContentId, Dtype, FetchProgramManifest, ProducerSigningKey, ProgramManifest,
};
use iroh::SecretKey;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::time::{Duration, timeout};
use tracing::warn;

mod codex_provider;
mod node;
mod node_handler;
mod openai_provider;
mod responses_fetch;
mod responses_projector;
pub mod work_config;

pub use work_config::{WorkConfig, load_work_config};

pub(crate) const DEFAULT_CODEX_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";

pub struct ServeOptions {
    pub port: Option<u16>,
    pub execute_policy: ExecutePolicy,
    pub queue_size: usize,
    pub preload_models: Vec<String>,
    pub artifact_store_path: Option<PathBuf>,
    /// The loaded paid-work configuration, not the path it came from.
    /// Its presence is still what serves the two work ALPNs; what is new
    /// is that the node holds the chain cross-check, the validator
    /// fan-out, the journal root, and the policies it would mount a
    /// channel with.
    pub work_config: Option<WorkConfig>,
    /// Read only by the fastresume load/save below, which go through
    /// `hellas-models` and so exist only on an `evaluate` build.
    #[cfg(feature = "evaluate")]
    pub store_records: Option<PathBuf>,
    pub metrics_port: Option<u16>,
    pub graffiti: String,
    pub dtype: Vec<Dtype>,
    pub fetch_config_file: Option<PathBuf>,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_size: usize,
    pub secret_key: SecretKey,
    pub producer_key: ProducerSigningKey,
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
    // What an earlier `hellas store adopt` already hashed.
    //
    // Without this a node re-hashes every weight shard the first time it
    // is asked to quote — 647 ms against 549 µs on a 29-blob cache — so
    // the whole benefit of `adopt` would accrue to a CLI process that
    // exited immediately afterwards.
    //
    // Two nodes sharing one record file is decided rather than avoided:
    // `save` is a write-and-rename, so the later writer wins whole and
    // the earlier one's work is lost. Losing it costs a re-hash, which
    // is the cost of not having adopted at all.
    #[cfg(feature = "evaluate")]
    let store_records = options
        .store_records
        .clone()
        .or_else(hellas_store::state::records_path);
    #[cfg(feature = "evaluate")]
    if let Some(path) = store_records.as_deref() {
        let loaded = hellas_models::load_store_records(path);
        info!(
            records = loaded,
            path = %path.display(),
            "loaded what an earlier run already hashed",
        );
    }

    // What the operator configured, said back once. The last line is the
    // one that matters: §4 disables setup and new work on missing
    // evidence and never disables recovery, so a node with no measured
    // artifact still serves its journals and still answers a contest.
    if let Some(work) = options.work_config.as_ref() {
        info!(
            network = %work.chain.network,
            validators = work.validators.len(),
            journal_root = %work.journal.root.display(),
            poll_ms = work.poll.as_millis(),
            response_alarm_margin_blocks = work.response_alarm_margin_blocks,
            "loaded the paid-work configuration",
        );
        if work.measured_artifact().is_none() {
            warn!("{}", work.admission_summary());
        } else {
            info!("{}", work.admission_summary());
        }
    }

    let preload_models = dedupe_preload_models(options.preload_models);
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
        preload_models: preload_models.clone(),
        build,
        graffiti,
        supported_dtypes: options.dtype,
        fetch_access_policy,
        artifact_store_path,
        fetch_routes,
        fetch_max_in_flight: options.fetch_max_in_flight,
        fetch_queue_size: options.fetch_queue_size,
        work_configured: options.work_config.is_some(),
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

    if !preload_models.is_empty() {
        info!(
            "Models available for quoting: {}",
            preload_models.join(", ")
        );
    }

    println!("RPC server running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for shutdown signal")?;

    println!("Shutting down...");
    // Before the shutdown timeout, which can end in `process::exit`.
    #[cfg(feature = "evaluate")]
    if let Some(path) = store_records.as_deref() {
        match hellas_models::save_store_records(path) {
            Ok(saved) => info!(
                records = saved,
                path = %path.display(),
                "saved what this run hashed",
            ),
            Err(error) => warn!(
                %error,
                path = %path.display(),
                "could not save what this run hashed; the next start will re-hash it",
            ),
        }
    }
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

fn dedupe_preload_models(mut models: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    models.retain(|model| {
        let trimmed = model.trim();
        !trimmed.is_empty() && seen.insert(trimmed.to_string())
    });
    models
        .into_iter()
        .map(|model| model.trim().to_string())
        .collect()
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

    #[test]
    fn dedupe_preload_models_preserves_first_occurrence() {
        let models = dedupe_preload_models(vec![
            "foo/bar".to_string(),
            "baz/qux".to_string(),
            "foo/bar".to_string(),
            "baz/qux@rev".to_string(),
        ]);
        assert_eq!(models, vec!["foo/bar", "baz/qux", "baz/qux@rev"]);
    }

    #[test]
    fn dedupe_preload_models_trims_and_drops_empty_entries() {
        let models = dedupe_preload_models(vec![
            " foo/bar ".to_string(),
            "".to_string(),
            "   ".to_string(),
            "baz/qux@rev".to_string(),
        ]);
        assert_eq!(models, vec!["foo/bar", "baz/qux@rev"]);
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
