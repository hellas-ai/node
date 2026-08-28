use super::proxy::ResponsesProxy;
use super::{GatewayOptions, ResponsesBackend, json_error};
use crate::execution::{
    CliRuntime, ExecutionRequest, ExecutionRequestOptions, ExecutionStrategy, PreparedExecution,
};
use anyhow::Context;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hellas_adaptors::{
    ContentPart as WireContentPart, ExecutionRequest as WireExecutionRequest, Input, InputItem,
    Message as WireMessage,
};
use hellas_client::{ExecutionRoute, ProducerTrust, RemoteNodeTarget};
#[cfg(feature = "evaluate")]
use hellas_executor::Executor;
use hellas_models::{ChatMessage, ModelAssets, PreparedPrompt, Reach};
use hellas_rpc::Dtype;
use hellas_rpc::Retention;
#[cfg(feature = "evaluate")]
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::provenance::ExecutionProvenance;
use iroh::EndpointId;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;

/// End-to-end deadline applied while consuming a prepared generation.
/// Covers preparation (quote / discovery) AND the entire decode stream.
pub(super) const DEFAULT_INFERENCE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub(super) struct GatewayState {
    #[cfg(feature = "evaluate")]
    pub(super) local: bool,
    #[cfg(feature = "evaluate")]
    pub(super) verify_local: bool,
    pub(super) verify_node_id: Option<EndpointId>,
    default_max_tokens: u32,
    pub(super) force_model: Option<String>,
    pub(super) inference_timeout: Duration,
    pub(super) dtype: Dtype,
    runtime: CliRuntime,
    pub(super) responses_proxy: Option<Arc<ResponsesProxy>>,
    pub(super) responses_fetch: Option<Arc<super::fetch_backend::ResponsesFetchBackend>>,
    runner_key: Arc<hellas_rpc::ProducerSigningKey>,
    assurance: hellas_rpc::Assurance,
    /// The one strategy every request runs, settled at startup by
    /// [`configured_strategy`]. The dial targets it was built from are
    /// deliberately not kept: there is no second place a route could be
    /// assembled, and so no place one could be assembled without an anchor.
    strategy: Option<ExecutionStrategy>,
    model_cache: Arc<RwLock<HashMap<String, Arc<ModelAssets>>>>,
    model_load_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

/// The execution strategy these options describe, or `None` when they
/// describe none.
///
/// A trust anchor is required exactly where one can be used. Every
/// remote constructor below — [`ExecutionRoute::remote`] and
/// [`RemoteNodeTarget::direct`] — takes a [`hellas_client::ProviderTrustAnchor`] by
/// value, so the `?` on the anchor is the only way past them: without
/// one there is no remote route to run, and a gateway with no route
/// refuses a request rather than dialling a provider it cannot verify.
/// Local execution answers to nobody remote and needs no anchor, so it
/// is built either way.
fn configured_strategy(options: &GatewayOptions) -> Option<ExecutionStrategy> {
    #[cfg(feature = "evaluate")]
    let primary = if options.local {
        ExecutionRoute::Local
    } else {
        ExecutionRoute::remote(
            options.node_id,
            options.node_addrs.clone(),
            options.retries,
            options.provider_trust.clone()?,
        )
    };
    #[cfg(not(feature = "evaluate"))]
    let primary = ExecutionRoute::remote(
        options.node_id,
        options.node_addrs.clone(),
        options.retries,
        options.provider_trust.clone()?,
    );

    #[cfg(feature = "evaluate")]
    if options.verify_local {
        return Some(ExecutionStrategy::Verify {
            primary,
            shadow: ExecutionRoute::Local,
        });
    }

    if let Some(node_id) = options.verify {
        return Some(ExecutionStrategy::Verify {
            primary,
            shadow: ExecutionRoute::RemoteDirect(RemoteNodeTarget::direct(
                node_id,
                options.provider_trust.clone()?,
            )),
        });
    }

    Some(ExecutionStrategy::Run(primary))
}

pub(super) struct PreparedGeneration {
    pub(super) prepared: PreparedExecution,
    /// Pre-flight provenance the executor committed to. `None` for routes
    /// that defer their quote until streaming starts (`RemoteDiscovery`);
    /// in that case headers can't be set and clients must rely on the
    /// in-band SSE `hellas-provenance` event.
    pub(super) provenance: Option<ExecutionProvenance>,
    pub(super) prompt_tokens: u32,
    pub(super) stop_token_ids: Vec<u32>,
    pub(super) assets: Arc<ModelAssets>,
    pub(super) inference_timeout: Duration,
}

#[derive(Debug)]
pub(super) struct HttpError {
    pub(super) status: StatusCode,
    pub(super) message: String,
}

impl GatewayState {
    pub(super) async fn from_options(options: &GatewayOptions) -> anyhow::Result<Self> {
        let runner_key = Arc::new(options.producer_key.clone());
        let responses_proxy = match options.responses_backend {
            ResponsesBackend::Hellas => None,
            ResponsesBackend::Proxy => Some(Arc::new(ResponsesProxy::new(
                &options.responses_proxy_url,
                &options.responses_proxy_api_key_env,
            )?)),
            ResponsesBackend::Fetch => None,
        };

        #[cfg(feature = "evaluate")]
        let runtime = if options.local || options.verify_local {
            CliRuntime::local(
                Executor::spawn_with_producer_key(
                    ExecutePolicy::Eager,
                    options.queue_size,
                    vec![options.dtype],
                    runner_key.as_ref().clone(),
                    options.provider_genesis.clone(),
                    options.assurance,
                )
                .context("failed to initialize local execution backend")?,
            )
            .with_remote(options.secret_key.clone())
            .await?
        } else {
            CliRuntime::remote(options.secret_key.clone()).await?
        };
        #[cfg(not(feature = "evaluate"))]
        let runtime = CliRuntime::remote(options.secret_key.clone()).await?;

        let responses_fetch = match options.responses_backend {
            ResponsesBackend::Fetch => {
                // Mirrors the producer-side default for trusted callers: with
                // no keys configured, only output signed by this gateway's own
                // producer key verifies.
                let producer_trust = if options.trusted_producer_public_keys.is_empty() {
                    ProducerTrust::keys([runner_key.public_key()])
                } else {
                    ProducerTrust::keys(options.trusted_producer_public_keys.iter().copied())
                };
                Some(Arc::new(super::fetch_backend::ResponsesFetchBackend::new(
                    runtime.clone(),
                    ExecutionRoute::remote(
                        options.node_id,
                        options.node_addrs.clone(),
                        options.retries,
                        // This backend dials a provider for every request
                        // it serves, so it is built only where the anchor
                        // that provider will be checked against exists.
                        options
                            .provider_trust
                            .clone()
                            .context("fetch responses backend requires a provider trust anchor")?,
                    ),
                    (
                        &options.responses_fetch_route_service,
                        &options.responses_fetch_route_method,
                        options
                            .responses_fetch_execution_environment
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "fetch responses backend requires an execution environment"
                                )
                            })?,
                    ),
                    runner_key.as_ref().clone(),
                    options.assurance,
                    producer_trust,
                    options.responses_fetch_request_overrides.clone(),
                )))
            }
            ResponsesBackend::Hellas | ResponsesBackend::Proxy => None,
        };

        Ok(Self {
            #[cfg(feature = "evaluate")]
            local: options.local,
            #[cfg(feature = "evaluate")]
            verify_local: options.verify_local,
            verify_node_id: options.verify,
            default_max_tokens: options.default_max_tokens,
            force_model: options.force_model.clone(),
            inference_timeout: DEFAULT_INFERENCE_TIMEOUT,
            dtype: options.dtype,
            runtime,
            responses_proxy,
            responses_fetch,
            runner_key,
            assurance: options.assurance,
            strategy: configured_strategy(options),
            model_cache: Arc::new(RwLock::new(HashMap::new())),
            model_load_locks: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn resolve_model(&self, request_model: &str) -> String {
        self.force_model
            .clone()
            .unwrap_or_else(|| request_model.to_string())
    }

    /// The strategy this request runs under, or the refusal of a gateway
    /// that was given no anchor and so holds no route to run it.
    fn execution_strategy(&self) -> Result<ExecutionStrategy, HttpError> {
        self.strategy.clone().ok_or_else(|| HttpError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "this gateway has no provider trust anchor, so it has no execution route; \
                      restart it with --provider <content-id>"
                .to_string(),
        })
    }

    /// This model's tokenizer and template, downloading them if this
    /// machine does not have them.
    ///
    /// # Why this may download, and what a deployer takes on by exposing
    /// it
    ///
    /// [`Reach::Download`] is deliberate here and is *not* the mistake
    /// the quote path had. The gateway is the operator's own client-side
    /// process: it tokenizes for requests it is itself submitting, so
    /// fetching a model it does not hold is work done on its owner's
    /// behalf. Nothing inside the executor may do this, which is why the
    /// reach is named at every call site rather than defaulted.
    ///
    /// The property that makes it safe is *who can reach it*, and that
    /// is no longer only a deployment decision:
    ///
    /// - `hellas gateway` refuses to bind anywhere but loopback
    ///   ([`crate::access::loopback_addr`]), so `--host 0.0.0.0` is an
    ///   error rather than an exposure, and every route in front of this
    ///   requires the run's credential ([`crate::access::BearerLayer`]).
    ///   A caller that cannot present it never names a model.
    /// - A container port publish or a reverse proxy pointed at the
    ///   loopback port still puts the port within someone else's reach.
    ///   What it does not hand them is the fetch primitive: without the
    ///   credential, which lives only in this process's memory and on
    ///   the operator's terminal, the request is refused before the
    ///   model id in its body is read.
    /// - `--force-model` remains the way to take the choice away from
    ///   callers who *are* credentialled: it replaces the request's model
    ///   before it reaches here.
    async fn model_assets(&self, model: &str) -> anyhow::Result<Arc<ModelAssets>> {
        {
            let cache = self.model_cache.read().await;
            if let Some(assets) = cache.get(model) {
                return Ok(assets.clone());
            }
        }

        let load_lock = {
            let mut locks = self.model_load_locks.lock().await;
            locks
                .entry(model.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _load_guard = load_lock.lock().await;

        {
            let cache = self.model_cache.read().await;
            if let Some(assets) = cache.get(model) {
                return Ok(assets.clone());
            }
        }

        let model_name = model.to_string();
        let dtype = self.dtype;
        let assets = tokio::task::spawn_blocking(move || {
            ModelAssets::load(&model_name, dtype, Reach::Download)
        })
        .await
        .context("local model loader panicked")??;

        let assets = Arc::new(assets);
        let mut cache = self.model_cache.write().await;
        cache.insert(model.to_string(), assets.clone());
        Ok(assets)
    }

    /// Drive the executor quote step and assemble a `PreparedGeneration`
    /// from already-prepared wire-adaptor inputs.
    async fn finalize_generation(
        &self,
        assets: Arc<ModelAssets>,
        prepared_prompt: PreparedPrompt,
        max_tokens: u32,
        prepare_error: &str,
        retention: Retention,
    ) -> Result<PreparedGeneration, HttpError> {
        let prompt_tokens = prepared_prompt.input_ids.len() as u32;
        let stop_token_ids = prepared_prompt.stop_token_ids.clone();
        let request = ExecutionRequest::new(
            self.runtime.clone(),
            assets.clone(),
            prepared_prompt,
            ExecutionRequestOptions {
                max_seq: max_tokens,
                assurance: self.assurance,
                retention,
            },
            self.execution_strategy()?,
            self.runner_key.as_ref().clone(),
        )
        .map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to build execution request: {err}"),
        })?;
        let prepared = request.prepare().await.map_err(|err| HttpError {
            status: StatusCode::BAD_GATEWAY,
            message: format!("{prepare_error}: {}", format_error_causes(&err)),
        })?;
        let provenance = prepared.provenance().cloned();

        Ok(PreparedGeneration {
            assets,
            prepared,
            provenance,
            prompt_tokens,
            stop_token_ids,
            inference_timeout: self.inference_timeout,
        })
    }

    pub(super) async fn prepare_wire_execution(
        &self,
        req: &WireExecutionRequest,
        retention: Retention,
    ) -> Result<PreparedGeneration, HttpError> {
        let max_tokens = req
            .canonical
            .sampling
            .max_output_tokens
            .unwrap_or(self.default_max_tokens);
        let model = self.resolve_model(&req.canonical.model.name);
        let assets = self.model_assets(&model).await.map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to load local model assets for `{model}`: {err}"),
        })?;

        let prepared_prompt = match &req.canonical.input {
            Input::Text(prompt) => assets.prepare_plain(prompt).map_err(|err| HttpError {
                status: StatusCode::BAD_REQUEST,
                message: format!(
                    "Failed to prepare completion prompt: {}",
                    format_error_causes(&err)
                ),
            })?,
            Input::Messages(messages) => {
                let messages = wire_messages_to_template(messages)?;
                let tools = wire_tools_to_raw(req);
                assets
                    .prepare_chat_with_options(
                        &messages,
                        (!tools.is_empty()).then_some(tools.as_slice()),
                        req.canonical.reasoning.is_some(),
                    )
                    .map_err(|err| HttpError {
                        status: StatusCode::BAD_REQUEST,
                        message: format!("Failed to prepare chat request: {err}"),
                    })?
            }
            Input::Items(items) => {
                let messages = wire_items_to_template_messages(items)?;
                let tools = wire_tools_to_raw(req);
                assets
                    .prepare_chat_with_options(
                        &messages,
                        (!tools.is_empty()).then_some(tools.as_slice()),
                        req.canonical.reasoning.is_some(),
                    )
                    .map_err(|err| HttpError {
                        status: StatusCode::BAD_REQUEST,
                        message: format!("Failed to prepare Responses input: {err}"),
                    })?
            }
        };

        self.finalize_generation(
            assets,
            prepared_prompt,
            max_tokens,
            "Failed to prepare Responses input",
            retention,
        )
        .await
    }
}

fn wire_tools_to_raw(req: &WireExecutionRequest) -> Vec<serde_json::Value> {
    req.canonical
        .tools
        .iter()
        .map(|tool| tool.raw.clone())
        .collect()
}

fn wire_messages_to_template(messages: &[WireMessage]) -> Result<Vec<ChatMessage>, HttpError> {
    messages
        .iter()
        .map(|message| {
            let content = content_parts_to_text(&message.content)?;
            Ok(ChatMessage {
                role: message.role.clone(),
                content: Some(content),
                tool_calls: Vec::new(),
                tool_call_id: None,
                name: message.name.clone(),
            })
        })
        .collect()
}

fn wire_items_to_template_messages(items: &[InputItem]) -> Result<Vec<ChatMessage>, HttpError> {
    let mut out = Vec::new();
    for item in items {
        match item {
            InputItem::Message(message) => {
                out.extend(wire_messages_to_template(std::slice::from_ref(message))?);
            }
            InputItem::ToolCall {
                id,
                name,
                arguments,
            } => {
                out.push(ChatMessage {
                    role: "assistant".to_string(),
                    content: None,
                    tool_calls: vec![serde_json::json!({
                        "id": id,
                        "type": "function",
                        "function": { "name": name, "arguments": arguments }
                    })],
                    tool_call_id: None,
                    name: None,
                });
            }
            InputItem::ToolResult { call_id, output } => {
                out.push(ChatMessage {
                    role: "tool".to_string(),
                    content: Some(content_parts_to_text(output)?),
                    tool_calls: Vec::new(),
                    tool_call_id: Some(call_id.clone()),
                    name: None,
                });
            }
            InputItem::Raw(value) => {
                out.push(ChatMessage::user(value.to_string()));
            }
        }
    }
    Ok(out)
}

fn content_parts_to_text(parts: &[WireContentPart]) -> Result<String, HttpError> {
    let mut out = String::new();
    for part in parts {
        match part {
            WireContentPart::Text { text } => out.push_str(text),
            WireContentPart::Json(value) => out.push_str(&value.to_string()),
            WireContentPart::Image { .. } | WireContentPart::File { .. } => {
                return Err(HttpError {
                    status: StatusCode::BAD_REQUEST,
                    message: "local Hellas backend does not support image or file Responses input"
                        .to_string(),
                });
            }
        }
    }
    Ok(out)
}

impl PreparedGeneration {
    /// Absolute deadline for this generation's stream consumption.
    /// Computed at call time; covers the whole lifecycle from this point on.
    pub(super) fn deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::now() + self.inference_timeout
    }
}

fn format_error_causes(err: &(dyn StdError + 'static)) -> String {
    let mut parts = Vec::new();
    let mut current = err.source().unwrap_or(err);
    parts.push(current.to_string());
    while let Some(source) = current.source() {
        parts.push(source.to_string());
        current = source;
    }
    parts.join(": ")
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            error!(
                status = %self.status,
                "gateway request failed"
            );
        } else {
            warn!(
                status = %self.status,
                "gateway request rejected"
            );
        }
        json_error(self.status, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_client::ProviderTrustAnchor;
    use std::str::FromStr;

    fn endpoint(byte: u8) -> EndpointId {
        match byte {
            1 => EndpointId::from_str(
                "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
            )
            .expect("valid endpoint id"),
            2 => EndpointId::from_str(
                "edfadcefb3917925de1111087f11925542c97e14ab00cf42b9447f7567a25b62",
            )
            .expect("valid endpoint id"),
            _ => panic!("unknown test endpoint"),
        }
    }

    fn anchor() -> ProviderTrustAnchor {
        ProviderTrustAnchor {
            expected_genesis: hellas_rpc::ContentId::from_bytes([9; 32]),
            required_assurance: hellas_rpc::Assurance::ProducerSigned,
            apple_app_attest: None,
        }
    }

    /// A gateway pointed at one node, which callers then vary.
    fn options(provider_trust: Option<ProviderTrustAnchor>) -> GatewayOptions {
        GatewayOptions {
            host: "127.0.0.1".to_string(),
            port: None,
            node_id: Some(endpoint(1)),
            node_addrs: Vec::new(),
            #[cfg(feature = "evaluate")]
            local: false,
            #[cfg(feature = "evaluate")]
            verify_local: false,
            verify: None,
            #[cfg(feature = "evaluate")]
            queue_size: 1,
            retries: 2,
            default_max_tokens: 128,
            force_model: None,
            metrics_port: None,
            dtype: Dtype::F32,
            responses_backend: ResponsesBackend::Hellas,
            responses_proxy_url: String::new(),
            responses_proxy_api_key_env: String::new(),
            responses_fetch_route_service: String::new(),
            responses_fetch_route_method: String::new(),
            responses_fetch_execution_environment: None,
            responses_fetch_request_overrides: Default::default(),
            trusted_producer_public_keys: Vec::new(),
            provider_trust,
            producer_key: hellas_rpc::ProducerSigningKey::from_secret_bytes([3; 32])
                .expect("valid test key"),
            #[cfg(feature = "evaluate")]
            provider_genesis: Vec::new(),
            assurance: hellas_rpc::Assurance::ProducerSigned,
            secret_key: iroh::SecretKey::from([5; 32]),
            wrap: None,
            wrap_args: Vec::new(),
        }
    }

    /// Fails the day a remote route becomes constructible without the
    /// anchor the provider on it is verified against. Direct dial,
    /// discovery, and the verification shadow are each a provider dialled
    /// at run time, so each one alone is enough to withhold the strategy.
    #[test]
    fn every_remote_route_requires_a_provider_trust_anchor() {
        let direct = options(None);
        assert!(configured_strategy(&direct).is_none());

        let mut discovery = options(None);
        discovery.node_id = None;
        assert!(configured_strategy(&discovery).is_none());

        let mut verified = options(None);
        verified.verify = Some(endpoint(2));
        assert!(configured_strategy(&verified).is_none());

        // The same three configurations, with an anchor to dial against.
        assert!(configured_strategy(&options(Some(anchor()))).is_some());
        discovery.provider_trust = Some(anchor());
        assert!(configured_strategy(&discovery).is_some());
        verified.provider_trust = Some(anchor());
        assert!(configured_strategy(&verified).is_some());
    }

    #[test]
    fn execution_strategy_uses_remote_shadow_for_verify_node() {
        let mut options = options(Some(anchor()));
        options.verify = Some(endpoint(2));
        assert_eq!(
            configured_strategy(&options),
            Some(ExecutionStrategy::Verify {
                primary: ExecutionRoute::RemoteDirect(RemoteNodeTarget::direct(
                    endpoint(1),
                    anchor(),
                )),
                shadow: ExecutionRoute::RemoteDirect(RemoteNodeTarget::direct(
                    endpoint(2),
                    anchor(),
                )),
            })
        );
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn execution_strategy_uses_local_shadow_for_verify_local() {
        let mut options = options(Some(anchor()));
        options.verify_local = true;
        assert_eq!(
            configured_strategy(&options),
            Some(ExecutionStrategy::Verify {
                primary: ExecutionRoute::RemoteDirect(RemoteNodeTarget::direct(
                    endpoint(1),
                    anchor(),
                )),
                shadow: ExecutionRoute::Local,
            })
        );
    }

    /// Local execution dials nobody, so it is the one route that runs
    /// without an anchor.
    #[cfg(feature = "evaluate")]
    #[test]
    fn execution_strategy_uses_local_run_when_local_is_enabled() {
        let mut options = options(None);
        options.node_id = None;
        options.local = true;
        assert_eq!(
            configured_strategy(&options),
            Some(ExecutionStrategy::Run(ExecutionRoute::Local))
        );
    }
}
