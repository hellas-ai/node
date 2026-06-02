use super::proxy::ResponsesProxy;
use super::{GatewayOptions, ResponsesBackend, json_error};
use crate::execution::{
    ExecutionRequest, ExecutionRoute, ExecutionRuntime, ExecutionStrategy, PreparedExecution,
    RemoteNodeTarget,
};
use anyhow::Context;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use catgrad::prelude::Dtype;
use chatgrad::PreparedPrompt;
use chatgrad::types::Message;
use chatgrad::types::openai;
#[cfg(feature = "hellas-executor")]
use hellas_executor::Executor;
use hellas_rpc::model::ModelAssets;
#[cfg(feature = "hellas-executor")]
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_wire_adaptors::{
    ContentPart as WireContentPart, ExecutionRequest as WireExecutionRequest, Input, InputItem,
    Message as WireMessage,
};
use iroh::EndpointId;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;

/// End-to-end deadline applied while consuming a prepared generation.
/// Covers preparation (quote / discovery) AND the entire decode stream.
pub(super) const DEFAULT_INFERENCE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub(super) struct GatewayState {
    pub(super) node_id: Option<EndpointId>,
    pub(super) node_addrs: Vec<SocketAddr>,
    #[cfg(feature = "hellas-executor")]
    pub(super) local: bool,
    #[cfg(feature = "hellas-executor")]
    pub(super) verify_local: bool,
    pub(super) verify_node_id: Option<EndpointId>,
    pub(super) retries: usize,
    default_max_tokens: u32,
    pub(super) force_model: Option<String>,
    pub(super) inference_timeout: Duration,
    pub(super) dtype: Dtype,
    runtime: ExecutionRuntime,
    pub(super) responses_proxy: Option<Arc<ResponsesProxy>>,
    pub(super) responses_fetch: Option<Arc<super::fetch_backend::ResponsesFetchBackend>>,
    model_cache: Arc<RwLock<HashMap<String, Arc<ModelAssets>>>>,
    model_load_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

pub(super) struct PreparedGeneration {
    pub(super) prepared: PreparedExecution,
    /// Pre-flight provenance the executor committed to. `None` for routes
    /// that defer their quote until streaming starts (`RemoteDiscovery`);
    /// in that case headers can't be set and clients must rely on the
    /// in-band SSE `hellas-provenance` event.
    pub(super) provenance: Option<ExecutionProvenance>,
    pub(super) prompt_tokens: u32,
    pub(super) stop_token_ids: Vec<i32>,
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
        let responses_proxy = match options.responses_backend {
            ResponsesBackend::Hellas => None,
            ResponsesBackend::Proxy => Some(Arc::new(ResponsesProxy::new(
                &options.responses_proxy_url,
                &options.responses_proxy_api_key_env,
            )?)),
            ResponsesBackend::Fetch => None,
        };

        #[cfg(feature = "hellas-executor")]
        let runtime = if options.local || options.verify_local {
            let producer_key =
                crate::identity::load_or_create_producer_key(options.producer_key_path.as_deref())?;
            ExecutionRuntime::local(
                Executor::spawn_with_producer_key(
                    ExecutePolicy::Eager,
                    options.queue_size,
                    vec![options.dtype],
                    producer_key,
                )
                .context("failed to initialize local execution backend")?,
            )
            .with_remote(options.secret_key.clone())
            .await?
        } else {
            ExecutionRuntime::remote(options.secret_key.clone()).await?
        };
        #[cfg(not(feature = "hellas-executor"))]
        let runtime = ExecutionRuntime::remote(options.secret_key.clone()).await?;

        let responses_fetch = match options.responses_backend {
            ResponsesBackend::Fetch => {
                Some(Arc::new(super::fetch_backend::ResponsesFetchBackend::new(
                    runtime.clone(),
                    ExecutionRoute::remote(
                        options.node_id,
                        options.node_addrs.clone(),
                        options.retries,
                    ),
                    &options.responses_fetch_service,
                    &options.responses_fetch_method,
                    crate::identity::load_or_create_producer_key(
                        options.producer_key_path.as_deref(),
                    )?,
                )))
            }
            ResponsesBackend::Hellas | ResponsesBackend::Proxy => None,
        };

        Ok(Self {
            node_id: options.node_id,
            node_addrs: options.node_addrs.clone(),
            #[cfg(feature = "hellas-executor")]
            local: options.local,
            #[cfg(feature = "hellas-executor")]
            verify_local: options.verify_local,
            verify_node_id: options.verify,
            retries: options.retries,
            default_max_tokens: options.default_max_tokens,
            force_model: options.force_model.clone(),
            inference_timeout: DEFAULT_INFERENCE_TIMEOUT,
            dtype: options.dtype,
            runtime,
            responses_proxy,
            responses_fetch,
            model_cache: Arc::new(RwLock::new(HashMap::new())),
            model_load_locks: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn resolve_model(&self, request_model: &str) -> String {
        self.force_model
            .clone()
            .unwrap_or_else(|| request_model.to_string())
    }

    fn execution_route(&self) -> ExecutionRoute {
        #[cfg(feature = "hellas-executor")]
        if self.local {
            return ExecutionRoute::Local;
        }
        ExecutionRoute::remote(self.node_id, self.node_addrs.clone(), self.retries)
    }

    fn execution_strategy(&self) -> ExecutionStrategy {
        let primary = self.execution_route();

        #[cfg(feature = "hellas-executor")]
        if self.verify_local {
            return ExecutionStrategy::Verify {
                primary,
                shadow: ExecutionRoute::Local,
            };
        }

        if let Some(node_id) = self.verify_node_id {
            return ExecutionStrategy::Verify {
                primary,
                shadow: ExecutionRoute::RemoteDirect(RemoteNodeTarget::from(node_id)),
            };
        }

        ExecutionStrategy::Run(primary)
    }

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
        let assets = tokio::task::spawn_blocking(move || ModelAssets::load(&model_name, dtype))
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
    ) -> Result<PreparedGeneration, HttpError> {
        let prompt_tokens = prepared_prompt.input_ids.len() as u32;
        let stop_token_ids = prepared_prompt.stop_token_ids.clone();
        let request = ExecutionRequest::new(
            self.runtime.clone(),
            assets.clone(),
            prepared_prompt,
            max_tokens,
            self.execution_strategy(),
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
                let messages = wire_messages_to_openai(messages)?;
                let messages = messages.into_iter().map(Message::from).collect::<Vec<_>>();
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
                let messages = wire_items_to_openai_messages(items)?;
                let messages = messages.into_iter().map(Message::from).collect::<Vec<_>>();
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

fn wire_messages_to_openai(
    messages: &[WireMessage],
) -> Result<Vec<openai::ChatMessage>, HttpError> {
    messages
        .iter()
        .map(|message| {
            let content = content_parts_to_text(&message.content)?;
            Ok(openai::ChatMessage::builder()
                .role(message.role.clone())
                .content(Some(openai::MessageContent::Text(content)))
                .name(message.name.clone())
                .build())
        })
        .collect()
}

fn wire_items_to_openai_messages(
    items: &[InputItem],
) -> Result<Vec<openai::ChatMessage>, HttpError> {
    let mut out = Vec::new();
    for item in items {
        match item {
            InputItem::Message(message) => {
                out.extend(wire_messages_to_openai(std::slice::from_ref(message))?);
            }
            InputItem::ToolCall {
                id,
                name,
                arguments,
            } => {
                out.push(
                    openai::ChatMessage::builder()
                        .role("assistant".to_string())
                        .content(None)
                        .tool_calls(Some(vec![serde_json::json!({
                            "id": id,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": serde_json::to_string(arguments).unwrap_or_else(|_| "{}".to_string()),
                            }
                        })]))
                        .build(),
                );
            }
            InputItem::ToolResult { call_id, output } => {
                out.push(
                    openai::ChatMessage::builder()
                        .role("tool".to_string())
                        .content(Some(openai::MessageContent::Text(content_parts_to_text(
                            output,
                        )?)))
                        .tool_call_id(Some(call_id.clone()))
                        .build(),
                );
            }
            InputItem::Raw(value) => {
                out.push(openai::ChatMessage::user(value.to_string()));
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
                message = %self.message,
                "gateway request failed"
            );
        } else {
            warn!(
                status = %self.status,
                message = %self.message,
                "gateway request rejected"
            );
        }
        json_error(self.status, self.message)
    }
}

#[cfg(all(test, feature = "hellas-executor"))]
mod tests {
    use super::*;
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

    fn state(local: bool, verify_local: bool, verify_node_id: Option<EndpointId>) -> GatewayState {
        GatewayState {
            node_id: Some(endpoint(1)),
            node_addrs: Vec::new(),
            local,
            verify_local,
            verify_node_id,
            retries: 2,
            default_max_tokens: 128,
            force_model: None,
            inference_timeout: DEFAULT_INFERENCE_TIMEOUT,
            dtype: Dtype::F32,
            runtime: ExecutionRuntime::default(),
            responses_proxy: None,
            responses_fetch: None,
            model_cache: Arc::default(),
            model_load_locks: Arc::default(),
        }
    }

    #[test]
    fn execution_strategy_uses_local_shadow_for_verify_local() {
        let state = state(false, true, None);
        assert_eq!(
            state.execution_strategy(),
            ExecutionStrategy::Verify {
                primary: ExecutionRoute::RemoteDirect(RemoteNodeTarget::from(endpoint(1))),
                shadow: ExecutionRoute::Local,
            }
        );
    }

    #[test]
    fn execution_strategy_uses_remote_shadow_for_verify_node() {
        let verify_node = endpoint(2);
        let state = state(false, false, Some(verify_node));
        assert_eq!(
            state.execution_strategy(),
            ExecutionStrategy::Verify {
                primary: ExecutionRoute::RemoteDirect(RemoteNodeTarget::from(endpoint(1))),
                shadow: ExecutionRoute::RemoteDirect(RemoteNodeTarget::from(endpoint(2))),
            }
        );
    }

    #[test]
    fn execution_strategy_uses_local_run_when_local_is_enabled() {
        let state = state(true, false, None);
        assert_eq!(
            state.execution_strategy(),
            ExecutionStrategy::Run(ExecutionRoute::Local)
        );
    }
}
