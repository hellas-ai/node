use super::{GatewayOptions, json_error};
use crate::execution::{
    ExecutionEvent, ExecutionRequest, ExecutionRoute, ExecutionRuntime, ExecutionStrategy, Outcome,
    PreparedExecution, RemoteNodeTarget,
};
use crate::text_output::TextOutputDecoder;
use anyhow::Context;
use async_stream::try_stream;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use catgrad::prelude::Dtype;
use chatgrad::PreparedPrompt;
use chatgrad::types::Message;
use chatgrad::types::{anthropic, openai, plain};
use futures::Stream;
use futures::StreamExt;
#[cfg(feature = "hellas-executor")]
use hellas_executor::Executor;
use hellas_rpc::model::ModelAssets;
#[cfg(feature = "hellas-executor")]
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use hellas_rpc::provenance::ExecutionProvenance;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;
use iroh::EndpointId;

/// End-to-end deadline applied at the consumer of `PreparedGeneration::stream`.
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
    model_cache: Arc<RwLock<HashMap<String, Arc<ModelAssets>>>>,
    model_load_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

pub(super) struct PreparedGeneration {
    pub(super) model: String,
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

/// One observation from a generation. The `Done` event is the authoritative
/// terminal frame — its `Outcome::Completed.total_tokens` is what should
/// be reported in protocol-level usage frames.
#[derive(Debug, Clone)]
pub(super) enum GenerationEvent {
    Delta(String),
    Done(Outcome),
}

pub(super) struct HttpError {
    pub(super) status: StatusCode,
    pub(super) message: String,
}

impl GatewayState {
    pub(super) fn from_options(options: &GatewayOptions) -> anyhow::Result<Self> {
        #[cfg(feature = "hellas-executor")]
        let runtime = if options.local || options.verify_local {
            let producer_key =
                crate::identity::load_or_create_producer_key(options.producer_key_path.as_deref())?;
            ExecutionRuntime::with_local_executor(
                Executor::spawn_with_producer_key(
                    DownloadPolicy::Eager,
                    ExecutePolicy::Eager,
                    options.queue_size,
                    vec![options.dtype],
                    producer_key,
                )
                .context("failed to initialize local execution backend")?,
            )
            .with_secret_key(options.secret_key.clone())
        } else {
            ExecutionRuntime::default().with_secret_key(options.secret_key.clone())
        };
        #[cfg(not(feature = "hellas-executor"))]
        let runtime = ExecutionRuntime::default().with_secret_key(options.secret_key.clone());

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
                shadow: ExecutionRoute::RemoteDirect(RemoteNodeTarget {
                    node_id,
                    node_addrs: Vec::new(),
                }),
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
    /// from already-prepared inputs. Surface-specific assembly
    /// (`prepare_openai` / `prepare_anthropic` / `prepare_plain`)
    /// produces the `PreparedPrompt` before calling here.
    async fn finalize_generation(
        &self,
        model: String,
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
            message: format!("{prepare_error}: {}", format_error_causes(err.as_ref())),
        })?;
        let provenance = prepared.provenance().cloned();

        Ok(PreparedGeneration {
            model,
            assets,
            prepared,
            provenance,
            prompt_tokens,
            stop_token_ids,
            inference_timeout: self.inference_timeout,
        })
    }

    pub(super) async fn prepare_openai(
        &self,
        req: &openai::ChatCompletionRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let max_tokens = req.max_tokens.unwrap_or(self.default_max_tokens);
        let messages: Vec<Message> = req.messages.iter().cloned().map(Message::from).collect();
        let enable_thinking = req
            .reasoning_effort
            .is_some_and(openai::ReasoningEffort::enables_thinking);
        let model = self.resolve_model(&req.model);
        let assets = self.model_assets(&model).await.map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to load local model assets for `{model}`: {err}"),
        })?;
        let prepared_prompt = assets
            .prepare_chat_with_options(&messages, req.tools.as_deref(), enable_thinking)
            .map_err(|err| HttpError {
                status: StatusCode::BAD_REQUEST,
                message: format!("Failed to prepare chat request: {err}"),
            })?;
        self.finalize_generation(
            model,
            assets,
            prepared_prompt,
            max_tokens,
            "Failed to prepare chat request",
        )
        .await
    }

    pub(super) async fn prepare_anthropic(
        &self,
        req: &anthropic::MessageRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let messages = anthropic_request_to_openai_messages(req)
            .into_iter()
            .map(Message::from)
            .collect::<Vec<_>>();
        let model = self.resolve_model(&req.model);
        let assets = self.model_assets(&model).await.map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to load local model assets for `{model}`: {err}"),
        })?;
        let prepared_prompt = assets
            .prepare_chat_with_options(&messages, req.tools.as_deref(), false)
            .map_err(|err| HttpError {
                status: StatusCode::BAD_REQUEST,
                message: format!("Failed to prepare chat request: {err}"),
            })?;
        self.finalize_generation(
            model,
            assets,
            prepared_prompt,
            req.max_tokens,
            "Failed to prepare chat request",
        )
        .await
    }

    pub(super) async fn prepare_plain(
        &self,
        req: &plain::CompletionRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let max_tokens = req.max_tokens.unwrap_or(self.default_max_tokens);
        let prompt = req.prompt.clone();
        let model = self.resolve_model(&req.model);
        let assets = self.model_assets(&model).await.map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to load local model assets for `{model}`: {err}"),
        })?;
        let prepared_prompt = assets.prepare_plain(&prompt).map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "Failed to prepare completion prompt: {}",
                format_error_causes(&err)
            ),
        })?;
        self.finalize_generation(
            model,
            assets,
            prepared_prompt,
            max_tokens,
            "Failed to prepare completion prompt",
        )
        .await
    }
}

impl PreparedGeneration {
    /// Drive the execution to completion as a stream of `GenerationEvent`s.
    ///
    /// Owning consumption: dropping the returned stream cancels everything
    /// downstream (broadcast subscriber → executor's per-running cancel
    /// token, or tonic stream → server-side close-monitor on remote).
    ///
    /// The `inference_timeout` field on `PreparedGeneration` is *not*
    /// applied here — callers wrap the stream with `tokio::time::timeout_at`
    /// against `Self::deadline()` so the protocol can shape the timeout
    /// frame in its own format.
    pub(super) fn stream(self) -> impl Stream<Item = anyhow::Result<GenerationEvent>> + Send {
        let Self {
            prepared,
            assets,
            stop_token_ids,
            ..
        } = self;
        try_stream! {
            let mut decoder = TextOutputDecoder::new(assets, &stop_token_ids);
            let inner = prepared.stream();
            tokio::pin!(inner);
            while let Some(event) = inner.next().await {
                match event? {
                    ExecutionEvent::Chunk { tokens, .. } => {
                        let delta = decoder.push_bytes(&tokens)?;
                        if !delta.is_empty() {
                            yield GenerationEvent::Delta(delta);
                        }
                    }
                    ExecutionEvent::Done(outcome) => {
                        yield GenerationEvent::Done(outcome);
                        return;
                    }
                }
            }
            Err(anyhow::anyhow!("execution stream ended without terminal outcome"))?;
        }
    }

    /// Absolute deadline for this generation's stream consumption.
    /// Computed at call time; covers the whole lifecycle from this point on.
    pub(super) fn deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::now() + self.inference_timeout
    }
}

/// Convert an Anthropic `MessageRequest` into a flat list of OpenAI chat
/// messages so the existing OpenAI-style chat templates can consume it.
///
/// Rules:
/// - `req.system` becomes a leading `system` role message.
/// - Assistant messages with `ToolUse` blocks collapse into one OpenAI
///   assistant message whose `tool_calls` carries each call.
/// - User messages with `ToolResult` blocks expand into one `tool` role
///   message per result (optionally preceded by a `user` message if the same
///   Anthropic message also carried text blocks).
fn anthropic_request_to_openai_messages(
    req: &anthropic::MessageRequest,
) -> Vec<openai::ChatMessage> {
    let mut out = Vec::new();

    if let Some(system) = &req.system {
        let text = match system {
            anthropic::SystemPrompt::Text(text) => text.clone(),
            anthropic::SystemPrompt::Blocks(blocks) => blocks
                .iter()
                .map(|block| block.text.as_str())
                .collect::<Vec<_>>()
                .join(""),
        };
        out.push(openai::ChatMessage::system(text));
    }

    for msg in &req.messages {
        let blocks = match &msg.content {
            anthropic::MessageContent::Text(text) => {
                vec![anthropic::ContentBlock::Text { text: text.clone() }]
            }
            anthropic::MessageContent::Blocks(blocks) => blocks.clone(),
        };
        match msg.role.as_str() {
            "user" => emit_user_turn(&mut out, blocks),
            "assistant" => emit_assistant_turn(&mut out, blocks),
            _ => {
                let text = blocks
                    .iter()
                    .filter_map(|block| match block {
                        anthropic::ContentBlock::Text { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                out.push(
                    openai::ChatMessage::builder()
                        .role(msg.role.clone())
                        .content(Some(openai::MessageContent::Text(text)))
                        .build(),
                );
            }
        }
    }

    out
}

fn emit_user_turn(out: &mut Vec<openai::ChatMessage>, blocks: Vec<anthropic::ContentBlock>) {
    let mut text_parts = Vec::new();
    let mut tool_results = Vec::new();
    for block in blocks {
        match block {
            anthropic::ContentBlock::Text { text } => text_parts.push(text),
            anthropic::ContentBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => tool_results.push((tool_use_id, content)),
            anthropic::ContentBlock::ToolUse { .. } => {}
        }
    }
    if !text_parts.is_empty() {
        out.push(openai::ChatMessage::user(text_parts.join("")));
    }
    for (tool_use_id, content) in tool_results {
        out.push(
            openai::ChatMessage::builder()
                .role("tool".to_string())
                .content(Some(openai::MessageContent::Text(
                    anthropic_tool_result_to_string(&content),
                )))
                .tool_call_id(Some(tool_use_id))
                .build(),
        );
    }
}

fn emit_assistant_turn(out: &mut Vec<openai::ChatMessage>, blocks: Vec<anthropic::ContentBlock>) {
    let mut text_parts = Vec::new();
    let mut tool_calls = Vec::new();
    for block in blocks {
        match block {
            anthropic::ContentBlock::Text { text } => text_parts.push(text),
            anthropic::ContentBlock::ToolUse { id, name, input } => {
                let arguments = serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string());
                tool_calls.push(serde_json::json!({
                    "id": id,
                    "type": "function",
                    "function": { "name": name, "arguments": arguments },
                }));
            }
            anthropic::ContentBlock::ToolResult { .. } => {}
        }
    }
    let content = if text_parts.is_empty() {
        None
    } else {
        Some(openai::MessageContent::Text(text_parts.join("")))
    };
    let tool_calls = if tool_calls.is_empty() {
        None
    } else {
        Some(tool_calls)
    };
    out.push(
        openai::ChatMessage::builder()
            .role("assistant".to_string())
            .content(content)
            .tool_calls(tool_calls)
            .build(),
    );
}

/// Convert an Anthropic `tool_result.content` payload to the single-string
/// shape OpenAI's `tool` role message carries. Accepts raw strings, arrays of
/// text blocks (Anthropic permits both), or falls back to JSON serialization.
fn anthropic_tool_result_to_string(content: &serde_json::Value) -> String {
    match content {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Array(blocks) => blocks
            .iter()
            .filter_map(|block| {
                block
                    .as_object()
                    .and_then(|obj| obj.get("text"))
                    .and_then(serde_json::Value::as_str)
            })
            .collect(),
        other => serde_json::to_string(other).unwrap_or_default(),
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
                primary: ExecutionRoute::RemoteDirect(RemoteNodeTarget {
                    node_id: endpoint(1),
                    node_addrs: Vec::new(),
                }),
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
                primary: ExecutionRoute::RemoteDirect(RemoteNodeTarget {
                    node_id: endpoint(1),
                    node_addrs: Vec::new(),
                }),
                shadow: ExecutionRoute::RemoteDirect(RemoteNodeTarget {
                    node_id: endpoint(2),
                    node_addrs: Vec::new(),
                }),
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

#[cfg(test)]
mod anthropic_conversion_tests {
    use super::*;
    use serde_json::json;

    fn assistant_tool_calls(msg: &openai::ChatMessage) -> &[serde_json::Value] {
        msg.tool_calls.as_deref().expect("tool_calls populated")
    }

    #[test]
    fn system_prompt_text_becomes_leading_system_message() {
        let req = anthropic::MessageRequest::builder()
            .model("m".into())
            .messages(vec![anthropic::AnthropicMessage::user("hi")])
            .max_tokens(16)
            .system(Some(anthropic::SystemPrompt::Text("be brief".into())))
            .build();
        let out = anthropic_request_to_openai_messages(&req);
        assert_eq!(out[0].role, "system");
        assert_eq!(
            out[0].content,
            Some(openai::MessageContent::Text("be brief".into()))
        );
        assert_eq!(out[1].role, "user");
    }

    #[test]
    fn assistant_tool_use_collapses_to_openai_tool_calls() {
        let req = anthropic::MessageRequest::builder()
            .model("m".into())
            .messages(vec![
                anthropic::AnthropicMessage::user("what's the weather in Paris?"),
                anthropic::AnthropicMessage {
                    role: "assistant".into(),
                    content: anthropic::MessageContent::Blocks(vec![
                        anthropic::ContentBlock::Text {
                            text: "Let me check.".into(),
                        },
                        anthropic::ContentBlock::ToolUse {
                            id: "toolu_1".into(),
                            name: "get_weather".into(),
                            input: json!({"city": "Paris"}),
                        },
                    ]),
                },
            ])
            .max_tokens(16)
            .build();
        let out = anthropic_request_to_openai_messages(&req);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].role, "assistant");
        assert_eq!(
            out[1].content,
            Some(openai::MessageContent::Text("Let me check.".into()))
        );
        let tool_calls = assistant_tool_calls(&out[1]);
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0]["id"], "toolu_1");
        assert_eq!(tool_calls[0]["type"], "function");
        assert_eq!(tool_calls[0]["function"]["name"], "get_weather");
        assert_eq!(
            tool_calls[0]["function"]["arguments"],
            r#"{"city":"Paris"}"#
        );
    }

    #[test]
    fn user_tool_result_becomes_tool_role_message() {
        let req = anthropic::MessageRequest::builder()
            .model("m".into())
            .messages(vec![anthropic::AnthropicMessage {
                role: "user".into(),
                content: anthropic::MessageContent::Blocks(vec![
                    anthropic::ContentBlock::ToolResult {
                        tool_use_id: "toolu_1".into(),
                        content: json!("sunny, 22C"),
                        is_error: None,
                    },
                ]),
            }])
            .max_tokens(16)
            .build();
        let out = anthropic_request_to_openai_messages(&req);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].role, "tool");
        assert_eq!(out[0].tool_call_id.as_deref(), Some("toolu_1"));
        assert_eq!(
            out[0].content,
            Some(openai::MessageContent::Text("sunny, 22C".into()))
        );
    }

    #[test]
    fn user_message_with_text_and_tool_result_splits() {
        let req = anthropic::MessageRequest::builder()
            .model("m".into())
            .messages(vec![anthropic::AnthropicMessage {
                role: "user".into(),
                content: anthropic::MessageContent::Blocks(vec![
                    anthropic::ContentBlock::ToolResult {
                        tool_use_id: "toolu_1".into(),
                        content: json!("sunny"),
                        is_error: None,
                    },
                    anthropic::ContentBlock::Text {
                        text: "thanks!".into(),
                    },
                ]),
            }])
            .max_tokens(16)
            .build();
        let out = anthropic_request_to_openai_messages(&req);
        // Text flushes first, then the tool messages follow.
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].role, "user");
        assert_eq!(
            out[0].content,
            Some(openai::MessageContent::Text("thanks!".into()))
        );
        assert_eq!(out[1].role, "tool");
        assert_eq!(out[1].tool_call_id.as_deref(), Some("toolu_1"));
    }

    #[test]
    fn tool_result_content_accepts_blocks_or_object() {
        assert_eq!(
            anthropic_tool_result_to_string(&json!("plain")),
            "plain".to_string()
        );
        assert_eq!(
            anthropic_tool_result_to_string(&json!([
                {"type": "text", "text": "alpha"},
                {"type": "text", "text": "beta"},
            ])),
            "alphabeta".to_string()
        );
        assert_eq!(
            anthropic_tool_result_to_string(&json!({"result": 42})),
            r#"{"result":42}"#.to_string()
        );
    }

    #[test]
    fn parallel_tool_calls_all_land_on_single_assistant_message() {
        let req = anthropic::MessageRequest::builder()
            .model("m".into())
            .messages(vec![anthropic::AnthropicMessage {
                role: "assistant".into(),
                content: anthropic::MessageContent::Blocks(vec![
                    anthropic::ContentBlock::ToolUse {
                        id: "toolu_1".into(),
                        name: "get_weather".into(),
                        input: json!({"city": "Paris"}),
                    },
                    anthropic::ContentBlock::ToolUse {
                        id: "toolu_2".into(),
                        name: "get_time".into(),
                        input: json!({"tz": "UTC"}),
                    },
                ]),
            }])
            .max_tokens(16)
            .build();
        let out = anthropic_request_to_openai_messages(&req);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].role, "assistant");
        assert_eq!(out[0].content, None);
        let tool_calls = assistant_tool_calls(&out[0]);
        assert_eq!(tool_calls.len(), 2);
        assert_eq!(tool_calls[0]["id"], "toolu_1");
        assert_eq!(tool_calls[1]["id"], "toolu_2");
    }
}
