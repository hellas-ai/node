use super::{GatewayOptions, json_error};
use crate::execution::{
    ExecutionOutput, ExecutionRequest, ExecutionRoute, ExecutionRuntime, ExecutionStrategy,
    RemoteNodeTarget,
};
use crate::text_output::TextOutputDecoder;
use anyhow::Context;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use catgrad_llm::types::Message;
use catgrad_llm::types::{anthropic, openai, plain};
use catgrad::prelude::Dtype;
use catgrad_llm::PreparedPrompt;
#[cfg(feature = "hellas-executor")]
use hellas_executor::Executor;
#[cfg(feature = "hellas-executor")]
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use hellas_rpc::model::ModelAssets;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Duration, timeout};
use tonic_iroh_transport::iroh::EndpointId;

const DEFAULT_INFERENCE_TIMEOUT: Duration = Duration::from_secs(300);

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
    pub(super) request: ExecutionRequest,
    pub(super) prompt_tokens: u32,
    pub(super) stop_token_ids: Vec<i32>,
    pub(super) has_tools: bool,
    assets: Arc<ModelAssets>,
    inference_timeout: Duration,
}

pub(super) enum GenerationError {
    Timeout(Duration),
    Failed(anyhow::Error),
}

pub(super) struct HttpError {
    pub(super) status: StatusCode,
    pub(super) message: String,
}

impl GatewayState {
    pub(super) fn from_options(options: &GatewayOptions) -> anyhow::Result<Self> {
        #[cfg(feature = "hellas-executor")]
        let runtime = if options.local || options.verify_local {
            ExecutionRuntime::with_local_executor(
                Executor::spawn(
                    DownloadPolicy::Eager,
                    ExecutePolicy::Eager,
                    options.queue_size,
                    vec![options.dtype],
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

    async fn prepare_generation<F, E>(
        &self,
        request_model: &str,
        max_tokens: u32,
        prepare_error: &str,
        has_tools: bool,
        prepare: F,
    ) -> Result<PreparedGeneration, HttpError>
    where
        F: FnOnce(&ModelAssets) -> Result<PreparedPrompt, E>,
        E: StdError + Send + Sync + 'static,
    {
        let model = self.resolve_model(request_model);
        let assets = self.model_assets(&model).await.map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to load local model assets for `{model}`: {err}"),
        })?;
        let prepared_prompt = prepare(assets.as_ref()).map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("{prepare_error}: {}", format_error_causes(&err)),
        })?;
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

        Ok(PreparedGeneration {
            model,
            assets,
            request,
            prompt_tokens,
            stop_token_ids,
            has_tools,
            inference_timeout: self.inference_timeout,
        })
    }

    pub(super) async fn prepare_openai(
        &self,
        req: &openai::ChatCompletionRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let max_tokens = req.max_tokens.unwrap_or(self.default_max_tokens);
        let messages: Vec<Message> = req
            .messages
            .iter()
            .cloned()
            .map(Message::from)
            .collect();
        let tools = req.tools.clone();
        let has_tools = tools.as_ref().is_some_and(|t| !t.is_empty());
        let enable_thinking = req
            .reasoning_effort
            .is_some_and(openai::ReasoningEffort::enables_thinking);
        self.prepare_generation(
            &req.model,
            max_tokens,
            "Failed to prepare chat request",
            has_tools,
            move |assets| assets.prepare_chat_with_tools(&messages, tools.as_deref(), enable_thinking),
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
        let tools = req
            .tools
            .as_ref()
            .map(|tools| tools.iter().map(anthropic_tool_to_openai).collect::<Vec<_>>());
        let has_tools = tools.as_ref().is_some_and(|t| !t.is_empty());
        self.prepare_generation(
            &req.model,
            req.max_tokens,
            "Failed to prepare chat request",
            has_tools,
            move |assets| assets.prepare_chat_with_tools(&messages, tools.as_deref(), false),
        )
        .await
    }

    pub(super) async fn prepare_plain(
        &self,
        req: &plain::CompletionRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let max_tokens = req.max_tokens.unwrap_or(self.default_max_tokens);
        let prompt = req.prompt.clone();
        self.prepare_generation(
            &req.model,
            max_tokens,
            "Failed to prepare completion prompt",
            false,
            move |assets| assets.prepare_plain(&prompt),
        )
        .await
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

fn emit_user_turn(
    out: &mut Vec<openai::ChatMessage>,
    blocks: Vec<anthropic::ContentBlock>,
) {
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

fn emit_assistant_turn(
    out: &mut Vec<openai::ChatMessage>,
    blocks: Vec<anthropic::ContentBlock>,
) {
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

/// Convert an Anthropic tool schema (`{name, description, input_schema}`) to
/// the OpenAI shape (`{type:"function", function:{name, description, parameters}}`)
/// that our chat templates consume.
fn anthropic_tool_to_openai(tool: &serde_json::Value) -> serde_json::Value {
    let Some(obj) = tool.as_object() else {
        return tool.clone();
    };
    let mut function = serde_json::Map::new();
    if let Some(name) = obj.get("name") {
        function.insert("name".to_string(), name.clone());
    }
    if let Some(description) = obj.get("description") {
        function.insert("description".to_string(), description.clone());
    }
    if let Some(schema) = obj.get("input_schema") {
        function.insert("parameters".to_string(), schema.clone());
    }
    serde_json::json!({
        "type": "function",
        "function": serde_json::Value::Object(function),
    })
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

impl PreparedGeneration {
    async fn run<F>(&self, mut on_output: F) -> Result<ExecutionOutput, GenerationError>
    where
        F: FnMut(&[u8]) -> anyhow::Result<()> + Send,
    {
        let output = timeout(self.inference_timeout, self.request.run(&mut on_output))
            .await
            .map_err(|_| GenerationError::Timeout(self.inference_timeout))??;
        Ok(output)
    }

    pub(super) async fn run_to_text(&self) -> Result<(ExecutionOutput, String), GenerationError> {
        let output = self.run(|_| Ok(())).await?;
        let text = TextOutputDecoder::decode_output(self.assets.as_ref(), &output)?;
        Ok((output, text))
    }

    pub(super) fn parse_tool_calls(
        &self,
        text: &str,
    ) -> anyhow::Result<Option<catgrad_llm::helpers::ToolUseStep>> {
        self.assets.parse_tool_calls(text).map_err(Into::into)
    }

    pub(super) async fn stream_text<F>(
        &self,
        mut on_text: F,
    ) -> Result<ExecutionOutput, GenerationError>
    where
        F: FnMut(&str) -> anyhow::Result<()> + Send,
    {
        let mut decoder = TextOutputDecoder::new(self.assets.clone(), &self.stop_token_ids);
        self.run(|output| {
            let delta = decoder.push_output(output)?;
            if delta.is_empty() {
                return Ok(());
            }
            on_text(&delta)
        })
        .await
    }
}

impl fmt::Display for GenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenerationError::Timeout(duration) => {
                write!(f, "inference timed out after {}s", duration.as_secs())
            }
            GenerationError::Failed(err) => write!(f, "{err}"),
        }
    }
}

impl From<anyhow::Error> for GenerationError {
    fn from(err: anyhow::Error) -> Self {
        GenerationError::Failed(err)
    }
}

impl IntoResponse for GenerationError {
    fn into_response(self) -> Response {
        let status = match self {
            GenerationError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            GenerationError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        match &self {
            GenerationError::Timeout(duration) => {
                warn!(
                    timeout_secs = duration.as_secs(),
                    "gateway inference timed out"
                );
            }
            GenerationError::Failed(err) => {
                error!(error = %err, "gateway inference failed");
            }
        }
        json_error(status, format!("Inference error: {self}"))
    }
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

    #[test]
    fn anthropic_tool_schema_converts_to_openai_function() {
        let schema = json!({
            "name": "get_weather",
            "description": "Fetch the weather for a city.",
            "input_schema": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            },
        });
        let converted = anthropic_tool_to_openai(&schema);
        assert_eq!(converted["type"], "function");
        assert_eq!(converted["function"]["name"], "get_weather");
        assert_eq!(
            converted["function"]["description"],
            "Fetch the weather for a city."
        );
        assert_eq!(
            converted["function"]["parameters"]["required"],
            json!(["city"])
        );
    }
}
