use super::proxy::ResponsesProxy;
use super::{GatewayOptions, ResponsesBackend, json_error};
use crate::execution::{
    ExecutionEvent, ExecutionRequest as RuntimeExecutionRequest, ExecutionRoute, ExecutionRuntime,
    ExecutionStrategy, Outcome, PreparedExecution, RemoteNodeTarget, StopReason,
};
use crate::text_output::TextOutputDecoder;
use anyhow::Context;
use async_stream::try_stream;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use catgrad::prelude::Dtype;
use catgrad_llm::PreparedPrompt;
use catgrad_llm::types::Message;
use catgrad_llm::types::{ThinkingPolicy, anthropic, openai, plain};
use futures::Stream;
use futures::StreamExt;
#[cfg(feature = "hellas-executor")]
use hellas_executor::Executor;
use hellas_rpc::model::{ModelAssets, ModelAssetsError};
#[cfg(feature = "hellas-executor")]
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use hellas_rpc::provenance::{CatnixReceiptCommitment, ExecutionProvenance};
use hellas_runtime::cid::Cid;
use hellas_runtime::runtime::TextReceipt;
use hellas_runtime::runtime::chat::{ChatOptions, ChatTurn, ToolDirectory};
use hellas_wire_adaptors::{
    CanonicalExecution, ContentPart as WireContentPart, ExecutionRequest as WireExecutionRequest,
    Input, InputItem, Message as WireMessage,
};
use serde_json::{Value as JsonValue, json};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;
use tonic_iroh_transport::iroh::EndpointId;

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
    pub(super) responses_proxy: Option<Arc<ResponsesProxy>>,
    model_cache: Arc<RwLock<HashMap<String, Arc<ModelAssets>>>>,
    model_load_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

pub(super) struct PreparedGeneration {
    pub(super) model: String,
    pub(super) prepared: PreparedExecution,
    /// Pre-flight provenance the executor committed to. `None` for routes
    /// that defer their quote until streaming starts (`RemoteDiscovery`);
    /// in that case headers can't be set up front and clients must rely
    /// on the in-band `hellas` extension carried by the stream.
    pub(super) provenance: Option<ExecutionProvenance>,
    pub(super) prompt_tokens: u32,
    pub(super) stop_token_ids: Vec<i32>,
    /// Bound chat-turn for surfaces that parse tool calls from model output.
    /// Plain text surfaces leave output decoding as text passthrough.
    pub(super) chat_turn: Option<ChatTurn>,
    pub(super) assets: Arc<ModelAssets>,
    pub(super) inference_timeout: Duration,
}

/// One observation from a generation. The `Done` event is the authoritative
/// terminal frame — its `Outcome::Completed.total_tokens` is what should
/// be reported in protocol-level usage frames.
#[derive(Debug, Clone)]
pub(super) enum GenerationEvent {
    Provenance(ExecutionProvenance),
    Delta(String),
    Done(Outcome),
}

#[derive(Debug)]
pub(super) struct HttpError {
    pub(super) status: StatusCode,
    pub(super) message: String,
}

pub(super) struct CompletedTextGeneration {
    pub(super) text: String,
    pub(super) provenance: Option<ExecutionProvenance>,
    pub(super) total_tokens: u64,
    pub(super) stop_reason: StopReason,
    pub(super) receipt_cid: Cid<TextReceipt>,
    pub(super) catnix_receipt_commitment: Option<CatnixReceiptCommitment>,
}

pub(super) enum TextGenerationError {
    Failed { position: u64, error: String },
    Stream(String),
}

impl GatewayState {
    pub(super) fn from_options(options: &GatewayOptions) -> anyhow::Result<Self> {
        let responses_proxy = match options.responses_backend {
            ResponsesBackend::Hellas => None,
            ResponsesBackend::Proxy => Some(Arc::new(ResponsesProxy::new(
                &options.responses_proxy_url,
                &options.responses_proxy_api_key_env,
            )?)),
        };

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
            responses_proxy,
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
    /// produces the `PreparedPrompt` (and, for chat surfaces, the
    /// `ChatTurn`) before calling here.
    async fn finalize_generation(
        &self,
        model: String,
        assets: Arc<ModelAssets>,
        prepared_prompt: PreparedPrompt,
        max_tokens: u32,
        chat_turn: Option<ChatTurn>,
        prepare_error: &str,
    ) -> Result<PreparedGeneration, HttpError> {
        let prompt_tokens = prepared_prompt.input_ids.len() as u32;
        let stop_token_ids = prepared_prompt.stop_token_ids.clone();
        let request = RuntimeExecutionRequest::new(
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
            chat_turn,
            inference_timeout: self.inference_timeout,
        })
    }

    pub(super) async fn prepare_openai(
        &self,
        req: &openai::ChatCompletionRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let max_tokens = req.max_tokens.unwrap_or(self.default_max_tokens);
        let messages: Vec<Message> = req.messages.iter().cloned().map(Message::from).collect();
        let thinking = ThinkingPolicy::from(req.reasoning_effort);
        let tools_dir = ToolDirectory::from_openai_tools(req.tools.as_deref().unwrap_or(&[]))
            .map_err(|err| HttpError {
                status: StatusCode::BAD_REQUEST,
                message: format!("Invalid tool definitions: {err}"),
            })?;
        let model = self.resolve_model(&req.model);
        let assets = self.model_assets(&model).await.map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to load local model assets for `{model}`: {err}"),
        })?;
        let chat_turn = assets
            .chat_turn(tools_dir, ChatOptions { thinking })
            .map_err(classify_chat_turn_error)?;
        let prepared_prompt = chat_turn.render(&messages).map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to prepare chat request: {err}"),
        })?;
        self.finalize_generation(
            model,
            assets,
            prepared_prompt,
            max_tokens,
            Some(chat_turn),
            "Failed to prepare chat request",
        )
        .await
    }

    pub(super) async fn prepare_anthropic(
        &self,
        req: &anthropic::MessageRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let messages = Vec::<Message>::from(req);
        let thinking = ThinkingPolicy::from(req.thinking);
        let model = self.resolve_model(&req.model);
        let assets = self.model_assets(&model).await.map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to load local model assets for `{model}`: {err}"),
        })?;
        let chat_turn = assets
            .chat_turn(None, ChatOptions { thinking })
            .map_err(classify_chat_turn_error)?;
        let prepared_prompt = chat_turn.render(&messages).map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to prepare chat request: {err}"),
        })?;
        self.finalize_generation(
            model,
            assets,
            prepared_prompt,
            req.max_tokens,
            Some(chat_turn),
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
            None,
            "Failed to prepare completion prompt",
        )
        .await
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
        let messages = wire_messages(&req.canonical).map_err(|message| HttpError {
            status: StatusCode::BAD_REQUEST,
            message,
        })?;
        let tools = wire_tools(&req.canonical);
        let assets = self.model_assets(&model).await.map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to load local model assets for `{model}`: {err}"),
        })?;
        let prepared_prompt = assets
            .prepare_chat_with_options(&messages, ThinkingPolicy::Disabled, tools.as_ref())
            .map_err(|err| HttpError {
                status: StatusCode::BAD_REQUEST,
                message: format!(
                    "Failed to prepare Responses request: {}",
                    format_error_causes(&err)
                ),
            })?;
        self.finalize_generation(
            model,
            assets,
            prepared_prompt,
            max_tokens,
            None,
            "Failed to prepare Responses request",
        )
        .await
    }
}

fn wire_messages(canonical: &CanonicalExecution) -> Result<Vec<Message>, String> {
    let mut messages = Vec::new();
    if let Some(instructions) = &canonical.instructions {
        messages.push(Message::openai(openai::ChatMessage::system(
            instructions.clone(),
        )));
    }

    match &canonical.input {
        Input::Text(text) => {
            messages.push(Message::openai(openai::ChatMessage::user(text.clone())))
        }
        Input::Messages(input_messages) => {
            for message in input_messages {
                messages.push(Message::openai(wire_message_to_openai(message)?));
            }
        }
        Input::Items(items) => {
            for item in items {
                messages.push(Message::openai(wire_item_to_openai(item)?));
            }
        }
    }

    Ok(messages)
}

fn wire_item_to_openai(item: &InputItem) -> Result<openai::ChatMessage, String> {
    match item {
        InputItem::Message(message) => wire_message_to_openai(message),
        InputItem::ToolResult { call_id, output } => Ok(openai::ChatMessage::builder()
            .role("tool".to_string())
            .content(Some(openai::MessageContent::Text(wire_content_text(
                output,
            ))))
            .tool_call_id(Some(call_id.clone()))
            .build()),
        InputItem::ToolCall {
            id,
            name,
            arguments,
        } => Ok(openai::ChatMessage::builder()
            .role("assistant".to_string())
            .content(None)
            .tool_calls(Some(vec![json!({
                "id": id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json_to_wire_string(arguments),
                },
            })]))
            .build()),
        InputItem::Raw(_) => Err("unsupported raw Responses input item".to_string()),
    }
}

fn wire_message_to_openai(message: &WireMessage) -> Result<openai::ChatMessage, String> {
    Ok(openai::ChatMessage::builder()
        .role(message.role.clone())
        .content(wire_message_content(&message.content)?)
        .name(message.name.clone())
        .build())
}

fn wire_message_content(
    content: &[WireContentPart],
) -> Result<Option<openai::MessageContent>, String> {
    match content {
        [] => Ok(None),
        [WireContentPart::Text { text }] => Ok(Some(openai::MessageContent::Text(text.clone()))),
        parts => parts
            .iter()
            .map(wire_content_part)
            .collect::<Result<Vec<_>, _>>()
            .map(openai::MessageContent::Parts)
            .map(Some),
    }
}

fn wire_content_part(part: &WireContentPart) -> Result<openai::ContentPart, String> {
    match part {
        WireContentPart::Text { text } => Ok(openai::ContentPart::Text { text: text.clone() }),
        WireContentPart::Image { uri: Some(uri), .. } => Ok(openai::ContentPart::ImageUrl {
            image_url: openai::ImageUrl { url: uri.clone() },
        }),
        WireContentPart::Image { uri: None, .. } => {
            Err("image content requires a URI for local execution".to_string())
        }
        WireContentPart::File { .. } => {
            Err("file content is not supported by local chat templates".to_string())
        }
        WireContentPart::Json(_) => {
            Err("JSON content parts are not supported by local chat templates".to_string())
        }
    }
}

fn wire_content_text(content: &[WireContentPart]) -> String {
    content
        .iter()
        .map(|part| match part {
            WireContentPart::Text { text } => text.clone(),
            WireContentPart::Image { uri, .. } => uri.clone().unwrap_or_default(),
            WireContentPart::File {
                file_id,
                filename,
                data,
            } => file_id
                .as_ref()
                .or(filename.as_ref())
                .or(data.as_ref())
                .cloned()
                .unwrap_or_default(),
            WireContentPart::Json(value) => json_to_wire_string(value),
        })
        .collect::<Vec<_>>()
        .join("")
}

fn wire_tools(canonical: &CanonicalExecution) -> Option<JsonValue> {
    (!canonical.tools.is_empty()).then(|| {
        JsonValue::Array(
            canonical
                .tools
                .iter()
                .map(|tool| tool.raw.clone())
                .collect(),
        )
    })
}

fn json_to_wire_string(value: &JsonValue) -> String {
    match value {
        JsonValue::String(value) => value.clone(),
        _ => serde_json::to_string(value).expect("serializing JSON value cannot fail"),
    }
}

/// Map a `ModelAssets::chat_turn` failure to an HTTP status. Bad
/// schemas and unsupported-tool-arch are **request errors** (400):
/// the model never got to fail. Other failures (chat template
/// missing, etc.) are also request-shaped here.
fn classify_chat_turn_error(err: ModelAssetsError) -> HttpError {
    match err {
        ModelAssetsError::ChatTurnConfig(inner) => HttpError {
            status: StatusCode::BAD_REQUEST,
            message: inner.to_string(),
        },
        other => HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to prepare chat request: {other}"),
        },
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
                    ExecutionEvent::Provenance(provenance) => {
                        yield GenerationEvent::Provenance(provenance);
                    }
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

    pub(super) async fn collect_text(self) -> Result<CompletedTextGeneration, TextGenerationError> {
        let deadline = self.deadline();
        let mut provenance = self.provenance.clone();
        let stream = self.stream();
        tokio::pin!(stream);
        let mut text = String::new();
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(Ok(GenerationEvent::Provenance(prov)))) => provenance = Some(prov),
                Ok(Some(Ok(GenerationEvent::Delta(delta)))) => text.push_str(&delta),
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Completed {
                    total_tokens,
                    stop_reason,
                    receipt_cid,
                    catnix_receipt_commitment,
                })))) => {
                    return Ok(CompletedTextGeneration {
                        text,
                        provenance,
                        total_tokens,
                        stop_reason,
                        receipt_cid,
                        catnix_receipt_commitment,
                    });
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Failed { position, error })))) => {
                    return Err(TextGenerationError::Failed { position, error });
                }
                Ok(Some(Err(err))) => {
                    return Err(TextGenerationError::Stream(format!(
                        "Inference error: {err:#}"
                    )));
                }
                Ok(None) => {
                    return Err(TextGenerationError::Stream(
                        "execution stream ended without terminal outcome".to_string(),
                    ));
                }
                Err(_) => {
                    return Err(TextGenerationError::Stream(format!(
                        "inference timed out after {}s",
                        super::timeout_secs_until(deadline)
                    )));
                }
            }
        }
    }

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
mod wire_adaptor_tests {
    use super::*;
    use hellas_wire_adaptors::{ModelRef, SamplingOptions, ToolChoice};
    use serde_json::json;

    fn canonical(input: Input) -> CanonicalExecution {
        CanonicalExecution {
            model: ModelRef::new("model"),
            input,
            instructions: None,
            sampling: SamplingOptions::default(),
            tools: Vec::new(),
            tool_choice: ToolChoice::Auto,
            response_format: None,
            reasoning: None,
            previous_response_id: None,
            committed_fields: Default::default(),
        }
    }

    #[test]
    fn wire_messages_map_text_input_to_user_message() {
        let mut canonical = canonical(Input::Text("hello".to_string()));
        canonical.instructions = Some("be direct".to_string());

        let messages = wire_messages(&canonical).unwrap();
        assert_eq!(messages.len(), 2);

        let Message::OpenAI(system) = &messages[0] else {
            panic!("expected OpenAI system message");
        };
        assert_eq!(system.role, "system");

        let Message::OpenAI(user) = &messages[1] else {
            panic!("expected OpenAI user message");
        };
        assert_eq!(user.role, "user");
        assert_eq!(
            user.content,
            Some(openai::MessageContent::Text("hello".to_string()))
        );
    }

    #[test]
    fn wire_tool_call_maps_to_openai_assistant_tool_call() {
        let item = InputItem::ToolCall {
            id: "call_1".to_string(),
            name: "lookup".to_string(),
            arguments: json!({"query": "zurich"}),
        };

        let message = wire_item_to_openai(&item).unwrap();
        assert_eq!(message.role, "assistant");
        let tool_call = &message.tool_calls.as_ref().unwrap()[0];
        assert_eq!(tool_call["id"], "call_1");
        assert_eq!(tool_call["function"]["name"], "lookup");
        assert_eq!(tool_call["function"]["arguments"], r#"{"query":"zurich"}"#);
    }

    #[test]
    fn wire_message_rejects_file_content_for_local_template() {
        let message = WireMessage {
            role: "user".to_string(),
            content: vec![WireContentPart::File {
                file_id: Some("file_1".to_string()),
                filename: None,
                data: None,
            }],
            name: None,
        };

        let err = wire_message_to_openai(&message).unwrap_err();
        assert!(err.contains("file content is not supported"));
    }
}
