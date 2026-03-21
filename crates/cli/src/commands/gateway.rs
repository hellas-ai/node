use crate::commands::CliResult;
use crate::execution::{
    ExecutionOutput, ExecutionRequest, ExecutionRoute, ExecutionRuntime, ExecutionStrategy,
};
use crate::text_output::TextOutputDecoder;
use anyhow::{anyhow, Context};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use catgrad_llm::types::{self, anthropic, openai, plain};
use catgrad_llm::utils::from_json_slice;
use catgrad_llm::PreparedPrompt;
use hellas_executor::{DownloadPolicy, ExecutePolicy, Executor, ModelAssets};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{timeout, Duration};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic_iroh_transport::iroh::EndpointId;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
const DEFAULT_INFERENCE_TIMEOUT: Duration = Duration::from_secs(300);

pub struct GatewayOptions {
    pub host: String,
    pub port: u16,
    pub node_id: Option<EndpointId>,
    pub local: bool,
    pub queue_size: usize,
    pub retries: usize,
    pub default_max_tokens: u32,
    pub force_model: Option<String>,
}

#[derive(Clone)]
struct GatewayState {
    node_id: Option<EndpointId>,
    local: bool,
    retries: usize,
    default_max_tokens: u32,
    force_model: Option<String>,
    inference_timeout: Duration,
    runtime: ExecutionRuntime,
    model_cache: Arc<RwLock<HashMap<String, Arc<ModelAssets>>>>,
    model_load_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

struct PreparedGeneration {
    model: String,
    assets: Arc<ModelAssets>,
    request: ExecutionRequest,
    prompt_tokens: u32,
    stop_token_ids: Vec<i32>,
    inference_timeout: Duration,
}

enum GenerationError {
    Timeout(Duration),
    Failed(anyhow::Error),
}

struct HttpError {
    status: StatusCode,
    message: String,
}

impl GatewayState {
    fn resolve_model(&self, request_model: &str) -> String {
        self.force_model
            .clone()
            .unwrap_or_else(|| request_model.to_string())
    }

    fn execution_route(&self) -> ExecutionRoute {
        if self.local {
            ExecutionRoute::Local
        } else {
            ExecutionRoute::remote(self.node_id, self.retries, 0)
        }
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
        let assets = tokio::task::spawn_blocking(move || ModelAssets::load(&model_name))
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
        prepare: F,
    ) -> Result<PreparedGeneration, HttpError>
    where
        F: FnOnce(&ModelAssets) -> Result<PreparedPrompt, E>,
        E: fmt::Display,
    {
        let model = self.resolve_model(request_model);
        let assets = self.model_assets(&model).await.map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Failed to load local model assets for `{model}`: {err}"),
        })?;
        let prepared_prompt = prepare(assets.as_ref()).map_err(|err| HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("{prepare_error}: {err}"),
        })?;
        let prompt_tokens = prepared_prompt.input_ids.len() as u32;
        let stop_token_ids = prepared_prompt.stop_token_ids.clone();
        let request = ExecutionRequest::new(
            self.runtime.clone(),
            assets.clone(),
            prepared_prompt,
            max_tokens,
            ExecutionStrategy::Run(self.execution_route()),
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
            inference_timeout: self.inference_timeout,
        })
    }

    async fn prepare_openai(
        &self,
        req: &openai::ChatCompletionRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let max_tokens = req.max_tokens.unwrap_or(self.default_max_tokens);
        let messages: Vec<types::Message> = req
            .messages
            .iter()
            .cloned()
            .map(|message| types::Message::OpenAI(Box::new(message)))
            .collect();
        self.prepare_generation(
            &req.model,
            max_tokens,
            "Failed to prepare chat request",
            move |assets| assets.prepare_messages(&messages),
        )
        .await
    }

    async fn prepare_anthropic(
        &self,
        req: &anthropic::MessageRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let messages: Vec<_> = req.into();
        self.prepare_generation(
            &req.model,
            req.max_tokens,
            "Failed to prepare chat request",
            move |assets| assets.prepare_messages(&messages),
        )
        .await
    }

    async fn prepare_plain(
        &self,
        req: &plain::CompletionRequest,
    ) -> Result<PreparedGeneration, HttpError> {
        let max_tokens = req.max_tokens.unwrap_or(self.default_max_tokens);
        let prompt = req.prompt.clone();
        self.prepare_generation(
            &req.model,
            max_tokens,
            "Failed to prepare completion prompt",
            move |assets| assets.prepare_plain_prompt(&prompt),
        )
        .await
    }
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

    async fn run_to_text(&self) -> Result<(ExecutionOutput, String), GenerationError> {
        let output = self.run(|_| Ok(())).await?;
        let text = TextOutputDecoder::decode_output(self.assets.as_ref(), &output)?;
        Ok((output, text))
    }

    async fn stream_text<F>(&self, mut on_text: F) -> Result<ExecutionOutput, GenerationError>
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
        json_error(status, format!("Inference error: {self}"))
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        json_error(self.status, self.message)
    }
}

pub async fn run(options: GatewayOptions) -> CliResult<()> {
    let runtime = if options.local {
        ExecutionRuntime::with_local_executor(
            Executor::spawn(
                DownloadPolicy::Eager,
                ExecutePolicy::Eager,
                options.queue_size,
            )
            .context("failed to initialize local execution backend")?,
        )
    } else {
        ExecutionRuntime::default()
    };
    let state = Arc::new(GatewayState {
        node_id: options.node_id,
        local: options.local,
        retries: options.retries,
        default_max_tokens: options.default_max_tokens,
        force_model: options.force_model,
        inference_timeout: DEFAULT_INFERENCE_TIMEOUT,
        runtime,
        model_cache: Arc::new(RwLock::new(HashMap::new())),
        model_load_locks: Arc::new(Mutex::new(HashMap::new())),
    });

    let app = Router::new()
        .route("/v1/chat/completions", post(handle_openai))
        .route("/v1/messages", post(handle_anthropic))
        .route("/v1/completions", post(handle_plain))
        .with_state(state.clone());

    let addr = format!("{}:{}", options.host, options.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind gateway on {addr}"))?;

    println!("Hellas gateway listening on http://{addr}");
    println!("POST /v1/chat/completions (OpenAI)");
    println!("POST /v1/messages (Anthropic)");
    println!("POST /v1/completions (plain)");
    if state.local {
        println!("Using local catgrad execution backend");
        println!("Local execution queue size: {}", options.queue_size);
    }
    println!("Inference timeout: {}s", state.inference_timeout.as_secs());
    if let Some(model) = state.force_model.as_deref() {
        println!("Forcing request model override to `{model}`");
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("gateway server failed")?;

    Ok(())
}

async fn handle_openai(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<openai::ChatCompletionRequest>(&body, "OpenAI") {
        Ok(req) => req,
        Err(err) => return err.into_response(),
    };
    let stream = req.stream == Some(true);
    let stream_include_usage = req
        .stream_options
        .as_ref()
        .and_then(|options| options.include_usage)
        .unwrap_or(false);
    let prepared = match state.prepare_openai(&req).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream {
        return stream_openai(prepared, stream_include_usage);
    }

    respond_openai(prepared).await
}

async fn handle_anthropic(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<anthropic::MessageRequest>(&body, "Anthropic") {
        Ok(req) => req,
        Err(err) => return err.into_response(),
    };
    let stream = req.stream == Some(true);
    let prepared = match state.prepare_anthropic(&req).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream {
        return stream_anthropic(prepared);
    }

    respond_anthropic(prepared).await
}

async fn handle_plain(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<plain::CompletionRequest>(&body, "completion") {
        Ok(req) => req,
        Err(err) => return err.into_response(),
    };
    let stream = req.stream == Some(true);
    let prepared = match state.prepare_plain(&req).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream {
        return stream_plain(prepared);
    }

    respond_plain(prepared).await
}

fn stream_openai(prepared: PreparedGeneration, include_usage: bool) -> Response {
    let (tx, rx) = mpsc::unbounded_channel::<Result<Event, Infallible>>();
    tokio::spawn(async move {
        let id = next_id("chatcmpl");
        let created = now_unix();

        let start_chunk = openai::ChatCompletionChunk::builder()
            .id(id.clone())
            .object("chat.completion.chunk".to_string())
            .created(created)
            .model(prepared.model.clone())
            .choices(vec![openai::ChatStreamChoice::builder()
                .index(0)
                .delta(openai::ChatDelta {
                    role: Some("assistant".to_string()),
                    ..Default::default()
                })
                .build()])
            .build();

        if tx.send(Ok(sse_data(&start_chunk))).is_err() {
            return;
        }

        let generated = prepared
            .stream_text(|delta| {
                let chunk = openai::ChatCompletionChunk::builder()
                    .id(id.clone())
                    .object("chat.completion.chunk".to_string())
                    .created(created)
                    .model(prepared.model.clone())
                    .choices(vec![openai::ChatStreamChoice::builder()
                        .index(0)
                        .delta(openai::ChatDelta {
                            content: Some(delta.to_string()),
                            ..Default::default()
                        })
                        .build()])
                    .build();
                tx.send(Ok(sse_data(&chunk)))
                    .map_err(|_| anyhow!("stream closed"))?;
                Ok(())
            })
            .await;

        let generated = match generated {
            Ok(output) => output,
            Err(err) => {
                let _ = tx.send(Ok(sse_data(&json!({
                    "error": { "message": format!("Inference error: {err}") }
                }))));
                let _ = tx.send(Ok(Event::default().data("[DONE]")));
                return;
            }
        };

        let final_chunk = openai::ChatCompletionChunk::builder()
            .id(id.clone())
            .object("chat.completion.chunk".to_string())
            .created(created)
            .model(prepared.model.clone())
            .choices(vec![openai::ChatStreamChoice::builder()
                .index(0)
                .delta(openai::ChatDelta::default())
                .finish_reason(Some(openai::FinishReason::Stop))
                .build()])
            .build();
        if tx.send(Ok(sse_data(&final_chunk))).is_err() {
            return;
        }

        if include_usage {
            let usage_chunk = openai::ChatCompletionChunk::builder()
                .id(id)
                .object("chat.completion.chunk".to_string())
                .created(created)
                .model(prepared.model.clone())
                .choices(vec![])
                .usage(Some(openai::Usage::from_counts(
                    prepared.prompt_tokens,
                    generated.completion_tokens,
                )))
                .build();
            if tx.send(Ok(sse_data(&usage_chunk))).is_err() {
                return;
            }
        }

        let _ = tx.send(Ok(Event::default().data("[DONE]")));
    });

    Sse::new(UnboundedReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn stream_anthropic(prepared: PreparedGeneration) -> Response {
    let (tx, rx) = mpsc::unbounded_channel::<Result<Event, Infallible>>();
    tokio::spawn(async move {
        let id = next_id("msg");

        let message_start = anthropic::MessageStreamEvent::MessageStart {
            message: anthropic::MessageResponse::builder()
                .id(id.clone())
                .message_type(Some("message".to_string()))
                .role("assistant".to_string())
                .content(vec![])
                .model(prepared.model.clone())
                .usage(anthropic::AnthropicUsage::new(prepared.prompt_tokens, 0))
                .build(),
        };

        if tx
            .send(Ok(sse_event_data("message_start", &message_start)))
            .is_err()
        {
            return;
        }

        if tx
            .send(Ok(sse_event_data(
                "content_block_start",
                &anthropic::MessageStreamEvent::ContentBlockStart {
                    index: 0,
                    content_block: anthropic::ContentBlock::Text {
                        text: String::new(),
                    },
                },
            )))
            .is_err()
        {
            return;
        }

        let generated = prepared
            .stream_text(|delta| {
                let event = anthropic::MessageStreamEvent::ContentBlockDelta {
                    index: 0,
                    delta: anthropic::ContentBlockDelta::TextDelta {
                        text: delta.to_string(),
                    },
                };
                tx.send(Ok(sse_event_data("content_block_delta", &event)))
                    .map_err(|_| anyhow!("stream closed"))?;
                Ok(())
            })
            .await;

        if tx
            .send(Ok(sse_event_data(
                "content_block_stop",
                &anthropic::MessageStreamEvent::ContentBlockStop { index: 0 },
            )))
            .is_err()
        {
            return;
        }

        let generated = match generated {
            Ok(output) => output,
            Err(err) => {
                let _ = tx.send(Ok(sse_event_data(
                    "error",
                    &anthropic::MessageStreamEvent::Error {
                        error: anthropic::StreamError {
                            error_type: "invalid_request_error".to_string(),
                            message: format!("Inference error: {err}"),
                        },
                    },
                )));
                return;
            }
        };

        if tx
            .send(Ok(sse_event_data(
                "message_delta",
                &anthropic::MessageStreamEvent::MessageDelta {
                    delta: anthropic::StreamMessageDelta {
                        stop_reason: Some(anthropic::StopReason::EndTurn),
                    },
                    usage: anthropic::AnthropicUsage::new(
                        prepared.prompt_tokens,
                        generated.completion_tokens,
                    ),
                },
            )))
            .is_err()
        {
            return;
        }

        let _ = tx.send(Ok(sse_event_data(
            "message_stop",
            &anthropic::MessageStreamEvent::MessageStop,
        )));
    });

    Sse::new(UnboundedReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn stream_plain(prepared: PreparedGeneration) -> Response {
    let (tx, rx) = mpsc::unbounded_channel::<Result<Event, Infallible>>();
    tokio::spawn(async move {
        let id = next_id("cmpl");
        let created = now_unix();

        let generated = prepared
            .stream_text(|delta| {
                let chunk = plain::CompletionChunk::builder()
                    .id(id.clone())
                    .object("text_completion".to_string())
                    .created(created)
                    .model(prepared.model.clone())
                    .choices(vec![plain::CompletionChoice::builder()
                        .index(0)
                        .text(delta.to_string())
                        .build()])
                    .build();
                tx.send(Ok(sse_data(&chunk)))
                    .map_err(|_| anyhow!("stream closed"))?;
                Ok(())
            })
            .await;

        let _generated = match generated {
            Ok(output) => output,
            Err(err) => {
                let _ = tx.send(Ok(sse_data(&json!({
                    "error": {"message": format!("Inference error: {err}")}
                }))));
                let _ = tx.send(Ok(Event::default().data("[DONE]")));
                return;
            }
        };

        let final_chunk = plain::CompletionChunk::builder()
            .id(id)
            .object("text_completion".to_string())
            .created(created)
            .model(prepared.model.clone())
            .choices(vec![plain::CompletionChoice::builder()
                .index(0)
                .text(String::new())
                .finish_reason(Some(openai::FinishReason::Stop))
                .build()])
            .build();
        if tx.send(Ok(sse_data(&final_chunk))).is_err() {
            return;
        }

        let _ = tx.send(Ok(Event::default().data("[DONE]")));
    });

    Sse::new(UnboundedReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn respond_openai(prepared: PreparedGeneration) -> Response {
    let (generated, text) = match prepared.run_to_text().await {
        Ok(result) => result,
        Err(err) => return err.into_response(),
    };

    let response = openai::ChatCompletionResponse::builder()
        .id(next_id("chatcmpl"))
        .object("chat.completion".to_string())
        .created(now_unix())
        .model(prepared.model.clone())
        .choices(vec![openai::ChatChoice::builder()
            .index(0)
            .message(openai::ChatMessage::assistant(text))
            .finish_reason(Some(openai::FinishReason::Stop))
            .build()])
        .usage(Some(openai::Usage::from_counts(
            prepared.prompt_tokens,
            generated.completion_tokens,
        )))
        .build();

    Json(response).into_response()
}

async fn respond_anthropic(prepared: PreparedGeneration) -> Response {
    let (generated, text) = match prepared.run_to_text().await {
        Ok(result) => result,
        Err(err) => return err.into_response(),
    };

    let response = anthropic::MessageResponse::builder()
        .id(next_id("msg"))
        .message_type(Some("message".to_string()))
        .role("assistant".to_string())
        .content(vec![anthropic::ContentBlock::Text { text }])
        .model(prepared.model.clone())
        .stop_reason(Some(anthropic::StopReason::EndTurn))
        .usage(anthropic::AnthropicUsage::new(
            prepared.prompt_tokens,
            generated.completion_tokens,
        ))
        .build();

    Json(response).into_response()
}

async fn respond_plain(prepared: PreparedGeneration) -> Response {
    let (generated, text) = match prepared.run_to_text().await {
        Ok(result) => result,
        Err(err) => return err.into_response(),
    };

    let response = plain::CompletionResponse::builder()
        .id(next_id("cmpl"))
        .object("text_completion".to_string())
        .created(now_unix())
        .model(prepared.model.clone())
        .choices(vec![plain::CompletionChoice::builder()
            .index(0)
            .text(text)
            .finish_reason(Some(openai::FinishReason::Stop))
            .build()])
        .usage(Some(openai::Usage::from_counts(
            prepared.prompt_tokens,
            generated.completion_tokens,
        )))
        .build();

    Json(response).into_response()
}

fn parse_json_body<T: serde::de::DeserializeOwned>(
    body: &Bytes,
    protocol: &str,
) -> Result<T, HttpError> {
    from_json_slice::<T>(body).map_err(|err| HttpError {
        status: StatusCode::BAD_REQUEST,
        message: format!("Invalid {protocol} request: {err}"),
    })
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "message": message.into() } })),
    )
        .into_response()
}

fn sse_data<T: Serialize>(payload: &T) -> Event {
    let data = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    Event::default().data(data)
}

fn sse_event_data<T: Serialize>(event: &str, payload: &T) -> Event {
    let data = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    Event::default().event(event).data(data)
}

fn next_id(prefix: &str) -> String {
    let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{n}")
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
