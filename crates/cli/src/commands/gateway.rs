use crate::commands::CliResult;
use crate::execution::{
    ExecutionInvocation, ExecutionOutput, ExecutionRequest, ExecutionRoute, ExecutionRuntime,
    ExecutionStrategy,
};
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

enum GenerationError {
    Timeout(Duration),
    Failed(anyhow::Error),
}

struct HttpError {
    status: StatusCode,
    message: String,
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

    let model = resolve_model(&state, &req.model);
    let stream = req.stream == Some(true);
    let max_tokens = req.max_tokens.unwrap_or(state.default_max_tokens);
    let stream_include_usage = req
        .stream_options
        .as_ref()
        .and_then(|options| options.include_usage)
        .unwrap_or(false);
    let assets = match get_model_assets_cached(state.clone(), &model).await {
        Ok(assets) => assets,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("Failed to load local model assets for `{model}`: {err}"),
            );
        }
    };

    let messages: Vec<types::Message> = req
        .messages
        .iter()
        .cloned()
        .map(|message| types::Message::OpenAI(Box::new(message)))
        .collect();
    let prepared = match assets.prepare_messages(&messages) {
        Ok(prepared) => prepared,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("Failed to prepare chat request: {err}"),
            );
        }
    };

    if stream {
        let (tx, rx) = mpsc::unbounded_channel::<Result<Event, Infallible>>();
        let state_clone = state.clone();
        let assets_clone = assets.clone();
        let prompt_tokens = prepared.input_ids.len() as u32;
        let prepared_clone = prepared.clone();
        tokio::spawn(async move {
            let id = next_id("chatcmpl");
            let created = now_unix();

            let start_chunk = openai::ChatCompletionChunk::builder()
                .id(id.clone())
                .object("chat.completion.chunk".to_string())
                .created(created)
                .model(model.clone())
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

            let generated = generate_prepared(
                state_clone,
                assets_clone,
                prepared_clone,
                max_tokens,
                |delta| {
                    let chunk = openai::ChatCompletionChunk::builder()
                        .id(id.clone())
                        .object("chat.completion.chunk".to_string())
                        .created(created)
                        .model(model.clone())
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
                },
            )
            .await;

            let generated = match generated {
                Ok(out) => out,
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
                .model(model.clone())
                .choices(vec![openai::ChatStreamChoice::builder()
                    .index(0)
                    .delta(openai::ChatDelta::default())
                    .finish_reason(Some(openai::FinishReason::Stop))
                    .build()])
                .build();
            if tx.send(Ok(sse_data(&final_chunk))).is_err() {
                return;
            }

            if stream_include_usage {
                let usage_chunk = openai::ChatCompletionChunk::builder()
                    .id(id)
                    .object("chat.completion.chunk".to_string())
                    .created(created)
                    .model(model)
                    .choices(vec![])
                    .usage(Some(openai::Usage::from_counts(
                        prompt_tokens,
                        generated.completion_tokens,
                    )))
                    .build();
                if tx.send(Ok(sse_data(&usage_chunk))).is_err() {
                    return;
                }
            }

            let _ = tx.send(Ok(Event::default().data("[DONE]")));
        });

        return Sse::new(UnboundedReceiverStream::new(rx))
            .keep_alive(KeepAlive::default())
            .into_response();
    }

    let prompt_tokens = prepared.input_ids.len() as u32;
    let generated =
        match generate_prepared(state, assets, prepared.clone(), max_tokens, |_delta| Ok(())).await
        {
            Ok(out) => out,
            Err(err) => return inference_error_response(err),
        };

    let response = openai::ChatCompletionResponse::builder()
        .id(next_id("chatcmpl"))
        .object("chat.completion".to_string())
        .created(now_unix())
        .model(model)
        .choices(vec![openai::ChatChoice::builder()
            .index(0)
            .message(openai::ChatMessage::assistant(generated.text))
            .finish_reason(Some(openai::FinishReason::Stop))
            .build()])
        .usage(Some(openai::Usage::from_counts(
            prompt_tokens,
            generated.completion_tokens,
        )))
        .build();

    Json(response).into_response()
}

async fn handle_anthropic(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<anthropic::MessageRequest>(&body, "Anthropic") {
        Ok(req) => req,
        Err(err) => return err.into_response(),
    };

    let model = resolve_model(&state, &req.model);
    let stream = req.stream == Some(true);
    let max_tokens = req.max_tokens;
    let assets = match get_model_assets_cached(state.clone(), &model).await {
        Ok(assets) => assets,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("Failed to load local model assets for `{model}`: {err}"),
            );
        }
    };

    let messages: Vec<_> = (&req).into();
    let prepared = match assets.prepare_messages(&messages) {
        Ok(prepared) => prepared,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("Failed to prepare chat request: {err}"),
            );
        }
    };

    if stream {
        let (tx, rx) = mpsc::unbounded_channel::<Result<Event, Infallible>>();
        let state_clone = state.clone();
        let assets_clone = assets.clone();
        let prepared_clone = prepared.clone();
        tokio::spawn(async move {
            let id = next_id("msg");

            let message_start = anthropic::MessageStreamEvent::MessageStart {
                message: anthropic::MessageResponse::builder()
                    .id(id.clone())
                    .message_type(Some("message".to_string()))
                    .role("assistant".to_string())
                    .content(vec![])
                    .model(model.clone())
                    .usage(anthropic::AnthropicUsage::new(
                        prepared_clone.input_ids.len() as u32,
                        0,
                    ))
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

            let mut stream_delta = |delta: &str| {
                let event = anthropic::MessageStreamEvent::ContentBlockDelta {
                    index: 0,
                    delta: anthropic::ContentBlockDelta::TextDelta {
                        text: delta.to_string(),
                    },
                };
                tx.send(Ok(sse_event_data("content_block_delta", &event)))
                    .map_err(|_| anyhow!("stream closed"))?;
                Ok(())
            };
            let generated = generate_prepared(
                state_clone,
                assets_clone,
                prepared_clone.clone(),
                max_tokens,
                &mut stream_delta,
            )
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
                Ok(out) => out,
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
                            prepared_clone.input_ids.len() as u32,
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

        return Sse::new(UnboundedReceiverStream::new(rx))
            .keep_alive(KeepAlive::default())
            .into_response();
    }

    let prompt_tokens = prepared.input_ids.len() as u32;
    let generated =
        match generate_prepared(state, assets, prepared.clone(), max_tokens, |_delta| Ok(())).await
        {
            Ok(out) => out,
            Err(err) => return inference_error_response(err),
        };

    let response = anthropic::MessageResponse::builder()
        .id(next_id("msg"))
        .message_type(Some("message".to_string()))
        .role("assistant".to_string())
        .content(vec![anthropic::ContentBlock::Text {
            text: generated.text,
        }])
        .model(model)
        .stop_reason(Some(anthropic::StopReason::EndTurn))
        .usage(anthropic::AnthropicUsage::new(
            prompt_tokens,
            generated.completion_tokens,
        ))
        .build();

    Json(response).into_response()
}

async fn handle_plain(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<plain::CompletionRequest>(&body, "completion") {
        Ok(req) => req,
        Err(err) => return err.into_response(),
    };

    let model = resolve_model(&state, &req.model);
    let stream = req.stream == Some(true);
    let max_tokens = req.max_tokens.unwrap_or(state.default_max_tokens);
    let assets = match get_model_assets_cached(state.clone(), &model).await {
        Ok(assets) => assets,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("Failed to load local model assets for `{model}`: {err}"),
            );
        }
    };

    let prepared = match assets.prepare_plain_prompt(&req.prompt) {
        Ok(prepared) => prepared,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("Failed to prepare completion prompt: {err}"),
            );
        }
    };

    if stream {
        let (tx, rx) = mpsc::unbounded_channel::<Result<Event, Infallible>>();
        let state_clone = state.clone();
        let assets_clone = assets.clone();
        let prepared_clone = prepared.clone();
        tokio::spawn(async move {
            let id = next_id("cmpl");
            let created = now_unix();

            let generated = generate_prepared(
                state_clone,
                assets_clone,
                prepared_clone,
                max_tokens,
                |delta| {
                    let chunk = plain::CompletionChunk::builder()
                        .id(id.clone())
                        .object("text_completion".to_string())
                        .created(created)
                        .model(model.clone())
                        .choices(vec![plain::CompletionChoice::builder()
                            .index(0)
                            .text(delta.to_string())
                            .build()])
                        .build();
                    tx.send(Ok(sse_data(&chunk)))
                        .map_err(|_| anyhow!("stream closed"))?;
                    Ok(())
                },
            )
            .await;

            let _generated = match generated {
                Ok(out) => out,
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
                .model(model)
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

        return Sse::new(UnboundedReceiverStream::new(rx))
            .keep_alive(KeepAlive::default())
            .into_response();
    }

    let prompt_tokens = prepared.input_ids.len() as u32;
    let generated =
        match generate_prepared(state, assets, prepared, max_tokens, |_delta| Ok(())).await {
            Ok(out) => out,
            Err(err) => return inference_error_response(err),
        };

    let response = plain::CompletionResponse::builder()
        .id(next_id("cmpl"))
        .object("text_completion".to_string())
        .created(now_unix())
        .model(model)
        .choices(vec![plain::CompletionChoice::builder()
            .index(0)
            .text(generated.text)
            .finish_reason(Some(openai::FinishReason::Stop))
            .build()])
        .usage(Some(openai::Usage::from_counts(
            prompt_tokens,
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

fn resolve_model(state: &GatewayState, request_model: &str) -> String {
    state
        .force_model
        .clone()
        .unwrap_or_else(|| request_model.to_string())
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "message": message.into() } })),
    )
        .into_response()
}

fn inference_error_response(err: GenerationError) -> Response {
    let status = match err {
        GenerationError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        GenerationError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json_error(status, format!("Inference error: {err}"))
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

async fn get_model_assets_cached(
    state: Arc<GatewayState>,
    model: &str,
) -> anyhow::Result<Arc<ModelAssets>> {
    {
        let cache = state.model_cache.read().await;
        if let Some(assets) = cache.get(model) {
            return Ok(assets.clone());
        }
    }

    let load_lock = {
        let mut locks = state.model_load_locks.lock().await;
        locks
            .entry(model.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    let _load_guard = load_lock.lock().await;

    {
        let cache = state.model_cache.read().await;
        if let Some(assets) = cache.get(model) {
            return Ok(assets.clone());
        }
    }

    let model_name = model.to_string();
    let assets = tokio::task::spawn_blocking(move || ModelAssets::load(&model_name))
        .await
        .context("local model loader panicked")??;

    let assets = Arc::new(assets);
    let mut cache = state.model_cache.write().await;
    cache.insert(model.to_string(), assets.clone());
    Ok(assets)
}

async fn generate_prepared<F>(
    state: Arc<GatewayState>,
    assets: Arc<ModelAssets>,
    prepared_prompt: catgrad_llm::PreparedPrompt,
    max_seq: u32,
    mut on_delta: F,
) -> Result<ExecutionOutput, GenerationError>
where
    F: FnMut(&str) -> anyhow::Result<()> + Send,
{
    let request = ExecutionRequest::new(
        state.runtime.clone(),
        ExecutionInvocation::from_prepared_prompt(assets, prepared_prompt, max_seq)?,
        ExecutionStrategy::Run(execution_route(&state)),
    );
    let output = timeout(state.inference_timeout, request.run(&mut on_delta))
        .await
        .map_err(|_| GenerationError::Timeout(state.inference_timeout))??;

    Ok(output)
}

fn execution_route(state: &GatewayState) -> ExecutionRoute {
    if state.local {
        ExecutionRoute::Local
    } else {
        ExecutionRoute::remote(state.node_id, state.retries, 0)
    }
}
