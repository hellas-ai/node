use crate::commands::local_model::LocalModelAssets;
use crate::commands::{bind_client_endpoint, CliResult};
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
use catgrad_llm::IncrementalDetokenizer;
use futures::StreamExt;
use hellas_rpc::discovery::{
    shared_pkarr_client, AcceptedQuote, QuoteError, QuoteStream, QuoteStreamBuilder,
};
use hellas_rpc::pb::hellas::execute_client::ExecuteClient;
use hellas_rpc::pb::hellas::{
    ExecuteRequest, ExecuteStatusRequest, ExecutionStatus, GetQuoteRequest, GetQuoteResponse,
};
use hellas_rpc::service::ExecuteService;
use hellas_rpc::{decode_token_ids, GRPC_MESSAGE_LIMIT};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tokio::time::Duration;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::Channel;
use tonic_iroh_transport::iroh::address_lookup::mdns::MdnsAddressLookup;
use tonic_iroh_transport::iroh::address_lookup::pkarr::dht::DhtAddressLookup;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::swarm::{DhtBackend, Locator, MdnsBackend, ServiceRegistry};
use tonic_iroh_transport::IrohConnect;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct GatewayState {
    node_id: Option<EndpointId>,
    retries: usize,
    default_max_tokens: u32,
    force_model: Option<String>,
    model_cache: Arc<RwLock<HashMap<String, Arc<LocalModelAssets>>>>,
}

struct GenerationOutput {
    text: String,
    prompt_tokens: u32,
    completion_tokens: u32,
}

struct PreparedRemoteExecution {
    _endpoint: Endpoint,
    client: ExecuteClient<Channel>,
    quote: GetQuoteResponse,
}

pub async fn run(
    host: String,
    port: u16,
    node_id: Option<EndpointId>,
    retries: usize,
    default_max_tokens: u32,
    force_model: Option<String>,
) -> CliResult<()> {
    let state = Arc::new(GatewayState {
        node_id,
        retries,
        default_max_tokens,
        force_model,
        model_cache: Arc::new(RwLock::new(HashMap::new())),
    });

    let app = Router::new()
        .route("/v1/chat/completions", post(handle_openai))
        .route("/v1/messages", post(handle_anthropic))
        .route("/v1/completions", post(handle_plain))
        .with_state(state.clone());

    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind gateway on {addr}"))?;

    println!("Hellas gateway listening on http://{addr}");
    println!("POST /v1/chat/completions (OpenAI)");
    println!("POST /v1/messages (Anthropic)");
    println!("POST /v1/completions (plain)");
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
        Err(err) => return err,
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
                    .finish_reason(Some(openai_finish_reason()))
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
                        generated.prompt_tokens,
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

    let generated =
        match generate_prepared(state, assets, prepared.clone(), max_tokens, |_delta| Ok(())).await
        {
            Ok(out) => out,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Inference error: {err}"),
                );
            }
        };

    let response = openai::ChatCompletionResponse::builder()
        .id(next_id("chatcmpl"))
        .object("chat.completion".to_string())
        .created(now_unix())
        .model(model)
        .choices(vec![openai::ChatChoice::builder()
            .index(0)
            .message(openai::ChatMessage::assistant(generated.text))
            .finish_reason(Some(openai_finish_reason()))
            .build()])
        .usage(Some(openai::Usage::from_counts(
            generated.prompt_tokens,
            generated.completion_tokens,
        )))
        .build();

    Json(response).into_response()
}

fn openai_finish_reason() -> openai::FinishReason {
    openai::FinishReason::Stop
}

async fn handle_anthropic(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<anthropic::MessageRequest>(&body, "Anthropic") {
        Ok(req) => req,
        Err(err) => return err,
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
                            stop_reason: Some(anthropic_stop_reason()),
                            ..Default::default()
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

    let generated =
        match generate_prepared(state, assets, prepared.clone(), max_tokens, |_delta| Ok(())).await
        {
            Ok(out) => out,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Inference error: {err}"),
                );
            }
        };

    let response = anthropic::MessageResponse::builder()
        .id(next_id("msg"))
        .message_type(Some("message".to_string()))
        .role("assistant".to_string())
        .content(vec![anthropic::ContentBlock::Text {
            text: generated.text,
        }])
        .model(model)
        .stop_reason(Some(anthropic_stop_reason()))
        .usage(anthropic::AnthropicUsage::new(
            generated.prompt_tokens,
            generated.completion_tokens,
        ))
        .build();

    Json(response).into_response()
}

fn anthropic_stop_reason() -> anthropic::StopReason {
    anthropic::StopReason::EndTurn
}

async fn handle_plain(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<plain::CompletionRequest>(&body, "completion") {
        Ok(req) => req,
        Err(err) => return err,
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

    let generated =
        match generate_prepared(state, assets, prepared, max_tokens, |_delta| Ok(())).await {
            Ok(out) => out,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Inference error: {err}"),
                );
            }
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
            generated.prompt_tokens,
            generated.completion_tokens,
        )))
        .build();

    Json(response).into_response()
}

fn parse_json_body<T: serde::de::DeserializeOwned>(
    body: &Bytes,
    protocol: &str,
) -> Result<T, Response> {
    from_json_slice::<T>(body).map_err(|err| {
        json_error(
            StatusCode::BAD_REQUEST,
            format!("Invalid {protocol} request: {err}"),
        )
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
) -> anyhow::Result<Arc<LocalModelAssets>> {
    {
        let cache = state.model_cache.read().await;
        if let Some(assets) = cache.get(model) {
            return Ok(assets.clone());
        }
    }

    let model_name = model.to_string();
    let assets = tokio::task::spawn_blocking(move || LocalModelAssets::load(&model_name))
        .await
        .context("local model loader panicked")??;

    let assets = Arc::new(assets);
    let mut cache = state.model_cache.write().await;
    cache.insert(model.to_string(), assets.clone());
    Ok(assets)
}

async fn generate_prepared<F>(
    state: Arc<GatewayState>,
    assets: Arc<LocalModelAssets>,
    prepared_prompt: catgrad_llm::PreparedPrompt,
    max_seq: u32,
    mut on_delta: F,
) -> anyhow::Result<GenerationOutput>
where
    F: FnMut(&str) -> anyhow::Result<()> + Send,
{
    let max_attempts = state.retries.saturating_add(1);
    for attempt in 1..=max_attempts {
        let prepared = prepare_generation(
            state.clone(),
            assets.clone(),
            prepared_prompt.clone(),
            max_seq,
        )
        .await?;

        match execute_prepared(
            prepared,
            assets.clone(),
            prepared_prompt.clone(),
            &mut on_delta,
        )
        .await
        {
            Ok(output) => return Ok(output),
            Err(err) => {
                if attempt == max_attempts {
                    return Err(err.context(format!("max retries ({}) exceeded", state.retries)));
                }
                tracing::warn!(attempt, "execution failed, retrying: {err:#}");
            }
        }
    }

    Err(anyhow!("max retries ({}) exceeded", state.retries))
}

async fn prepare_generation(
    state: Arc<GatewayState>,
    assets: Arc<LocalModelAssets>,
    prepared_prompt: catgrad_llm::PreparedPrompt,
    max_seq: u32,
) -> anyhow::Result<PreparedRemoteExecution> {
    let quote_req = assets.build_quote_request(&prepared_prompt, max_seq)?;

    match state.node_id {
        Some(node_id) => prepare_direct(node_id, quote_req).await,
        None => prepare_discovery(quote_req).await,
    }
}

async fn prepare_direct(
    node_id: EndpointId,
    quote_req: GetQuoteRequest,
) -> anyhow::Result<PreparedRemoteExecution> {
    let endpoint = bind_client_endpoint().await?;
    let channel = ExecuteService::connect(&endpoint, node_id.into())
        .await
        .with_context(|| format!("failed to connect to node {node_id}"))?;
    let mut client = ExecuteClient::new(channel)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
    let quote = client
        .get_quote(quote_req)
        .await
        .with_context(|| format!("node {node_id} declined quote"))?
        .into_inner();

    Ok(PreparedRemoteExecution {
        _endpoint: endpoint,
        client,
        quote,
    })
}

async fn prepare_discovery(quote_req: GetQuoteRequest) -> anyhow::Result<PreparedRemoteExecution> {
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    let mdns = MdnsAddressLookup::builder()
        .advertise(false)
        .service_name("hellas")
        .build(endpoint.id())
        .context("failed to start mDNS discovery")?;
    endpoint.address_lookup().add(mdns.clone());

    let shared_pkarr = shared_pkarr_client().context("failed to initialize shared pkarr client")?;
    let shared_dht = Arc::new(
        shared_pkarr
            .dht()
            .ok_or_else(|| anyhow!("shared pkarr client has no DHT handle"))?,
    );

    let pkarr = DhtAddressLookup::builder()
        .client(shared_pkarr)
        .n0_dns_pkarr_relay()
        .no_publish()
        .build()
        .context("failed to initialize pkarr+DHT discovery")?;
    endpoint.address_lookup().add(pkarr);

    let mut registry = ServiceRegistry::new(&endpoint);
    registry.add(MdnsBackend::new(mdns));
    registry.add(DhtBackend::with_dht(&endpoint, shared_dht));
    let locator = registry
        .find::<ExecuteService>()
        .timeout(DISCOVERY_TIMEOUT)
        .start();

    let mut quotes = QuoteStreamBuilder::new(quote_req).start(locator);
    let (client, quote) = next_accepted_quote(&mut quotes).await?;
    Ok(PreparedRemoteExecution {
        _endpoint: endpoint,
        client,
        quote,
    })
}

async fn next_accepted_quote(quotes: &mut QuoteStream<Locator>) -> anyhow::Result<AcceptedQuote> {
    while let Some(result) = quotes.next().await {
        match result {
            Ok(accepted) => return Ok(accepted),
            Err(QuoteError::Declined(status)) => {
                tracing::info!("provider declined quote: {status}")
            }
            Err(QuoteError::ConnectFailed(err)) => {
                tracing::debug!("candidate connect error: {err:#}")
            }
        }
    }
    Err(anyhow!("no provider could serve the request"))
}

async fn execute_and_collect<F>(
    client: &mut ExecuteClient<Channel>,
    quote: &GetQuoteResponse,
    assets: Arc<LocalModelAssets>,
    prepared_prompt: catgrad_llm::PreparedPrompt,
    on_delta: &mut F,
) -> anyhow::Result<(String, u32)>
where
    F: FnMut(&str) -> anyhow::Result<()> + Send,
{
    let execute = client
        .execute(ExecuteRequest {
            quote_id: quote.quote_id.clone(),
            stream_batch_size: Some(1),
        })
        .await
        .context("Execute RPC failed")?
        .into_inner();

    let mut stream = client
        .execute_stream(ExecuteStatusRequest {
            execution_id: execute.execution_id,
        })
        .await
        .context("ExecuteStream RPC failed")?
        .into_inner();

    let mut decoder = IncrementalDetokenizer::new(
        {
            let assets = Arc::clone(&assets);
            move |tokens| assets.decode_tokens(tokens)
        },
        &prepared_prompt.stop_token_ids,
    );
    let mut completion_tokens = 0u32;
    while let Some(progress) = stream.next().await {
        let progress = progress.context("ExecuteStream RPC progress failed")?;
        let status =
            ExecutionStatus::try_from(progress.status).unwrap_or(ExecutionStatus::Unspecified);
        completion_tokens = u32::try_from(progress.progress).unwrap_or(u32::MAX);
        if !progress.chunk.is_empty() {
            let token_ids = decode_token_ids(&progress.chunk)
                .map_err(|err| anyhow!("failed to decode streamed token batch: {err}"))?;
            let token_ids: Vec<i32> = token_ids
                .into_iter()
                .map(|token| {
                    i32::try_from(token)
                        .map_err(|_| anyhow!("streamed token id {token} exceeds i32 range"))
                })
                .collect::<Result<_, _>>()?;
            let delta = decoder
                .push_tokens(&token_ids)
                .context("failed to detokenize streamed token batch")?;
            if !delta.is_empty() {
                on_delta(&delta)?;
            }
        }
        if status == ExecutionStatus::Failed {
            return Err(anyhow!("remote execution failed"));
        }
        if status == ExecutionStatus::Completed {
            break;
        }
    }

    Ok((decoder.finish(), completion_tokens))
}

async fn execute_prepared<F>(
    mut prepared: PreparedRemoteExecution,
    assets: Arc<LocalModelAssets>,
    prepared_prompt: catgrad_llm::PreparedPrompt,
    on_delta: &mut F,
) -> anyhow::Result<GenerationOutput>
where
    F: FnMut(&str) -> anyhow::Result<()> + Send,
{
    let (text, completion_tokens) = execute_and_collect(
        &mut prepared.client,
        &prepared.quote,
        assets,
        prepared_prompt.clone(),
        on_delta,
    )
    .await?;

    Ok(GenerationOutput {
        text,
        prompt_tokens: prepared_prompt.input_ids.len() as u32,
        completion_tokens,
    })
}
