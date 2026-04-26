use super::state::{GatewayState, GenerationEvent, PreparedGeneration};
use super::{
    next_id, now_unix, parse_json_body, provenance_sse_event, receipt_sse_event, sse_data,
    sse_response,
};
use crate::execution::{Outcome, StopReason};
use async_stream::stream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use catgrad_llm::helpers::{ToolCall, ToolUseStep};
use catgrad_llm::types::openai;
use futures::StreamExt;
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<openai::ChatCompletionRequest>(&body, "OpenAI") {
        Ok(req) => req,
        Err(err) => return err.into_response(),
    };
    let stream_response_flag = req.stream == Some(true);
    let include_usage = req
        .stream_options
        .as_ref()
        .and_then(|options| options.include_usage)
        .unwrap_or(false);
    let prepared = match state.prepare_openai(&req).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream_response_flag {
        return stream_response(prepared, include_usage);
    }
    respond(prepared).await
}

fn stream_response(prepared: PreparedGeneration, include_usage: bool) -> Response {
    let id = next_id("chatcmpl");
    let created = now_unix();
    let model = prepared.model.clone();
    let assets = prepared.assets.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let has_tools = prepared.has_tools;
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();

    let stream_provenance = provenance.clone();
    let mut response = sse_response(stream! {
        // Initial in-band provenance frame for browser EventSource clients
        // (which can't read response headers). Skipped when provenance is
        // unknown pre-flight (e.g. RemoteDiscovery — quote happens lazily).
        if let Some(prov) = stream_provenance.as_ref() {
            yield Ok(provenance_sse_event(prov));
        }

        // Initial role frame.
        yield Ok(sse_data(&build_chunk(
            &id,
            created,
            &model,
            openai::ChatDelta {
                role: Some("assistant".to_string()),
                ..Default::default()
            },
            None,
        )));

        let inner = prepared.stream();
        tokio::pin!(inner);

        // For tools we buffer the whole generation (so we can parse tool-call
        // blocks and emit them in one frame). For plain text we forward every
        // delta as it arrives.
        let mut tool_buffer = String::new();
        let mut outcome: Option<Outcome> = None;
        let mut transport_error: Option<String> = None;
        let mut timed_out = false;

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Delta(text)))) => {
                    if has_tools {
                        tool_buffer.push_str(&text);
                    } else {
                        yield Ok(sse_data(&build_chunk(&id, created, &model, text_delta(text), None)));
                    }
                }
                Ok(Some(Ok(GenerationEvent::Done(o)))) => {
                    outcome = Some(o);
                    break;
                }
                Ok(Some(Err(err))) => {
                    transport_error = Some(format!("{err:#}"));
                    break;
                }
                Ok(None) => {
                    transport_error =
                        Some("execution stream ended without terminal outcome".to_string());
                    break;
                }
                Err(_) => {
                    timed_out = true;
                    break;
                }
            }
        }

        // Render terminal frames based on what we observed.
        if let Some(error) = transport_error {
            yield Ok(sse_data(&json!({
                "error": { "message": format!("Inference error: {error}") }
            })));
            yield Ok(axum::response::sse::Event::default().data("[DONE]"));
            return;
        }
        if timed_out {
            yield Ok(sse_data(&json!({
                "error": { "message": format!(
                    "inference timed out after {}s",
                    super::timeout_secs_until(deadline)
                )}
            })));
            yield Ok(axum::response::sse::Event::default().data("[DONE]"));
            return;
        }
        let outcome = outcome.expect("loop only breaks with a terminal observation");
        match outcome {
            Outcome::Failed { error, .. } => {
                yield Ok(sse_data(&json!({
                    "error": { "message": format!("Inference error: {error}") }
                })));
                yield Ok(axum::response::sse::Event::default().data("[DONE]"));
                return;
            }
            Outcome::Completed {
                stop_reason,
                total_tokens,
                receipt_cid,
            } => {
                let finish = if has_tools {
                    let parsed = assets.parse_tool_calls(&tool_buffer).unwrap_or_else(|err| {
                        warn!(error = %err, "failed to parse tool calls from streamed text");
                        None
                    });
                    match parsed {
                        Some(step) => {
                            if !step.assistant_content.is_empty() {
                                yield Ok(sse_data(&build_chunk(
                                    &id,
                                    created,
                                    &model,
                                    text_delta(step.assistant_content.clone()),
                                    None,
                                )));
                            }
                            let tool_calls = step
                                .tool_calls
                                .iter()
                                .enumerate()
                                .map(|(idx, call)| tool_call_value(idx, call))
                                .collect();
                            yield Ok(sse_data(&build_chunk(
                                &id,
                                created,
                                &model,
                                openai::ChatDelta {
                                    tool_calls: Some(tool_calls),
                                    ..Default::default()
                                },
                                None,
                            )));
                            openai::FinishReason::ToolCalls
                        }
                        None => {
                            yield Ok(sse_data(&build_chunk(&id, created, &model, text_delta(tool_buffer), None)));
                            map_finish_reason(stop_reason, false)
                        }
                    }
                } else {
                    map_finish_reason(stop_reason, false)
                };

                yield Ok(sse_data(&build_chunk(&id, created, &model, openai::ChatDelta::default(), Some(finish))));

                if include_usage {
                    let usage_chunk = openai::ChatCompletionChunk::builder()
                        .id(id.clone())
                        .object("chat.completion.chunk".to_string())
                        .created(created)
                        .model(model.clone())
                        .choices(vec![])
                        .usage(Some(openai::Usage::from_counts(
                            prompt_tokens,
                            u32::try_from(total_tokens).unwrap_or(u32::MAX),
                        )))
                        .build();
                    yield Ok(sse_data(&usage_chunk));
                }

                yield Ok(receipt_sse_event(&receipt_cid));
                yield Ok(axum::response::sse::Event::default().data("[DONE]"));
            }
        }
    });
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    }
    response
}

async fn respond(prepared: PreparedGeneration) -> Response {
    let id = next_id("chatcmpl");
    let created = now_unix();
    let model = prepared.model.clone();
    let assets = prepared.assets.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();

    let stream = prepared.stream();
    tokio::pin!(stream);
    let mut text = String::new();
    let outcome = loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(GenerationEvent::Delta(d)))) => text.push_str(&d),
            Ok(Some(Ok(GenerationEvent::Done(o)))) => break Ok(o),
            Ok(Some(Err(err))) => break Err(format!("Inference error: {err:#}")),
            Ok(None) => break Err("execution stream ended without terminal outcome".to_string()),
            Err(_) => {
                break Err(format!(
                    "inference timed out after {}s",
                    super::timeout_secs_until(deadline)
                ));
            }
        }
    };

    let outcome = match outcome {
        Ok(o) => o,
        Err(message) => {
            error!(%message, "openai chat request failed");
            return super::json_error(StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };

    let (total_tokens, stop_reason, receipt_cid) = match outcome {
        Outcome::Completed {
            total_tokens,
            stop_reason,
            receipt_cid,
        } => (total_tokens, stop_reason, receipt_cid),
        Outcome::Failed { position, error } => {
            warn!(position, %error, "openai chat request failed");
            return super::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
    };

    let (message, finish_reason) = match assets.parse_tool_calls(&text) {
        Ok(Some(step)) => (tool_call_message(&step), openai::FinishReason::ToolCalls),
        Ok(None) => (
            openai::ChatMessage::assistant(text),
            map_finish_reason(stop_reason, false),
        ),
        Err(err) => {
            warn!(error = %err, "failed to parse tool calls from generated text");
            (
                openai::ChatMessage::assistant(text),
                map_finish_reason(stop_reason, false),
            )
        }
    };

    let response = openai::ChatCompletionResponse::builder()
        .id(id)
        .object("chat.completion".to_string())
        .created(created)
        .model(model)
        .choices(vec![
            openai::ChatChoice::builder()
                .index(0)
                .message(message)
                .finish_reason(Some(finish_reason))
                .build(),
        ])
        .usage(Some(openai::Usage::from_counts(
            prompt_tokens,
            u32::try_from(total_tokens).unwrap_or(u32::MAX),
        )))
        .build();

    let mut response = Json(response).into_response();
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    }
    response.extensions_mut().insert(receipt_cid);
    response
}

fn map_finish_reason(stop: StopReason, has_tool_calls: bool) -> openai::FinishReason {
    match (stop, has_tool_calls) {
        (StopReason::EndOfSequence, true) => openai::FinishReason::ToolCalls,
        (StopReason::EndOfSequence, false) | (StopReason::Cancelled, _) => {
            openai::FinishReason::Stop
        }
        (StopReason::MaxNewTokens, _) => openai::FinishReason::Length,
    }
}

fn text_delta(content: String) -> openai::ChatDelta {
    openai::ChatDelta {
        content: Some(content),
        ..Default::default()
    }
}

fn build_chunk(
    id: &str,
    created: i64,
    model: &str,
    delta: openai::ChatDelta,
    finish: Option<openai::FinishReason>,
) -> openai::ChatCompletionChunk {
    openai::ChatCompletionChunk::builder()
        .id(id.to_string())
        .object("chat.completion.chunk".to_string())
        .created(created)
        .model(model.to_string())
        .choices(vec![
            openai::ChatStreamChoice::builder()
                .index(0)
                .delta(delta)
                .finish_reason(finish)
                .build(),
        ])
        .build()
}

fn tool_call_message(step: &ToolUseStep) -> openai::ChatMessage {
    let tool_calls: Vec<Value> = step
        .tool_calls
        .iter()
        .enumerate()
        .map(|(idx, call)| tool_call_value(idx, call))
        .collect();
    let content = if step.assistant_content.is_empty() {
        None
    } else {
        Some(openai::MessageContent::Text(step.assistant_content.clone()))
    };
    openai::ChatMessage::builder()
        .role("assistant".to_string())
        .content(content)
        .tool_calls(Some(tool_calls))
        .build()
}

fn tool_call_value(index: usize, call: &ToolCall) -> Value {
    let arguments = serde_json::to_string(&call.arguments).unwrap_or_else(|_| "{}".to_string());
    json!({
        "id": format!("call_{index}"),
        "type": "function",
        "function": {
            "name": call.name,
            "arguments": arguments,
        },
    })
}
