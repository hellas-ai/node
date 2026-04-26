use super::state::{GatewayState, GenerationEvent, PreparedGeneration};
use super::{next_id, parse_json_body, sse_event_data, sse_response};
use crate::execution::{Outcome, StopReason};
use async_stream::stream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::Event;
use axum::response::{IntoResponse, Response};
use catgrad_llm::helpers::{ToolCall, ToolUseStep};
use catgrad_llm::types::anthropic;
use futures::StreamExt;
use serde_json::{Map, Value};
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<anthropic::MessageRequest>(&body, "Anthropic") {
        Ok(req) => req,
        Err(err) => return err.into_response(),
    };
    let stream_response_flag = req.stream == Some(true);
    let prepared = match state.prepare_anthropic(&req).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream_response_flag {
        return stream_response(prepared);
    }
    respond(prepared).await
}

fn stream_response(prepared: PreparedGeneration) -> Response {
    let id = next_id("msg");
    let model = prepared.model.clone();
    let assets = prepared.assets.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let has_tools = prepared.has_tools;
    let deadline = prepared.deadline();

    sse_response(stream! {
        // message_start always first.
        let message_start = anthropic::MessageStreamEvent::MessageStart {
            message: anthropic::MessageResponse::builder()
                .id(id.clone())
                .message_type(Some("message".to_string()))
                .role("assistant".to_string())
                .content(vec![])
                .model(model)
                .usage(anthropic::AnthropicUsage::new(prompt_tokens, 0))
                .build(),
        };
        yield Ok(sse_event_data("message_start", &message_start));

        // For non-tools we open a content_block_start eagerly so deltas
        // arrive inside a block. For tools we wait until end-of-stream and
        // emit tool_use blocks at that point.
        if !has_tools {
            yield Ok(sse_event_data(
                "content_block_start",
                &anthropic::MessageStreamEvent::ContentBlockStart {
                    index: 0,
                    content_block: anthropic::ContentBlock::Text {
                        text: String::new(),
                    },
                },
            ));
        }

        let inner = prepared.stream();
        tokio::pin!(inner);

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
                        yield Ok(sse_event_data(
                            "content_block_delta",
                            &anthropic::MessageStreamEvent::ContentBlockDelta {
                                index: 0,
                                delta: anthropic::ContentBlockDelta::TextDelta { text },
                            },
                        ));
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

        // If we opened the eager content block, close it now (whatever happened).
        if !has_tools {
            yield Ok(sse_event_data(
                "content_block_stop",
                &anthropic::MessageStreamEvent::ContentBlockStop { index: 0 },
            ));
        }

        if let Some(error) = transport_error.or_else(|| {
            timed_out.then(|| format!("inference timed out after {}s", super::timeout_secs_until(deadline)))
        }) {
            yield Ok(sse_event_data(
                "error",
                &anthropic::MessageStreamEvent::Error {
                    error: anthropic::StreamError {
                        error_type: "invalid_request_error".to_string(),
                        message: format!("Inference error: {error}"),
                    },
                },
            ));
            return;
        }

        let outcome = outcome.expect("loop only breaks with a terminal observation");
        match outcome {
            Outcome::Failed { error, .. } => {
                yield Ok(sse_event_data(
                    "error",
                    &anthropic::MessageStreamEvent::Error {
                        error: anthropic::StreamError {
                            error_type: "invalid_request_error".to_string(),
                            message: format!("Inference error: {error}"),
                        },
                    },
                ));
                return;
            }
            Outcome::Completed {
                stop_reason,
                total_tokens,
                ..
            } => {
                let final_stop_reason = if has_tools {
                    let parsed = assets.parse_tool_calls(&tool_buffer).unwrap_or_else(|err| {
                        warn!(error = %err, "failed to parse tool calls from streamed text");
                        None
                    });
                    match parsed {
                        Some(step) => {
                            for event in tool_use_block_events(&step) {
                                yield Ok(event);
                            }
                            anthropic::StopReason::ToolUse
                        }
                        None => {
                            if !tool_buffer.is_empty() {
                                for event in text_block_events(0, &tool_buffer) {
                                    yield Ok(event);
                                }
                            }
                            map_stop_reason(stop_reason, false)
                        }
                    }
                } else {
                    map_stop_reason(stop_reason, false)
                };

                yield Ok(sse_event_data(
                    "message_delta",
                    &anthropic::MessageStreamEvent::MessageDelta {
                        delta: anthropic::StreamMessageDelta {
                            stop_reason: Some(final_stop_reason),
                        },
                        usage: anthropic::AnthropicUsage::new(
                            prompt_tokens,
                            u32::try_from(total_tokens).unwrap_or(u32::MAX),
                        ),
                    },
                ));
                yield Ok(sse_event_data(
                    "message_stop",
                    &anthropic::MessageStreamEvent::MessageStop,
                ));
            }
        }
    })
}

fn text_block_events(index: u32, text: &str) -> Vec<Event> {
    vec![
        sse_event_data(
            "content_block_start",
            &anthropic::MessageStreamEvent::ContentBlockStart {
                index,
                content_block: anthropic::ContentBlock::Text {
                    text: String::new(),
                },
            },
        ),
        sse_event_data(
            "content_block_delta",
            &anthropic::MessageStreamEvent::ContentBlockDelta {
                index,
                delta: anthropic::ContentBlockDelta::TextDelta {
                    text: text.to_string(),
                },
            },
        ),
        sse_event_data(
            "content_block_stop",
            &anthropic::MessageStreamEvent::ContentBlockStop { index },
        ),
    ]
}

fn tool_use_block_events(step: &ToolUseStep) -> Vec<Event> {
    let mut events = Vec::new();
    let mut index: u32 = 0;
    if !step.assistant_content.is_empty() {
        events.extend(text_block_events(index, &step.assistant_content));
        index += 1;
    }
    for (call_idx, call) in step.tool_calls.iter().enumerate() {
        events.extend(tool_use_block_event_set(index, call_idx, call));
        index += 1;
    }
    events
}

fn tool_use_block_event_set(index: u32, call_idx: usize, call: &ToolCall) -> Vec<Event> {
    let partial_json = serde_json::to_string(&call.arguments).unwrap_or_else(|_| "{}".to_string());
    vec![
        sse_event_data(
            "content_block_start",
            &anthropic::MessageStreamEvent::ContentBlockStart {
                index,
                content_block: anthropic::ContentBlock::ToolUse {
                    id: format!("toolu_{call_idx}"),
                    name: call.name.clone(),
                    input: Value::Object(Map::new()),
                },
            },
        ),
        sse_event_data(
            "content_block_delta",
            &anthropic::MessageStreamEvent::ContentBlockDelta {
                index,
                delta: anthropic::ContentBlockDelta::InputJsonDelta { partial_json },
            },
        ),
        sse_event_data(
            "content_block_stop",
            &anthropic::MessageStreamEvent::ContentBlockStop { index },
        ),
    ]
}

async fn respond(prepared: PreparedGeneration) -> Response {
    let id = next_id("msg");
    let model = prepared.model.clone();
    let assets = prepared.assets.clone();
    let prompt_tokens = prepared.prompt_tokens;
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
            error!(%message, "anthropic message request failed");
            return super::json_error(StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };

    let (total_tokens, stop_reason) = match outcome {
        Outcome::Completed {
            total_tokens,
            stop_reason,
            ..
        } => (total_tokens, stop_reason),
        Outcome::Failed { position, error } => {
            warn!(position, %error, "anthropic message request failed");
            return super::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
    };

    let step = assets.parse_tool_calls(&text).unwrap_or_else(|err| {
        warn!(error = %err, "failed to parse tool calls from generated text");
        None
    });
    let (content, stop_reason) = match step {
        Some(step) => (tool_use_blocks(&step), anthropic::StopReason::ToolUse),
        None => (
            vec![anthropic::ContentBlock::Text { text }],
            map_stop_reason(stop_reason, false),
        ),
    };

    let response = anthropic::MessageResponse::builder()
        .id(id)
        .message_type(Some("message".to_string()))
        .role("assistant".to_string())
        .content(content)
        .model(model)
        .stop_reason(Some(stop_reason))
        .usage(anthropic::AnthropicUsage::new(
            prompt_tokens,
            u32::try_from(total_tokens).unwrap_or(u32::MAX),
        ))
        .build();

    Json(response).into_response()
}

/// Convert a parsed tool-use step into Anthropic content blocks.
/// Emits a leading Text block for any assistant prefix, followed by one
/// ToolUse block per tool call.
fn tool_use_blocks(step: &ToolUseStep) -> Vec<anthropic::ContentBlock> {
    let mut blocks = Vec::new();
    if !step.assistant_content.is_empty() {
        blocks.push(anthropic::ContentBlock::Text {
            text: step.assistant_content.clone(),
        });
    }
    for (idx, call) in step.tool_calls.iter().enumerate() {
        blocks.push(anthropic::ContentBlock::ToolUse {
            id: format!("toolu_{idx}"),
            name: call.name.clone(),
            input: Value::Object(call.arguments.clone()),
        });
    }
    blocks
}

fn map_stop_reason(stop: StopReason, has_tool_calls: bool) -> anthropic::StopReason {
    match (stop, has_tool_calls) {
        (StopReason::EndOfSequence, true) => anthropic::StopReason::ToolUse,
        (StopReason::EndOfSequence, false) | (StopReason::Cancelled, _) => {
            anthropic::StopReason::EndTurn
        }
        (StopReason::MaxNewTokens, _) => anthropic::StopReason::MaxTokens,
    }
}
