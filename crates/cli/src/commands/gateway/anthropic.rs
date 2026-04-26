use super::state::{GatewayState, PreparedGeneration};
use super::{SseSender, next_id, parse_json_body, sse_event_data, sse_response};
use anyhow::anyhow;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use catgrad_llm::helpers::{ToolCall, ToolUseStep};
use catgrad_llm::types::anthropic;
use serde_json::{Map, Value};
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
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
        return stream_response(prepared);
    }

    respond(prepared).await
}

fn stream_response(prepared: PreparedGeneration) -> Response {
    sse_response(move |tx| async move {
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

        // When tools are requested, buffer the whole generation so we can emit
        // ToolUse content blocks at the end. Otherwise stream text deltas.
        let (generated, accumulated) = if prepared.has_tools {
            let mut buf = String::new();
            let result = prepared
                .stream_text(|delta| {
                    buf.push_str(delta);
                    Ok(())
                })
                .await;
            (result, buf)
        } else {
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

            let result = prepared
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
            (result, String::new())
        };

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

        let stop_reason = if prepared.has_tools {
            let step = prepared.parse_tool_calls(&accumulated).unwrap_or_else(|err| {
                warn!(error = %err, "failed to parse tool calls from streamed text");
                None
            });
            match step {
                Some(step) => {
                    if emit_tool_use_blocks(&tx, &step).is_err() {
                        return;
                    }
                    anthropic::StopReason::ToolUse
                }
                None => {
                    if !accumulated.is_empty()
                        && emit_text_block(&tx, 0, &accumulated).is_err()
                    {
                        return;
                    }
                    anthropic::StopReason::EndTurn
                }
            }
        } else {
            anthropic::StopReason::EndTurn
        };

        if tx
            .send(Ok(sse_event_data(
                "message_delta",
                &anthropic::MessageStreamEvent::MessageDelta {
                    delta: anthropic::StreamMessageDelta {
                        stop_reason: Some(stop_reason),
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
    })
}

fn emit_tool_use_blocks(tx: &SseSender, step: &ToolUseStep) -> Result<(), ()> {
    let mut index: u32 = 0;
    if !step.assistant_content.is_empty() {
        emit_text_block(tx, index, &step.assistant_content)?;
        index += 1;
    }
    for (call_idx, call) in step.tool_calls.iter().enumerate() {
        emit_tool_use_block(tx, index, call_idx, call)?;
        index += 1;
    }
    Ok(())
}

fn emit_text_block(tx: &SseSender, index: u32, text: &str) -> Result<(), ()> {
    send_event(
        tx,
        "content_block_start",
        &anthropic::MessageStreamEvent::ContentBlockStart {
            index,
            content_block: anthropic::ContentBlock::Text {
                text: String::new(),
            },
        },
    )?;
    send_event(
        tx,
        "content_block_delta",
        &anthropic::MessageStreamEvent::ContentBlockDelta {
            index,
            delta: anthropic::ContentBlockDelta::TextDelta {
                text: text.to_string(),
            },
        },
    )?;
    send_event(
        tx,
        "content_block_stop",
        &anthropic::MessageStreamEvent::ContentBlockStop { index },
    )
}

fn emit_tool_use_block(
    tx: &SseSender,
    index: u32,
    call_idx: usize,
    call: &ToolCall,
) -> Result<(), ()> {
    send_event(
        tx,
        "content_block_start",
        &anthropic::MessageStreamEvent::ContentBlockStart {
            index,
            content_block: anthropic::ContentBlock::ToolUse {
                id: format!("toolu_{call_idx}"),
                name: call.name.clone(),
                input: Value::Object(Map::new()),
            },
        },
    )?;
    let partial_json = serde_json::to_string(&call.arguments).unwrap_or_else(|_| "{}".to_string());
    send_event(
        tx,
        "content_block_delta",
        &anthropic::MessageStreamEvent::ContentBlockDelta {
            index,
            delta: anthropic::ContentBlockDelta::InputJsonDelta { partial_json },
        },
    )?;
    send_event(
        tx,
        "content_block_stop",
        &anthropic::MessageStreamEvent::ContentBlockStop { index },
    )
}

fn send_event(
    tx: &SseSender,
    event: &str,
    payload: &anthropic::MessageStreamEvent,
) -> Result<(), ()> {
    tx.send(Ok(sse_event_data(event, payload))).map_err(|_| ())
}

async fn respond(prepared: PreparedGeneration) -> Response {
    let (generated, text) = match prepared.run_to_text().await {
        Ok(result) => result,
        Err(err) => return err.into_response(),
    };

    let step = prepared.parse_tool_calls(&text).unwrap_or_else(|err| {
        warn!(error = %err, "failed to parse tool calls from generated text");
        None
    });
    let (content, stop_reason) = match step {
        Some(step) => (tool_use_blocks(&step), anthropic::StopReason::ToolUse),
        None => (
            vec![anthropic::ContentBlock::Text { text }],
            anthropic::StopReason::EndTurn,
        ),
    };

    let response = anthropic::MessageResponse::builder()
        .id(next_id("msg"))
        .message_type(Some("message".to_string()))
        .role("assistant".to_string())
        .content(content)
        .model(prepared.model.clone())
        .stop_reason(Some(stop_reason))
        .usage(anthropic::AnthropicUsage::new(
            prepared.prompt_tokens,
            generated.completion_tokens,
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
