use super::state::{GatewayState, GenerationEvent, PreparedGeneration};
use super::{
    next_id, parse_json_body, provenance_sse_event, receipt_sse_event, sse_event_data,
    sse_response,
};
use crate::execution::{Outcome, StopReason as ExecStopReason};
use async_stream::stream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::Event;
use axum::response::{IntoResponse, Response};
use catgrad_llm::runtime::chat::{
    DecodeEvent, IncrementalToolCallParser, StopReason as ParserStopReason,
};
use catgrad_llm::types::anthropic;
use futures::StreamExt;
use serde_json::{Map, Value};
use std::collections::HashMap;
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

/// One in-flight tool call as the streaming surface needs it. The
/// wire ID is emitted at `ToolCallStart` time and not held here —
/// subsequent `ArgsDelta` / `End` events on the wire reference the
/// content-block index, not the tool-call ID. See "Tool-call IDs" and
/// "Anthropic content-block indexing — separate counter" in the
/// project plan's P6 implementation contract.
struct CallInProgress {
    /// Anthropic content-block index assigned at start time. Distinct
    /// from the parser's tool-call index.
    block_index: u32,
}

/// What block (if any) is currently open in the streaming Anthropic
/// response. Anthropic requires every `content_block_*` event to carry
/// a stable index across `start` / `delta`* / `stop`, and forbids
/// interleaving deltas across different blocks. The tracker enforces
/// that by closing a text block before opening a tool-use block (and
/// vice versa).
enum OpenBlock {
    None,
    Text { index: u32 },
    ToolUse { block_index: u32 },
}

fn map_to_parser_stop(stop: ExecStopReason) -> ParserStopReason {
    match stop {
        ExecStopReason::EndOfSequence => ParserStopReason::EndOfText,
        ExecStopReason::MaxNewTokens => ParserStopReason::MaxTokens,
        ExecStopReason::Cancelled => ParserStopReason::EndOfText,
    }
}

/// Map executor `StopReason` + `saw_tool_call` to the Anthropic wire
/// `stop_reason`. `tool_use` wins over `end_turn` whenever any call
/// was emitted.
fn map_stop_reason(stop: ExecStopReason, saw_tool_call: bool) -> anthropic::StopReason {
    if saw_tool_call {
        return anthropic::StopReason::ToolUse;
    }
    match stop {
        ExecStopReason::EndOfSequence | ExecStopReason::Cancelled => {
            anthropic::StopReason::EndTurn
        }
        ExecStopReason::MaxNewTokens => anthropic::StopReason::MaxTokens,
    }
}

async fn respond(prepared: PreparedGeneration) -> Response {
    let id = next_id("msg");
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();
    let mut parser: Box<dyn IncrementalToolCallParser> = prepared
        .chat_turn
        .as_ref()
        .expect("Anthropic surface always carries a ChatTurn")
        .make_parser();

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

    let (total_tokens, exec_stop, receipt_cid) = match outcome {
        Outcome::Completed {
            total_tokens,
            stop_reason,
            receipt_cid,
        } => {
            info!(
                %receipt_cid,
                ?provenance,
                total_tokens,
                ?stop_reason,
                "anthropic message completion ready"
            );
            (total_tokens, stop_reason, receipt_cid)
        }
        Outcome::Failed { position, error } => {
            warn!(position, %error, "anthropic message request failed");
            return super::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
    };

    let parser_stop = map_to_parser_stop(exec_stop);
    let mut events = parser.feed(&text);
    events.extend(parser.finish(parser_stop));

    let (blocks, saw_tool_call) = match events_to_blocks(events) {
        Ok(out) => out,
        Err(message) => {
            warn!(%message, "anthropic message aborted with parser protocol error");
            return super::HttpError {
                status: StatusCode::BAD_GATEWAY,
                message,
            }
            .into_response();
        }
    };

    let response = anthropic::MessageResponse::builder()
        .id(id)
        .message_type(Some("message".to_string()))
        .role("assistant".to_string())
        .content(blocks)
        .model(model)
        .stop_reason(Some(map_stop_reason(exec_stop, saw_tool_call)))
        .usage(anthropic::AnthropicUsage::new(
            prompt_tokens,
            u32::try_from(total_tokens).unwrap_or(u32::MAX),
        ))
        .build();

    let mut response = Json(response).into_response();
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    }
    response.extensions_mut().insert(receipt_cid);
    response
}

fn stream_response(prepared: PreparedGeneration) -> Response {
    let id = next_id("msg");
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();
    let mut parser: Box<dyn IncrementalToolCallParser> = prepared
        .chat_turn
        .as_ref()
        .expect("Anthropic surface always carries a ChatTurn")
        .make_parser();

    let stream_provenance = provenance.clone();
    let mut response = sse_response(stream! {
        if let Some(prov) = stream_provenance.as_ref() {
            yield Ok(provenance_sse_event(prov));
        }

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

        let inner = prepared.stream();
        tokio::pin!(inner);

        let mut next_block_index: u32 = 0;
        let mut open: OpenBlock = OpenBlock::None;
        let mut in_progress: HashMap<usize, CallInProgress> = HashMap::new();
        let mut saw_tool_call = false;
        let mut outcome: Option<Outcome> = None;
        let mut transport_error: Option<String> = None;
        let mut timed_out = false;
        let mut protocol_error: Option<String> = None;

        // Per-token loop. Each delta is fed through the parser; events
        // are routed to text or tool-use block streams. Block
        // transitions (text → tool, tool → text, tool → tool) are
        // bracketed with content_block_stop / content_block_start so
        // the wire format never interleaves deltas across blocks.
        'outer: loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Delta(text)))) => {
                    let events = parser.feed(&text);
                    for event in events {
                        match event {
                            DecodeEvent::TextDelta(s) => {
                                let block_index = match open {
                                    OpenBlock::Text { index } => index,
                                    OpenBlock::ToolUse { block_index, .. } => {
                                        yield Ok(sse_event_data(
                                            "content_block_stop",
                                            &anthropic::MessageStreamEvent::ContentBlockStop {
                                                index: block_index,
                                            },
                                        ));
                                        let new_index = next_block_index;
                                        next_block_index += 1;
                                        open = OpenBlock::Text { index: new_index };
                                        yield Ok(text_block_start(new_index));
                                        new_index
                                    }
                                    OpenBlock::None => {
                                        let new_index = next_block_index;
                                        next_block_index += 1;
                                        open = OpenBlock::Text { index: new_index };
                                        yield Ok(text_block_start(new_index));
                                        new_index
                                    }
                                };
                                yield Ok(sse_event_data(
                                    "content_block_delta",
                                    &anthropic::MessageStreamEvent::ContentBlockDelta {
                                        index: block_index,
                                        delta: anthropic::ContentBlockDelta::TextDelta { text: s },
                                    },
                                ));
                            }
                            DecodeEvent::ToolCallStart { index, name } => {
                                saw_tool_call = true;
                                // Close any open block before starting
                                // the tool-use block.
                                match open {
                                    OpenBlock::Text { index: text_idx } => {
                                        yield Ok(sse_event_data(
                                            "content_block_stop",
                                            &anthropic::MessageStreamEvent::ContentBlockStop {
                                                index: text_idx,
                                            },
                                        ));
                                    }
                                    OpenBlock::ToolUse { block_index, .. } => {
                                        yield Ok(sse_event_data(
                                            "content_block_stop",
                                            &anthropic::MessageStreamEvent::ContentBlockStop {
                                                index: block_index,
                                            },
                                        ));
                                    }
                                    OpenBlock::None => {}
                                }
                                let block_index = next_block_index;
                                next_block_index += 1;
                                let wire_id = next_id("toolu");
                                in_progress.insert(index, CallInProgress { block_index });
                                open = OpenBlock::ToolUse { block_index };
                                yield Ok(sse_event_data(
                                    "content_block_start",
                                    &anthropic::MessageStreamEvent::ContentBlockStart {
                                        index: block_index,
                                        content_block: anthropic::ContentBlock::ToolUse {
                                            id: wire_id,
                                            name,
                                            input: Value::Object(Map::new()),
                                        },
                                    },
                                ));
                            }
                            DecodeEvent::ToolCallArgsDelta { index, delta } => {
                                if let Some(call) = in_progress.get(&index) {
                                    yield Ok(sse_event_data(
                                        "content_block_delta",
                                        &anthropic::MessageStreamEvent::ContentBlockDelta {
                                            index: call.block_index,
                                            delta: anthropic::ContentBlockDelta::InputJsonDelta {
                                                partial_json: delta,
                                            },
                                        },
                                    ));
                                }
                            }
                            DecodeEvent::ToolCallEnd { index, .. } => {
                                if let Some(call) = in_progress.remove(&index) {
                                    yield Ok(sse_event_data(
                                        "content_block_stop",
                                        &anthropic::MessageStreamEvent::ContentBlockStop {
                                            index: call.block_index,
                                        },
                                    ));
                                }
                                open = OpenBlock::None;
                            }
                            DecodeEvent::Stop { .. } => {}
                            DecodeEvent::UnknownTool { name, .. } => {
                                protocol_error = Some(format!(
                                    "model called unknown tool `{name}`"
                                ));
                                break 'outer;
                            }
                            DecodeEvent::InvalidArgs { name, errors, .. } => {
                                let detail = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");
                                protocol_error = Some(format!(
                                    "model called `{name}` with arguments that don't match the schema: {detail}"
                                ));
                                break 'outer;
                            }
                            DecodeEvent::ParseError { sentinel, source } => {
                                protocol_error = Some(format!(
                                    "model emitted malformed tool call within `{sentinel}`: {source}"
                                ));
                                break 'outer;
                            }
                        }
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

        // Protocol error path: emit Anthropic `error` event and
        // close. No `message_stop` follows — Anthropic clients treat
        // `error` as terminal.
        if let Some(message) = protocol_error {
            warn!(%message, "anthropic message aborted with parser protocol error");
            yield Ok(sse_event_data(
                "error",
                &anthropic::MessageStreamEvent::Error {
                    error: anthropic::StreamError {
                        error_type: "invalid_request_error".to_string(),
                        message,
                    },
                },
            ));
            return;
        }

        if let Some(error) = transport_error.or_else(|| {
            timed_out.then(|| {
                format!(
                    "inference timed out after {}s",
                    super::timeout_secs_until(deadline)
                )
            })
        }) {
            // Close any open block so the client sees a clean
            // bracketing before the error event.
            for ev in close_any_open_block(&open) {
                yield Ok(ev);
            }
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
                for ev in close_any_open_block(&open) {
                    yield Ok(ev);
                }
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
                receipt_cid,
            } => {
                info!(
                    %receipt_cid,
                    provenance = ?stream_provenance,
                    total_tokens,
                    ?stop_reason,
                    "anthropic message completion ready"
                );

                // Drain the parser's terminal events.
                let parser_stop = map_to_parser_stop(stop_reason);
                let tail = parser.finish(parser_stop);
                let mut tail_protocol_error: Option<String> = None;
                for event in tail {
                    match event {
                        DecodeEvent::TextDelta(s) => {
                            let block_index = match open {
                                OpenBlock::Text { index } => index,
                                OpenBlock::ToolUse { block_index, .. } => {
                                    yield Ok(sse_event_data(
                                        "content_block_stop",
                                        &anthropic::MessageStreamEvent::ContentBlockStop {
                                            index: block_index,
                                        },
                                    ));
                                    let new_index = next_block_index;
                                    next_block_index += 1;
                                    open = OpenBlock::Text { index: new_index };
                                    yield Ok(text_block_start(new_index));
                                    new_index
                                }
                                OpenBlock::None => {
                                    let new_index = next_block_index;
                                    next_block_index += 1;
                                    open = OpenBlock::Text { index: new_index };
                                    yield Ok(text_block_start(new_index));
                                    new_index
                                }
                            };
                            yield Ok(sse_event_data(
                                "content_block_delta",
                                &anthropic::MessageStreamEvent::ContentBlockDelta {
                                    index: block_index,
                                    delta: anthropic::ContentBlockDelta::TextDelta { text: s },
                                },
                            ));
                        }
                        DecodeEvent::Stop { .. } => {}
                        DecodeEvent::UnknownTool { name, .. } => {
                            tail_protocol_error = Some(format!(
                                "model called unknown tool `{name}`"
                            ));
                            break;
                        }
                        DecodeEvent::InvalidArgs { name, errors, .. } => {
                            let detail = errors
                                .iter()
                                .map(|e| e.to_string())
                                .collect::<Vec<_>>()
                                .join("; ");
                            tail_protocol_error = Some(format!(
                                "model called `{name}` with arguments that don't match the schema: {detail}"
                            ));
                            break;
                        }
                        DecodeEvent::ParseError { sentinel, source } => {
                            tail_protocol_error = Some(format!(
                                "model emitted malformed tool call within `{sentinel}`: {source}"
                            ));
                            break;
                        }
                        // Tool-call events on `finish()` shouldn't
                        // happen in practice (the parser would have
                        // already emitted them on the closing
                        // sentinel during `feed`), but if they do,
                        // ignore — the block stream would be
                        // incomplete and the call wasn't validated
                        // through the normal path.
                        _ => {}
                    }
                }

                if let Some(message) = tail_protocol_error {
                    warn!(%message, "anthropic message aborted with parser protocol error during finish");
                    yield Ok(sse_event_data(
                        "error",
                        &anthropic::MessageStreamEvent::Error {
                            error: anthropic::StreamError {
                                error_type: "invalid_request_error".to_string(),
                                message,
                            },
                        },
                    ));
                    return;
                }

                for ev in close_any_open_block(&open) {
                    yield Ok(ev);
                }

                yield Ok(sse_event_data(
                    "message_delta",
                    &anthropic::MessageStreamEvent::MessageDelta {
                        delta: anthropic::StreamMessageDelta {
                            stop_reason: Some(map_stop_reason(stop_reason, saw_tool_call)),
                        },
                        usage: anthropic::AnthropicUsage::new(
                            prompt_tokens,
                            u32::try_from(total_tokens).unwrap_or(u32::MAX),
                        ),
                    },
                ));
                yield Ok(receipt_sse_event(&receipt_cid));
                yield Ok(sse_event_data(
                    "message_stop",
                    &anthropic::MessageStreamEvent::MessageStop,
                ));
            }
        }
    });
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    }
    response
}

fn text_block_start(index: u32) -> Event {
    sse_event_data(
        "content_block_start",
        &anthropic::MessageStreamEvent::ContentBlockStart {
            index,
            content_block: anthropic::ContentBlock::Text {
                text: String::new(),
            },
        },
    )
}

/// Emit the `content_block_stop` event for whatever block (if any)
/// the streaming surface has open. Used before terminal frames so the
/// wire stream is well-bracketed.
fn close_any_open_block(open: &OpenBlock) -> Vec<Event> {
    match open {
        OpenBlock::None => Vec::new(),
        OpenBlock::Text { index } | OpenBlock::ToolUse { block_index: index, .. } => {
            vec![sse_event_data(
                "content_block_stop",
                &anthropic::MessageStreamEvent::ContentBlockStop { index: *index },
            )]
        }
    }
}

/// Walk a non-streaming parser event list into Anthropic content
/// blocks. Returns `(blocks, saw_tool_call)` on success, or an error
/// message string on a terminal parser event (caller maps to HTTP
/// 502). Text runs collapse into one Text block each; each completed
/// tool call becomes one ToolUse block; an empty result yields a
/// single empty Text block (Anthropic clients reject zero-block
/// content).
fn events_to_blocks(
    events: Vec<DecodeEvent>,
) -> Result<(Vec<anthropic::ContentBlock>, bool), String> {
    let mut blocks: Vec<anthropic::ContentBlock> = Vec::new();
    let mut current_text = String::new();
    let mut saw_tool_call = false;
    let mut in_progress: HashMap<usize, (String, String)> = HashMap::new();

    for event in events {
        match event {
            DecodeEvent::TextDelta(s) => current_text.push_str(&s),
            DecodeEvent::ToolCallStart { index, name } => {
                saw_tool_call = true;
                if !current_text.is_empty() {
                    blocks.push(anthropic::ContentBlock::Text {
                        text: std::mem::take(&mut current_text),
                    });
                }
                let wire_id = next_id("toolu");
                in_progress.insert(index, (wire_id, name));
            }
            DecodeEvent::ToolCallArgsDelta { .. } => {
                // Non-streaming: intra-call args deltas are ignored;
                // the final `args` Value on `ToolCallEnd` carries the
                // complete object.
            }
            DecodeEvent::ToolCallEnd { index, args } => {
                if let Some((wire_id, name)) = in_progress.remove(&index) {
                    let input = match args {
                        Value::Object(map) => Value::Object(map),
                        // Defensive: schema validation upstream
                        // ensures args is an object, but if it isn't
                        // we still emit something parseable.
                        other => other,
                    };
                    blocks.push(anthropic::ContentBlock::ToolUse {
                        id: wire_id,
                        name,
                        input,
                    });
                }
            }
            DecodeEvent::Stop { .. } => {}
            DecodeEvent::UnknownTool { name, .. } => {
                return Err(format!("model called unknown tool `{name}`"));
            }
            DecodeEvent::InvalidArgs { name, errors, .. } => {
                let detail = errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(format!(
                    "model called `{name}` with arguments that don't match the schema: {detail}"
                ));
            }
            DecodeEvent::ParseError { sentinel, source } => {
                return Err(format!(
                    "model emitted malformed tool call within `{sentinel}`: {source}"
                ));
            }
        }
    }

    if !current_text.is_empty() {
        blocks.push(anthropic::ContentBlock::Text {
            text: current_text,
        });
    }
    if blocks.is_empty() {
        blocks.push(anthropic::ContentBlock::Text {
            text: String::new(),
        });
    }
    Ok((blocks, saw_tool_call))
}

#[cfg(test)]
mod tests {
    //! Wire-mapping tests for the Anthropic surface. The non-streaming
    //! event-walker (`events_to_blocks`) is the unit under test;
    //! coverage maps to the same four scenarios as the OpenAI tests:
    //! no-tools sentinel passthrough, unknown tool, invalid args, and
    //! per-call atomic emission. The Anthropic-specific concerns
    //! (separate content-block index, tool_use vs text block
    //! transitions) are exercised directly.
    use super::*;
    use catgrad_llm::runtime::chat::{ParserError, SchemaError};
    use serde_json::json;

    /// No-tools surface: parser yields `TextDelta`s only; result is a
    /// single Text block. Sentinel-shaped text passes through.
    #[test]
    fn events_to_blocks_text_only_yields_one_text_block() {
        let events = vec![
            DecodeEvent::TextDelta("hello ".to_string()),
            DecodeEvent::TextDelta("<tool_call>literal</tool_call> world".to_string()),
            DecodeEvent::Stop {
                reason: ParserStopReason::EndOfText,
            },
        ];
        let (blocks, saw_tool_call) = events_to_blocks(events).unwrap();
        assert_eq!(blocks.len(), 1);
        let anthropic::ContentBlock::Text { text } = &blocks[0] else {
            panic!("expected Text block");
        };
        assert_eq!(text, "hello <tool_call>literal</tool_call> world");
        assert!(!saw_tool_call);
    }

    /// Unknown tool → terminal Err. Caller maps to HTTP 502.
    #[test]
    fn events_to_blocks_unknown_tool_is_err() {
        let events = vec![DecodeEvent::UnknownTool {
            name: "delete_db".to_string(),
            raw_args: json!({}),
        }];
        let err = events_to_blocks(events).unwrap_err();
        assert!(err.contains("delete_db"));
        assert!(err.contains("unknown tool"));
    }

    #[test]
    fn events_to_blocks_invalid_args_is_err_with_schema_detail() {
        let events = vec![DecodeEvent::InvalidArgs {
            name: "add".to_string(),
            args: json!({"a": "one"}),
            errors: vec![SchemaError {
                path: "/a".to_string(),
                message: "is not of type \"number\"".to_string(),
            }],
        }];
        let err = events_to_blocks(events).unwrap_err();
        assert!(err.contains("add"));
        assert!(err.contains("schema"));
        assert!(err.contains("/a"));
    }

    #[test]
    fn events_to_blocks_parse_error_is_err() {
        let events = vec![DecodeEvent::ParseError {
            sentinel: "<tool_call>",
            source: ParserError::MissingField("name"),
        }];
        let err = events_to_blocks(events).unwrap_err();
        assert!(err.contains("<tool_call>"));
    }

    /// Per-call atomic emission: a Start/ArgsDelta/End triple becomes
    /// one ToolUse block. The block carries the parsed args object,
    /// not the partial JSON delta.
    #[test]
    fn events_to_blocks_complete_call_yields_one_tool_use_block() {
        let events = vec![
            DecodeEvent::ToolCallStart {
                index: 0,
                name: "add".to_string(),
            },
            DecodeEvent::ToolCallArgsDelta {
                index: 0,
                delta: r#"{"a":1,"b":2}"#.to_string(),
            },
            DecodeEvent::ToolCallEnd {
                index: 0,
                args: json!({"a": 1, "b": 2}),
            },
            DecodeEvent::Stop {
                reason: ParserStopReason::EndOfText,
            },
        ];
        let (blocks, saw_tool_call) = events_to_blocks(events).unwrap();
        assert!(saw_tool_call);
        assert_eq!(blocks.len(), 1);
        let anthropic::ContentBlock::ToolUse { id, name, input } = &blocks[0] else {
            panic!("expected ToolUse block, got {:?}", blocks[0]);
        };
        assert_eq!(name, "add");
        assert!(id.starts_with("toolu-"));
        assert_eq!(input, &json!({"a": 1, "b": 2}));
    }

    /// Text → tool transition: text accumulates into a Text block,
    /// then a ToolUse block follows. Block order in the response
    /// matches event order.
    #[test]
    fn events_to_blocks_text_then_tool_emits_text_then_tool_use() {
        let events = vec![
            DecodeEvent::TextDelta("preamble ".to_string()),
            DecodeEvent::ToolCallStart {
                index: 0,
                name: "add".to_string(),
            },
            DecodeEvent::ToolCallEnd {
                index: 0,
                args: json!({"a": 1, "b": 2}),
            },
            DecodeEvent::Stop {
                reason: ParserStopReason::EndOfText,
            },
        ];
        let (blocks, _) = events_to_blocks(events).unwrap();
        assert_eq!(blocks.len(), 2);
        let anthropic::ContentBlock::Text { text } = &blocks[0] else {
            panic!("expected first block to be Text");
        };
        assert_eq!(text, "preamble ");
        assert!(matches!(&blocks[1], anthropic::ContentBlock::ToolUse { .. }));
    }

    #[test]
    fn map_stop_reason_tool_use_wins_over_end_turn() {
        // Per the P6 contract: tool_use wins whenever any call was
        // emitted, even on EOS.
        assert_eq!(
            map_stop_reason(ExecStopReason::EndOfSequence, true),
            anthropic::StopReason::ToolUse
        );
        assert_eq!(
            map_stop_reason(ExecStopReason::MaxNewTokens, true),
            anthropic::StopReason::ToolUse
        );
        assert_eq!(
            map_stop_reason(ExecStopReason::EndOfSequence, false),
            anthropic::StopReason::EndTurn
        );
        assert_eq!(
            map_stop_reason(ExecStopReason::MaxNewTokens, false),
            anthropic::StopReason::MaxTokens
        );
    }
}
