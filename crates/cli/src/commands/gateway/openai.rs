use super::state::{GatewayState, GenerationEvent, PreparedGeneration};
use super::{
    next_id, now_unix, parse_json_body, provenance_sse_event, receipt_sse_event, sse_data,
    sse_response,
};
use crate::execution::{Outcome, StopReason as ExecStopReason};
use async_stream::stream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use catgrad_llm::runtime::chat::{
    DecodeEvent, IncrementalToolCallParser, StopReason as ParserStopReason,
};
use catgrad_llm::types::openai;
use futures::StreamExt;
use serde_json::{Value, json};
use std::collections::HashMap;
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

/// One in-flight tool call, keyed by parser `index`. The wire ID is
/// minted at `ToolCallStart` time and reused for the matching
/// `ArgsDelta` / `End` events. See "Tool-call IDs" in the project
/// plan's P6 implementation contract.
struct CallInProgress {
    wire_id: String,
    name: String,
    arguments: String,
}

/// Outcome of feeding one parser event into the response accumulator.
enum EventOutcome {
    /// Continue processing further events.
    Continue,
    /// Terminal protocol error; abort processing and return this 502
    /// to the client without emitting any further frames or
    /// `finish_reason`. Per the P6 contract, the trailing
    /// `Stop { ProtocolError }` from the parser is intentionally
    /// dropped — never translated into a "success" finish.
    Terminal(super::HttpError),
}

/// Apply one `DecodeEvent` to the response accumulator. Returns
/// `Terminal` for the three fatal parser variants; `Continue` for
/// everything else (including the success-shaped `Stop`, which the
/// caller maps to `finish_reason` based on `saw_tool_call`).
fn apply_event(
    event: DecodeEvent,
    content: &mut String,
    tool_calls: &mut Vec<Value>,
    saw_tool_call: &mut bool,
    in_progress: &mut HashMap<usize, CallInProgress>,
) -> EventOutcome {
    match event {
        DecodeEvent::TextDelta(s) => content.push_str(&s),
        DecodeEvent::ToolCallStart { index, name } => {
            *saw_tool_call = true;
            in_progress.insert(
                index,
                CallInProgress {
                    wire_id: next_id("call"),
                    name,
                    arguments: String::new(),
                },
            );
        }
        DecodeEvent::ToolCallArgsDelta { index, delta } => {
            if let Some(call) = in_progress.get_mut(&index) {
                call.arguments.push_str(&delta);
            }
        }
        DecodeEvent::ToolCallEnd { index, .. } => {
            if let Some(call) = in_progress.remove(&index) {
                tool_calls.push(json!({
                    "id": call.wire_id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": call.arguments,
                    },
                }));
            }
        }
        DecodeEvent::Stop { .. } => {
            // Terminal frames are emitted by the caller based on
            // `saw_tool_call` and the executor's StopReason; the
            // parser's own `Stop` event is informational here.
        }
        DecodeEvent::UnknownTool { name, .. } => {
            return EventOutcome::Terminal(super::HttpError {
                status: StatusCode::BAD_GATEWAY,
                message: format!("model called unknown tool `{name}`"),
            });
        }
        DecodeEvent::InvalidArgs { name, errors, .. } => {
            let detail = errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return EventOutcome::Terminal(super::HttpError {
                status: StatusCode::BAD_GATEWAY,
                message: format!(
                    "model called `{name}` with arguments that don't match the schema: {detail}"
                ),
            });
        }
        DecodeEvent::ParseError { sentinel, source } => {
            return EventOutcome::Terminal(super::HttpError {
                status: StatusCode::BAD_GATEWAY,
                message: format!(
                    "model emitted malformed tool call within `{sentinel}`: {source}"
                ),
            });
        }
    }
    EventOutcome::Continue
}

/// Map executor `StopReason` to the parser's `StopReason`. The parser
/// uses this in `finish()` to decide whether trailing buffered text
/// is still being assembled or should be flushed.
fn map_to_parser_stop(stop: ExecStopReason) -> ParserStopReason {
    match stop {
        ExecStopReason::EndOfSequence => ParserStopReason::EndOfText,
        ExecStopReason::MaxNewTokens => ParserStopReason::MaxTokens,
        // Cancelled: behave like a normal end so the parser flushes.
        ExecStopReason::Cancelled => ParserStopReason::EndOfText,
    }
}

/// Map executor `StopReason` + `saw_tool_call` to the OpenAI wire
/// `finish_reason`. `tool_calls` wins over `stop` whenever any call
/// was emitted — clients use this to decide whether to dispatch
/// tools.
fn map_finish_reason(stop: ExecStopReason, saw_tool_call: bool) -> openai::FinishReason {
    if saw_tool_call {
        return openai::FinishReason::ToolCalls;
    }
    match stop {
        ExecStopReason::EndOfSequence | ExecStopReason::Cancelled => openai::FinishReason::Stop,
        ExecStopReason::MaxNewTokens => openai::FinishReason::Length,
    }
}

async fn respond(prepared: PreparedGeneration) -> Response {
    let id = next_id("chatcmpl");
    let created = now_unix();
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();
    // Build the parser before consuming `prepared` into `stream`.
    // ChatTurn::make_parser is `'static` (owns Arc<ToolDirectory>),
    // so this composes cleanly with the streaming await loop.
    let mut parser: Box<dyn IncrementalToolCallParser> = prepared
        .chat_turn
        .as_ref()
        .expect("OpenAI surface always carries a ChatTurn")
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
            error!(%message, "openai chat request failed");
            return super::json_error(StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };

    let (total_tokens, stop_reason, receipt_cid) = match outcome {
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
                "openai chat completion ready"
            );
            (total_tokens, stop_reason, receipt_cid)
        }
        Outcome::Failed { position, error } => {
            warn!(position, %error, "openai chat request failed");
            return super::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
    };

    // Feed the full output through the parser in one shot. The
    // parser's `feed` + `finish` produce the structured event stream
    // that the response builder consumes.
    let mut content = String::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    let mut saw_tool_call = false;
    let mut in_progress: HashMap<usize, CallInProgress> = HashMap::new();

    let parser_stop = map_to_parser_stop(stop_reason);
    let mut events = parser.feed(&text);
    events.extend(parser.finish(parser_stop));

    for event in events {
        match apply_event(
            event,
            &mut content,
            &mut tool_calls,
            &mut saw_tool_call,
            &mut in_progress,
        ) {
            EventOutcome::Continue => {}
            EventOutcome::Terminal(err) => {
                warn!(message = %err.message, "openai chat aborted with parser protocol error");
                return err.into_response();
            }
        }
    }

    let finish_reason = map_finish_reason(stop_reason, saw_tool_call);
    let message_content = if content.is_empty() {
        None
    } else {
        Some(openai::MessageContent::Text(content))
    };
    let message = openai::ChatMessage::builder()
        .role("assistant".to_string())
        .content(message_content)
        .tool_calls(if tool_calls.is_empty() {
            None
        } else {
            Some(tool_calls)
        })
        .build();

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

fn stream_response(prepared: PreparedGeneration, include_usage: bool) -> Response {
    let id = next_id("chatcmpl");
    let created = now_unix();
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();
    // Build the parser before consuming `prepared` into the stream.
    let mut parser: Box<dyn IncrementalToolCallParser> = prepared
        .chat_turn
        .as_ref()
        .expect("OpenAI surface always carries a ChatTurn")
        .make_parser();

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

        let mut saw_tool_call = false;
        let mut in_progress: HashMap<usize, CallInProgress> = HashMap::new();
        let mut outcome: Option<Outcome> = None;
        let mut transport_error: Option<String> = None;
        let mut timed_out = false;
        let mut protocol_error: Option<String> = None;

        // Per-token loop. Each delta is fed through the parser; the
        // resulting events become OpenAI SSE chunks. Terminal parser
        // errors emit an error frame and close the stream WITHOUT
        // [DONE] (per the P6 contract).
        'outer: loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Delta(text)))) => {
                    let events = parser.feed(&text);
                    for event in events {
                        match stream_apply_event(
                            event,
                            &id,
                            created,
                            &model,
                            &mut saw_tool_call,
                            &mut in_progress,
                        ) {
                            StreamOutcome::Yield(chunk) => {
                                yield Ok(sse_data(&chunk));
                            }
                            StreamOutcome::Continue => {}
                            StreamOutcome::Terminal(message) => {
                                protocol_error = Some(message);
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

        // Protocol error path: error frame, close, NO [DONE].
        // Per the OpenAI streaming convention, the stream simply
        // closes after an error frame. Sending [DONE] would tell
        // strict clients the response was a successful empty
        // completion.
        if let Some(message) = protocol_error {
            warn!(%message, "openai chat aborted with parser protocol error");
            yield Ok(sse_data(&json!({
                "error": {
                    "message": message,
                    "type": "invalid_response",
                }
            })));
            return;
        }

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
                info!(
                    %receipt_cid,
                    provenance = ?stream_provenance,
                    total_tokens,
                    ?stop_reason,
                    "openai chat completion ready"
                );

                // Drain the parser's terminal events.
                let parser_stop = map_to_parser_stop(stop_reason);
                let mut tail = parser.finish(parser_stop);
                let mut tail_protocol_error: Option<String> = None;
                for event in tail.drain(..) {
                    match stream_apply_event(
                        event,
                        &id,
                        created,
                        &model,
                        &mut saw_tool_call,
                        &mut in_progress,
                    ) {
                        StreamOutcome::Yield(chunk) => yield Ok(sse_data(&chunk)),
                        StreamOutcome::Continue => {}
                        StreamOutcome::Terminal(message) => {
                            tail_protocol_error = Some(message);
                            break;
                        }
                    }
                }
                if let Some(message) = tail_protocol_error {
                    warn!(%message, "openai chat aborted with parser protocol error during finish");
                    yield Ok(sse_data(&json!({
                        "error": {
                            "message": message,
                            "type": "invalid_response",
                        }
                    })));
                    return;
                }

                let finish = map_finish_reason(stop_reason, saw_tool_call);
                yield Ok(sse_data(&build_chunk(
                    &id,
                    created,
                    &model,
                    openai::ChatDelta::default(),
                    Some(finish),
                )));

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

/// Outcome of mapping one parser event to a streaming SSE chunk.
enum StreamOutcome {
    /// Emit this chunk to the SSE stream.
    Yield(openai::ChatCompletionChunk),
    /// No frame to emit for this event (e.g. ToolCallEnd is
    /// already covered by the preceding Start + ArgsDelta chunks).
    Continue,
    /// Terminal protocol error — the stream must close after an
    /// error frame, NOT emit `[DONE]`. Caller renders the message.
    Terminal(String),
}

fn stream_apply_event(
    event: DecodeEvent,
    id: &str,
    created: i64,
    model: &str,
    saw_tool_call: &mut bool,
    in_progress: &mut HashMap<usize, CallInProgress>,
) -> StreamOutcome {
    match event {
        DecodeEvent::TextDelta(s) => StreamOutcome::Yield(build_chunk(
            id,
            created,
            model,
            text_delta(s),
            None,
        )),
        DecodeEvent::ToolCallStart { index, name } => {
            *saw_tool_call = true;
            let wire_id = next_id("call");
            in_progress.insert(
                index,
                CallInProgress {
                    wire_id: wire_id.clone(),
                    name: name.clone(),
                    arguments: String::new(),
                },
            );
            // OpenAI streaming tool-call start chunk: a tool_call
            // entry in the delta carrying index, id, type, and the
            // initial function name. Subsequent ArgsDelta chunks
            // carry only the index + function.arguments fragment.
            StreamOutcome::Yield(build_chunk(
                id,
                created,
                model,
                openai::ChatDelta {
                    tool_calls: Some(vec![json!({
                        "index": index,
                        "id": wire_id,
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": "",
                        },
                    })]),
                    ..Default::default()
                },
                None,
            ))
        }
        DecodeEvent::ToolCallArgsDelta { index, delta } => {
            if let Some(call) = in_progress.get_mut(&index) {
                call.arguments.push_str(&delta);
            }
            StreamOutcome::Yield(build_chunk(
                id,
                created,
                model,
                openai::ChatDelta {
                    tool_calls: Some(vec![json!({
                        "index": index,
                        "function": {
                            "arguments": delta,
                        },
                    })]),
                    ..Default::default()
                },
                None,
            ))
        }
        DecodeEvent::ToolCallEnd { index, .. } => {
            // No separate frame: the preceding Start + ArgsDelta
            // chunks already carry the call to the wire. We just
            // drop our in-progress bookkeeping for this index.
            in_progress.remove(&index);
            StreamOutcome::Continue
        }
        DecodeEvent::Stop { .. } => StreamOutcome::Continue,
        DecodeEvent::UnknownTool { name, .. } => {
            StreamOutcome::Terminal(format!("model called unknown tool `{name}`"))
        }
        DecodeEvent::InvalidArgs { name, errors, .. } => {
            let detail = errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            StreamOutcome::Terminal(format!(
                "model called `{name}` with arguments that don't match the schema: {detail}"
            ))
        }
        DecodeEvent::ParseError { sentinel, source } => StreamOutcome::Terminal(format!(
            "model emitted malformed tool call within `{sentinel}`: {source}"
        )),
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

#[cfg(test)]
mod tests {
    //! Wire-mapping tests for the OpenAI surface. These exercise the
    //! event-walking helpers (`apply_event` / `stream_apply_event`) with
    //! synthetic `DecodeEvent` sequences — the same shape the per-arch
    //! parsers produce. They're independent of HTTP transport, fake
    //! executors, or any model.
    //!
    //! Coverage maps to the P6 contract:
    //!
    //! - **No-tools sentinel passthrough.** When tools aren't bound,
    //!   the per-arch parser is never instantiated; what feeds the
    //!   wire-mapper is `TextDelta` events. Asserts that text flows
    //!   through to `content` with no tool_calls and no Terminal.
    //! - **Unknown tool.** A model output naming a tool not in the
    //!   directory becomes a `Terminal` error, mapped to HTTP 502 (a
    //!   model-output error, not a client request error).
    //! - **Invalid args.** Schema-validation failure becomes a
    //!   `Terminal` carrying the schema-error detail.
    //! - **Per-call streaming after close sentinel.** A complete
    //!   `Start`/`ArgsDelta`/`End` triple in one feed yields the
    //!   expected wire chunks atomically. The `End` event itself
    //!   yields no separate frame — the preceding chunks already
    //!   carry the call.

    use super::*;
    use catgrad_llm::runtime::chat::{ParserError, SchemaError};
    use serde_json::json;

    /// No-tools surface: `TextDelta` events accumulate into content;
    /// no tool calls, no terminal.
    #[test]
    fn apply_event_text_passes_through_to_content() {
        let mut content = String::new();
        let mut tool_calls = Vec::new();
        let mut saw_tool_call = false;
        let mut in_progress = HashMap::new();

        // Pretend the parser emitted these events (would happen if a
        // sentinel-shaped string came through the passthrough parser).
        for s in ["hello ", "<tool_call>literal text</tool_call>", " world"] {
            match apply_event(
                DecodeEvent::TextDelta(s.to_string()),
                &mut content,
                &mut tool_calls,
                &mut saw_tool_call,
                &mut in_progress,
            ) {
                EventOutcome::Continue => {}
                EventOutcome::Terminal(_) => panic!("text events must not be terminal"),
            }
        }
        assert_eq!(content, "hello <tool_call>literal text</tool_call> world");
        assert!(tool_calls.is_empty());
        assert!(!saw_tool_call);
    }

    #[test]
    fn apply_event_unknown_tool_is_terminal_502() {
        let mut content = String::new();
        let mut tool_calls = Vec::new();
        let mut saw_tool_call = false;
        let mut in_progress = HashMap::new();

        let outcome = apply_event(
            DecodeEvent::UnknownTool {
                name: "delete_db".to_string(),
                raw_args: json!({}),
            },
            &mut content,
            &mut tool_calls,
            &mut saw_tool_call,
            &mut in_progress,
        );
        match outcome {
            EventOutcome::Terminal(err) => {
                assert_eq!(err.status, StatusCode::BAD_GATEWAY);
                assert!(err.message.contains("delete_db"));
                assert!(err.message.contains("unknown tool"));
            }
            EventOutcome::Continue => panic!("UnknownTool must be terminal"),
        }
    }

    #[test]
    fn apply_event_invalid_args_is_terminal_with_schema_detail() {
        let mut content = String::new();
        let mut tool_calls = Vec::new();
        let mut saw_tool_call = false;
        let mut in_progress = HashMap::new();

        let outcome = apply_event(
            DecodeEvent::InvalidArgs {
                name: "add".to_string(),
                args: json!({ "a": "one" }),
                errors: vec![SchemaError {
                    path: "/a".to_string(),
                    message: "is not of type \"number\"".to_string(),
                }],
            },
            &mut content,
            &mut tool_calls,
            &mut saw_tool_call,
            &mut in_progress,
        );
        match outcome {
            EventOutcome::Terminal(err) => {
                assert_eq!(err.status, StatusCode::BAD_GATEWAY);
                assert!(err.message.contains("add"));
                assert!(err.message.contains("schema"));
                assert!(err.message.contains("/a"));
            }
            EventOutcome::Continue => panic!("InvalidArgs must be terminal"),
        }
    }

    #[test]
    fn apply_event_parse_error_is_terminal() {
        let mut content = String::new();
        let mut tool_calls = Vec::new();
        let mut saw_tool_call = false;
        let mut in_progress = HashMap::new();

        let outcome = apply_event(
            DecodeEvent::ParseError {
                sentinel: "<tool_call>",
                source: ParserError::MissingField("name"),
            },
            &mut content,
            &mut tool_calls,
            &mut saw_tool_call,
            &mut in_progress,
        );
        assert!(matches!(outcome, EventOutcome::Terminal(_)));
    }

    #[test]
    fn apply_event_complete_call_assembles_tool_calls_array() {
        let mut content = String::new();
        let mut tool_calls = Vec::new();
        let mut saw_tool_call = false;
        let mut in_progress = HashMap::new();

        for event in [
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
        ] {
            let _ = apply_event(
                event,
                &mut content,
                &mut tool_calls,
                &mut saw_tool_call,
                &mut in_progress,
            );
        }

        assert_eq!(content, "");
        assert!(saw_tool_call);
        assert!(in_progress.is_empty());
        assert_eq!(tool_calls.len(), 1);
        let call = &tool_calls[0];
        assert_eq!(call["type"], "function");
        assert_eq!(call["function"]["name"], "add");
        // OpenAI wire convention: `arguments` is a JSON-encoded string.
        assert_eq!(call["function"]["arguments"], r#"{"a":1,"b":2}"#);
        assert!(
            call["id"].as_str().is_some_and(|s| s.starts_with("call-")),
            "expected process-unique id, got {}",
            call["id"]
        );
    }

    /// Per-call streaming proof: a complete Start / ArgsDelta / End
    /// triple in one feed yields exactly two wire chunks (Start emits
    /// a chunk with name; ArgsDelta emits a chunk with arguments
    /// fragment; End emits no separate chunk — its content is
    /// already on the wire).
    #[test]
    fn stream_apply_event_emits_per_call_chunks_atomically() {
        let mut saw_tool_call = false;
        let mut in_progress = HashMap::new();

        let start = stream_apply_event(
            DecodeEvent::ToolCallStart {
                index: 0,
                name: "add".to_string(),
            },
            "chatcmpl-test",
            42,
            "test-model",
            &mut saw_tool_call,
            &mut in_progress,
        );
        let StreamOutcome::Yield(start_chunk) = start else {
            panic!("ToolCallStart must yield a chunk");
        };
        let start_value = serde_json::to_value(&start_chunk).unwrap();
        let tool_calls = &start_value["choices"][0]["delta"]["tool_calls"];
        assert_eq!(tool_calls[0]["index"], 0);
        assert_eq!(tool_calls[0]["function"]["name"], "add");
        assert!(tool_calls[0]["id"].as_str().unwrap().starts_with("call-"));
        assert!(saw_tool_call);

        let args = stream_apply_event(
            DecodeEvent::ToolCallArgsDelta {
                index: 0,
                delta: r#"{"a":1,"b":2}"#.to_string(),
            },
            "chatcmpl-test",
            42,
            "test-model",
            &mut saw_tool_call,
            &mut in_progress,
        );
        let StreamOutcome::Yield(args_chunk) = args else {
            panic!("ToolCallArgsDelta must yield a chunk");
        };
        let args_value = serde_json::to_value(&args_chunk).unwrap();
        let arg_calls = &args_value["choices"][0]["delta"]["tool_calls"];
        assert_eq!(arg_calls[0]["index"], 0);
        assert_eq!(
            arg_calls[0]["function"]["arguments"],
            r#"{"a":1,"b":2}"#
        );
        // Start-chunk's `id` and `name` are NOT repeated on subsequent
        // delta chunks (per OpenAI streaming convention).
        assert!(arg_calls[0].get("id").is_none());

        let end = stream_apply_event(
            DecodeEvent::ToolCallEnd {
                index: 0,
                args: json!({"a": 1, "b": 2}),
            },
            "chatcmpl-test",
            42,
            "test-model",
            &mut saw_tool_call,
            &mut in_progress,
        );
        // ToolCallEnd emits no separate frame — preceding chunks
        // already carry the call to the wire.
        assert!(matches!(end, StreamOutcome::Continue));
        assert!(in_progress.is_empty());
    }

    #[test]
    fn stream_apply_event_text_yields_content_delta() {
        let mut saw_tool_call = false;
        let mut in_progress = HashMap::new();

        let out = stream_apply_event(
            DecodeEvent::TextDelta("hello".to_string()),
            "chatcmpl-test",
            42,
            "test-model",
            &mut saw_tool_call,
            &mut in_progress,
        );
        let StreamOutcome::Yield(chunk) = out else {
            panic!("TextDelta must yield a chunk");
        };
        let value = serde_json::to_value(&chunk).unwrap();
        assert_eq!(value["choices"][0]["delta"]["content"], "hello");
        assert!(value["choices"][0]["delta"].get("tool_calls").is_none());
        assert!(!saw_tool_call);
    }

    #[test]
    fn stream_apply_event_unknown_tool_is_terminal() {
        let mut saw_tool_call = false;
        let mut in_progress = HashMap::new();
        let out = stream_apply_event(
            DecodeEvent::UnknownTool {
                name: "delete_db".to_string(),
                raw_args: json!({}),
            },
            "chatcmpl-test",
            42,
            "test-model",
            &mut saw_tool_call,
            &mut in_progress,
        );
        let StreamOutcome::Terminal(message) = out else {
            panic!("UnknownTool must be terminal");
        };
        assert!(message.contains("delete_db"));
        assert!(message.contains("unknown tool"));
    }

    #[test]
    fn map_finish_reason_tool_calls_wins_over_stop() {
        // Per the P6 contract: tool_calls wins whenever any call was
        // emitted, even if the executor stopped on EOS.
        assert_eq!(
            map_finish_reason(ExecStopReason::EndOfSequence, true),
            openai::FinishReason::ToolCalls
        );
        assert_eq!(
            map_finish_reason(ExecStopReason::MaxNewTokens, true),
            openai::FinishReason::ToolCalls
        );
        assert_eq!(
            map_finish_reason(ExecStopReason::EndOfSequence, false),
            openai::FinishReason::Stop
        );
        assert_eq!(
            map_finish_reason(ExecStopReason::MaxNewTokens, false),
            openai::FinishReason::Length
        );
    }
}
