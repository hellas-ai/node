use super::hellas_ext::{HellasExt, WithHellas};
use super::state::{GatewayState, GenerationEvent, PreparedGeneration};
use super::{next_id, now_unix, parse_json_body, sse_data, sse_response};
use crate::execution::{Outcome, StopReason as ExecStopReason};
use async_stream::stream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use catgrad_llm::runtime::chat::wire::openai::{OpenAiStreamFrame, OpenAiStreamMapper};
use catgrad_llm::runtime::chat::wire::{PumpError, pump_finish, pump_text};
use catgrad_llm::runtime::chat::{
    DecodeFailure, IncrementalToolCallParser, StopReason as ParserStopReason,
};
use catgrad_llm::types::openai;
use futures::StreamExt;
use hellas_rpc::provenance::ExecutionProvenance;
use serde_json::json;
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

/// Non-streaming endpoint. Drives the same per-delta pipeline as the
/// streaming endpoint; the only difference is the sink — frames are
/// discarded, and the buffered assistant payload comes from
/// `mapper.snapshot()` at the end.
async fn respond(prepared: PreparedGeneration) -> Response {
    let id = next_id("chatcmpl");
    let created = now_unix();
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();

    let mut parser: Box<dyn IncrementalToolCallParser> = prepared
        .chat_turn
        .as_ref()
        .expect("OpenAI surface always carries a ChatTurn")
        .make_parser();
    let mut mapper = OpenAiStreamMapper::new(|prefix: &str| next_id(prefix));

    let stream = prepared.stream();
    tokio::pin!(stream);

    let outcome = loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(GenerationEvent::Delta(d)))) => {
                if let Err(PumpError { failure, .. }) = pump_text(&mut *parser, &mut mapper, &d) {
                    // Non-streaming: cleanup frames are wire-bracketing
                    // and irrelevant when no wire stream exists. Discard.
                    return failure_to_json_response(failure);
                }
                // Non-streaming: discard frames; snapshot at end.
            }
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

    let (total_tokens, stop_reason, receipt) = match outcome {
        Outcome::Completed {
            total_tokens,
            stop_reason,
            receipt,
        } => {
            info!(
                receipt = %receipt.encoded(),
                ?provenance,
                total_tokens,
                ?stop_reason,
                "openai chat completion ready"
            );
            (total_tokens, stop_reason, receipt)
        }
        Outcome::Failed { position, error } => {
            warn!(position, %error, "openai chat request failed");
            return super::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
    };

    let parser_stop = map_to_parser_stop(stop_reason);
    if let Err(PumpError { failure, .. }) = pump_finish(&mut *parser, &mut mapper, parser_stop) {
        return failure_to_json_response(failure);
    }

    let snapshot = match mapper.snapshot() {
        Ok(s) => s,
        Err(failure) => return failure_to_json_response(failure),
    };
    let response = openai::ChatCompletionResponse::builder()
        .id(id)
        .object("chat.completion".to_string())
        .created(created)
        .model(model)
        .choices(vec![
            openai::ChatChoice::builder()
                .index(0)
                .message(snapshot.message)
                .finish_reason(Some(snapshot.finish_reason))
                .build(),
        ])
        .usage(Some(openai::Usage::from_counts(
            prompt_tokens,
            u32::try_from(total_tokens).unwrap_or(u32::MAX),
        )))
        .build();

    let hellas = match provenance.as_ref() {
        Some(prov) => HellasExt::both(prov, &receipt),
        None => HellasExt::receipt(&receipt),
    };
    let body = WithHellas::new(response, hellas);

    let mut response = Json(body).into_response();
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    }
    response.extensions_mut().insert(receipt);
    response
}

/// Streaming endpoint. Per-event: feed parser → feed mapper → wrap
/// frames in `ChatCompletionChunk` → SSE. On `Err(DecodeFailure)`,
/// emit error frame and close immediately (no `[DONE]`); per the P6
/// contract we do **not** call `mapper.finish()` after a `feed()`
/// failure — terminal handling is fully synchronous with the error.
///
/// The actual stream-building lives in
/// [`build_openai_sse_stream`] so the wire-output contract can be
/// tested directly with synthetic upstream streams (no axum / no
/// real executor required).
fn stream_response(prepared: PreparedGeneration, include_usage: bool) -> Response {
    let id = next_id("chatcmpl");
    let created = now_unix();
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();

    let parser: Box<dyn IncrementalToolCallParser> = prepared
        .chat_turn
        .as_ref()
        .expect("OpenAI surface always carries a ChatTurn")
        .make_parser();
    let mapper = OpenAiStreamMapper::new(|prefix: &str| next_id(prefix));

    let stream_provenance = provenance.clone();
    let upstream = prepared.stream();
    let payloads = build_openai_sse_stream(
        id,
        created,
        model,
        prompt_tokens,
        deadline,
        include_usage,
        parser,
        mapper,
        stream_provenance,
        upstream,
    );
    let events = payloads.map(|payload| Ok::<_, std::convert::Infallible>(payload.into_event()));
    let mut response = sse_response(events);
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    }
    response
}

/// One unit of wire output the OpenAI streaming endpoint emits.
/// Tests assert on this directly; production maps each variant to
/// an `axum::response::sse::Event` via `into_event`.
#[cfg_attr(test, derive(Debug))]
enum OpenAiSsePayload {
    /// `data: <json>\n\n` — used for chunks and error frames.
    Json(serde_json::Value),
    /// `data: [DONE]\n\n` — terminates a successful completion.
    /// Per the wire convention enforced by the regression tests
    /// below, MUST NOT follow any error frame.
    Done,
}

impl OpenAiSsePayload {
    fn into_event(self) -> axum::response::sse::Event {
        match self {
            Self::Json(v) => sse_data(&v),
            Self::Done => axum::response::sse::Event::default().data("[DONE]"),
        }
    }
}

/// Inner SSE-event generator, generic over the upstream
/// `GenerationEvent` stream. Returns a stream of [`OpenAiSsePayload`]s
/// (rather than opaque axum `Event`s) so tests can inspect the
/// emitted wire shape directly. Production wraps via `into_event`.
fn build_openai_sse_stream<S>(
    id: String,
    created: i64,
    model: String,
    prompt_tokens: u32,
    deadline: tokio::time::Instant,
    include_usage: bool,
    mut parser: Box<dyn IncrementalToolCallParser>,
    mut mapper: OpenAiStreamMapper,
    provenance: Option<ExecutionProvenance>,
    upstream: S,
) -> impl futures::Stream<Item = OpenAiSsePayload> + Send
where
    S: futures::Stream<Item = anyhow::Result<GenerationEvent>> + Send + 'static,
{
    stream! {
        // Start frame: role:assistant chunk carrying hellas.commitment
        // when provenance is available. Browser EventSource and many
        // WASM HTTP wrappers swallow response headers, so the in-band
        // JSON extension is the canonical commitment carrier here.
        let start_frame = wrap_chunk(
            &id,
            created,
            &model,
            OpenAiStreamFrame {
                delta: openai::ChatDelta {
                    role: Some("assistant".to_string()),
                    ..Default::default()
                },
                finish_reason: None,
            },
        );
        let start_hellas = match provenance.as_ref() {
            Some(prov) => HellasExt::commitment(prov),
            None => HellasExt::default(),
        };
        yield OpenAiSsePayload::Json(
            serde_json::to_value(WithHellas::new(start_frame, start_hellas)).unwrap(),
        );

        let inner = upstream;
        tokio::pin!(inner);

        let mut outcome: Option<Outcome> = None;
        let mut transport_error: Option<String> = None;
        let mut timed_out = false;
        let mut protocol_failure: Option<PumpError<OpenAiStreamFrame>> = None;

        'outer: loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Delta(text)))) => {
                    match pump_text(&mut *parser, &mut mapper, &text) {
                        Ok(frames) => {
                            for frame in frames {
                                yield OpenAiSsePayload::Json(
                                    serde_json::to_value(wrap_chunk(&id, created, &model, frame))
                                        .unwrap(),
                                );
                            }
                        }
                        Err(err) => {
                            // `err` carries both `failure` (the
                            // structured cause) and `cleanup` (any
                            // wire-bracketing frames the pump
                            // already drained from the mapper).
                            // For OpenAI cleanup is always empty,
                            // but we hold onto the value uniformly
                            // and emit cleanup before the error frame.
                            protocol_failure = Some(err);
                            break 'outer;
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

        // Protocol-error path: error frame, close, NO [DONE].
        // Per the OpenAI streaming convention an error frame closes
        // the stream — appending [DONE] would tell strict clients the
        // response was a successful empty completion.
        if let Some(PumpError { failure, cleanup }) = protocol_failure {
            warn!(message = %failure, "openai chat aborted with parser protocol error");
            // OpenAI cleanup is always empty (no wire bracketing) but
            // emit uniformly so the pattern matches Anthropic.
            for frame in cleanup {
                yield OpenAiSsePayload::Json(
                    serde_json::to_value(wrap_chunk(&id, created, &model, frame)).unwrap(),
                );
            }
            yield OpenAiSsePayload::Json(error_frame(&failure));
            return;
        }

        // Convention: NO `data: [DONE]` after any error frame
        // (transport, timeout, executor failure, or parser-level
        // protocol error above). Strict OpenAI clients treat `[DONE]`
        // as "success terminator," so emitting it after an error
        // would be read as a successful empty completion. The
        // protocol-error branch above already follows this; the
        // transport/timeout/Outcome::Failed branches now match.
        if let Some(error) = transport_error {
            yield OpenAiSsePayload::Json(json!({
                "error": { "message": format!("Inference error: {error}") }
            }));
            return;
        }
        if timed_out {
            yield OpenAiSsePayload::Json(json!({
                "error": { "message": format!(
                    "inference timed out after {}s",
                    super::timeout_secs_until(deadline)
                )}
            }));
            return;
        }
        let outcome = outcome.expect("loop only breaks with a terminal observation");
        match outcome {
            Outcome::Failed { error, .. } => {
                yield OpenAiSsePayload::Json(json!({
                    "error": { "message": format!("Inference error: {error}") }
                }));
                return;
            }
            Outcome::Completed {
                stop_reason,
                total_tokens,
                receipt,
            } => {
                info!(
                    receipt = %receipt.encoded(),
                    provenance = ?provenance,
                    total_tokens,
                    ?stop_reason,
                    "openai chat completion ready"
                );

                // Drain parser tail + mapper.finish via the same pump.
                // Any failure takes the error-frame-and-close path.
                let parser_stop = map_to_parser_stop(stop_reason);
                let finish_frames = match pump_finish(&mut *parser, &mut mapper, parser_stop) {
                    Ok(frames) => frames,
                    Err(PumpError { failure, cleanup }) => {
                        warn!(message = %failure, "openai chat aborted with parser protocol error during finish");
                        for frame in cleanup {
                            yield OpenAiSsePayload::Json(
                                serde_json::to_value(wrap_chunk(&id, created, &model, frame))
                                    .unwrap(),
                            );
                        }
                        yield OpenAiSsePayload::Json(error_frame(&failure));
                        return;
                    }
                };

                // Build all post-pump chunks (mapper finish output +
                // optional usage chunk) into one ordered vec so we can
                // tag the LAST one with hellas.receipt. Per the
                // approved plan: receipt rides the SEMANTIC TERMINAL
                // event — the last `data:` chunk before `[DONE]`. With
                // include_usage that's the usage chunk; otherwise the
                // finish-reason chunk.
                let mut tail_chunks: Vec<openai::ChatCompletionChunk> = finish_frames
                    .into_iter()
                    .map(|frame| wrap_chunk(&id, created, &model, frame))
                    .collect();

                if include_usage {
                    tail_chunks.push(
                        openai::ChatCompletionChunk::builder()
                            .id(id.clone())
                            .object("chat.completion.chunk".to_string())
                            .created(created)
                            .model(model.clone())
                            .choices(vec![])
                            .usage(Some(openai::Usage::from_counts(
                                prompt_tokens,
                                u32::try_from(total_tokens).unwrap_or(u32::MAX),
                            )))
                            .build(),
                    );
                }

                // Mapper-contract assertion: a successful Completed
                // outcome must yield at least one tail chunk to ride
                // the receipt. If empty, the mapper or this gateway
                // has a bug and the receipt has no destination —
                // synthesize a minimal finish-reason chunk to carry
                // it rather than silently drop it on the floor.
                if tail_chunks.is_empty() {
                    error!(
                        receipt = %receipt.encoded(),
                        "openai chat finish produced zero tail chunks; synthesizing terminal frame to carry receipt"
                    );
                    tail_chunks.push(wrap_chunk(
                        &id,
                        created,
                        &model,
                        OpenAiStreamFrame {
                            delta: openai::ChatDelta::default(),
                            finish_reason: Some(openai::FinishReason::Stop),
                        },
                    ));
                }

                let last_idx = tail_chunks.len() - 1;
                for (idx, chunk) in tail_chunks.into_iter().enumerate() {
                    if idx == last_idx {
                        let wrapped = WithHellas::new(chunk, HellasExt::receipt(&receipt));
                        yield OpenAiSsePayload::Json(serde_json::to_value(wrapped).unwrap());
                    } else {
                        yield OpenAiSsePayload::Json(serde_json::to_value(chunk).unwrap());
                    }
                }

                yield OpenAiSsePayload::Done;
            }
        }
    }
}

fn wrap_chunk(
    id: &str,
    created: i64,
    model: &str,
    frame: OpenAiStreamFrame,
) -> openai::ChatCompletionChunk {
    openai::ChatCompletionChunk::builder()
        .id(id.to_string())
        .object("chat.completion.chunk".to_string())
        .created(created)
        .model(model.to_string())
        .choices(vec![
            openai::ChatStreamChoice::builder()
                .index(0)
                .delta(frame.delta)
                .finish_reason(frame.finish_reason)
                .build(),
        ])
        .build()
}

fn error_frame(failure: &DecodeFailure) -> serde_json::Value {
    json!({
        "error": {
            "message": failure.to_string(),
            "type": match failure {
                DecodeFailure::InternalSequence { .. } => "internal_error",
                _ => "invalid_response",
            },
        }
    })
}

fn failure_to_json_response(failure: DecodeFailure) -> Response {
    let status = match failure {
        DecodeFailure::InternalSequence { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_GATEWAY,
    };
    let message = failure.to_string();
    warn!(%message, "openai chat aborted with parser protocol error");
    super::json_error(status, message)
}

/// Map executor `StopReason` to the parser's `StopReason`. The parser
/// uses this in `finish()` to decide whether trailing buffered text is
/// still being assembled or should be flushed; the mapper consumes the
/// same value to resolve its terminal `finish_reason`.
fn map_to_parser_stop(stop: ExecStopReason) -> ParserStopReason {
    match stop {
        ExecStopReason::EndOfSequence => ParserStopReason::EndOfText,
        ExecStopReason::MaxNewTokens => ParserStopReason::MaxTokens,
        // Cancelled: behave like a normal end so the parser flushes.
        ExecStopReason::Cancelled => ParserStopReason::EndOfText,
    }
}

#[cfg(test)]
mod streaming_done_tests {
    //! Regression tests for the "no `data: [DONE]` after any error
    //! frame" convention plus the in-band hellas-extension wire shape.
    //!
    //! Each error path (transport, timeout, executor failure) is driven
    //! via a synthetic upstream stream through `build_openai_sse_stream`.
    //! The generator returns `OpenAiSsePayload` directly, so tests can
    //! match on variants without inspecting opaque axum `Event`s.
    //!
    //! A `[DONE]` after an error frame would tell strict OpenAI
    //! clients the response was a successful empty completion.
    //!
    //! Positive-path coverage asserts:
    //! - first chunk carries `hellas.commitment` when provenance is
    //!   provided, and no `hellas` field otherwise;
    //! - the SEMANTIC TERMINAL chunk (last `data:` before `[DONE]`)
    //!   carries `hellas.receipt`. With `include_usage=true` that's
    //!   the trailing usage chunk; without, the finish-reason chunk;
    //! - error paths NEVER emit `hellas.receipt`;
    //! - no separate `event: hellas-*` SSE events appear (the
    //!   `OpenAiSsePayload` enum no longer has variants for them).

    use super::*;
    use crate::execution::{Outcome, ReceiptArtifact, StopReason as ExecStopReason};
    use catgrad_llm::runtime::chat::PassthroughParser;
    use futures::StreamExt;
    use std::time::Duration;
    use tokio::time::Instant;

    fn make_test_inputs() -> (
        String,
        i64,
        String,
        u32,
        Box<dyn IncrementalToolCallParser>,
        OpenAiStreamMapper,
    ) {
        (
            "chatcmpl-test".into(),
            0,
            "test-model".into(),
            0,
            Box::new(PassthroughParser),
            OpenAiStreamMapper::new(|prefix: &str| format!("{prefix}-test")),
        )
    }

    fn test_provenance() -> ExecutionProvenance {
        ExecutionProvenance {
            commitment_id: [0xab; 32],
        }
    }

    fn test_receipt() -> ReceiptArtifact {
        ReceiptArtifact::from_test_bytes(vec![0xcd; 32])
    }

    /// Successful upstream: one delta then `Outcome::Completed`. The
    /// receipt CID lands inside the terminal frame via the gateway's
    /// `Outcome::Completed` arm.
    fn happy_upstream(
        receipt: ReceiptArtifact,
    ) -> impl futures::Stream<Item = anyhow::Result<GenerationEvent>> + Send + 'static {
        futures::stream::iter(vec![
            Ok(GenerationEvent::Delta("hi".to_string())),
            Ok(GenerationEvent::Done(Outcome::Completed {
                total_tokens: 1,
                stop_reason: ExecStopReason::EndOfSequence,
                receipt,
            })),
        ])
    }

    /// True iff the payload is a JSON value with an `error` field —
    /// either an inference-side error frame or a parser-protocol one.
    fn is_error_frame(p: &OpenAiSsePayload) -> bool {
        matches!(p, OpenAiSsePayload::Json(v) if v.get("error").is_some())
    }

    fn is_done(p: &OpenAiSsePayload) -> bool {
        matches!(p, OpenAiSsePayload::Done)
    }

    fn error_message(p: &OpenAiSsePayload) -> Option<&str> {
        match p {
            OpenAiSsePayload::Json(v) => v
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str()),
            _ => None,
        }
    }

    /// Extract the JSON value out of a `Json` payload variant for
    /// hellas-field inspection. Panics on non-JSON variants — tests
    /// pre-filter to skip the trailing `Done`.
    fn as_json(p: &OpenAiSsePayload) -> &serde_json::Value {
        match p {
            OpenAiSsePayload::Json(v) => v,
            OpenAiSsePayload::Done => panic!("called as_json on Done payload"),
        }
    }

    /// `chunk.hellas.commitment` if present.
    fn commitment_of(p: &OpenAiSsePayload) -> Option<&str> {
        as_json(p)
            .get("hellas")
            .and_then(|h| h.get("commitment"))
            .and_then(|v| v.as_str())
    }

    /// `chunk.hellas.receipt` if present.
    fn receipt_of(p: &OpenAiSsePayload) -> Option<&str> {
        as_json(p)
            .get("hellas")
            .and_then(|h| h.get("receipt"))
            .and_then(|v| v.as_str())
    }

    fn has_finish_reason(p: &OpenAiSsePayload) -> bool {
        as_json(p)
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|c| c.get("finish_reason"))
            .map(|v| !v.is_null())
            .unwrap_or(false)
    }

    fn is_usage_chunk(p: &OpenAiSsePayload) -> bool {
        let v = as_json(p);
        let choices_empty = v
            .get("choices")
            .and_then(|c| c.as_array())
            .map(|arr| arr.is_empty())
            .unwrap_or(false);
        let has_usage = v.get("usage").is_some_and(|u| !u.is_null());
        choices_empty && has_usage
    }

    /// Drive with an upstream that yields a single transport `Err`.
    /// Assert: error frame is emitted, no `[DONE]`, no receipt leaks.
    #[tokio::test]
    async fn transport_error_emits_error_frame_without_done() {
        let (id, created, model, prompt_tokens, parser, mapper) = make_test_inputs();
        let deadline = Instant::now() + Duration::from_secs(60);
        let upstream = futures::stream::iter(vec![
            Err(anyhow::anyhow!("upstream blew up")) as anyhow::Result<GenerationEvent>
        ]);

        let payloads: Vec<OpenAiSsePayload> = build_openai_sse_stream(
            id,
            created,
            model,
            prompt_tokens,
            deadline,
            false,
            parser,
            mapper,
            Some(test_provenance()),
            upstream,
        )
        .collect()
        .await;

        assert!(
            payloads.iter().any(|p| is_error_frame(p)
                && error_message(p).is_some_and(|m| m.contains("upstream blew up"))),
            "expected error frame, got: {payloads:#?}"
        );
        assert!(
            !payloads.iter().any(is_done),
            "must not emit [DONE] after transport error, got: {payloads:#?}"
        );
        // Error-path fence: no receipt anywhere in the stream.
        assert!(
            payloads
                .iter()
                .filter(|p| matches!(p, OpenAiSsePayload::Json(_)))
                .all(|p| receipt_of(p).is_none()),
            "transport error must not leak hellas.receipt, got: {payloads:#?}"
        );
    }

    /// Drive with an upstream that never yields, deadline in the
    /// past. Assert: timeout error frame, no `[DONE]`, no receipt leak.
    #[tokio::test]
    async fn timeout_emits_error_frame_without_done() {
        let (id, created, model, prompt_tokens, parser, mapper) = make_test_inputs();
        let deadline = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let upstream = futures::stream::pending::<anyhow::Result<GenerationEvent>>();

        let payloads: Vec<OpenAiSsePayload> = build_openai_sse_stream(
            id,
            created,
            model,
            prompt_tokens,
            deadline,
            false,
            parser,
            mapper,
            Some(test_provenance()),
            upstream,
        )
        .collect()
        .await;

        assert!(
            payloads
                .iter()
                .any(|p| is_error_frame(p)
                    && error_message(p).is_some_and(|m| m.contains("timed out"))),
            "expected timeout error frame, got: {payloads:#?}"
        );
        assert!(
            !payloads.iter().any(is_done),
            "must not emit [DONE] after timeout, got: {payloads:#?}"
        );
        assert!(
            payloads
                .iter()
                .filter(|p| matches!(p, OpenAiSsePayload::Json(_)))
                .all(|p| receipt_of(p).is_none()),
            "timeout must not leak hellas.receipt, got: {payloads:#?}"
        );
    }

    /// Drive with an upstream completing via `Outcome::Failed`.
    /// Assert: error frame, no `[DONE]`, no receipt leak.
    #[tokio::test]
    async fn outcome_failed_emits_error_frame_without_done() {
        let (id, created, model, prompt_tokens, parser, mapper) = make_test_inputs();
        let deadline = Instant::now() + Duration::from_secs(60);
        let upstream = futures::stream::iter(vec![Ok(GenerationEvent::Done(Outcome::Failed {
            position: 0,
            error: "executor exploded".to_string(),
        })) as anyhow::Result<GenerationEvent>]);

        let payloads: Vec<OpenAiSsePayload> = build_openai_sse_stream(
            id,
            created,
            model,
            prompt_tokens,
            deadline,
            false,
            parser,
            mapper,
            Some(test_provenance()),
            upstream,
        )
        .collect()
        .await;

        assert!(
            payloads.iter().any(|p| is_error_frame(p)
                && error_message(p).is_some_and(|m| m.contains("executor exploded"))),
            "expected Outcome::Failed error frame, got: {payloads:#?}"
        );
        assert!(
            !payloads.iter().any(is_done),
            "must not emit [DONE] after Outcome::Failed, got: {payloads:#?}"
        );
        assert!(
            payloads
                .iter()
                .filter(|p| matches!(p, OpenAiSsePayload::Json(_)))
                .all(|p| receipt_of(p).is_none()),
            "Outcome::Failed must not leak hellas.receipt, got: {payloads:#?}"
        );
    }

    /// Happy path with provenance: first chunk carries
    /// `hellas.commitment`; the SEMANTIC TERMINAL chunk (the one
    /// just before `[DONE]`) carries `hellas.receipt`; intermediate
    /// chunks carry no hellas field.
    #[tokio::test]
    async fn commitment_on_first_chunk_receipt_on_terminal_chunk() {
        let (id, created, model, prompt_tokens, parser, mapper) = make_test_inputs();
        let deadline = Instant::now() + Duration::from_secs(60);
        let prov = test_provenance();
        let receipt = test_receipt();
        let expected_receipt = receipt.encoded();

        let payloads: Vec<OpenAiSsePayload> = build_openai_sse_stream(
            id,
            created,
            model,
            prompt_tokens,
            deadline,
            false,
            parser,
            mapper,
            Some(prov.clone()),
            happy_upstream(receipt),
        )
        .collect()
        .await;

        // [DONE] always last on success.
        assert!(matches!(payloads.last(), Some(OpenAiSsePayload::Done)));

        // First chunk has commitment.
        let first = payloads.first().expect("non-empty");
        assert_eq!(commitment_of(first), Some("ab".repeat(32).as_str()));
        assert_eq!(receipt_of(first), None);

        // Terminal data event = last payload before Done.
        let json_payloads: Vec<&OpenAiSsePayload> = payloads
            .iter()
            .filter(|p| matches!(p, OpenAiSsePayload::Json(_)))
            .collect();
        let terminal = json_payloads.last().expect("at least one json chunk");
        assert!(
            has_finish_reason(terminal),
            "without include_usage, terminal chunk must carry finish_reason: {terminal:?}"
        );
        assert_eq!(receipt_of(terminal), Some(expected_receipt.as_str()));

        // Receipt appears EXACTLY once across the whole stream.
        let receipts: Vec<_> = json_payloads.iter().filter_map(|p| receipt_of(p)).collect();
        assert_eq!(receipts.len(), 1, "exactly one receipt: {receipts:?}");
    }

    /// Happy path WITHOUT provenance: first chunk has no hellas
    /// field at all; receipt still rides the terminal chunk because
    /// it's known regardless of whether commitment was set.
    #[tokio::test]
    async fn no_provenance_means_no_commitment_field() {
        let (id, created, model, prompt_tokens, parser, mapper) = make_test_inputs();
        let deadline = Instant::now() + Duration::from_secs(60);
        let receipt = test_receipt();
        let expected_receipt = receipt.encoded();

        let payloads: Vec<OpenAiSsePayload> = build_openai_sse_stream(
            id,
            created,
            model,
            prompt_tokens,
            deadline,
            false,
            parser,
            mapper,
            None,
            happy_upstream(receipt),
        )
        .collect()
        .await;

        let first = payloads.first().expect("non-empty");
        assert_eq!(commitment_of(first), None);
        // The first chunk's outer object must have no `hellas` key
        // at all (skip_serializing_if applied to an empty HellasExt).
        assert!(
            as_json(first).get("hellas").is_none(),
            "no provenance → no `hellas` field on first chunk: {first:?}"
        );

        let json_last = payloads
            .iter()
            .filter(|p| matches!(p, OpenAiSsePayload::Json(_)))
            .last()
            .unwrap();
        assert_eq!(receipt_of(json_last), Some(expected_receipt.as_str()));
    }

    /// `include_usage=true`: receipt rides the trailing usage chunk
    /// (semantic terminal in this mode), NOT the finish-reason chunk.
    #[tokio::test]
    async fn include_usage_routes_receipt_to_usage_chunk() {
        let (id, created, model, prompt_tokens, parser, mapper) = make_test_inputs();
        let deadline = Instant::now() + Duration::from_secs(60);

        let receipt = test_receipt();
        let expected_receipt = receipt.encoded();
        let payloads: Vec<OpenAiSsePayload> = build_openai_sse_stream(
            id,
            created,
            model,
            prompt_tokens,
            deadline,
            true, // include_usage
            parser,
            mapper,
            Some(test_provenance()),
            happy_upstream(receipt),
        )
        .collect()
        .await;

        let json_payloads: Vec<&OpenAiSsePayload> = payloads
            .iter()
            .filter(|p| matches!(p, OpenAiSsePayload::Json(_)))
            .collect();

        // Find the usage chunk and the finish-reason chunk.
        let usage = json_payloads
            .iter()
            .find(|p| is_usage_chunk(p))
            .expect("include_usage emits a usage chunk");
        let finish = json_payloads
            .iter()
            .find(|p| has_finish_reason(p))
            .expect("finish-reason chunk always emitted on success");

        // Usage chunk is the terminal event and carries the receipt.
        assert_eq!(receipt_of(usage), Some(expected_receipt.as_str()));
        // Finish-reason chunk is NO LONGER the terminal event when
        // usage is enabled — it must NOT carry the receipt.
        assert_eq!(
            receipt_of(finish),
            None,
            "with include_usage, finish-reason chunk must not carry receipt; got {finish:?}"
        );

        // Usage chunk is positioned just before [DONE].
        assert!(matches!(payloads.last(), Some(OpenAiSsePayload::Done)));
        let last_json = json_payloads.last().unwrap();
        assert!(
            is_usage_chunk(last_json),
            "with include_usage the last data event is the usage chunk: {last_json:?}"
        );
    }
}
