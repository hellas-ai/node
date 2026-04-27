use super::hellas_ext::{HellasExt, WithHellas};
use super::state::{GatewayState, GenerationEvent, PreparedGeneration};
use super::{next_id, parse_json_body, sse_event_data, sse_response};
use crate::execution::{Outcome, StopReason as ExecStopReason};
use async_stream::stream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::Event;
use axum::response::{IntoResponse, Response};
use catgrad_llm::runtime::chat::wire::anthropic::{AnthropicStreamFrame, AnthropicStreamMapper};
use catgrad_llm::runtime::chat::wire::{PumpError, pump_finish, pump_text};
use catgrad_llm::runtime::chat::{
    DecodeFailure, IncrementalToolCallParser, StopReason as ParserStopReason,
};
use catgrad_llm::types::anthropic;
use futures::StreamExt;
use hellas_rpc::provenance::ExecutionProvenance;
use serde_json::json;
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

/// Non-streaming endpoint. Same per-delta pipeline as streaming;
/// frames are discarded and `mapper.snapshot()` provides the buffered
/// content blocks + stop_reason.
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
    let mut mapper = AnthropicStreamMapper::new(|prefix: &str| next_id(prefix));

    let stream = prepared.stream();
    tokio::pin!(stream);

    let outcome = loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(GenerationEvent::Delta(d)))) => {
                if let Err(PumpError { failure, .. }) =
                    pump_text(&mut *parser, &mut mapper, &d)
                {
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
    if let Err(PumpError { failure, .. }) =
        pump_finish(&mut *parser, &mut mapper, parser_stop)
    {
        return failure_to_json_response(failure);
    }

    let snapshot = match mapper.snapshot() {
        Ok(s) => s,
        Err(failure) => return failure_to_json_response(failure),
    };
    let response = anthropic::MessageResponse::builder()
        .id(id)
        .message_type(Some("message".to_string()))
        .role("assistant".to_string())
        .content(snapshot.blocks)
        .model(model)
        .stop_reason(Some(snapshot.stop_reason))
        .usage(anthropic::AnthropicUsage::new(
            prompt_tokens,
            u32::try_from(total_tokens).unwrap_or(u32::MAX),
        ))
        .build();

    let hellas = match provenance.as_ref() {
        Some(prov) => HellasExt::both(prov, &receipt_cid),
        None => HellasExt::receipt(&receipt_cid),
    };
    let body = WithHellas::new(response, hellas);

    let mut response = Json(body).into_response();
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    }
    response.extensions_mut().insert(receipt_cid);
    response
}

/// One unit of wire output the Anthropic streaming endpoint emits.
/// Tests assert on `name` + `json` directly; production maps each
/// to `axum::response::sse::Event::default().event(name).data(json)`
/// via `into_event`. There is no `[DONE]` equivalent — `message_stop`
/// (or `error`) is the structural terminator.
#[cfg_attr(test, derive(Debug))]
struct AnthropicSsePayload {
    name: &'static str,
    json: serde_json::Value,
}

impl AnthropicSsePayload {
    fn into_event(self) -> Event {
        sse_event_data(self.name, &self.json)
    }
}

/// Streaming endpoint. The mapper owns content-block bookkeeping; this
/// function emits `message_start` / `message_stop` envelopes and wraps
/// each `AnthropicStreamFrame` into the matching SSE event. The actual
/// stream-building lives in [`build_anthropic_sse_stream`] so the wire
/// shape can be tested directly with synthetic upstream streams (no
/// axum / no real executor required).
fn stream_response(prepared: PreparedGeneration) -> Response {
    let id = next_id("msg");
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();

    let parser: Box<dyn IncrementalToolCallParser> = prepared
        .chat_turn
        .as_ref()
        .expect("Anthropic surface always carries a ChatTurn")
        .make_parser();
    let mapper = AnthropicStreamMapper::new(|prefix: &str| next_id(prefix));

    let stream_provenance = provenance.clone();
    let upstream = prepared.stream();
    let payloads = build_anthropic_sse_stream(
        id,
        model,
        prompt_tokens,
        deadline,
        parser,
        mapper,
        stream_provenance,
        upstream,
    );
    let events = payloads
        .map(|payload| Ok::<_, std::convert::Infallible>(payload.into_event()));
    let mut response = sse_response(events);
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    }
    response
}

/// Inner SSE-event generator, generic over the upstream
/// `GenerationEvent` stream. Returns a stream of [`AnthropicSsePayload`]s
/// (rather than opaque axum `Event`s) so tests can inspect the
/// emitted wire shape directly. Production wraps via `into_event`.
fn build_anthropic_sse_stream<S>(
    id: String,
    model: String,
    prompt_tokens: u32,
    deadline: tokio::time::Instant,
    mut parser: Box<dyn IncrementalToolCallParser>,
    mut mapper: AnthropicStreamMapper,
    provenance: Option<ExecutionProvenance>,
    upstream: S,
) -> impl futures::Stream<Item = AnthropicSsePayload> + Send
where
    S: futures::Stream<Item = anyhow::Result<GenerationEvent>> + Send + 'static,
{
    stream! {
        // Stamp hellas.commitment_id INSIDE message_start.message
        // (on the MessageResponse), so the field path is identical
        // between streaming (`message_start.message.hellas.commitment_id`)
        // and non-streaming (`hellas.commitment_id` on MessageResponse).
        // Browser EventSource consumers can't read response headers,
        // so this in-band placement is the canonical commitment carrier.
        let message = anthropic::MessageResponse::builder()
            .id(id.clone())
            .message_type(Some("message".to_string()))
            .role("assistant".to_string())
            .content(vec![])
            .model(model)
            .usage(anthropic::AnthropicUsage::new(prompt_tokens, 0))
            .build();
        let message_hellas = match provenance.as_ref() {
            Some(prov) => HellasExt::commitment(prov),
            None => HellasExt::default(),
        };
        let wrapped_message = WithHellas::new(message, message_hellas);
        // MessageStreamEvent::MessageStart { message: MessageResponse }
        // is a typed variant, so we can't substitute WithHellas<MessageResponse>
        // for the field. Construct the JSON envelope manually — the only
        // boundary where we step around the typed enum.
        yield AnthropicSsePayload {
            name: "message_start",
            json: json!({
                "type": "message_start",
                "message": wrapped_message,
            }),
        };

        let inner = upstream;
        tokio::pin!(inner);

        let mut outcome: Option<Outcome> = None;
        let mut transport_error: Option<String> = None;
        let mut timed_out = false;
        let mut protocol_failure: Option<PumpError<AnthropicStreamFrame>> = None;

        'outer: loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Delta(text)))) => {
                    match pump_text(&mut *parser, &mut mapper, &text) {
                        Ok(frames) => {
                            for frame in frames {
                                // No final usage yet — only used by
                                // Stop frame, which the mapper only
                                // emits from finish().
                                if let Some(p) =
                                    frame_to_payload(frame, prompt_tokens, 0)
                                {
                                    yield p;
                                }
                            }
                        }
                        Err(err) => {
                            // PumpError already drained close_for_error
                            // from the mapper — stash and emit with the
                            // error frame below.
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

        // Protocol error path: emit any cleanup frames the pump
        // drained from close_for_error (so the `error` event arrives
        // in a bracketed stream — fixes the "open block + error"
        // wire bug), then emit `error` and close. No `message_stop`
        // follows — Anthropic clients treat `error` as terminal.
        if let Some(PumpError { failure, cleanup }) = protocol_failure {
            warn!(message = %failure, "anthropic message aborted with parser protocol error");
            for frame in cleanup {
                if let Some(p) = frame_to_payload(frame, prompt_tokens, 0) {
                    yield p;
                }
            }
            yield error_payload(error_type_for(&failure), failure.to_string());
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
            // Close any open content block before the terminal error
            // frame so the wire stays bracketed. Same `close_for_error`
            // helper as the protocol-error path.
            for frame in mapper.close_for_error() {
                if let Some(p) = frame_to_payload(frame, prompt_tokens, 0) {
                    yield p;
                }
            }
            yield error_payload(
                "invalid_request_error",
                format!("Inference error: {error}"),
            );
            return;
        }

        let outcome = outcome.expect("loop only breaks with a terminal observation");
        match outcome {
            Outcome::Failed { error, .. } => {
                for frame in mapper.close_for_error() {
                    if let Some(p) = frame_to_payload(frame, prompt_tokens, 0) {
                        yield p;
                    }
                }
                yield error_payload(
                    "invalid_request_error",
                    format!("Inference error: {error}"),
                );
                return;
            }
            Outcome::Completed {
                stop_reason,
                total_tokens,
                receipt_cid,
            } => {
                info!(
                    %receipt_cid,
                    provenance = ?provenance,
                    total_tokens,
                    ?stop_reason,
                    "anthropic message completion ready"
                );

                let parser_stop = map_to_parser_stop(stop_reason);
                let output_tokens = u32::try_from(total_tokens).unwrap_or(u32::MAX);

                // Drain parser tail + mapper.finish via the pump.
                // Frames are: (zero or more) block-close frames, then
                // the terminal Stop (becomes `message_delta` with our
                // output_tokens).
                match pump_finish(&mut *parser, &mut mapper, parser_stop) {
                    Ok(frames) => {
                        for frame in frames {
                            if let Some(p) =
                                frame_to_payload(frame, prompt_tokens, output_tokens)
                            {
                                yield p;
                            }
                        }
                    }
                    Err(PumpError { failure, cleanup }) => {
                        warn!(message = %failure, "anthropic message aborted with parser protocol error during finish");
                        for frame in cleanup {
                            if let Some(p) =
                                frame_to_payload(frame, prompt_tokens, output_tokens)
                            {
                                yield p;
                            }
                        }
                        yield error_payload(error_type_for(&failure), failure.to_string());
                        return;
                    }
                }

                // message_stop is the SEMANTIC TERMINAL event.
                // Wrapping it with hellas.receipt_id makes "receipt
                // is on the terminal event" a testable invariant.
                let stop_event = WithHellas::new(
                    anthropic::MessageStreamEvent::MessageStop,
                    HellasExt::receipt(&receipt_cid),
                );
                yield AnthropicSsePayload {
                    name: "message_stop",
                    json: serde_json::to_value(stop_event).unwrap(),
                };
            }
        }
    }
}

fn error_payload(error_type: &str, message: String) -> AnthropicSsePayload {
    AnthropicSsePayload {
        name: "error",
        json: serde_json::to_value(anthropic::MessageStreamEvent::Error {
            error: anthropic::StreamError {
                error_type: error_type.to_string(),
                message,
            },
        })
        .unwrap(),
    }
}

/// Convert one `AnthropicStreamFrame` into the matching SSE payload
/// (event name + JSON body). The mapper produces content-block-level
/// frames plus a terminal `Stop` carrying the resolved stop_reason;
/// this function adds the `message_delta` envelope (with caller-owned
/// usage) for the stop, and the corresponding `content_block_*` event
/// names for each block-level frame.
fn frame_to_payload(
    frame: AnthropicStreamFrame,
    prompt_tokens: u32,
    output_tokens: u32,
) -> Option<AnthropicSsePayload> {
    let (name, ev) = match frame {
        AnthropicStreamFrame::BlockStart { index, block } => (
            "content_block_start",
            anthropic::MessageStreamEvent::ContentBlockStart {
                index,
                content_block: block,
            },
        ),
        AnthropicStreamFrame::BlockDelta { index, delta } => (
            "content_block_delta",
            anthropic::MessageStreamEvent::ContentBlockDelta { index, delta },
        ),
        AnthropicStreamFrame::BlockStop { index } => (
            "content_block_stop",
            anthropic::MessageStreamEvent::ContentBlockStop { index },
        ),
        AnthropicStreamFrame::Stop(stop_reason) => (
            "message_delta",
            anthropic::MessageStreamEvent::MessageDelta {
                delta: anthropic::StreamMessageDelta {
                    stop_reason: Some(stop_reason),
                },
                usage: anthropic::AnthropicUsage::new(prompt_tokens, output_tokens),
            },
        ),
    };
    Some(AnthropicSsePayload {
        name,
        json: serde_json::to_value(ev).unwrap(),
    })
}

fn error_type_for(failure: &DecodeFailure) -> &'static str {
    match failure {
        DecodeFailure::InternalSequence { .. } => "internal_error",
        _ => "invalid_request_error",
    }
}

fn failure_to_json_response(failure: DecodeFailure) -> Response {
    let status = match failure {
        DecodeFailure::InternalSequence { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_GATEWAY,
    };
    let message = failure.to_string();
    warn!(%message, "anthropic message aborted with parser protocol error");
    super::json_error(status, message)
}

fn map_to_parser_stop(stop: ExecStopReason) -> ParserStopReason {
    match stop {
        ExecStopReason::EndOfSequence => ParserStopReason::EndOfText,
        ExecStopReason::MaxNewTokens => ParserStopReason::MaxTokens,
        ExecStopReason::Cancelled => ParserStopReason::EndOfText,
    }
}

#[cfg(test)]
mod streaming_tests {
    //! Wire-shape tests for the Anthropic streaming endpoint.
    //!
    //! Drives `build_anthropic_sse_stream` with synthetic upstream
    //! streams and asserts the contract:
    //! - first event is `message_start` and its `.message` carries
    //!   `hellas.commitment_id` (parity with non-streaming
    //!   `MessageResponse`);
    //! - on `Outcome::Completed`, `message_stop` is the SEMANTIC
    //!   TERMINAL event and carries `hellas.receipt_id`;
    //! - error paths (transport / timeout / `Outcome::Failed`) emit
    //!   NO `hellas.receipt_id` and the `error` event is the closer
    //!   (no `message_stop` follows it).
    //! - `message_delta` does NOT carry the receipt — that lives on
    //!   `message_stop`.

    use super::*;
    use crate::execution::{Outcome, StopReason as ExecStopReason};
    use catgrad::cid::Cid;
    use catgrad_llm::runtime::TextReceipt;
    use catgrad_llm::runtime::chat::PassthroughParser;
    use futures::StreamExt;
    use std::time::Duration;
    use tokio::time::Instant;

    fn make_test_inputs() -> (
        String,
        String,
        u32,
        Box<dyn IncrementalToolCallParser>,
        AnthropicStreamMapper,
    ) {
        (
            "msg-test".into(),
            "test-model".into(),
            0,
            Box::new(PassthroughParser),
            AnthropicStreamMapper::new(|prefix: &str| format!("{prefix}-test")),
        )
    }

    fn test_provenance() -> ExecutionProvenance {
        ExecutionProvenance {
            commitment_id: [0xab; 32],
        }
    }

    fn test_receipt() -> Cid<TextReceipt> {
        Cid::<TextReceipt>::from_bytes([0xcd; 32])
    }

    fn happy_upstream(
        receipt_cid: Cid<TextReceipt>,
    ) -> impl futures::Stream<Item = anyhow::Result<GenerationEvent>> + Send + 'static {
        futures::stream::iter(vec![
            Ok(GenerationEvent::Delta("hi".to_string())),
            Ok(GenerationEvent::Done(Outcome::Completed {
                total_tokens: 1,
                stop_reason: ExecStopReason::EndOfSequence,
                receipt_cid,
            })),
        ])
    }

    fn receipt_of(p: &AnthropicSsePayload) -> Option<&str> {
        p.json
            .get("hellas")
            .and_then(|h| h.get("receipt_id"))
            .and_then(|v| v.as_str())
    }

    fn commitment_in_message_start(p: &AnthropicSsePayload) -> Option<&str> {
        if p.name != "message_start" {
            return None;
        }
        p.json
            .get("message")
            .and_then(|m| m.get("hellas"))
            .and_then(|h| h.get("commitment_id"))
            .and_then(|v| v.as_str())
    }

    /// Happy path: message_start.message carries commitment;
    /// message_stop carries receipt; message_delta does NOT carry
    /// receipt; message_stop is the last event.
    #[tokio::test]
    async fn commitment_in_message_start_receipt_in_message_stop() {
        let (id, model, prompt_tokens, parser, mapper) = make_test_inputs();
        let deadline = Instant::now() + Duration::from_secs(60);

        let payloads: Vec<AnthropicSsePayload> = build_anthropic_sse_stream(
            id,
            model,
            prompt_tokens,
            deadline,
            parser,
            mapper,
            Some(test_provenance()),
            happy_upstream(test_receipt()),
        )
        .collect()
        .await;

        let first = payloads.first().expect("non-empty");
        assert_eq!(first.name, "message_start");
        assert_eq!(
            commitment_in_message_start(first),
            Some("ab".repeat(32).as_str())
        );

        let last = payloads.last().expect("non-empty");
        assert_eq!(last.name, "message_stop", "message_stop must be terminal");
        assert_eq!(receipt_of(last), Some("cd".repeat(32).as_str()));

        // Receipt appears EXACTLY once and only on message_stop.
        let receipt_carriers: Vec<&'static str> = payloads
            .iter()
            .filter(|p| receipt_of(p).is_some())
            .map(|p| p.name)
            .collect();
        assert_eq!(receipt_carriers, vec!["message_stop"]);

        // message_delta exists in the stream but doesn't carry receipt.
        let deltas: Vec<&AnthropicSsePayload> =
            payloads.iter().filter(|p| p.name == "message_delta").collect();
        assert!(!deltas.is_empty(), "expected at least one message_delta");
        for d in deltas {
            assert!(
                receipt_of(d).is_none(),
                "message_delta must not carry hellas.receipt_id: {d:?}"
            );
        }
    }

    /// No provenance: message_start.message has no hellas key at all.
    #[tokio::test]
    async fn no_provenance_means_no_message_start_hellas() {
        let (id, model, prompt_tokens, parser, mapper) = make_test_inputs();
        let deadline = Instant::now() + Duration::from_secs(60);

        let payloads: Vec<AnthropicSsePayload> = build_anthropic_sse_stream(
            id,
            model,
            prompt_tokens,
            deadline,
            parser,
            mapper,
            None,
            happy_upstream(test_receipt()),
        )
        .collect()
        .await;

        let first = payloads.first().expect("non-empty");
        assert_eq!(first.name, "message_start");
        assert!(
            first
                .json
                .get("message")
                .and_then(|m| m.get("hellas"))
                .is_none(),
            "no provenance → no `hellas` field inside message: {first:?}"
        );
    }

    /// Transport error: error event is the closer, no message_stop,
    /// no receipt anywhere.
    #[tokio::test]
    async fn transport_error_emits_error_no_message_stop_no_receipt() {
        let (id, model, prompt_tokens, parser, mapper) = make_test_inputs();
        let deadline = Instant::now() + Duration::from_secs(60);
        let upstream = futures::stream::iter(vec![
            Err(anyhow::anyhow!("upstream blew up")) as anyhow::Result<GenerationEvent>,
        ]);

        let payloads: Vec<AnthropicSsePayload> = build_anthropic_sse_stream(
            id,
            model,
            prompt_tokens,
            deadline,
            parser,
            mapper,
            Some(test_provenance()),
            upstream,
        )
        .collect()
        .await;

        let last = payloads.last().expect("non-empty");
        assert_eq!(last.name, "error", "error must be the closer");
        assert!(
            payloads.iter().all(|p| p.name != "message_stop"),
            "transport error must not emit message_stop"
        );
        assert!(
            payloads.iter().all(|p| receipt_of(p).is_none()),
            "transport error must not leak hellas.receipt_id: {payloads:#?}"
        );
    }

    /// Timeout: same shape as transport error.
    #[tokio::test]
    async fn timeout_emits_error_no_message_stop_no_receipt() {
        let (id, model, prompt_tokens, parser, mapper) = make_test_inputs();
        let deadline = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let upstream = futures::stream::pending::<anyhow::Result<GenerationEvent>>();

        let payloads: Vec<AnthropicSsePayload> = build_anthropic_sse_stream(
            id,
            model,
            prompt_tokens,
            deadline,
            parser,
            mapper,
            Some(test_provenance()),
            upstream,
        )
        .collect()
        .await;

        let last = payloads.last().expect("non-empty");
        assert_eq!(last.name, "error");
        assert!(payloads.iter().all(|p| p.name != "message_stop"));
        assert!(payloads.iter().all(|p| receipt_of(p).is_none()));
    }

    /// Outcome::Failed: same shape.
    #[tokio::test]
    async fn outcome_failed_emits_error_no_message_stop_no_receipt() {
        let (id, model, prompt_tokens, parser, mapper) = make_test_inputs();
        let deadline = Instant::now() + Duration::from_secs(60);
        let upstream = futures::stream::iter(vec![Ok(GenerationEvent::Done(
            Outcome::Failed {
                position: 0,
                error: "executor exploded".to_string(),
            },
        ))
            as anyhow::Result<GenerationEvent>]);

        let payloads: Vec<AnthropicSsePayload> = build_anthropic_sse_stream(
            id,
            model,
            prompt_tokens,
            deadline,
            parser,
            mapper,
            Some(test_provenance()),
            upstream,
        )
        .collect()
        .await;

        let last = payloads.last().expect("non-empty");
        assert_eq!(last.name, "error");
        assert!(payloads.iter().all(|p| p.name != "message_stop"));
        assert!(payloads.iter().all(|p| receipt_of(p).is_none()));
    }
}
