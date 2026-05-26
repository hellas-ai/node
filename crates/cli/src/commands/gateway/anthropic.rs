use super::next_id;
use super::state::{GatewayState, GenerationEvent, PreparedGeneration};
use super::wire_adaptor::{
    adaptor_error, attach_provenance, chat_stream_response, parse_execution_request,
    provenance_from_parts, usage, wire_response,
};
use crate::execution::{Outcome, StopReason as ExecStopReason};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use hellas_runtime::runtime::chat::wire::anthropic::{AnthropicStopReason, AnthropicStreamMapper};
use hellas_runtime::runtime::chat::wire::{PumpError, pump_finish, pump_text};
use hellas_runtime::runtime::chat::{
    DecodeFailure, IncrementalToolCallParser, StopReason as ParserStopReason,
};
use hellas_wire_adaptors::anthropic::{AnthropicMessagesAdaptor, ParsedAnthropicMessageRequest};
use hellas_wire_adaptors::{
    ExecutionResult, OutputItem, RenderContext, StopReason as WireStopReason, WireAdaptor,
};
use serde_json::Value as JsonValue;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let adaptor = AnthropicMessagesAdaptor;
    let (parsed, execution) = match parse_execution_request(&adaptor, &body, "Anthropic Messages") {
        Ok(request) => request,
        Err(response) => return response,
    };
    let stream_response_flag = parsed.stream == Some(true);
    let prepared = match state.prepare_anthropic_execution(&execution).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream_response_flag {
        return stream_response(adaptor, parsed, prepared);
    }
    respond(adaptor, parsed, prepared).await
}

/// Non-streaming endpoint. Same per-delta pipeline as streaming;
/// frames are discarded and `mapper.snapshot()` provides the buffered
/// content blocks + stop_reason.
async fn respond(
    adaptor: AnthropicMessagesAdaptor,
    mut parsed: ParsedAnthropicMessageRequest,
    prepared: PreparedGeneration,
) -> Response {
    let id = next_id("msg");
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let mut provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();

    let mut parser: Box<dyn IncrementalToolCallParser> = prepared
        .chat_turn
        .as_ref()
        .expect("Anthropic preparation attaches a ChatTurn")
        .make_parser();
    let mut mapper = AnthropicStreamMapper::new(|prefix: &str| next_id(prefix));

    let stream = prepared.stream();
    tokio::pin!(stream);

    let outcome = loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(GenerationEvent::Provenance(prov)))) => {
                provenance = Some(prov);
            }
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
            error!(%message, "anthropic message request failed");
            return super::json_error(StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };

    let (total_tokens, exec_stop, _receipt_cid, catnix_receipt) = match outcome {
        Outcome::Completed {
            total_tokens,
            stop_reason,
            receipt_cid,
            catnix_receipt_commitment,
        } => {
            info!(
                %receipt_cid,
                ?provenance,
                total_tokens,
                ?stop_reason,
                ?catnix_receipt_commitment,
                "anthropic message completion ready"
            );
            (
                total_tokens,
                stop_reason,
                receipt_cid,
                catnix_receipt_commitment,
            )
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
    if let Err(PumpError { failure, .. }) = pump_finish(&mut *parser, &mut mapper, parser_stop) {
        return failure_to_json_response(failure);
    }

    let snapshot = match mapper.snapshot() {
        Ok(s) => s,
        Err(failure) => return failure_to_json_response(failure),
    };
    let stop_reason = snapshot.stop_reason;
    parsed.model = model;
    let result = ExecutionResult {
        output: vec![OutputItem::Raw(JsonValue::Array(snapshot.blocks))],
        usage: Some(usage(prompt_tokens, total_tokens)),
        stop_reason: wire_stop_reason_from_anthropic(stop_reason),
        provenance: provenance_from_parts(provenance.as_ref(), catnix_receipt.as_ref()),
    };
    let rendered = match adaptor.render_response(
        &parsed,
        result,
        RenderContext::new(id, next_id("unused"), 0),
    ) {
        Ok(rendered) => rendered,
        Err(err) => return adaptor_error("Anthropic Messages", err),
    };
    let mut response = match wire_response(rendered) {
        Ok(response) => response,
        Err(message) => return super::json_error(StatusCode::INTERNAL_SERVER_ERROR, message),
    };
    attach_provenance(&mut response, provenance, catnix_receipt);
    response
}

fn wire_stop_reason_from_anthropic(reason: AnthropicStopReason) -> WireStopReason {
    match reason {
        AnthropicStopReason::EndTurn => WireStopReason::EndOfText,
        AnthropicStopReason::MaxTokens => WireStopReason::MaxOutputTokens,
        AnthropicStopReason::ToolUse => WireStopReason::ToolCall,
    }
}

fn stream_response(
    adaptor: AnthropicMessagesAdaptor,
    mut parsed: ParsedAnthropicMessageRequest,
    prepared: PreparedGeneration,
) -> Response {
    parsed.model = prepared.model.clone();
    chat_stream_response(
        adaptor,
        parsed,
        prepared,
        RenderContext::new(next_id("msg"), next_id("unused"), 0),
        "toolu",
        "anthropic message completion ready",
    )
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
