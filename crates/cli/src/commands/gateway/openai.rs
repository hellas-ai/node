use super::state::{GatewayState, GenerationEvent, PreparedGeneration};
use super::wire_adaptor::{
    adaptor_error, attach_provenance, chat_stream_response, parse_execution_request,
    provenance_from_parts, usage, wire_response,
};
use super::{next_id, now_unix};
use crate::execution::{Outcome, StopReason as ExecStopReason};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use hellas_runtime::runtime::chat::wire::openai::{OpenAiFinishReason, OpenAiStreamMapper};
use hellas_runtime::runtime::chat::wire::{PumpError, pump_finish, pump_text};
use hellas_runtime::runtime::chat::{
    DecodeFailure, IncrementalToolCallParser, StopReason as ParserStopReason,
};
use hellas_wire_adaptors::openai::chat_completions::{
    OpenAiChatCompletionsAdaptor, ParsedChatCompletionRequest,
};
use hellas_wire_adaptors::{
    ExecutionResult, OutputItem, RenderContext, StopReason as WireStopReason, WireAdaptor,
};
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let adaptor = OpenAiChatCompletionsAdaptor;
    let (parsed, execution) =
        match parse_execution_request(&adaptor, &body, "OpenAI Chat Completions") {
            Ok(request) => request,
            Err(response) => return response,
        };
    let stream_response_flag = parsed.stream == Some(true);
    let prepared = match state.prepare_openai_chat_execution(&execution).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream_response_flag {
        return stream_response(adaptor, parsed, prepared);
    }
    respond(adaptor, parsed, prepared).await
}

/// Non-streaming endpoint. Drives the same per-delta pipeline as the
/// streaming endpoint; the only difference is the sink — frames are
/// discarded, and the buffered assistant payload comes from
/// `mapper.snapshot()` at the end.
async fn respond(
    adaptor: OpenAiChatCompletionsAdaptor,
    mut parsed: ParsedChatCompletionRequest,
    prepared: PreparedGeneration,
) -> Response {
    let id = next_id("chatcmpl");
    let created = now_unix();
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let mut provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();

    let mut parser: Box<dyn IncrementalToolCallParser> = prepared
        .chat_turn
        .as_ref()
        .expect("OpenAI chat preparation attaches a ChatTurn")
        .make_parser();
    let mut mapper = OpenAiStreamMapper::new(|prefix: &str| next_id(prefix));

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
            error!(%message, "openai chat request failed");
            return super::json_error(StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };

    let (total_tokens, stop_reason, _receipt_cid, catnix_receipt) = match outcome {
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
                "openai chat completion ready"
            );
            (
                total_tokens,
                stop_reason,
                receipt_cid,
                catnix_receipt_commitment,
            )
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
    let finish_reason = snapshot.finish_reason;
    let message = match serde_json::to_value(snapshot.message) {
        Ok(message) => message,
        Err(err) => {
            error!(%err, "openai chat response serialization failed");
            return super::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialize chat response",
            );
        }
    };
    parsed.model = model;
    let result = ExecutionResult {
        output: vec![OutputItem::Raw(message)],
        usage: Some(usage(prompt_tokens, total_tokens)),
        stop_reason: wire_stop_reason_from_openai_finish(finish_reason),
        provenance: provenance_from_parts(provenance.as_ref(), catnix_receipt.as_ref()),
    };
    let rendered = match adaptor.render_response(
        &parsed,
        result,
        RenderContext::new(id, next_id("msg"), created),
    ) {
        Ok(rendered) => rendered,
        Err(err) => return adaptor_error("OpenAI Chat Completions", err),
    };
    let mut response = match wire_response(rendered) {
        Ok(response) => response,
        Err(message) => return super::json_error(StatusCode::INTERNAL_SERVER_ERROR, message),
    };
    attach_provenance(&mut response, provenance, catnix_receipt);
    response
}

fn wire_stop_reason_from_openai_finish(reason: OpenAiFinishReason) -> WireStopReason {
    match reason {
        OpenAiFinishReason::Stop => WireStopReason::EndOfText,
        OpenAiFinishReason::Length => WireStopReason::MaxOutputTokens,
        OpenAiFinishReason::ToolCalls => WireStopReason::ToolCall,
    }
}

fn stream_response(
    adaptor: OpenAiChatCompletionsAdaptor,
    mut parsed: ParsedChatCompletionRequest,
    prepared: PreparedGeneration,
) -> Response {
    parsed.model = prepared.model.clone();
    chat_stream_response(
        adaptor,
        parsed,
        prepared,
        RenderContext::new(next_id("chatcmpl"), next_id("msg"), now_unix()),
        "call",
        "openai chat completion ready",
    )
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
