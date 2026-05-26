use super::state::{GatewayState, GenerationEvent, PreparedGeneration, TextGenerationError};
use super::{next_id, now_unix, sse_data, sse_event_data, sse_response};
use crate::execution::{Outcome, StopReason as RuntimeStopReason};
use async_stream::stream;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use hellas_rpc::provenance::{CatnixReceiptCommitment, ExecutionProvenance, encode_hex};
use hellas_wire_adaptors::openai::responses::{OpenAiResponsesAdaptor, ParsedResponseRequest};
use hellas_wire_adaptors::{
    AdaptorError, ExecutionResult, OutputEvent, OutputItem, Provenance, RawRequest, RenderContext,
    StopReason, TextChannel, Usage, WireAdaptor, WireBody, WireEventData, WireResponse,
    WireStreamEvent,
};
use serde_json::json;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    if let Some(proxy) = state.responses_proxy.as_ref() {
        return match proxy.forward(body).await {
            Ok(response) => response,
            Err(err) => err.into_response(),
        };
    }

    let adaptor = OpenAiResponsesAdaptor;
    let raw = match RawRequest::from_slice(&body) {
        Ok(raw) => raw,
        Err(err) => return adaptor_error("OpenAI Responses", err),
    };
    let parsed = match adaptor.parse(raw) {
        Ok(parsed) => parsed,
        Err(err) => return adaptor_error("OpenAI Responses", err),
    };
    let execution = match adaptor.to_execution_request(&parsed) {
        Ok(execution) => execution,
        Err(err) => return adaptor_error("OpenAI Responses", err),
    };
    let stream = parsed.stream.unwrap_or(false);
    let prepared = match state.prepare_wire_execution(&execution).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream {
        stream_response(adaptor, parsed, prepared)
    } else {
        respond(adaptor, parsed, prepared).await
    }
}

async fn respond(
    adaptor: OpenAiResponsesAdaptor,
    parsed: ParsedResponseRequest,
    prepared: PreparedGeneration,
) -> Response {
    let context = render_context();
    let prompt_tokens = prepared.prompt_tokens;

    let completed = match prepared.collect_text().await {
        Ok(completed) => {
            info!(
                %completed.receipt_cid,
                provenance = ?completed.provenance,
                total_tokens = completed.total_tokens,
                stop_reason = ?completed.stop_reason,
                "openai response ready"
            );
            completed
        }
        Err(TextGenerationError::Failed { position, error }) => {
            warn!(position, %error, "openai response request failed");
            return super::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
        Err(TextGenerationError::Stream(message)) => {
            error!(%message, "openai response request failed");
            return super::json_error(StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };

    let provenance = completed.provenance.clone();
    let receipt = completed.catnix_receipt_commitment.clone();
    let result = execution_result(
        completed.text,
        prompt_tokens,
        completed.total_tokens,
        completed.stop_reason,
        provenance.as_ref(),
        receipt.as_ref(),
    );

    let wire = match adaptor.render_response(&parsed, result, context) {
        Ok(response) => response,
        Err(err) => return adaptor_error("OpenAI Responses", err),
    };
    let mut response = match wire_response(wire) {
        Ok(response) => response,
        Err(message) => return super::json_error(StatusCode::INTERNAL_SERVER_ERROR, message),
    };
    attach_provenance(&mut response, provenance, receipt);
    response
}

fn stream_response(
    adaptor: OpenAiResponsesAdaptor,
    parsed: ParsedResponseRequest,
    prepared: PreparedGeneration,
) -> Response {
    let context = render_context();
    let prompt_tokens = prepared.prompt_tokens;
    let initial_provenance = prepared.provenance.clone();
    let response_provenance = initial_provenance.clone();
    let deadline = prepared.deadline();

    let mut response = sse_response(stream! {
        let mut state = adaptor.initial_state(&parsed, context);
        if let Some(provenance) = initial_provenance.as_ref().and_then(provenance_from_execution) {
            match adaptor.render_stream_event(&parsed, &mut state, OutputEvent::Provenance(provenance)) {
                Ok(events) => {
                    for event in events {
                        yield Ok(sse_event(event));
                    }
                }
                Err(err) => {
                    yield Ok(wire_error_event(err));
                    return;
                }
            }
        }
        match adaptor.render_stream_start(&parsed, &mut state) {
            Ok(events) => {
                for event in events {
                    yield Ok(sse_event(event));
                }
            }
            Err(err) => {
                yield Ok(wire_error_event(err));
                return;
            }
        }

        let inner = prepared.stream();
        tokio::pin!(inner);
        let mut stream_provenance = initial_provenance.clone();
        let mut text = String::new();

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Provenance(prov)))) => {
                    stream_provenance = Some(prov);
                    if let Some(provenance) = stream_provenance.as_ref().and_then(provenance_from_execution) {
                        match adaptor.render_stream_event(&parsed, &mut state, OutputEvent::Provenance(provenance)) {
                            Ok(events) => {
                                for event in events {
                                    yield Ok(sse_event(event));
                                }
                            }
                            Err(err) => {
                                yield Ok(wire_error_event(err));
                                return;
                            }
                        }
                    }
                }
                Ok(Some(Ok(GenerationEvent::Delta(delta)))) => {
                    text.push_str(&delta);
                    match adaptor.render_stream_event(
                        &parsed,
                        &mut state,
                        OutputEvent::TextDelta {
                            index: 0,
                            delta,
                            channel: TextChannel::Output,
                        },
                    ) {
                        Ok(events) => {
                            for event in events {
                                yield Ok(sse_event(event));
                            }
                        }
                        Err(err) => {
                            yield Ok(wire_error_event(err));
                            return;
                        }
                    }
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Completed {
                    total_tokens,
                    stop_reason,
                    receipt_cid,
                    catnix_receipt_commitment,
                })))) => {
                    info!(
                        %receipt_cid,
                        provenance = ?stream_provenance,
                        total_tokens,
                        ?stop_reason,
                        "openai response ready"
                    );
                    if let Some(provenance) = provenance_from_parts(
                        stream_provenance.as_ref(),
                        catnix_receipt_commitment.as_ref(),
                    ) {
                        match adaptor.render_stream_event(&parsed, &mut state, OutputEvent::Provenance(provenance)) {
                            Ok(events) => {
                                for event in events {
                                    yield Ok(sse_event(event));
                                }
                            }
                            Err(err) => {
                                yield Ok(wire_error_event(err));
                                return;
                            }
                        }
                    }
                    let usage = usage(prompt_tokens, total_tokens);
                    match adaptor.render_stream_event(
                        &parsed,
                        &mut state,
                        OutputEvent::Finished {
                            stop_reason: stop_reason_from_runtime(stop_reason),
                            usage: Some(usage),
                        },
                    ) {
                        Ok(events) => {
                            for event in events {
                                yield Ok(sse_event(event));
                            }
                        }
                        Err(err) => yield Ok(wire_error_event(err)),
                    }
                    return;
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Failed { error, .. })))) => {
                    yield Ok(output_error_event(format!("Inference error: {error}")));
                    return;
                }
                Ok(Some(Err(err))) => {
                    yield Ok(output_error_event(format!("Inference error: {err:#}")));
                    return;
                }
                Ok(None) => {
                    yield Ok(output_error_event("execution stream ended without terminal outcome"));
                    return;
                }
                Err(_) => {
                    yield Ok(output_error_event(format!(
                        "inference timed out after {}s",
                        super::timeout_secs_until(deadline)
                    )));
                    return;
                }
            }
        }
    });

    if let Some(provenance) = response_provenance {
        response.extensions_mut().insert(provenance);
    }
    response
}

fn render_context() -> RenderContext {
    RenderContext::new(next_id("resp"), next_id("msg"), now_unix())
}

fn execution_result(
    text: String,
    prompt_tokens: u32,
    output_tokens: u64,
    stop_reason: RuntimeStopReason,
    provenance: Option<&ExecutionProvenance>,
    receipt: Option<&CatnixReceiptCommitment>,
) -> ExecutionResult {
    ExecutionResult {
        output: vec![OutputItem::Text {
            text,
            channel: TextChannel::Output,
        }],
        usage: Some(usage(prompt_tokens, output_tokens)),
        stop_reason: stop_reason_from_runtime(stop_reason),
        provenance: provenance_from_parts(provenance, receipt),
    }
}

fn usage(prompt_tokens: u32, output_tokens: u64) -> Usage {
    let input_tokens = u64::from(prompt_tokens);
    Usage {
        input_tokens: Some(input_tokens),
        output_tokens: Some(output_tokens),
        total_tokens: Some(input_tokens.saturating_add(output_tokens)),
    }
}

fn provenance_from_parts(
    provenance: Option<&ExecutionProvenance>,
    receipt: Option<&CatnixReceiptCommitment>,
) -> Option<Provenance> {
    let mut out = provenance
        .and_then(provenance_from_execution)
        .unwrap_or_default();
    if let Some(receipt) = receipt {
        out.receipt_commitment = Some(encode_hex(&receipt.0));
    }
    (out.call_commitment.is_some() || out.receipt_commitment.is_some()).then_some(out)
}

fn provenance_from_execution(provenance: &ExecutionProvenance) -> Option<Provenance> {
    provenance
        .catnix_call_commitment
        .as_ref()
        .map(encode_hex)
        .map(|call_commitment| Provenance {
            call_commitment: Some(call_commitment),
            receipt_commitment: None,
        })
}

fn stop_reason_from_runtime(stop_reason: RuntimeStopReason) -> StopReason {
    match stop_reason {
        RuntimeStopReason::EndOfSequence => StopReason::EndOfText,
        RuntimeStopReason::MaxNewTokens => StopReason::MaxOutputTokens,
        RuntimeStopReason::Cancelled => StopReason::Cancelled,
    }
}

fn wire_response(response: WireResponse) -> Result<Response, String> {
    let status = StatusCode::from_u16(response.status)
        .map_err(|err| format!("adaptor rendered invalid HTTP status: {err}"))?;
    let body = match response.body {
        WireBody::Json(value) => Body::from(
            serde_json::to_vec(&value)
                .map_err(|err| format!("failed to encode JSON response: {err}"))?,
        ),
        WireBody::Bytes(bytes) => Body::from(bytes),
    };

    let mut builder = Response::builder().status(status);
    for (name, value) in response.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|err| format!("adaptor rendered invalid header name `{name}`: {err}"))?;
        let value = HeaderValue::from_str(&value)
            .map_err(|err| format!("adaptor rendered invalid header value for `{name}`: {err}"))?;
        builder = builder.header(name, value);
    }

    builder
        .body(body)
        .map_err(|err| format!("failed to build HTTP response: {err}"))
}

fn attach_provenance(
    response: &mut Response,
    provenance: Option<ExecutionProvenance>,
    receipt: Option<CatnixReceiptCommitment>,
) {
    if let Some(provenance) = provenance {
        response.extensions_mut().insert(provenance);
    }
    if let Some(receipt) = receipt {
        response.extensions_mut().insert(receipt);
    }
}

fn sse_event(event: WireStreamEvent) -> axum::response::sse::Event {
    match (event.name, event.data) {
        (Some(name), WireEventData::Json(value)) => sse_event_data(&name, &value),
        (Some(name), WireEventData::Text(value)) => axum::response::sse::Event::default()
            .event(name)
            .data(value),
        (Some(name), WireEventData::Bytes(value)) => axum::response::sse::Event::default()
            .event(name)
            .data(String::from_utf8_lossy(&value)),
        (None, WireEventData::Json(value)) => sse_data(&value),
        (None, WireEventData::Text(value)) => axum::response::sse::Event::default().data(value),
        (None, WireEventData::Bytes(value)) => {
            axum::response::sse::Event::default().data(String::from_utf8_lossy(&value))
        }
    }
}

fn wire_error_event(error: AdaptorError) -> axum::response::sse::Event {
    output_error_event(error.to_string())
}

fn output_error_event(message: impl Into<String>) -> axum::response::sse::Event {
    sse_event_data(
        "error",
        &json!({
            "error": { "message": message.into() }
        }),
    )
}

fn adaptor_error(surface: &str, error: AdaptorError) -> Response {
    let status = match error {
        AdaptorError::InvalidJson(_)
        | AdaptorError::InvalidRequest { .. }
        | AdaptorError::Unsupported { .. }
        | AdaptorError::Projection { .. } => StatusCode::BAD_REQUEST,
        AdaptorError::Render { .. } => StatusCode::INTERNAL_SERVER_ERROR,
    };
    super::json_error(status, format!("{surface}: {error}"))
}
