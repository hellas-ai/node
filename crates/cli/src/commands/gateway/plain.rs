use super::hellas_ext::{HellasExt, WithHellas};
use super::state::{GatewayState, GenerationEvent, PreparedGeneration, TextGenerationError};
use super::{next_id, now_unix, sse_data, sse_response};
use crate::execution::{Outcome, StopReason as RuntimeStopReason};
use async_stream::stream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use catgrad_llm::types::{openai, plain};
use futures::StreamExt;
use hellas_rpc::provenance::{CatnixReceiptCommitment, ExecutionProvenance, encode_hex};
use hellas_runtime::cid::Cid;
use hellas_runtime::runtime::TextReceipt;
use hellas_wire_adaptors::openai::completions::{
    OpenAiCompletionsAdaptor, ParsedCompletionRequest,
};
use hellas_wire_adaptors::{
    AdaptorError, ExecutionResult, OutputItem, Provenance, RawRequest, RenderContext,
    StopReason as WireStopReason, TextChannel, Usage, WireAdaptor, WireBody,
};
use serde_json::json;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let adaptor = OpenAiCompletionsAdaptor;
    let raw = match RawRequest::from_slice(&body) {
        Ok(raw) => raw,
        Err(err) => return adaptor_error("OpenAI Completions", err),
    };
    let parsed = match adaptor.parse(raw) {
        Ok(parsed) => parsed,
        Err(err) => return adaptor_error("OpenAI Completions", err),
    };
    let execution = match adaptor.to_execution_request(&parsed) {
        Ok(execution) => execution,
        Err(err) => return adaptor_error("OpenAI Completions", err),
    };
    let stream_response_flag = parsed.stream == Some(true);
    let prepared = match state.prepare_plain_execution(&execution).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream_response_flag {
        return stream_response(prepared);
    }
    respond(adaptor, parsed, prepared).await
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

fn stream_response(prepared: PreparedGeneration) -> Response {
    let id = next_id("cmpl");
    let created = now_unix();
    let model = prepared.model.clone();
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();

    let mut stream_provenance = provenance.clone();
    let mut response = sse_response(stream! {
        let inner = prepared.stream();
        tokio::pin!(inner);

        let mut completed: Option<(
            openai::FinishReason,
            Cid<TextReceipt>,
            Option<CatnixReceiptCommitment>,
        )> = None;
        let mut error_message: Option<String> = None;
        // Track whether the commitment has been stamped on a chunk
        // yet. The first per-delta chunk carries it; if the stream
        // terminates with zero deltas, the terminal chunk carries
        // both catnix commitment and catnix receipt.
        let mut commitment_pending = stream_provenance.is_some();

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Provenance(prov)))) => {
                    stream_provenance = Some(prov);
                    commitment_pending = true;
                }
                Ok(Some(Ok(GenerationEvent::Delta(text)))) => {
                    let chunk = plain::CompletionChunk::builder()
                        .id(id.clone())
                        .object("text_completion".to_string())
                        .created(created)
                        .model(model.clone())
                        .choices(vec![
                            plain::CompletionChoice::builder()
                                .index(0)
                                .text(text)
                                .build(),
                        ])
                        .build();
                    let hellas = if commitment_pending {
                        commitment_pending = false;
                        match stream_provenance.as_ref() {
                            Some(prov) => HellasExt::commitment(prov),
                            None => HellasExt::default(),
                        }
                    } else {
                        HellasExt::default()
                    };
                    yield Ok(sse_data(&WithHellas::new(chunk, hellas)));
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Completed {
                    stop_reason,
                    total_tokens,
                    receipt_cid,
                    catnix_receipt_commitment,
                })))) => {
                    info!(
                        %receipt_cid,
                        provenance = ?stream_provenance,
                        total_tokens,
                        ?stop_reason,
                        "completion request ready"
                    );
                    completed = Some((
                        map_finish_reason(stop_reason),
                        receipt_cid,
                        catnix_receipt_commitment,
                    ));
                    break;
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Failed { error, .. })))) => {
                    error_message = Some(error);
                    break;
                }
                Ok(Some(Err(err))) => {
                    error_message = Some(format!("{err:#}"));
                    break;
                }
                Ok(None) => {
                    error_message =
                        Some("execution stream ended without terminal outcome".to_string());
                    break;
                }
                Err(_) => {
                    error_message =
                        Some(format!("inference timed out after {}s", super::timeout_secs_until(deadline)));
                    break;
                }
            }
        }

        if let Some(err) = error_message {
            // Error path: receipt stays fenced inside the Completed
            // arm. Commitment can still ride the error frame if it
            // hasn't been stamped yet — the stream terminated before
            // any delta carried it.
            let mut error_value = json!({
                "error": { "message": format!("Inference error: {err}") }
            });
            if commitment_pending {
                if let (Some(prov), Some(map)) = (
                    stream_provenance.as_ref(),
                    error_value.as_object_mut(),
                ) {
                    map.insert(
                        "hellas".to_string(),
                        serde_json::to_value(HellasExt::commitment(prov)).unwrap(),
                    );
                }
            }
            yield Ok(sse_data(&error_value));
        } else if let Some((reason, _receipt_cid, catnix_receipt)) = completed {
            let final_chunk = plain::CompletionChunk::builder()
                .id(id.clone())
                .object("text_completion".to_string())
                .created(created)
                .model(model.clone())
                .choices(vec![
                    plain::CompletionChoice::builder()
                        .index(0)
                        .text(String::new())
                        .finish_reason(Some(reason))
                        .build(),
                ])
                .build();
            // Terminal chunk carries the receipt. If zero deltas ran,
            // it ALSO carries the commitment.
            let hellas = if commitment_pending {
                match stream_provenance.as_ref() {
                    Some(prov) => HellasExt::both(prov, catnix_receipt.as_ref()),
                    None => HellasExt::receipt(catnix_receipt.as_ref()),
                }
            } else {
                HellasExt::receipt(catnix_receipt.as_ref())
            };
            yield Ok(sse_data(&WithHellas::new(final_chunk, hellas)));
        }

        yield Ok(axum::response::sse::Event::default().data("[DONE]"));
    });
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    }
    response
}

async fn respond(
    adaptor: OpenAiCompletionsAdaptor,
    mut parsed: ParsedCompletionRequest,
    prepared: PreparedGeneration,
) -> Response {
    let id = next_id("cmpl");
    let created = now_unix();
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let initial_provenance = prepared.provenance.clone();

    let completed = match prepared.collect_text().await {
        Ok(completed) => {
            info!(
                %completed.receipt_cid,
                provenance = ?completed.provenance,
                total_tokens = completed.total_tokens,
                stop_reason = ?completed.stop_reason,
                "completion request ready"
            );
            completed
        }
        Err(TextGenerationError::Failed { position, error }) => {
            warn!(position, %error, "completion request failed");
            return super::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
        Err(TextGenerationError::Stream(message)) => {
            error!(%message, "completion request failed");
            return super::json_error(StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };

    let provenance = completed.provenance.clone();
    let receipt = completed.catnix_receipt_commitment.clone();
    parsed.model = model;
    let result = ExecutionResult {
        output: vec![OutputItem::Text {
            text: completed.text,
            channel: TextChannel::Output,
        }],
        usage: Some(usage(prompt_tokens, completed.total_tokens)),
        stop_reason: wire_stop_reason_from_runtime(completed.stop_reason),
        provenance: provenance_from_parts(provenance.as_ref(), receipt.as_ref()),
    };
    let rendered = match adaptor.render_response(
        &parsed,
        result,
        RenderContext::new(id, next_id("unused"), created),
    ) {
        Ok(rendered) => rendered,
        Err(err) => return adaptor_error("OpenAI Completions", err),
    };
    let WireBody::Json(body) = rendered.body else {
        error!("completion adaptor rendered a non-json response");
        return super::json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "completion adaptor rendered an invalid response body",
        );
    };
    let status = match StatusCode::from_u16(rendered.status) {
        Ok(status) => status,
        Err(err) => {
            error!(%err, "completion adaptor rendered an invalid status");
            return super::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "completion adaptor rendered an invalid response status",
            );
        }
    };

    let mut response = (status, Json(body)).into_response();
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    } else if let Some(prov) = initial_provenance {
        response.extensions_mut().insert(prov);
    }
    if let Some(catnix) = receipt {
        response.extensions_mut().insert(catnix);
    }
    response
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

fn wire_stop_reason_from_runtime(stop: RuntimeStopReason) -> WireStopReason {
    match stop {
        RuntimeStopReason::EndOfSequence => WireStopReason::EndOfText,
        RuntimeStopReason::MaxNewTokens => WireStopReason::MaxOutputTokens,
        RuntimeStopReason::Cancelled => WireStopReason::Cancelled,
    }
}

fn map_finish_reason(stop: RuntimeStopReason) -> openai::FinishReason {
    match stop {
        RuntimeStopReason::EndOfSequence | RuntimeStopReason::Cancelled => {
            openai::FinishReason::Stop
        }
        RuntimeStopReason::MaxNewTokens => openai::FinishReason::Length,
    }
}
