use super::hellas_ext::{HellasExt, WithHellas};
use super::state::{GatewayState, GenerationEvent, PreparedGeneration, TextGenerationError};
use super::{next_id, now_unix, parse_json_body, sse_data, sse_response};
use crate::execution::{Outcome, StopReason};
use async_stream::stream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use catgrad_llm::types::{openai, plain};
use futures::StreamExt;
use hellas_rpc::provenance::CatnixReceiptCommitment;
use hellas_runtime::cid::Cid;
use hellas_runtime::runtime::TextReceipt;
use serde_json::json;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<plain::CompletionRequest>(&body, "completion") {
        Ok(req) => req,
        Err(err) => return err.into_response(),
    };
    let stream_response_flag = req.stream == Some(true);
    let prepared = match state.prepare_plain(&req).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream_response_flag {
        return stream_response(prepared);
    }
    respond(prepared).await
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

async fn respond(prepared: PreparedGeneration) -> Response {
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
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
        Err(TextGenerationError::Stream(message)) => {
            error!(%message, "completion request failed");
            return super::json_error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };

    let response = plain::CompletionResponse::builder()
        .id(id)
        .object("text_completion".to_string())
        .created(created)
        .model(model)
        .choices(vec![
            plain::CompletionChoice::builder()
                .index(0)
                .text(completed.text)
                .finish_reason(Some(map_finish_reason(completed.stop_reason)))
                .build(),
        ])
        .usage(Some(openai::Usage::from_counts(
            prompt_tokens,
            u32::try_from(completed.total_tokens).unwrap_or(u32::MAX),
        )))
        .build();

    let provenance = completed.provenance.clone();
    let hellas = match provenance.as_ref() {
        Some(prov) => HellasExt::both(prov, completed.catnix_receipt_commitment.as_ref()),
        None => HellasExt::receipt(completed.catnix_receipt_commitment.as_ref()),
    };
    let body = WithHellas::new(response, hellas);

    let mut response = Json(body).into_response();
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    } else if let Some(prov) = initial_provenance {
        response.extensions_mut().insert(prov);
    }
    if let Some(catnix) = completed.catnix_receipt_commitment {
        response.extensions_mut().insert(catnix);
    }
    response
}

fn map_finish_reason(stop: StopReason) -> openai::FinishReason {
    match stop {
        StopReason::EndOfSequence | StopReason::Cancelled => openai::FinishReason::Stop,
        StopReason::MaxNewTokens => openai::FinishReason::Length,
    }
}
