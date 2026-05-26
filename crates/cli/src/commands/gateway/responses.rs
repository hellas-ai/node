use super::hellas_ext::{HellasExt, WithHellas};
use super::state::{GatewayState, GenerationEvent, PreparedGeneration, TextGenerationError};
use super::{next_id, now_unix, parse_json_body, sse_event_data, sse_response};
use crate::execution::Outcome;
use async_stream::stream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use catgrad_llm::types::openai::responses;
use futures::StreamExt;
use hellas_rpc::provenance::CatnixReceiptCommitment;
use serde_json::json;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<responses::ResponseRequest>(&body, "OpenAI Responses") {
        Ok(req) => req,
        Err(err) => return err.into_response(),
    };
    let stream_response_flag = req.stream == Some(true);
    let prepared = match state.prepare_openai_response(&req).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream_response_flag {
        return stream_response(prepared);
    }
    respond(prepared).await
}

async fn respond(prepared: PreparedGeneration) -> Response {
    let response_id = next_id("resp");
    let message_id = next_id("msg");
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
                "openai response ready"
            );
            completed
        }
        Err(TextGenerationError::Failed { position, error }) => {
            warn!(position, %error, "openai response request failed");
            return super::json_error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
        Err(TextGenerationError::Stream(message)) => {
            error!(%message, "openai response request failed");
            return super::json_error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };

    let response = build_response(
        &response_id,
        created,
        &model,
        responses::ResponseStatus::Completed,
        vec![build_response_message(
            &message_id,
            responses::ResponseStatus::Completed,
            vec![build_response_text(completed.text)],
        )],
        Some(responses::ResponseUsage::from_counts(
            prompt_tokens,
            u32::try_from(completed.total_tokens).unwrap_or(u32::MAX),
        )),
    );

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

fn stream_response(prepared: PreparedGeneration) -> Response {
    let response_id = next_id("resp");
    let message_id = next_id("msg");
    let created = now_unix();
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let provenance = prepared.provenance.clone();
    let mut stream_provenance = provenance.clone();
    let deadline = prepared.deadline();

    let mut response = sse_response(stream! {
        let mut sequence_number = 0u64;
        let created_event = responses::ResponseStreamEvent::Created {
            sequence_number,
            response: build_response(
                &response_id,
                created,
                &model,
                responses::ResponseStatus::Queued,
                vec![],
                None,
            ),
        };
        sequence_number += 1;
        let created_hellas = stream_provenance
            .as_ref()
            .map(HellasExt::commitment)
            .unwrap_or_default();
        yield Ok(response_event(created_event, created_hellas));

        yield Ok(response_event(
            responses::ResponseStreamEvent::InProgress {
                sequence_number,
                response: build_response(
                    &response_id,
                    created,
                    &model,
                    responses::ResponseStatus::InProgress,
                    vec![],
                    None,
                ),
            },
            HellasExt::default(),
        ));
        sequence_number += 1;

        yield Ok(response_event(
            responses::ResponseStreamEvent::OutputItemAdded {
                sequence_number,
                output_index: 0,
                item: build_response_message(
                    &message_id,
                    responses::ResponseStatus::InProgress,
                    vec![],
                ),
            },
            HellasExt::default(),
        ));
        sequence_number += 1;

        yield Ok(response_event(
            responses::ResponseStreamEvent::ContentPartAdded {
                sequence_number,
                item_id: message_id.clone(),
                output_index: 0,
                content_index: 0,
                part: build_response_text(String::new()),
            },
            HellasExt::default(),
        ));
        sequence_number += 1;

        let inner = prepared.stream();
        tokio::pin!(inner);
        let mut text = String::new();
        let mut completed: Option<(
            u64,
            hellas_runtime::cid::Cid<hellas_runtime::runtime::TextReceipt>,
            Option<CatnixReceiptCommitment>,
        )> = None;
        let mut error_message: Option<String> = None;
        let mut commitment_pending = false;

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Provenance(prov)))) => {
                    stream_provenance = Some(prov);
                    commitment_pending = true;
                }
                Ok(Some(Ok(GenerationEvent::Delta(delta)))) => {
                    text.push_str(&delta);
                    let hellas = if commitment_pending {
                        commitment_pending = false;
                        stream_provenance
                            .as_ref()
                            .map(HellasExt::commitment)
                            .unwrap_or_default()
                    } else {
                        HellasExt::default()
                    };
                    yield Ok(response_event(
                        responses::ResponseStreamEvent::OutputTextDelta {
                            sequence_number,
                            item_id: message_id.clone(),
                            output_index: 0,
                            content_index: 0,
                            delta,
                        },
                        hellas,
                    ));
                    sequence_number += 1;
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
                    completed = Some((total_tokens, receipt_cid, catnix_receipt_commitment));
                    break;
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Failed { error, .. })))) => {
                    error_message = Some(format!("Inference error: {error}"));
                    break;
                }
                Ok(Some(Err(err))) => {
                    error_message = Some(format!("Inference error: {err:#}"));
                    break;
                }
                Ok(None) => {
                    error_message =
                        Some("execution stream ended without terminal outcome".to_string());
                    break;
                }
                Err(_) => {
                    error_message = Some(format!(
                        "inference timed out after {}s",
                        super::timeout_secs_until(deadline)
                    ));
                    break;
                }
            }
        }

        if let Some(message) = error_message {
            yield Ok(sse_event_data("error", &json!({
                "error": { "message": message }
            })));
            return;
        }

        let Some((total_tokens, _receipt_cid, catnix_receipt)) = completed else {
            yield Ok(sse_event_data("error", &json!({
                "error": { "message": "execution stream ended without terminal outcome" }
            })));
            return;
        };

        yield Ok(response_event(
            responses::ResponseStreamEvent::OutputTextDone {
                sequence_number,
                item_id: message_id.clone(),
                output_index: 0,
                content_index: 0,
                text: text.clone(),
            },
            HellasExt::default(),
        ));
        sequence_number += 1;

        let completed_part = build_response_text(text);
        yield Ok(response_event(
            responses::ResponseStreamEvent::ContentPartDone {
                sequence_number,
                item_id: message_id.clone(),
                output_index: 0,
                content_index: 0,
                part: completed_part.clone(),
            },
            HellasExt::default(),
        ));
        sequence_number += 1;

        let completed_item = build_response_message(
            &message_id,
            responses::ResponseStatus::Completed,
            vec![completed_part],
        );
        yield Ok(response_event(
            responses::ResponseStreamEvent::OutputItemDone {
                sequence_number,
                output_index: 0,
                item: completed_item.clone(),
            },
            HellasExt::default(),
        ));
        sequence_number += 1;

        yield Ok(response_event(
            responses::ResponseStreamEvent::Completed {
                sequence_number,
                response: build_response(
                    &response_id,
                    created,
                    &model,
                    responses::ResponseStatus::Completed,
                    vec![completed_item],
                    Some(responses::ResponseUsage::from_counts(
                        prompt_tokens,
                        u32::try_from(total_tokens).unwrap_or(u32::MAX),
                    )),
                ),
            },
            if commitment_pending {
                match stream_provenance.as_ref() {
                    Some(prov) => HellasExt::both(prov, catnix_receipt.as_ref()),
                    None => HellasExt::receipt(catnix_receipt.as_ref()),
                }
            } else {
                HellasExt::receipt(catnix_receipt.as_ref())
            },
        ));
    });

    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    }
    response
}

fn response_event(
    event: responses::ResponseStreamEvent,
    hellas: HellasExt,
) -> axum::response::sse::Event {
    sse_event_data(response_event_name(&event), &WithHellas::new(event, hellas))
}

fn response_event_name(event: &responses::ResponseStreamEvent) -> &'static str {
    match event {
        responses::ResponseStreamEvent::Created { .. } => "response.created",
        responses::ResponseStreamEvent::InProgress { .. } => "response.in_progress",
        responses::ResponseStreamEvent::OutputItemAdded { .. } => "response.output_item.added",
        responses::ResponseStreamEvent::ContentPartAdded { .. } => "response.content_part.added",
        responses::ResponseStreamEvent::OutputTextDelta { .. } => "response.output_text.delta",
        responses::ResponseStreamEvent::OutputTextDone { .. } => "response.output_text.done",
        responses::ResponseStreamEvent::ContentPartDone { .. } => "response.content_part.done",
        responses::ResponseStreamEvent::OutputItemDone { .. } => "response.output_item.done",
        responses::ResponseStreamEvent::Completed { .. } => "response.completed",
    }
}

fn build_response(
    response_id: &str,
    created_at: i64,
    model: &str,
    status: responses::ResponseStatus,
    output: Vec<responses::ResponseOutputMessage>,
    usage: Option<responses::ResponseUsage>,
) -> responses::Response {
    responses::Response::builder()
        .id(response_id.to_string())
        .object("response".to_string())
        .created_at(created_at)
        .status(status)
        .model(model.to_string())
        .output(output)
        .usage(usage)
        .build()
}

fn build_response_message(
    message_id: &str,
    status: responses::ResponseStatus,
    content: Vec<responses::ResponseOutputText>,
) -> responses::ResponseOutputMessage {
    responses::ResponseOutputMessage::builder()
        .id(message_id.to_string())
        .item_type("message".to_string())
        .status(status)
        .role("assistant".to_string())
        .content(content)
        .annotations(Some(vec![]))
        .build()
}

fn build_response_text(text: String) -> responses::ResponseOutputText {
    responses::ResponseOutputText::builder()
        .content_type("output_text".to_string())
        .text(text)
        .annotations(Some(vec![]))
        .build()
}
