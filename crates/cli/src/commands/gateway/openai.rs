use super::hellas_ext::{HellasExt, WithHellas};
use super::state::{GatewayState, GenerationEvent, PreparedGeneration};
use super::{next_id, now_unix, parse_json_body, sse_data, sse_response};
use crate::execution::{Outcome, ReceiptArtifact, StopReason};
use async_stream::stream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chatgrad::types::openai;
use futures::StreamExt;
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

async fn respond(prepared: PreparedGeneration) -> Response {
    let id = next_id("chatcmpl");
    let created = now_unix();
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();

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

    let (completion_tokens, finish_reason, receipt) = match outcome {
        Ok(Outcome::Completed {
            total_tokens,
            stop_reason,
            receipt,
        }) => {
            info!(
                receipt = %receipt.encoded(),
                ?provenance,
                total_tokens,
                ?stop_reason,
                "openai chat completion ready"
            );
            (total_tokens, map_finish_reason(stop_reason), receipt)
        }
        Ok(Outcome::Failed { position, error }) => {
            warn!(position, %error, "openai chat request failed");
            return super::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
        Err(message) => {
            error!(%message, "openai chat request failed");
            return super::json_error(StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };

    let response = openai::ChatCompletionResponse::builder()
        .id(id)
        .object("chat.completion".to_string())
        .created(created)
        .model(model)
        .choices(vec![
            openai::ChatChoice::builder()
                .index(0)
                .message(openai::ChatMessage::assistant(text))
                .finish_reason(Some(finish_reason))
                .build(),
        ])
        .usage(Some(openai::Usage::from_counts(
            prompt_tokens,
            u32::try_from(completion_tokens).unwrap_or(u32::MAX),
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

fn stream_response(prepared: PreparedGeneration, include_usage: bool) -> Response {
    let id = next_id("chatcmpl");
    let created = now_unix();
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();

    let stream_provenance = provenance.clone();
    let mut response = sse_response(stream! {
        let start_chunk = chat_chunk(
            &id,
            created,
            &model,
            openai::ChatDelta {
                role: Some("assistant".to_string()),
                ..Default::default()
            },
            None,
        );
        let start_hellas = match stream_provenance.as_ref() {
            Some(prov) => HellasExt::commitment(prov),
            None => HellasExt::default(),
        };
        yield Ok(sse_data(&WithHellas::new(start_chunk, start_hellas)));

        let inner = prepared.stream();
        tokio::pin!(inner);
        let mut completed: Option<(openai::FinishReason, u64, ReceiptArtifact)> = None;
        let mut error_message: Option<String> = None;

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Delta(text)))) => {
                    let chunk = chat_chunk(
                        &id,
                        created,
                        &model,
                        openai::ChatDelta {
                            content: Some(text),
                            ..Default::default()
                        },
                        None,
                    );
                    yield Ok(sse_data(&chunk));
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Completed {
                    stop_reason,
                    total_tokens,
                    receipt,
                })))) => {
                    info!(
                        receipt = %receipt.encoded(),
                        provenance = ?stream_provenance,
                        total_tokens,
                        ?stop_reason,
                        "openai chat completion ready"
                    );
                    completed = Some((map_finish_reason(stop_reason), total_tokens, receipt));
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
                    error_message = Some(format!(
                        "inference timed out after {}s",
                        super::timeout_secs_until(deadline)
                    ));
                    break;
                }
            }
        }

        if let Some(err) = error_message {
            yield Ok(sse_data(&json!({
                "error": { "message": format!("Inference error: {err}") }
            })));
            return;
        }

        if let Some((finish_reason, total_tokens, receipt)) = completed {
            let finish_chunk = chat_chunk(
                &id,
                created,
                &model,
                openai::ChatDelta::default(),
                Some(finish_reason),
            );
            if include_usage {
                yield Ok(sse_data(&finish_chunk));
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
                yield Ok(sse_data(&WithHellas::new(
                    usage_chunk,
                    HellasExt::receipt(&receipt),
                )));
            } else {
                yield Ok(sse_data(&WithHellas::new(
                    finish_chunk,
                    HellasExt::receipt(&receipt),
                )));
            }
            yield Ok(axum::response::sse::Event::default().data("[DONE]"));
        }
    });
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    }
    response
}

fn chat_chunk(
    id: &str,
    created: i64,
    model: &str,
    delta: openai::ChatDelta,
    finish_reason: Option<openai::FinishReason>,
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
                .finish_reason(finish_reason)
                .build(),
        ])
        .build()
}

fn map_finish_reason(stop: StopReason) -> openai::FinishReason {
    match stop {
        StopReason::EndOfSequence | StopReason::Cancelled => openai::FinishReason::Stop,
        StopReason::MaxNewTokens => openai::FinishReason::Length,
    }
}
