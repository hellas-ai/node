use super::state::{GatewayState, GenerationEvent, PreparedGeneration};
use super::{next_id, now_unix, parse_json_body, sse_data, sse_response};
use crate::execution::{Outcome, StopReason};
use async_stream::stream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use catgrad_llm::types::{openai, plain};
use futures::StreamExt;
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
    let deadline = prepared.deadline();

    sse_response(stream! {
        let inner = prepared.stream();
        tokio::pin!(inner);

        let mut finish_reason: Option<openai::FinishReason> = None;
        let mut error_message: Option<String> = None;

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
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
                    yield Ok(sse_data(&chunk));
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Completed { stop_reason, .. })))) => {
                    finish_reason = Some(map_finish_reason(stop_reason));
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
            yield Ok(sse_data(&json!({
                "error": { "message": format!("Inference error: {err}") }
            })));
        } else if let Some(reason) = finish_reason {
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
            yield Ok(sse_data(&final_chunk));
        }

        yield Ok(axum::response::sse::Event::default().data("[DONE]"));
    })
}

async fn respond(prepared: PreparedGeneration) -> Response {
    let id = next_id("cmpl");
    let created = now_unix();
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
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

    let (completion_tokens, finish_reason) = match outcome {
        Ok(Outcome::Completed {
            total_tokens,
            stop_reason,
            ..
        }) => (total_tokens, map_finish_reason(stop_reason)),
        Ok(Outcome::Failed { position, error }) => {
            warn!(position, %error, "completion request failed");
            return super::json_error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
        Err(message) => {
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
                .text(text)
                .finish_reason(Some(finish_reason))
                .build(),
        ])
        .usage(Some(openai::Usage::from_counts(
            prompt_tokens,
            u32::try_from(completion_tokens).unwrap_or(u32::MAX),
        )))
        .build();

    Json(response).into_response()
}

fn map_finish_reason(stop: StopReason) -> openai::FinishReason {
    match stop {
        StopReason::EndOfSequence | StopReason::Cancelled => openai::FinishReason::Stop,
        StopReason::MaxNewTokens => openai::FinishReason::Length,
    }
}
