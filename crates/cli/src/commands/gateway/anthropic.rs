use super::hellas_ext::{HellasExt, WithHellas};
use super::state::{GatewayState, GenerationEvent, PreparedGeneration};
use super::{next_id, parse_json_body, sse_event_data, sse_response};
use crate::execution::{Outcome, ReceiptArtifact, StopReason};
use async_stream::stream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::Event;
use axum::response::{IntoResponse, Response};
use chatgrad::types::anthropic;
use futures::StreamExt;
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

async fn respond(prepared: PreparedGeneration) -> Response {
    let id = next_id("msg");
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

    let (completion_tokens, stop_reason, receipt) = match outcome {
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
                "anthropic message completion ready"
            );
            (total_tokens, map_stop_reason(stop_reason), receipt)
        }
        Ok(Outcome::Failed { position, error }) => {
            warn!(position, %error, "anthropic message request failed");
            return super::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
        Err(message) => {
            error!(%message, "anthropic message request failed");
            return super::json_error(StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };

    let response = anthropic::MessageResponse::builder()
        .id(id)
        .message_type(Some("message".to_string()))
        .role("assistant".to_string())
        .content(vec![anthropic::ContentBlock::Text { text }])
        .model(model)
        .stop_reason(Some(stop_reason))
        .usage(anthropic::AnthropicUsage::new(
            prompt_tokens,
            u32::try_from(completion_tokens).unwrap_or(u32::MAX),
        ))
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

fn stream_response(prepared: PreparedGeneration) -> Response {
    let id = next_id("msg");
    let model = prepared.model.clone();
    let prompt_tokens = prepared.prompt_tokens;
    let provenance = prepared.provenance.clone();
    let deadline = prepared.deadline();

    let stream_provenance = provenance.clone();
    let payloads = stream! {
        let message = anthropic::MessageResponse::builder()
            .id(id.clone())
            .message_type(Some("message".to_string()))
            .role("assistant".to_string())
            .content(vec![])
            .model(model.clone())
            .usage(anthropic::AnthropicUsage::new(prompt_tokens, 0))
            .build();
        let message_hellas = match stream_provenance.as_ref() {
            Some(prov) => HellasExt::commitment(prov),
            None => HellasExt::default(),
        };
        yield AnthropicSsePayload {
            name: "message_start",
            json: json!({
                "type": "message_start",
                "message": WithHellas::new(message, message_hellas),
            }),
        };

        let inner = prepared.stream();
        tokio::pin!(inner);
        let mut content_started = false;
        let mut completed: Option<(anthropic::StopReason, u64, ReceiptArtifact)> = None;
        let mut error_message: Option<String> = None;

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Delta(text)))) => {
                    if !content_started {
                        content_started = true;
                        yield content_block_start();
                    }
                    yield AnthropicSsePayload {
                        name: "content_block_delta",
                        json: serde_json::to_value(
                            anthropic::MessageStreamEvent::ContentBlockDelta {
                                index: 0,
                                delta: anthropic::ContentBlockDelta::TextDelta { text },
                            },
                        )
                        .unwrap(),
                    };
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
                        "anthropic message completion ready"
                    );
                    completed = Some((map_stop_reason(stop_reason), total_tokens, receipt));
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
            if content_started {
                yield content_block_stop();
            }
            yield error_payload(format!("Inference error: {err}"));
            return;
        }

        if let Some((stop_reason, total_tokens, receipt)) = completed {
            if content_started {
                yield content_block_stop();
            }
            yield AnthropicSsePayload {
                name: "message_delta",
                json: serde_json::to_value(anthropic::MessageStreamEvent::MessageDelta {
                    delta: anthropic::StreamMessageDelta {
                        stop_reason: Some(stop_reason),
                    },
                    usage: anthropic::AnthropicUsage::new(
                        prompt_tokens,
                        u32::try_from(total_tokens).unwrap_or(u32::MAX),
                    ),
                })
                .unwrap(),
            };
            yield AnthropicSsePayload {
                name: "message_stop",
                json: serde_json::to_value(WithHellas::new(
                    anthropic::MessageStreamEvent::MessageStop,
                    HellasExt::receipt(&receipt),
                ))
                .unwrap(),
            };
        }
    };
    let events = payloads.map(|payload| Ok::<_, std::convert::Infallible>(payload.into_event()));
    let mut response = sse_response(events);
    if let Some(prov) = provenance {
        response.extensions_mut().insert(prov);
    }
    response
}

fn content_block_start() -> AnthropicSsePayload {
    AnthropicSsePayload {
        name: "content_block_start",
        json: serde_json::to_value(anthropic::MessageStreamEvent::ContentBlockStart {
            index: 0,
            content_block: anthropic::ContentBlock::Text {
                text: String::new(),
            },
        })
        .unwrap(),
    }
}

fn content_block_stop() -> AnthropicSsePayload {
    AnthropicSsePayload {
        name: "content_block_stop",
        json: serde_json::to_value(anthropic::MessageStreamEvent::ContentBlockStop { index: 0 })
            .unwrap(),
    }
}

fn error_payload(message: String) -> AnthropicSsePayload {
    AnthropicSsePayload {
        name: "error",
        json: serde_json::to_value(anthropic::MessageStreamEvent::Error {
            error: anthropic::StreamError {
                error_type: "invalid_request_error".to_string(),
                message,
            },
        })
        .unwrap(),
    }
}

fn map_stop_reason(stop: StopReason) -> anthropic::StopReason {
    match stop {
        StopReason::EndOfSequence | StopReason::Cancelled => anthropic::StopReason::EndTurn,
        StopReason::MaxNewTokens => anthropic::StopReason::MaxTokens,
    }
}
