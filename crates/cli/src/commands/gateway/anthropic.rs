use super::state::{GatewayState, PreparedGeneration};
use super::{next_id, parse_json_body, sse_event_data, sse_response};
use anyhow::anyhow;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use catgrad_llm::types::anthropic;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<anthropic::MessageRequest>(&body, "Anthropic") {
        Ok(req) => req,
        Err(err) => return err.into_response(),
    };
    let stream = req.stream == Some(true);
    let prepared = match state.prepare_anthropic(&req).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream {
        return stream_response(prepared);
    }

    respond(prepared).await
}

fn stream_response(prepared: PreparedGeneration) -> Response {
    sse_response(move |tx| async move {
        let id = next_id("msg");

        let message_start = anthropic::MessageStreamEvent::MessageStart {
            message: anthropic::MessageResponse::builder()
                .id(id.clone())
                .message_type(Some("message".to_string()))
                .role("assistant".to_string())
                .content(vec![])
                .model(prepared.model.clone())
                .usage(anthropic::AnthropicUsage::new(prepared.prompt_tokens, 0))
                .build(),
        };

        if tx
            .send(Ok(sse_event_data("message_start", &message_start)))
            .is_err()
        {
            return;
        }

        if tx
            .send(Ok(sse_event_data(
                "content_block_start",
                &anthropic::MessageStreamEvent::ContentBlockStart {
                    index: 0,
                    content_block: anthropic::ContentBlock::Text {
                        text: String::new(),
                    },
                },
            )))
            .is_err()
        {
            return;
        }

        let generated = prepared
            .stream_text(|delta| {
                let event = anthropic::MessageStreamEvent::ContentBlockDelta {
                    index: 0,
                    delta: anthropic::ContentBlockDelta::TextDelta {
                        text: delta.to_string(),
                    },
                };
                tx.send(Ok(sse_event_data("content_block_delta", &event)))
                    .map_err(|_| anyhow!("stream closed"))?;
                Ok(())
            })
            .await;

        if tx
            .send(Ok(sse_event_data(
                "content_block_stop",
                &anthropic::MessageStreamEvent::ContentBlockStop { index: 0 },
            )))
            .is_err()
        {
            return;
        }

        let generated = match generated {
            Ok(output) => output,
            Err(err) => {
                let _ = tx.send(Ok(sse_event_data(
                    "error",
                    &anthropic::MessageStreamEvent::Error {
                        error: anthropic::StreamError {
                            error_type: "invalid_request_error".to_string(),
                            message: format!("Inference error: {err}"),
                        },
                    },
                )));
                return;
            }
        };

        if tx
            .send(Ok(sse_event_data(
                "message_delta",
                &anthropic::MessageStreamEvent::MessageDelta {
                    delta: anthropic::StreamMessageDelta {
                        stop_reason: Some(anthropic::StopReason::EndTurn),
                    },
                    usage: anthropic::AnthropicUsage::new(
                        prepared.prompt_tokens,
                        generated.completion_tokens,
                    ),
                },
            )))
            .is_err()
        {
            return;
        }

        let _ = tx.send(Ok(sse_event_data(
            "message_stop",
            &anthropic::MessageStreamEvent::MessageStop,
        )));
    })
}

async fn respond(prepared: PreparedGeneration) -> Response {
    let (generated, text) = match prepared.run_to_text().await {
        Ok(result) => result,
        Err(err) => return err.into_response(),
    };

    let response = anthropic::MessageResponse::builder()
        .id(next_id("msg"))
        .message_type(Some("message".to_string()))
        .role("assistant".to_string())
        .content(vec![anthropic::ContentBlock::Text { text }])
        .model(prepared.model.clone())
        .stop_reason(Some(anthropic::StopReason::EndTurn))
        .usage(anthropic::AnthropicUsage::new(
            prepared.prompt_tokens,
            generated.completion_tokens,
        ))
        .build();

    Json(response).into_response()
}
