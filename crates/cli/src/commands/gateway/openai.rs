use super::state::{GatewayState, PreparedGeneration};
use super::{next_id, now_unix, parse_json_body, sse_data, sse_response};
use anyhow::anyhow;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use catgrad_llm::types::openai;
use serde_json::json;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<openai::ChatCompletionRequest>(&body, "OpenAI") {
        Ok(req) => req,
        Err(err) => return err.into_response(),
    };
    let stream = req.stream == Some(true);
    let include_usage = req
        .stream_options
        .as_ref()
        .and_then(|options| options.include_usage)
        .unwrap_or(false);
    let prepared = match state.prepare_openai(&req).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream {
        return stream_response(prepared, include_usage);
    }

    respond(prepared).await
}

fn stream_response(prepared: PreparedGeneration, include_usage: bool) -> Response {
    sse_response(move |tx| async move {
        let id = next_id("chatcmpl");
        let created = now_unix();

        let start_chunk = openai::ChatCompletionChunk::builder()
            .id(id.clone())
            .object("chat.completion.chunk".to_string())
            .created(created)
            .model(prepared.model.clone())
            .choices(vec![
                openai::ChatStreamChoice::builder()
                    .index(0)
                    .delta(openai::ChatDelta {
                        role: Some("assistant".to_string()),
                        ..Default::default()
                    })
                    .build(),
            ])
            .build();

        if tx.send(Ok(sse_data(&start_chunk))).is_err() {
            return;
        }

        let generated = prepared
            .stream_text(|delta| {
                let chunk = openai::ChatCompletionChunk::builder()
                    .id(id.clone())
                    .object("chat.completion.chunk".to_string())
                    .created(created)
                    .model(prepared.model.clone())
                    .choices(vec![
                        openai::ChatStreamChoice::builder()
                            .index(0)
                            .delta(openai::ChatDelta {
                                content: Some(delta.to_string()),
                                ..Default::default()
                            })
                            .build(),
                    ])
                    .build();
                tx.send(Ok(sse_data(&chunk)))
                    .map_err(|_| anyhow!("stream closed"))?;
                Ok(())
            })
            .await;

        let generated = match generated {
            Ok(output) => output,
            Err(err) => {
                let _ = tx.send(Ok(sse_data(&json!({
                    "error": { "message": format!("Inference error: {err}") }
                }))));
                let _ = tx.send(Ok(axum::response::sse::Event::default().data("[DONE]")));
                return;
            }
        };

        let final_chunk = openai::ChatCompletionChunk::builder()
            .id(id.clone())
            .object("chat.completion.chunk".to_string())
            .created(created)
            .model(prepared.model.clone())
            .choices(vec![
                openai::ChatStreamChoice::builder()
                    .index(0)
                    .delta(openai::ChatDelta::default())
                    .finish_reason(Some(openai::FinishReason::Stop))
                    .build(),
            ])
            .build();
        if tx.send(Ok(sse_data(&final_chunk))).is_err() {
            return;
        }

        if include_usage {
            let usage_chunk = openai::ChatCompletionChunk::builder()
                .id(id)
                .object("chat.completion.chunk".to_string())
                .created(created)
                .model(prepared.model.clone())
                .choices(vec![])
                .usage(Some(openai::Usage::from_counts(
                    prepared.prompt_tokens,
                    generated.completion_tokens,
                )))
                .build();
            if tx.send(Ok(sse_data(&usage_chunk))).is_err() {
                return;
            }
        }

        let _ = tx.send(Ok(axum::response::sse::Event::default().data("[DONE]")));
    })
}

async fn respond(prepared: PreparedGeneration) -> Response {
    let (generated, text) = match prepared.run_to_text().await {
        Ok(result) => result,
        Err(err) => return err.into_response(),
    };

    let response = openai::ChatCompletionResponse::builder()
        .id(next_id("chatcmpl"))
        .object("chat.completion".to_string())
        .created(now_unix())
        .model(prepared.model.clone())
        .choices(vec![
            openai::ChatChoice::builder()
                .index(0)
                .message(openai::ChatMessage::assistant(text))
                .finish_reason(Some(openai::FinishReason::Stop))
                .build(),
        ])
        .usage(Some(openai::Usage::from_counts(
            prepared.prompt_tokens,
            generated.completion_tokens,
        )))
        .build();

    Json(response).into_response()
}
