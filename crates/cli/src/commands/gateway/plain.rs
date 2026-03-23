use super::state::{GatewayState, PreparedGeneration};
use super::{next_id, now_unix, parse_json_body, sse_data, sse_response};
use anyhow::anyhow;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use catgrad_llm::types::{openai, plain};
use serde_json::json;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let req = match parse_json_body::<plain::CompletionRequest>(&body, "completion") {
        Ok(req) => req,
        Err(err) => return err.into_response(),
    };
    let stream = req.stream == Some(true);
    let prepared = match state.prepare_plain(&req).await {
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
        let id = next_id("cmpl");
        let created = now_unix();

        let generated = prepared
            .stream_text(|delta| {
                let chunk = plain::CompletionChunk::builder()
                    .id(id.clone())
                    .object("text_completion".to_string())
                    .created(created)
                    .model(prepared.model.clone())
                    .choices(vec![
                        plain::CompletionChoice::builder()
                            .index(0)
                            .text(delta.to_string())
                            .build(),
                    ])
                    .build();
                tx.send(Ok(sse_data(&chunk)))
                    .map_err(|_| anyhow!("stream closed"))?;
                Ok(())
            })
            .await;

        let _generated = match generated {
            Ok(output) => output,
            Err(err) => {
                let _ = tx.send(Ok(sse_data(&json!({
                    "error": {"message": format!("Inference error: {err}")}
                }))));
                let _ = tx.send(Ok(axum::response::sse::Event::default().data("[DONE]")));
                return;
            }
        };

        let final_chunk = plain::CompletionChunk::builder()
            .id(id)
            .object("text_completion".to_string())
            .created(created)
            .model(prepared.model.clone())
            .choices(vec![
                plain::CompletionChoice::builder()
                    .index(0)
                    .text(String::new())
                    .finish_reason(Some(openai::FinishReason::Stop))
                    .build(),
            ])
            .build();
        if tx.send(Ok(sse_data(&final_chunk))).is_err() {
            return;
        }

        let _ = tx.send(Ok(axum::response::sse::Event::default().data("[DONE]")));
    })
}

async fn respond(prepared: PreparedGeneration) -> Response {
    let (generated, text) = match prepared.run_to_text().await {
        Ok(result) => result,
        Err(err) => return err.into_response(),
    };

    let response = plain::CompletionResponse::builder()
        .id(next_id("cmpl"))
        .object("text_completion".to_string())
        .created(now_unix())
        .model(prepared.model.clone())
        .choices(vec![
            plain::CompletionChoice::builder()
                .index(0)
                .text(text)
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
