use super::state::{GatewayState, PreparedGeneration};
use super::{next_id, now_unix, parse_json_body, sse_data, sse_response};
use anyhow::anyhow;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use catgrad_llm::helpers::{ToolCall, ToolUseStep};
use catgrad_llm::types::openai;
use serde_json::{Value, json};
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
        let model = prepared.model.clone();

        let mk_chunk = |delta: openai::ChatDelta, finish: Option<openai::FinishReason>| {
            openai::ChatCompletionChunk::builder()
                .id(id.clone())
                .object("chat.completion.chunk".to_string())
                .created(created)
                .model(model.clone())
                .choices(vec![
                    openai::ChatStreamChoice::builder()
                        .index(0)
                        .delta(delta)
                        .finish_reason(finish)
                        .build(),
                ])
                .build()
        };
        let text_delta = |content: String| openai::ChatDelta {
            content: Some(content),
            ..Default::default()
        };

        if tx
            .send(Ok(sse_data(&mk_chunk(
                openai::ChatDelta {
                    role: Some("assistant".to_string()),
                    ..Default::default()
                },
                None,
            ))))
            .is_err()
        {
            return;
        }

        // When tools are requested, buffer the whole generation so we can parse
        // tool-call blocks and emit them in one frame. Otherwise stream deltas.
        let (generated, accumulated) = if prepared.has_tools {
            let mut buf = String::new();
            let result = prepared
                .stream_text(|delta| {
                    buf.push_str(delta);
                    Ok(())
                })
                .await;
            (result, buf)
        } else {
            let result = prepared
                .stream_text(|delta| {
                    tx.send(Ok(sse_data(&mk_chunk(text_delta(delta.to_string()), None))))
                        .map_err(|_| anyhow!("stream closed"))?;
                    Ok(())
                })
                .await;
            (result, String::new())
        };

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

        let finish_reason = if prepared.has_tools {
            let step = prepared.parse_tool_calls(&accumulated).unwrap_or_else(|err| {
                warn!(error = %err, "failed to parse tool calls from streamed text");
                None
            });
            match step {
                Some(step) => {
                    if !step.assistant_content.is_empty()
                        && tx
                            .send(Ok(sse_data(&mk_chunk(
                                text_delta(step.assistant_content.clone()),
                                None,
                            ))))
                            .is_err()
                    {
                        return;
                    }
                    let tool_calls = step
                        .tool_calls
                        .iter()
                        .enumerate()
                        .map(|(idx, call)| tool_call_value(idx, call))
                        .collect();
                    if tx
                        .send(Ok(sse_data(&mk_chunk(
                            openai::ChatDelta {
                                tool_calls: Some(tool_calls),
                                ..Default::default()
                            },
                            None,
                        ))))
                        .is_err()
                    {
                        return;
                    }
                    openai::FinishReason::ToolCalls
                }
                None => {
                    if tx
                        .send(Ok(sse_data(&mk_chunk(text_delta(accumulated), None))))
                        .is_err()
                    {
                        return;
                    }
                    openai::FinishReason::Stop
                }
            }
        } else {
            openai::FinishReason::Stop
        };

        if tx
            .send(Ok(sse_data(&mk_chunk(
                openai::ChatDelta::default(),
                Some(finish_reason),
            ))))
            .is_err()
        {
            return;
        }

        if include_usage {
            let usage_chunk = openai::ChatCompletionChunk::builder()
                .id(id)
                .object("chat.completion.chunk".to_string())
                .created(created)
                .model(model)
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

    let (message, finish_reason) = match prepared.parse_tool_calls(&text) {
        Ok(Some(step)) => (
            tool_call_message(&step),
            openai::FinishReason::ToolCalls,
        ),
        Ok(None) => (
            openai::ChatMessage::assistant(text),
            openai::FinishReason::Stop,
        ),
        Err(err) => {
            warn!(error = %err, "failed to parse tool calls from generated text");
            (
                openai::ChatMessage::assistant(text),
                openai::FinishReason::Stop,
            )
        }
    };

    let response = openai::ChatCompletionResponse::builder()
        .id(next_id("chatcmpl"))
        .object("chat.completion".to_string())
        .created(now_unix())
        .model(prepared.model.clone())
        .choices(vec![
            openai::ChatChoice::builder()
                .index(0)
                .message(message)
                .finish_reason(Some(finish_reason))
                .build(),
        ])
        .usage(Some(openai::Usage::from_counts(
            prepared.prompt_tokens,
            generated.completion_tokens,
        )))
        .build();

    Json(response).into_response()
}

fn tool_call_message(step: &ToolUseStep) -> openai::ChatMessage {
    let tool_calls: Vec<Value> = step
        .tool_calls
        .iter()
        .enumerate()
        .map(|(idx, call)| tool_call_value(idx, call))
        .collect();
    let content = if step.assistant_content.is_empty() {
        None
    } else {
        Some(openai::MessageContent::Text(step.assistant_content.clone()))
    };
    openai::ChatMessage::builder()
        .role("assistant".to_string())
        .content(content)
        .tool_calls(Some(tool_calls))
        .build()
}

fn tool_call_value(index: usize, call: &ToolCall) -> Value {
    let arguments = serde_json::to_string(&call.arguments).unwrap_or_else(|_| "{}".to_string());
    json!({
        "id": format!("call_{index}"),
        "type": "function",
        "function": {
            "name": call.name,
            "arguments": arguments,
        },
    })
}
