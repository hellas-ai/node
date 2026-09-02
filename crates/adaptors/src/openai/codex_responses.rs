//! Caller-facing renderer for the signed Codex Responses Fetch vocabulary.
//! Request admission and upstream response validation live in the attested
//! Fetch adaptor; this lens only reconstructs the already-typed wire events.

use serde_json::{Value as JsonValue, json};

use crate::{
    AdaptorError, AdaptorEvent, AdaptorResult, CanonicalExecution, CodexCompleted, CodexItemStatus,
    CodexMessageContent, CodexMessagePhase, CodexResponseItem, CodexResponsesEvent,
    ExecutionRequest, ExecutionResult, Input, InputItem, ModelRef, OutputEvent, RawRequest,
    RenderContext, WireAdaptor, WireResponse, WireStreamEvent,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct CodexResponsesAdaptor;

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedCodexRequest {
    pub model: String,
    input: Vec<JsonValue>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodexStreamState {
    completed: bool,
}

impl WireAdaptor for CodexResponsesAdaptor {
    type ParsedRequest = ParsedCodexRequest;
    type StreamState = CodexStreamState;

    fn parse(&self, raw: RawRequest) -> AdaptorResult<Self::ParsedRequest> {
        let object = raw
            .value()
            .as_object()
            .ok_or_else(|| AdaptorError::invalid_request("Codex request must be an object"))?;
        let model = object
            .get("model")
            .and_then(JsonValue::as_str)
            .filter(|model| !model.is_empty())
            .ok_or_else(|| AdaptorError::invalid_request("Codex request requires model"))?
            .to_string();
        let input = object
            .get("input")
            .and_then(JsonValue::as_array)
            .cloned()
            .ok_or_else(|| AdaptorError::invalid_request("Codex request requires input array"))?;
        let stream = object
            .get("stream")
            .and_then(JsonValue::as_bool)
            .ok_or_else(|| {
                AdaptorError::invalid_request("Codex request requires stream boolean")
            })?;
        if !stream {
            return Err(AdaptorError::invalid_request(
                "sealed Codex Fetch requires stream=true",
            ));
        }
        Ok(ParsedCodexRequest { model, input })
    }

    fn to_execution_request(
        &self,
        request: &Self::ParsedRequest,
    ) -> AdaptorResult<ExecutionRequest> {
        // Fetch forwards the signed RawRequest, not this presentation-only
        // canonical projection. Keep each heterogeneous Codex history item
        // intact while supplying the model selector required by BackendRequest.
        let input = Input::Items(request.input.iter().cloned().map(InputItem::Raw).collect());
        Ok(ExecutionRequest::new(CanonicalExecution::new(
            ModelRef::new(request.model.clone()),
            input,
        )))
    }

    fn initial_state(
        &self,
        _request: &Self::ParsedRequest,
        _context: RenderContext,
    ) -> Self::StreamState {
        CodexStreamState::default()
    }

    fn render_response(
        &self,
        _request: &Self::ParsedRequest,
        _result: ExecutionResult,
        _context: RenderContext,
    ) -> AdaptorResult<WireResponse> {
        Err(AdaptorError::unsupported(
            "sealed Codex Fetch only supports streaming responses",
        ))
    }

    fn render_stream_event(
        &self,
        _request: &Self::ParsedRequest,
        state: &mut Self::StreamState,
        event: OutputEvent,
    ) -> AdaptorResult<Vec<WireStreamEvent>> {
        match event {
            OutputEvent::Adaptor(AdaptorEvent::CodexResponses(event)) => {
                if state.completed {
                    return Err(AdaptorError::render(
                        "signed Codex event arrived after response.completed",
                    ));
                }
                if matches!(event, CodexResponsesEvent::Completed(_)) {
                    state.completed = true;
                }
                Ok(vec![render_codex_event(event)?])
            }
            OutputEvent::Finished { .. } if state.completed => Ok(Vec::new()),
            OutputEvent::Provenance(_) => Ok(Vec::new()),
            OutputEvent::Error { message, code } => {
                if state.completed {
                    return Err(AdaptorError::render(
                        "signed Codex error arrived after terminal stream event",
                    ));
                }
                state.completed = true;
                Ok(vec![WireStreamEvent::json(
                    Some("error".to_string()),
                    json!({"type":"error","code":code,"message":message}),
                )])
            }
            other => Err(AdaptorError::render(format!(
                "non-Codex output event on sealed Codex stream: {other:?}"
            ))),
        }
    }
}

fn render_codex_event(event: CodexResponsesEvent) -> AdaptorResult<WireStreamEvent> {
    let (kind, data) = match event {
        CodexResponsesEvent::Created { response_id } => {
            let response = response_id.map_or_else(|| json!({}), |id| json!({"id":id}));
            (
                "response.created",
                json!({"type":"response.created","response":response}),
            )
        }
        CodexResponsesEvent::OutputItemAdded(item) => (
            "response.output_item.added",
            json!({"type":"response.output_item.added","item":item_json(item)}),
        ),
        CodexResponsesEvent::OutputItemDone(item) => (
            "response.output_item.done",
            json!({"type":"response.output_item.done","item":item_json(item)}),
        ),
        CodexResponsesEvent::OutputTextDelta { delta } => (
            "response.output_text.delta",
            json!({"type":"response.output_text.delta","delta":delta}),
        ),
        CodexResponsesEvent::CustomToolCallInputDelta {
            item_id,
            call_id,
            delta,
        } => (
            "response.custom_tool_call_input.delta",
            json!({
                "type":"response.custom_tool_call_input.delta",
                "item_id":item_id,
                "call_id":call_id,
                "delta":delta
            }),
        ),
        CodexResponsesEvent::ReasoningSummaryDelta {
            delta,
            summary_index,
        } => (
            "response.reasoning_summary_text.delta",
            json!({
                "type":"response.reasoning_summary_text.delta",
                "delta":delta,
                "summary_index":summary_index
            }),
        ),
        CodexResponsesEvent::ReasoningSummaryDone {
            item_id,
            text,
            summary_index,
        } => (
            "response.reasoning_summary_text.done",
            json!({
                "type":"response.reasoning_summary_text.done",
                "item_id":item_id,
                "text":text,
                "summary_index":summary_index
            }),
        ),
        CodexResponsesEvent::ReasoningContentDelta {
            delta,
            content_index,
        } => (
            "response.reasoning_text.delta",
            json!({
                "type":"response.reasoning_text.delta",
                "delta":delta,
                "content_index":content_index
            }),
        ),
        CodexResponsesEvent::ReasoningSummaryPartAdded { summary_index } => (
            "response.reasoning_summary_part.added",
            json!({
                "type":"response.reasoning_summary_part.added",
                "summary_index":summary_index
            }),
        ),
        CodexResponsesEvent::Completed(completed) => {
            ("response.completed", completed_json(completed)?)
        }
    };
    Ok(WireStreamEvent::json(
        Some(kind.to_string()),
        without_null_fields(data),
    ))
}

fn without_null_fields(mut value: JsonValue) -> JsonValue {
    match &mut value {
        JsonValue::Object(object) => {
            object.retain(|_, value| !value.is_null());
            for value in object.values_mut() {
                *value = without_null_fields(std::mem::take(value));
            }
        }
        JsonValue::Array(values) => {
            for value in values {
                *value = without_null_fields(std::mem::take(value));
            }
        }
        _ => {}
    }
    value
}

fn item_json(item: CodexResponseItem) -> JsonValue {
    match item {
        CodexResponseItem::Message { id, content, phase } => json!({
            "type":"message",
            "id":id,
            "role":"assistant",
            "content":content.into_iter().map(|part| match part {
                CodexMessageContent::OutputText { text } => {
                    json!({"type":"output_text","text":text})
                }
            }).collect::<Vec<_>>(),
            "phase":phase.map(phase_string),
        }),
        CodexResponseItem::Reasoning {
            id,
            summary,
            content,
            encrypted_content,
        } => json!({
            "type":"reasoning",
            "id":id,
            "summary":summary.into_iter().map(|part| {
                json!({"type":"summary_text","text":part.text})
            }).collect::<Vec<_>>(),
            "content":content.map(|parts| parts.into_iter().map(|part| {
                json!({"type":"reasoning_text","text":part.text})
            }).collect::<Vec<_>>()),
            "encrypted_content":encrypted_content,
        }),
        CodexResponseItem::FunctionCall {
            id,
            call_id,
            name,
            arguments,
        } => json!({
            "type":"function_call",
            "id":id,
            "call_id":call_id,
            "name":name,
            "arguments":arguments,
        }),
        CodexResponseItem::CustomToolCall {
            id,
            status,
            call_id,
            name,
            input,
        } => json!({
            "type":"custom_tool_call",
            "id":id,
            "status":status.map(status_string),
            "call_id":call_id,
            "name":name,
            "input":input,
        }),
        CodexResponseItem::ToolSearchCall {
            id,
            call_id,
            status,
            arguments,
        } => json!({
            "type":"tool_search_call",
            "id":id,
            "call_id":call_id,
            "status":status.map(status_string),
            "execution":"client",
            "arguments":{"query":arguments.query,"limit":arguments.limit},
        }),
    }
}

fn completed_json(completed: CodexCompleted) -> AdaptorResult<JsonValue> {
    let usage = completed.usage;
    let mut usage_json = json!({
        "input_tokens":usage.input_tokens,
        "input_tokens_details":usage.input_tokens_details.map(|details| json!({
            "cached_tokens":details.cached_tokens,
            "cache_write_tokens":details.cache_write_tokens,
        })),
        "output_tokens":usage.output_tokens,
        "output_tokens_details":usage.output_tokens_details.map(|details| json!({
            "reasoning_tokens":details.reasoning_tokens,
        })),
        "total_tokens":usage.total_tokens,
    });
    if let Some(units) = usage.codex_rollout_budget_units {
        usage_json["codex_rollout_budget_units"] = JsonValue::Number(units);
    }
    Ok(json!({
        "type":"response.completed",
        "response":{
            "id":completed.response_id,
            "model":completed.server_model,
            "usage":usage_json,
            "usage_metadata":completed.usage_metadata.map(|metadata| {
                json!({"amount":metadata.amount})
            }),
            "end_turn":completed.end_turn,
        }
    }))
}

const fn status_string(status: CodexItemStatus) -> &'static str {
    match status {
        CodexItemStatus::InProgress => "in_progress",
        CodexItemStatus::Completed => "completed",
        CodexItemStatus::Incomplete => "incomplete",
    }
}

const fn phase_string(phase: CodexMessagePhase) -> &'static str {
    match phase {
        CodexMessagePhase::Commentary => "commentary",
        CodexMessagePhase::FinalAnswer => "final_answer",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CodexToolSearchArguments, CodexUsage, CodexUsageMetadata};
    use serde_json::Number;

    #[test]
    fn renderer_preserves_encrypted_reasoning_and_fractional_rollout_units() {
        let reasoning = render_codex_event(CodexResponsesEvent::OutputItemDone(
            CodexResponseItem::Reasoning {
                id: Some("rs_1".to_string()),
                summary: Vec::new(),
                content: None,
                encrypted_content: Some("cipher".to_string()),
            },
        ))
        .unwrap();
        assert_eq!(
            match reasoning.data {
                crate::WireEventData::Json(value) => {
                    assert!(value["item"].get("status").is_none());
                    assert!(value["item"].get("content").is_none());
                    value["item"]["encrypted_content"].clone()
                }
                _ => unreachable!(),
            },
            "cipher"
        );

        let message = render_codex_event(CodexResponsesEvent::OutputItemDone(
            CodexResponseItem::Message {
                id: None,
                content: vec![CodexMessageContent::OutputText {
                    text: "hello".to_string(),
                }],
                phase: None,
            },
        ))
        .unwrap();
        let crate::WireEventData::Json(message) = message.data else {
            unreachable!()
        };
        assert!(message["item"].get("id").is_none());
        assert!(message["item"].get("status").is_none());
        assert!(message["item"].get("phase").is_none());

        let completed = render_codex_event(CodexResponsesEvent::Completed(CodexCompleted {
            response_id: "resp_1".to_string(),
            server_model: Some("gpt-5.5-codex".to_string()),
            usage: CodexUsage {
                input_tokens: 2,
                input_tokens_details: None,
                output_tokens: 1,
                output_tokens_details: None,
                total_tokens: 3,
                codex_rollout_budget_units: Number::from_f64(2.5),
            },
            usage_metadata: Some(CodexUsageMetadata {
                amount: Some("0.1".to_string()),
            }),
            end_turn: Some(false),
        }))
        .unwrap();
        assert_eq!(
            match completed.data {
                crate::WireEventData::Json(value) => {
                    value["response"]["usage"]["codex_rollout_budget_units"].clone()
                }
                _ => unreachable!(),
            },
            json!(2.5)
        );
    }

    #[test]
    fn renderer_goldens_sparse_message_and_tool_search_items() {
        let message = render_codex_event(CodexResponsesEvent::OutputItemDone(
            CodexResponseItem::Message {
                id: None,
                content: vec![CodexMessageContent::OutputText {
                    text: "hello".to_string(),
                }],
                phase: None,
            },
        ))
        .unwrap();
        assert_eq!(
            message,
            WireStreamEvent::json(
                Some("response.output_item.done".to_string()),
                json!({
                    "type":"response.output_item.done",
                    "item":{
                        "type":"message",
                        "role":"assistant",
                        "content":[{"type":"output_text","text":"hello"}]
                    }
                }),
            )
        );

        let search = render_codex_event(CodexResponsesEvent::OutputItemDone(
            CodexResponseItem::ToolSearchCall {
                id: Some("ts_1".to_string()),
                call_id: "search_1".to_string(),
                status: Some(CodexItemStatus::Completed),
                arguments: CodexToolSearchArguments {
                    query: "calendar create".to_string(),
                    limit: Some(1),
                },
            },
        ))
        .unwrap();
        assert_eq!(
            search,
            WireStreamEvent::json(
                Some("response.output_item.done".to_string()),
                json!({
                    "type":"response.output_item.done",
                    "item":{
                        "type":"tool_search_call",
                        "id":"ts_1",
                        "call_id":"search_1",
                        "status":"completed",
                        "execution":"client",
                        "arguments":{"query":"calendar create","limit":1}
                    }
                }),
            )
        );
    }

    #[test]
    fn renderer_rejects_events_after_terminal_error() {
        let adaptor = CodexResponsesAdaptor;
        let request = ParsedCodexRequest {
            model: "gpt-5.5-codex".to_string(),
            input: Vec::new(),
        };
        let mut state = CodexStreamState::default();
        adaptor
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::Error {
                    message: "failed".to_string(),
                    code: None,
                },
            )
            .unwrap();
        assert!(
            adaptor
                .render_stream_event(
                    &request,
                    &mut state,
                    OutputEvent::Error {
                        message: "late".to_string(),
                        code: None,
                    },
                )
                .is_err()
        );
    }
}
