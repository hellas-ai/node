use serde_json::{Map as JsonMap, Value as JsonValue, json};

use crate::{
    AdaptorError, AdaptorResult, CanonicalExecution, ExecutionRequest, ExecutionResult, Input,
    ModelRef, OutputEvent, OutputItem, RawRequest, RenderContext, StopReason, TextChannel,
    WireAdaptor, WireEventData, WireResponse, WireStreamEvent,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct OpenAiCompletionsAdaptor;

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedCompletionRequest {
    pub raw: RawRequest,
    pub model: String,
    pub prompt: String,
    pub max_tokens: Option<u32>,
    pub stream: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionStreamState {
    id: String,
    created: i64,
    model: String,
    provenance: Option<crate::Provenance>,
}

impl WireAdaptor for OpenAiCompletionsAdaptor {
    type ParsedRequest = ParsedCompletionRequest;
    type StreamState = CompletionStreamState;

    fn parse(&self, raw: RawRequest) -> AdaptorResult<Self::ParsedRequest> {
        ParsedCompletionRequest::parse(raw)
    }

    fn to_execution_request(
        &self,
        request: &Self::ParsedRequest,
    ) -> AdaptorResult<ExecutionRequest> {
        request.to_execution_request()
    }

    fn initial_state(
        &self,
        request: &Self::ParsedRequest,
        context: RenderContext,
    ) -> Self::StreamState {
        CompletionStreamState {
            id: context.response_id,
            created: context.created_at,
            model: request.model.clone(),
            provenance: None,
        }
    }

    fn render_response(
        &self,
        request: &Self::ParsedRequest,
        result: ExecutionResult,
        context: RenderContext,
    ) -> AdaptorResult<WireResponse> {
        if let Some(error) = result.error {
            return Ok(WireResponse::json(
                500,
                attach_hellas(
                    json!({
                        "error": {
                            "message": error.message,
                            "type": "server_error",
                            "code": error.code.unwrap_or_else(|| "server_error".to_string()),
                        }
                    }),
                    result.provenance.as_ref(),
                ),
            ));
        }
        let mut body = json!({
            "id": context.response_id,
            "object": "text_completion",
            "created": context.created_at,
            "model": request.model,
            "choices": [{
                "index": 0,
                "text": output_text(&result.output),
                "finish_reason": finish_reason_json(result.stop_reason),
            }],
        });
        if let Some(usage) = result.usage {
            body["usage"] = usage_json(usage);
        }
        Ok(WireResponse::json(
            200,
            attach_hellas(body, result.provenance.as_ref()),
        ))
    }

    fn render_stream_event(
        &self,
        _request: &Self::ParsedRequest,
        state: &mut Self::StreamState,
        event: OutputEvent,
    ) -> AdaptorResult<Vec<WireStreamEvent>> {
        match event {
            OutputEvent::TextDelta {
                delta,
                channel: TextChannel::Output | TextChannel::Reasoning,
                ..
            }
            | OutputEvent::StructuredOutputDelta(crate::StructuredDelta::Text(delta)) => {
                Ok(vec![WireStreamEvent::json(
                    None,
                    completion_chunk_json(state, delta, None),
                )])
            }
            OutputEvent::StructuredOutputDelta(crate::StructuredDelta::Json(value)) => {
                Ok(vec![WireStreamEvent::json(
                    None,
                    completion_chunk_json(state, json_to_wire_string(&value), None),
                )])
            }
            OutputEvent::ToolCallStart(_)
            | OutputEvent::ToolCallArgumentsDelta(_)
            | OutputEvent::ToolCallEnd(_) => Err(AdaptorError::unsupported(
                "text completions cannot render tool-call deltas",
            )),
            OutputEvent::Usage(_) => Ok(Vec::new()),
            OutputEvent::Provenance(provenance) => {
                state.provenance = Some(provenance);
                Ok(Vec::new())
            }
            OutputEvent::Error { message, code } => Ok(vec![WireStreamEvent::json(
                None,
                json!({
                    "error": {
                        "message": message,
                        "code": code,
                    },
                }),
            )]),
            OutputEvent::Finished { stop_reason, .. } => Ok(vec![
                WireStreamEvent::json(
                    None,
                    completion_chunk_json(state, String::new(), Some(stop_reason)),
                ),
                WireStreamEvent {
                    name: None,
                    data: WireEventData::Text("[DONE]".to_string()),
                },
            ]),
        }
    }
}

impl ParsedCompletionRequest {
    fn parse(raw: RawRequest) -> AdaptorResult<Self> {
        let object = raw.value().as_object().ok_or_else(|| {
            AdaptorError::invalid_request("Completions request must be a JSON object")
        })?;
        let model = required_string(object, "model")?;
        let prompt = required_string(object, "prompt")?;
        let max_tokens = optional_u32(object, "max_tokens")?;
        let stream = optional_bool(object, "stream")?;
        Ok(Self {
            raw,
            model,
            prompt,
            max_tokens,
            stream,
        })
    }

    fn to_execution_request(&self) -> AdaptorResult<ExecutionRequest> {
        let mut canonical = CanonicalExecution::new(
            ModelRef::new(self.model.clone()),
            Input::Text(self.prompt.clone()),
        );
        if let Some(max_tokens) = self.max_tokens {
            canonical.sampling.max_output_tokens = Some(max_tokens);
        }
        Ok(ExecutionRequest::new(canonical))
    }
}

fn output_text(output: &[OutputItem]) -> String {
    output
        .iter()
        .map(|item| match item {
            OutputItem::Text { text, .. } => text.clone(),
            OutputItem::StructuredJson(value) | OutputItem::Raw(value) => {
                json_to_wire_string(value)
            }
            OutputItem::ToolCall {
                id,
                name,
                arguments,
            } => json_to_wire_string(&json!({
                "id": id,
                "name": name,
                "arguments": arguments,
            })),
        })
        .collect::<Vec<_>>()
        .join("")
}

fn completion_chunk_json(
    state: &CompletionStreamState,
    text: String,
    stop_reason: Option<StopReason>,
) -> JsonValue {
    attach_hellas(
        json!({
            "id": state.id,
            "object": "text_completion",
            "created": state.created,
            "model": state.model,
            "choices": [{
                "index": 0,
                "text": text,
                "finish_reason": stop_reason.map(finish_reason_json).unwrap_or(JsonValue::Null),
            }],
        }),
        state.provenance.as_ref(),
    )
}

fn attach_hellas(mut body: JsonValue, provenance: Option<&crate::Provenance>) -> JsonValue {
    if let Some(hellas) = provenance.and_then(provenance_json) {
        body["hellas"] = hellas;
    }
    body
}

fn usage_json(usage: crate::Usage) -> JsonValue {
    let prompt_tokens = usage.input_tokens.unwrap_or(0);
    let completion_tokens = usage.output_tokens.unwrap_or(0);
    json!({
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": usage.total_tokens.unwrap_or_else(|| {
            prompt_tokens.saturating_add(completion_tokens)
        }),
    })
}

fn provenance_json(provenance: &crate::Provenance) -> Option<JsonValue> {
    let mut object = JsonMap::new();
    if let Some(commitment) = &provenance.call_commitment {
        object.insert(
            "commitment".to_string(),
            JsonValue::String(commitment.clone()),
        );
    }
    if let Some(receipt) = &provenance.receipt {
        object.insert("receipt".to_string(), JsonValue::String(receipt.clone()));
    }
    (!object.is_empty()).then_some(JsonValue::Object(object))
}

fn finish_reason_json(stop_reason: StopReason) -> JsonValue {
    let value = match stop_reason {
        StopReason::EndOfText | StopReason::StopSequence | StopReason::Cancelled => "stop",
        StopReason::MaxOutputTokens => "length",
        StopReason::ToolCall => "tool_calls",
    };
    JsonValue::String(value.to_string())
}

fn json_to_wire_string(value: &JsonValue) -> String {
    match value {
        JsonValue::String(value) => value.clone(),
        _ => serde_json::to_string(value).expect("serializing JSON value cannot fail"),
    }
}

fn required_string(object: &JsonMap<String, JsonValue>, key: &str) -> AdaptorResult<String> {
    object
        .get(key)
        .and_then(JsonValue::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| AdaptorError::invalid_request(format!("missing or invalid `{key}`")))
}

fn optional_bool(object: &JsonMap<String, JsonValue>, key: &str) -> AdaptorResult<Option<bool>> {
    match object.get(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| AdaptorError::invalid_request(format!("`{key}` must be a bool"))),
    }
}

fn optional_u32(object: &JsonMap<String, JsonValue>, key: &str) -> AdaptorResult<Option<u32>> {
    match object.get(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| AdaptorError::invalid_request(format!("`{key}` must be a u32"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Provenance, Usage, WireBody, WireEventData};

    fn adaptor() -> OpenAiCompletionsAdaptor {
        OpenAiCompletionsAdaptor
    }

    fn raw(value: JsonValue) -> RawRequest {
        RawRequest::from_value(value).unwrap()
    }

    #[test]
    fn parse_preserves_raw_request() {
        let request = adaptor()
            .parse(raw(json!({
                "model": "gpt-3.5-turbo-instruct",
                "prompt": "Hello",
                "max_tokens": 16,
                "stream": true,
                "temperature": 0.7
            })))
            .unwrap();
        assert_eq!(request.model, "gpt-3.5-turbo-instruct");
        assert_eq!(request.prompt, "Hello");
        assert_eq!(request.max_tokens, Some(16));
        assert_eq!(request.stream, Some(true));
        assert_eq!(request.raw.value()["temperature"], 0.7);
    }

    #[test]
    fn projection_sets_model_prompt_and_limit() {
        let request = adaptor()
            .parse(raw(json!({
                "model": "gpt-3.5-turbo-instruct",
                "prompt": "Hello",
                "max_tokens": 16
            })))
            .unwrap();
        let execution = adaptor().to_execution_request(&request).unwrap();
        assert_eq!(execution.canonical.model.name, "gpt-3.5-turbo-instruct");
        assert_eq!(execution.canonical.input, Input::Text("Hello".to_string()));
        assert_eq!(execution.canonical.sampling.max_output_tokens, Some(16));
    }

    #[test]
    fn render_response_uses_completion_shape() {
        let request = adaptor()
            .parse(raw(json!({
                "model": "gpt-3.5-turbo-instruct",
                "prompt": "Hello"
            })))
            .unwrap();
        let result = ExecutionResult {
            output: vec![OutputItem::Text {
                text: " world".to_string(),
                channel: TextChannel::Output,
            }],
            usage: Some(Usage {
                input_tokens: Some(1),
                output_tokens: Some(2),
                total_tokens: Some(3),
            }),
            stop_reason: StopReason::EndOfText,
            provenance: Some(Provenance {
                call_commitment: Some("aa".repeat(32)),
                receipt: Some("bb".repeat(32)),
            }),
            error: None,
        };
        let response = adaptor()
            .render_response(
                &request,
                result,
                RenderContext::new("cmpl-test", "cmpl-test", 123),
            )
            .unwrap();
        assert_eq!(response.status, 200);
        let WireBody::Json(body) = response.body else {
            panic!("expected json body");
        };
        assert_eq!(body["object"], "text_completion");
        assert_eq!(body["choices"][0]["text"], " world");
        assert_eq!(body["usage"]["total_tokens"], 3);
        assert_eq!(body["hellas"]["commitment"], "aa".repeat(32));
        assert_eq!(body["hellas"]["receipt"], "bb".repeat(32));
    }

    #[test]
    fn parse_project_render_uses_projected_request() {
        let request = adaptor()
            .parse(raw(json!({
                "model": "gpt-3.5-turbo-instruct",
                "prompt": "Hello",
                "stream": false,
                "temperature": 0.7
            })))
            .unwrap();
        adaptor().to_execution_request(&request).unwrap();

        let response = adaptor()
            .render_response(
                &request,
                ExecutionResult {
                    output: vec![OutputItem::Text {
                        text: " world".to_string(),
                        channel: TextChannel::Output,
                    }],
                    usage: None,
                    stop_reason: StopReason::EndOfText,
                    provenance: None,
                    error: None,
                },
                RenderContext::new("cmpl-test", "cmpl-test", 123),
            )
            .unwrap();
        let WireBody::Json(body) = response.body else {
            panic!("expected json body");
        };
        assert_eq!(body["model"], request.model);
        assert_eq!(body["choices"][0]["text"], " world");
    }

    #[test]
    fn render_stream_events_carry_provenance_in_chunks() {
        let request = adaptor()
            .parse(raw(json!({
                "model": "gpt-3.5-turbo-instruct",
                "prompt": "Hello",
                "stream": true
            })))
            .unwrap();
        let mut state =
            adaptor().initial_state(&request, RenderContext::new("cmpl-test", "cmpl-test", 123));

        adaptor()
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::Provenance(Provenance {
                    call_commitment: Some("aa".repeat(32)),
                    receipt: None,
                }),
            )
            .unwrap();
        let delta = adaptor()
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::TextDelta {
                    index: 0,
                    delta: " world".to_string(),
                    channel: TextChannel::Output,
                },
            )
            .unwrap();
        let WireEventData::Json(delta_json) = &delta[0].data else {
            panic!("expected json delta");
        };
        assert_eq!(delta_json["choices"][0]["text"], " world");
        assert_eq!(delta_json["hellas"]["commitment"], "aa".repeat(32));

        adaptor()
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::Provenance(Provenance {
                    call_commitment: Some("aa".repeat(32)),
                    receipt: Some("bb".repeat(32)),
                }),
            )
            .unwrap();
        let finished = adaptor()
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::Finished {
                    stop_reason: StopReason::EndOfText,
                    usage: None,
                },
            )
            .unwrap();
        let WireEventData::Json(done_json) = &finished[0].data else {
            panic!("expected json terminal chunk");
        };
        assert_eq!(done_json["hellas"]["commitment"], "aa".repeat(32));
        assert_eq!(done_json["hellas"]["receipt"], "bb".repeat(32));
        assert!(matches!(finished[1].data, WireEventData::Text(ref text) if text == "[DONE]"));
    }
}
