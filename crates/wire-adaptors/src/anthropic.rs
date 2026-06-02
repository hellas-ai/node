use serde_json::{Map as JsonMap, Value as JsonValue, json};

use crate::{
    AdaptorError, AdaptorResult, CanonicalExecution, ExecutionRequest, ExecutionResult, Input,
    InputItem, ModelRef, OutputEvent, OutputItem, PassthroughBag, RawRequest, ReasoningOptions,
    RenderContext, StopReason, TextChannel, WireAdaptor, WireResponse, WireStreamEvent,
};

const KNOWN_TOP_LEVEL_FIELDS: &[&str] = &[
    "model",
    "messages",
    "max_tokens",
    "system",
    "stream",
    "thinking",
];

// Anthropic tool declarations stay in passthrough until there is a
// provider-neutral tool schema for this surface. Tool-use history itself is
// preserved in the message content blocks.

#[derive(Clone, Copy, Debug, Default)]
pub struct AnthropicMessagesAdaptor;

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedAnthropicMessageRequest {
    pub raw: RawRequest,
    pub model: String,
    pub messages: Vec<JsonValue>,
    pub max_tokens: u32,
    pub system: Option<JsonValue>,
    pub stream: Option<bool>,
    pub thinking: Option<JsonValue>,
    pub passthrough: PassthroughBag,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnthropicMessagesStreamState {
    id: String,
    model: String,
    started: bool,
    usage: Option<crate::Usage>,
    provenance: Option<crate::Provenance>,
    next_block_index: usize,
    open_block: Option<AnthropicOpenBlock>,
    tool_calls: Vec<AnthropicToolCallState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AnthropicOpenBlock {
    index: usize,
    kind: AnthropicBlockKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnthropicBlockKind {
    Text,
    Thinking,
    Tool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AnthropicToolCallState {
    parser_index: usize,
    block_index: usize,
}

impl WireAdaptor for AnthropicMessagesAdaptor {
    type ParsedRequest = ParsedAnthropicMessageRequest;
    type StreamState = AnthropicMessagesStreamState;

    fn parse(&self, raw: RawRequest) -> AdaptorResult<Self::ParsedRequest> {
        ParsedAnthropicMessageRequest::parse(raw)
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
        AnthropicMessagesStreamState {
            id: context.response_id,
            model: request.model.clone(),
            started: false,
            usage: None,
            provenance: None,
            next_block_index: 0,
            open_block: None,
            tool_calls: Vec::new(),
        }
    }

    fn render_response(
        &self,
        request: &Self::ParsedRequest,
        result: ExecutionResult,
        context: RenderContext,
    ) -> AdaptorResult<WireResponse> {
        let mut body = json!({
            "id": context.response_id,
            "type": "message",
            "role": "assistant",
            "content": output_blocks_json(&result.output),
            "model": request.model,
            "stop_reason": stop_reason_json(result.stop_reason),
        });
        if let Some(usage) = result.usage {
            body["usage"] = usage_json(usage);
        }
        Ok(WireResponse::json(
            200,
            attach_hellas(body, result.provenance.as_ref()),
        ))
    }

    fn render_stream_start(
        &self,
        _request: &Self::ParsedRequest,
        state: &mut Self::StreamState,
    ) -> AdaptorResult<Vec<WireStreamEvent>> {
        if state.started {
            return Ok(Vec::new());
        }
        state.started = true;
        Ok(vec![WireStreamEvent::json(
            Some("message_start".to_string()),
            attach_hellas(
                json!({
                    "type": "message_start",
                    "message": {
                        "id": state.id,
                        "type": "message",
                        "role": "assistant",
                        "content": [],
                        "model": state.model,
                        "usage": usage_json(crate::Usage {
                            input_tokens: Some(0),
                            output_tokens: Some(0),
                            total_tokens: Some(0),
                        }),
                    },
                }),
                state.provenance.as_ref(),
            ),
        )])
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
                channel: TextChannel::Output,
                ..
            } => render_text_delta(state, AnthropicBlockKind::Text, delta),
            OutputEvent::TextDelta {
                delta,
                channel: TextChannel::Reasoning,
                ..
            } => render_text_delta(state, AnthropicBlockKind::Thinking, delta),
            OutputEvent::StructuredOutputDelta(delta) => render_text_delta(
                state,
                AnthropicBlockKind::Text,
                structured_delta_string(delta),
            ),
            OutputEvent::ToolCallStart(start) => render_tool_call_start(state, start),
            OutputEvent::ToolCallArgumentsDelta(delta) => {
                render_tool_call_arguments_delta(state, delta.index, delta.delta)
            }
            OutputEvent::ToolCallEnd(end) => render_tool_call_end(state, end.index),
            OutputEvent::Usage(usage) => {
                state.usage = Some(usage);
                Ok(Vec::new())
            }
            OutputEvent::Provenance(provenance) => {
                state.provenance = Some(provenance);
                Ok(Vec::new())
            }
            OutputEvent::Error { message, code } => {
                let mut events = close_open_block(state);
                events.push(WireStreamEvent::json(
                    Some("error".to_string()),
                    json!({
                        "type": "error",
                        "error": {
                            "type": code.unwrap_or_else(|| "invalid_request_error".to_string()),
                            "message": message,
                        },
                    }),
                ));
                Ok(events)
            }
            OutputEvent::Finished { stop_reason, usage } => {
                if let Some(usage) = usage {
                    state.usage = Some(usage);
                }
                let mut events = close_open_block(state);
                events.push(WireStreamEvent::json(
                    Some("message_delta".to_string()),
                    json!({
                        "type": "message_delta",
                        "delta": {"stop_reason": stop_reason_json(stop_reason)},
                        "usage": state.usage.map(usage_json).unwrap_or_else(|| {
                            usage_json(crate::Usage::default())
                        }),
                    }),
                ));
                events.push(WireStreamEvent::json(
                    Some("message_stop".to_string()),
                    attach_hellas(json!({"type": "message_stop"}), state.provenance.as_ref()),
                ));
                Ok(events)
            }
        }
    }
}

impl ParsedAnthropicMessageRequest {
    fn parse(raw: RawRequest) -> AdaptorResult<Self> {
        let object = raw.value().as_object().ok_or_else(|| {
            AdaptorError::invalid_request("Anthropic Messages request must be a JSON object")
        })?;
        let model = required_string(object, "model")?;
        let messages = required_array(object, "messages")?;
        for message in &messages {
            validate_message(message)?;
        }
        let max_tokens = required_u32(object, "max_tokens")?;
        let system = object.get("system").cloned();
        if let Some(system) = &system {
            validate_system(system)?;
        }
        let stream = optional_bool(object, "stream")?;
        let thinking = object.get("thinking").cloned();
        if let Some(thinking) = &thinking {
            validate_thinking(thinking)?;
        }
        let passthrough = passthrough_fields(object);

        Ok(Self {
            raw,
            model,
            messages,
            max_tokens,
            system,
            stream,
            thinking,
            passthrough,
        })
    }

    fn to_execution_request(&self) -> AdaptorResult<ExecutionRequest> {
        let mut items =
            Vec::with_capacity(self.messages.len() + usize::from(self.system.is_some()));
        if let Some(system) = &self.system {
            items.push(InputItem::Raw(json!({
                "role": "system",
                "content": system,
            })));
        }
        items.extend(self.messages.iter().cloned().map(InputItem::Raw));

        let mut canonical =
            CanonicalExecution::new(ModelRef::new(self.model.clone()), Input::Items(items));
        canonical.sampling.max_output_tokens = Some(self.max_tokens);
        if let Some(thinking) = &self.thinking {
            canonical.reasoning = Some(ReasoningOptions {
                value: thinking.clone(),
            });
        }

        Ok(ExecutionRequest::new(canonical, self.passthrough.clone()))
    }
}

fn passthrough_fields(object: &JsonMap<String, JsonValue>) -> PassthroughBag {
    let mut bag = PassthroughBag::new();
    for (key, value) in object {
        if !KNOWN_TOP_LEVEL_FIELDS.contains(&key.as_str()) {
            bag.push(key.as_str(), value.clone());
        }
    }
    if let Some(value) = object.get("stream") {
        bag.push("stream", value.clone());
    }
    bag
}

fn validate_message(value: &JsonValue) -> AdaptorResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("Anthropic message must be a JSON object"))?;
    required_string(object, "role")?;
    let content = object
        .get("content")
        .ok_or_else(|| AdaptorError::invalid_request("Anthropic message missing `content`"))?;
    validate_content(content)
}

fn validate_system(value: &JsonValue) -> AdaptorResult<()> {
    match value {
        JsonValue::String(_) => Ok(()),
        JsonValue::Array(blocks) => {
            for block in blocks {
                validate_text_block(block, "system block")?;
            }
            Ok(())
        }
        _ => Err(AdaptorError::invalid_request(
            "`system` must be a string or text block array",
        )),
    }
}

fn validate_content(value: &JsonValue) -> AdaptorResult<()> {
    match value {
        JsonValue::String(_) => Ok(()),
        JsonValue::Array(blocks) => {
            for block in blocks {
                validate_text_block(block, "content block")?;
            }
            Ok(())
        }
        _ => Err(AdaptorError::invalid_request(
            "Anthropic message `content` must be a string or block array",
        )),
    }
}

fn validate_text_block(value: &JsonValue, label: &str) -> AdaptorResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request(format!("{label} must be a JSON object")))?;
    let block_type = required_string(object, "type")?;
    match block_type.as_str() {
        "text" => {
            required_string(object, "text")?;
            Ok(())
        }
        _ => Err(AdaptorError::invalid_request(format!(
            "unsupported Anthropic {label} type `{block_type}`"
        ))),
    }
}

fn validate_thinking(value: &JsonValue) -> AdaptorResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("`thinking` must be a JSON object"))?;
    match required_string(object, "type")?.as_str() {
        "enabled" => {
            required_u32(object, "budget_tokens")?;
            Ok(())
        }
        "disabled" => Ok(()),
        other => Err(AdaptorError::invalid_request(format!(
            "unsupported Anthropic thinking type `{other}`"
        ))),
    }
}

fn output_blocks_json(output: &[OutputItem]) -> Vec<JsonValue> {
    let mut text = String::new();
    let mut blocks = Vec::new();
    for item in output {
        match item {
            OutputItem::Text {
                text: part,
                channel: TextChannel::Output | TextChannel::Reasoning,
            } => text.push_str(part),
            OutputItem::StructuredJson(value) => text.push_str(&json_to_wire_string(value)),
            OutputItem::ToolCall {
                id,
                name,
                arguments,
            } => blocks.push(json!({
                "type": "tool_use",
                "id": id,
                "name": name,
                "input": arguments,
            })),
            OutputItem::Raw(value) => match value {
                JsonValue::Array(values) => blocks.extend(values.clone()),
                JsonValue::Object(_) => blocks.push(value.clone()),
                _ => text.push_str(&json_to_wire_string(value)),
            },
        }
    }
    if !text.is_empty() || blocks.is_empty() {
        blocks.insert(0, json!({"type": "text", "text": text}));
    }
    blocks
}

fn render_text_delta(
    state: &mut AnthropicMessagesStreamState,
    kind: AnthropicBlockKind,
    delta: String,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let mut events = ensure_open_block(state, kind);
    let index = state
        .open_block
        .as_ref()
        .expect("ensure_open_block leaves a block open")
        .index;
    let delta = match kind {
        AnthropicBlockKind::Text => json!({"type": "text_delta", "text": delta}),
        AnthropicBlockKind::Thinking => json!({"type": "thinking_delta", "thinking": delta}),
        AnthropicBlockKind::Tool => {
            return Err(AdaptorError::render(
                "tool blocks cannot render text deltas",
            ));
        }
    };
    events.push(WireStreamEvent::json(
        Some("content_block_delta".to_string()),
        json!({
            "type": "content_block_delta",
            "index": index,
            "delta": delta,
        }),
    ));
    Ok(events)
}

fn ensure_open_block(
    state: &mut AnthropicMessagesStreamState,
    kind: AnthropicBlockKind,
) -> Vec<WireStreamEvent> {
    if state
        .open_block
        .as_ref()
        .is_some_and(|block| block.kind == kind)
    {
        return Vec::new();
    }

    let mut events = close_open_block(state);
    let index = next_block_index(state);
    state.open_block = Some(AnthropicOpenBlock { index, kind });
    events.push(WireStreamEvent::json(
        Some("content_block_start".to_string()),
        json!({
            "type": "content_block_start",
            "index": index,
            "content_block": block_start_json(kind),
        }),
    ));
    events
}

fn block_start_json(kind: AnthropicBlockKind) -> JsonValue {
    match kind {
        AnthropicBlockKind::Text => json!({"type": "text", "text": ""}),
        AnthropicBlockKind::Thinking => json!({"type": "thinking", "thinking": ""}),
        AnthropicBlockKind::Tool => unreachable!("tool block start requires tool metadata"),
    }
}

fn close_open_block(state: &mut AnthropicMessagesStreamState) -> Vec<WireStreamEvent> {
    let Some(block) = state.open_block.take() else {
        return Vec::new();
    };
    vec![WireStreamEvent::json(
        Some("content_block_stop".to_string()),
        json!({
            "type": "content_block_stop",
            "index": block.index,
        }),
    )]
}

fn next_block_index(state: &mut AnthropicMessagesStreamState) -> usize {
    let index = state.next_block_index;
    state.next_block_index = state.next_block_index.saturating_add(1);
    index
}

fn render_tool_call_start(
    state: &mut AnthropicMessagesStreamState,
    start: crate::ToolCallStart,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let id = start
        .id
        .ok_or_else(|| AdaptorError::render("Anthropic tool call start requires an id"))?;
    if state
        .tool_calls
        .iter()
        .any(|call| call.parser_index == start.index)
    {
        return Err(AdaptorError::render(format!(
            "duplicate tool call start for index {}",
            start.index
        )));
    }

    let mut events = close_open_block(state);
    let block_index = next_block_index(state);
    state.open_block = Some(AnthropicOpenBlock {
        index: block_index,
        kind: AnthropicBlockKind::Tool,
    });
    state.tool_calls.push(AnthropicToolCallState {
        parser_index: start.index,
        block_index,
    });

    events.push(WireStreamEvent::json(
        Some("content_block_start".to_string()),
        json!({
            "type": "content_block_start",
            "index": block_index,
            "content_block": {
                "type": "tool_use",
                "id": id,
                "name": start.name,
                "input": {},
            },
        }),
    ));
    Ok(events)
}

fn render_tool_call_arguments_delta(
    state: &AnthropicMessagesStreamState,
    index: usize,
    delta: String,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let block_index = tool_call_block_index(state, index)?;
    Ok(vec![WireStreamEvent::json(
        Some("content_block_delta".to_string()),
        json!({
            "type": "content_block_delta",
            "index": block_index,
            "delta": {
                "type": "input_json_delta",
                "partial_json": delta,
            },
        }),
    )])
}

fn render_tool_call_end(
    state: &mut AnthropicMessagesStreamState,
    index: usize,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let block_index = tool_call_block_index(state, index)?;
    state.tool_calls.retain(|call| call.parser_index != index);
    if state
        .open_block
        .as_ref()
        .is_some_and(|block| block.index == block_index && block.kind == AnthropicBlockKind::Tool)
    {
        return Ok(close_open_block(state));
    }
    Err(AdaptorError::render(format!(
        "tool call index {index} is not open"
    )))
}

fn tool_call_block_index(
    state: &AnthropicMessagesStreamState,
    parser_index: usize,
) -> AdaptorResult<usize> {
    state
        .tool_calls
        .iter()
        .find(|call| call.parser_index == parser_index)
        .map(|call| call.block_index)
        .ok_or_else(|| AdaptorError::render(format!("unknown tool call index {parser_index}")))
}

fn attach_hellas(mut body: JsonValue, provenance: Option<&crate::Provenance>) -> JsonValue {
    if let Some(hellas) = provenance.and_then(provenance_json) {
        body["hellas"] = hellas;
    }
    body
}

fn usage_json(usage: crate::Usage) -> JsonValue {
    json!({
        "input_tokens": usage.input_tokens.unwrap_or(0),
        "output_tokens": usage.output_tokens.unwrap_or(0),
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

fn stop_reason_json(stop_reason: StopReason) -> JsonValue {
    let value = match stop_reason {
        StopReason::EndOfText | StopReason::StopSequence | StopReason::Cancelled => "end_turn",
        StopReason::MaxOutputTokens => "max_tokens",
        StopReason::ToolCall => "tool_use",
    };
    JsonValue::String(value.to_string())
}

fn structured_delta_string(delta: crate::StructuredDelta) -> String {
    match delta {
        crate::StructuredDelta::Text(text) => text,
        crate::StructuredDelta::Json(value) => json_to_wire_string(&value),
    }
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

fn required_u32(object: &JsonMap<String, JsonValue>, key: &str) -> AdaptorResult<u32> {
    object
        .get(key)
        .and_then(JsonValue::as_u64)
        .and_then(|value| u32::try_from(value).ok())
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

fn required_array(object: &JsonMap<String, JsonValue>, key: &str) -> AdaptorResult<Vec<JsonValue>> {
    match object.get(key) {
        Some(JsonValue::Array(values)) => Ok(values.clone()),
        _ => Err(AdaptorError::invalid_request(format!(
            "`{key}` must be an array"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FieldPath, Provenance, Usage, WireBody, WireEventData};

    fn adaptor() -> AnthropicMessagesAdaptor {
        AnthropicMessagesAdaptor
    }

    fn raw(value: JsonValue) -> RawRequest {
        RawRequest::from_value(value).unwrap()
    }

    fn sample_request() -> ParsedAnthropicMessageRequest {
        adaptor()
            .parse(raw(json!({
                "model": "claude-3-5-sonnet",
                "system": [{"type": "text", "text": "Be brief"}],
                "messages": [{
                    "role": "user",
                    "content": [{"type": "text", "text": "Hi"}]
                }],
                "max_tokens": 32,
                "stream": true,
                "thinking": {"type": "enabled", "budget_tokens": 1024},
                "metadata": {"user_id": "u-1"},
                "temperature": 0.4
            })))
            .unwrap()
    }

    #[test]
    fn parse_preserves_passthrough() {
        let request = sample_request();
        assert_eq!(request.model, "claude-3-5-sonnet");
        assert_eq!(request.max_tokens, 32);
        assert_eq!(request.stream, Some(true));
        let paths = request
            .passthrough
            .fields()
            .iter()
            .map(|field| field.path.clone())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(paths, field_set(["stream", "metadata", "temperature"]));
    }

    #[test]
    fn projection_sets_messages_system_tokens_and_thinking() {
        let execution = adaptor()
            .to_execution_request(&sample_request())
            .expect("request projects");
        assert_eq!(execution.canonical.model.name, "claude-3-5-sonnet");
        assert_eq!(execution.canonical.sampling.max_output_tokens, Some(32));
        assert!(execution.canonical.reasoning.is_some());
        let Input::Items(items) = execution.canonical.input else {
            panic!("expected raw input items");
        };
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn render_response_accepts_raw_blocks() {
        let result = ExecutionResult {
            output: vec![OutputItem::Raw(json!([
                {"type": "text", "text": "done"}
            ]))],
            usage: Some(Usage {
                input_tokens: Some(3),
                output_tokens: Some(2),
                total_tokens: Some(5),
            }),
            stop_reason: StopReason::EndOfText,
            provenance: Some(Provenance {
                call_commitment: Some("aa".repeat(32)),
                receipt: Some("bb".repeat(32)),
            }),
        };
        let response = adaptor()
            .render_response(
                &sample_request(),
                result,
                RenderContext::new("msg-test", "unused", 0),
            )
            .unwrap();
        assert_eq!(response.status, 200);
        let WireBody::Json(body) = response.body else {
            panic!("expected json body");
        };
        assert_eq!(body["type"], "message");
        assert_eq!(body["content"][0]["text"], "done");
        assert_eq!(body["usage"]["input_tokens"], 3);
        assert_eq!(body["hellas"]["commitment"], "aa".repeat(32));
        assert_eq!(body["hellas"]["receipt"], "bb".repeat(32));
    }

    #[test]
    fn parse_project_render_keeps_passthrough_available() {
        let request = sample_request();
        let execution = adaptor().to_execution_request(&request).unwrap();
        assert_eq!(execution.passthrough, request.passthrough);

        let response = adaptor()
            .render_response(
                &request,
                ExecutionResult {
                    output: vec![OutputItem::Text {
                        text: "done".to_string(),
                        channel: TextChannel::Output,
                    }],
                    usage: None,
                    stop_reason: StopReason::EndOfText,
                    provenance: None,
                },
                RenderContext::new("msg-test", "unused", 0),
            )
            .unwrap();
        let WireBody::Json(body) = response.body else {
            panic!("expected json body");
        };
        assert_eq!(body["model"], request.model);
        assert_eq!(body["content"][0]["text"], "done");
    }

    #[test]
    fn stream_finish_renders_delta_and_stop() {
        let request = sample_request();
        let mut state =
            adaptor().initial_state(&request, RenderContext::new("msg-test", "unused", 0));
        let events = adaptor()
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::Finished {
                    stop_reason: StopReason::MaxOutputTokens,
                    usage: Some(Usage {
                        input_tokens: Some(1),
                        output_tokens: Some(2),
                        total_tokens: Some(3),
                    }),
                },
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].name.as_deref(), Some("message_delta"));
        assert_eq!(events[1].name.as_deref(), Some("message_stop"));
    }

    #[test]
    fn stream_text_delta_opens_and_finish_closes_content_block() {
        let request = sample_request();
        let mut state =
            adaptor().initial_state(&request, RenderContext::new("msg-test", "unused", 0));

        let text = adaptor()
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::TextDelta {
                    index: 0,
                    delta: "hello".to_string(),
                    channel: TextChannel::Output,
                },
            )
            .unwrap();
        let finish = adaptor()
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::Finished {
                    stop_reason: StopReason::EndOfText,
                    usage: None,
                },
            )
            .unwrap();

        assert_eq!(text[0].name.as_deref(), Some("content_block_start"));
        assert_eq!(text[1].name.as_deref(), Some("content_block_delta"));
        let WireEventData::Json(start_json) = &text[0].data else {
            panic!("expected content block start json");
        };
        assert_eq!(start_json["index"], 0);
        assert_eq!(start_json["content_block"]["type"], "text");
        let WireEventData::Json(delta_json) = &text[1].data else {
            panic!("expected content block delta json");
        };
        assert_eq!(delta_json["index"], 0);
        assert_eq!(delta_json["delta"]["text"], "hello");

        assert_eq!(finish[0].name.as_deref(), Some("content_block_stop"));
        assert_eq!(finish[1].name.as_deref(), Some("message_delta"));
        assert_eq!(finish[2].name.as_deref(), Some("message_stop"));
    }

    #[test]
    fn stream_tool_call_events_render_anthropic_blocks() {
        let request = sample_request();
        let mut state =
            adaptor().initial_state(&request, RenderContext::new("msg-test", "unused", 0));

        let start = adaptor()
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::ToolCallStart(crate::ToolCallStart {
                    index: 0,
                    id: Some("toolu_1".to_string()),
                    name: "lookup".to_string(),
                }),
            )
            .unwrap();
        let args = adaptor()
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::ToolCallArgumentsDelta(crate::ToolCallArgumentsDelta {
                    index: 0,
                    delta: "{\"query\":\"tea\"}".to_string(),
                }),
            )
            .unwrap();
        let end = adaptor()
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::ToolCallEnd(crate::ToolCallEnd {
                    index: 0,
                    arguments: json!({"query": "tea"}),
                }),
            )
            .unwrap();
        let finish = adaptor()
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::Finished {
                    stop_reason: StopReason::ToolCall,
                    usage: Some(Usage {
                        input_tokens: Some(4),
                        output_tokens: Some(2),
                        total_tokens: Some(6),
                    }),
                },
            )
            .unwrap();

        assert_eq!(start[0].name.as_deref(), Some("content_block_start"));
        let WireEventData::Json(start_json) = &start[0].data else {
            panic!("expected tool start json");
        };
        assert_eq!(start_json["content_block"]["type"], "tool_use");
        assert_eq!(start_json["content_block"]["id"], "toolu_1");
        assert_eq!(start_json["content_block"]["name"], "lookup");

        assert_eq!(args[0].name.as_deref(), Some("content_block_delta"));
        let WireEventData::Json(args_json) = &args[0].data else {
            panic!("expected tool arguments json");
        };
        assert_eq!(args_json["delta"]["type"], "input_json_delta");
        assert_eq!(args_json["delta"]["partial_json"], "{\"query\":\"tea\"}");

        assert_eq!(end[0].name.as_deref(), Some("content_block_stop"));
        let WireEventData::Json(finish_json) = &finish[0].data else {
            panic!("expected finish json");
        };
        assert_eq!(finish_json["delta"]["stop_reason"], "tool_use");
        assert_eq!(finish[1].name.as_deref(), Some("message_stop"));
    }

    fn field_set<const N: usize>(fields: [&str; N]) -> std::collections::BTreeSet<FieldPath> {
        fields.into_iter().map(FieldPath::from).collect()
    }
}
