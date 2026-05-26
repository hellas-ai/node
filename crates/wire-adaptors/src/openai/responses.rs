use serde_json::{Map as JsonMap, Value as JsonValue, json};

use crate::{
    AdaptorError, AdaptorResult, CanonicalExecution, ContentPart, ExecutionRequest,
    ExecutionResult, FieldPath, Input, InputItem, Message, ModelRef, OutputEvent, OutputItem,
    PassthroughBag, RawRequest, ReasoningOptions, RenderContext, ResponseFormat, StructuredDelta,
    TextChannel, ToolCallDelta, ToolChoice, ToolKind, ToolSpec, Usage, WireAdaptor, WireResponse,
    WireStreamEvent,
};

const KNOWN_TOP_LEVEL_FIELDS: &[&str] = &[
    "model",
    "input",
    "instructions",
    "tools",
    "max_output_tokens",
    "stream",
    "temperature",
    "top_p",
    "top_logprobs",
    "parallel_tool_calls",
    "truncation",
    "tool_choice",
    "text",
    "response_format",
    "reasoning",
    "previous_response_id",
    "metadata",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct OpenAiResponsesAdaptor;

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedResponseRequest {
    pub raw: RawRequest,
    pub model: String,
    pub input: JsonValue,
    pub instructions: Option<String>,
    pub tools: Vec<JsonValue>,
    pub max_output_tokens: Option<u32>,
    pub stream: Option<bool>,
    pub sampling: ResponseSampling,
    pub tool_choice: Option<JsonValue>,
    pub response_format: Option<JsonValue>,
    pub reasoning: Option<JsonValue>,
    pub previous_response_id: Option<String>,
    pub passthrough: PassthroughBag,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResponseSampling {
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_logprobs: Option<u32>,
    pub parallel_tool_calls: Option<bool>,
    pub truncation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponsesStreamState {
    response_id: String,
    message_id: String,
    created_at: i64,
    sequence_number: u64,
    text: String,
    output_started: bool,
    usage: Option<Usage>,
    provenance: Option<crate::Provenance>,
}

impl WireAdaptor for OpenAiResponsesAdaptor {
    type ParsedRequest = ParsedResponseRequest;
    type StreamState = ResponsesStreamState;

    fn parse(&self, raw: RawRequest) -> AdaptorResult<Self::ParsedRequest> {
        ParsedResponseRequest::parse(raw)
    }

    fn to_execution_request(
        &self,
        request: &Self::ParsedRequest,
    ) -> AdaptorResult<ExecutionRequest> {
        request.to_execution_request()
    }

    fn initial_state(
        &self,
        _request: &Self::ParsedRequest,
        context: RenderContext,
    ) -> Self::StreamState {
        ResponsesStreamState {
            response_id: context.response_id,
            message_id: context.message_id,
            created_at: context.created_at,
            sequence_number: 0,
            text: String::new(),
            output_started: false,
            usage: None,
            provenance: None,
        }
    }

    fn render_response(
        &self,
        request: &Self::ParsedRequest,
        result: ExecutionResult,
        context: RenderContext,
    ) -> AdaptorResult<WireResponse> {
        let body = response_json(
            &context.response_id,
            context.created_at,
            &request.model,
            "completed",
            output_items_json(&context.message_id, &result.output)?,
            result.usage,
            result.provenance.as_ref(),
        );
        Ok(WireResponse::json(200, body))
    }

    fn render_stream_start(
        &self,
        request: &Self::ParsedRequest,
        state: &mut Self::StreamState,
    ) -> AdaptorResult<Vec<WireStreamEvent>> {
        if state.output_started {
            return Ok(Vec::new());
        }
        state.output_started = true;

        let created = response_event(
            "response.created",
            response_status_event(
                state,
                request,
                "response.created",
                "queued",
                Vec::new(),
                None,
            ),
        );
        let in_progress = response_event(
            "response.in_progress",
            response_status_event(
                state,
                request,
                "response.in_progress",
                "in_progress",
                Vec::new(),
                None,
            ),
        );
        let item = message_item_json(&state.message_id, "in_progress", Vec::new());
        let output_item_added = response_event(
            "response.output_item.added",
            json!({
                "type": "response.output_item.added",
                "sequence_number": next_sequence(state),
                "output_index": 0,
                "item": item,
            }),
        );
        let part = output_text_json("");
        let content_part_added = response_event(
            "response.content_part.added",
            json!({
                "type": "response.content_part.added",
                "sequence_number": next_sequence(state),
                "item_id": state.message_id,
                "output_index": 0,
                "content_index": 0,
                "part": part,
            }),
        );

        Ok(vec![
            created,
            in_progress,
            output_item_added,
            content_part_added,
        ])
    }

    fn render_stream_event(
        &self,
        request: &Self::ParsedRequest,
        state: &mut Self::StreamState,
        event: OutputEvent,
    ) -> AdaptorResult<Vec<WireStreamEvent>> {
        match event {
            OutputEvent::TextDelta {
                delta,
                channel: TextChannel::Output,
                ..
            } => {
                state.text.push_str(&delta);
                Ok(vec![response_event(
                    "response.output_text.delta",
                    json!({
                        "type": "response.output_text.delta",
                        "sequence_number": next_sequence(state),
                        "item_id": state.message_id,
                        "output_index": 0,
                        "content_index": 0,
                        "delta": delta,
                    }),
                )])
            }
            OutputEvent::TextDelta {
                delta,
                channel: TextChannel::Reasoning,
                ..
            } => Ok(vec![response_event(
                "response.reasoning_text.delta",
                json!({
                    "type": "response.reasoning_text.delta",
                    "sequence_number": next_sequence(state),
                    "delta": delta,
                }),
            )]),
            OutputEvent::ToolCallDelta(delta) => render_tool_call_delta(state, delta),
            OutputEvent::StructuredOutputDelta(delta) => render_structured_delta(state, delta),
            OutputEvent::Usage(usage) => {
                state.usage = Some(usage);
                Ok(Vec::new())
            }
            OutputEvent::Provenance(provenance) => {
                state.provenance = Some(provenance);
                Ok(Vec::new())
            }
            OutputEvent::Error { message, code } => Ok(vec![response_event(
                "error",
                json!({
                    "error": {
                        "message": message,
                        "code": code,
                    }
                }),
            )]),
            OutputEvent::Finished { usage, .. } => {
                if let Some(usage) = usage {
                    state.usage = Some(usage);
                }
                let completed_text = output_text_json(&state.text);
                let content_done = response_event(
                    "response.output_text.done",
                    json!({
                        "type": "response.output_text.done",
                        "sequence_number": next_sequence(state),
                        "item_id": state.message_id,
                        "output_index": 0,
                        "content_index": 0,
                        "text": state.text,
                    }),
                );
                let part_done = response_event(
                    "response.content_part.done",
                    json!({
                        "type": "response.content_part.done",
                        "sequence_number": next_sequence(state),
                        "item_id": state.message_id,
                        "output_index": 0,
                        "content_index": 0,
                        "part": completed_text,
                    }),
                );
                let item = message_item_json(&state.message_id, "completed", vec![completed_text]);
                let item_done = response_event(
                    "response.output_item.done",
                    json!({
                        "type": "response.output_item.done",
                        "sequence_number": next_sequence(state),
                        "output_index": 0,
                        "item": item.clone(),
                    }),
                );
                let completed = response_event(
                    "response.completed",
                    json!({
                        "type": "response.completed",
                        "sequence_number": next_sequence(state),
                        "response": response_json(
                            &state.response_id,
                            state.created_at,
                            &request.model,
                            "completed",
                            vec![item],
                            state.usage,
                            state.provenance.as_ref(),
                        ),
                    }),
                );
                Ok(vec![content_done, part_done, item_done, completed])
            }
        }
    }
}

impl ParsedResponseRequest {
    fn parse(raw: RawRequest) -> AdaptorResult<Self> {
        let object = raw.value().as_object().ok_or_else(|| {
            AdaptorError::invalid_request("Responses request must be a JSON object")
        })?;

        let model = required_string(object, "model")?;
        let input = object
            .get("input")
            .cloned()
            .ok_or_else(|| AdaptorError::invalid_request("Responses request missing `input`"))?;
        let instructions = optional_string(object, "instructions")?;
        let tools = optional_array(object, "tools")?.unwrap_or_default();
        let max_output_tokens = optional_u32(object, "max_output_tokens")?;
        let stream = optional_bool(object, "stream")?;
        let sampling = ResponseSampling {
            temperature: optional_f32(object, "temperature")?,
            top_p: optional_f32(object, "top_p")?,
            top_logprobs: optional_u32(object, "top_logprobs")?,
            parallel_tool_calls: optional_bool(object, "parallel_tool_calls")?,
            truncation: optional_string(object, "truncation")?,
        };
        let tool_choice = object.get("tool_choice").cloned();
        let response_format = response_format_value(object);
        let reasoning = object.get("reasoning").cloned();
        let previous_response_id = optional_string(object, "previous_response_id")?;

        let passthrough = passthrough_fields(object);

        Ok(Self {
            raw,
            model,
            input,
            instructions,
            tools,
            max_output_tokens,
            stream,
            sampling,
            tool_choice,
            response_format,
            reasoning,
            previous_response_id,
            passthrough,
        })
    }

    fn to_execution_request(&self) -> AdaptorResult<ExecutionRequest> {
        let mut canonical = CanonicalExecution::new(
            ModelRef::new(self.model.clone()),
            project_input(&self.input)?,
        );
        canonical.commit_field("model");
        canonical.commit_field("input");

        if let Some(instructions) = &self.instructions {
            canonical.instructions = Some(instructions.clone());
            canonical.commit_field("instructions");
        }
        if let Some(max_output_tokens) = self.max_output_tokens {
            canonical.sampling.max_output_tokens = Some(max_output_tokens);
            canonical.commit_field("max_output_tokens");
        }
        if let Some(temperature) = self.sampling.temperature {
            canonical.sampling.temperature = Some(temperature);
            canonical.commit_field("temperature");
        }
        if let Some(top_p) = self.sampling.top_p {
            canonical.sampling.top_p = Some(top_p);
            canonical.commit_field("top_p");
        }
        if let Some(top_logprobs) = self.sampling.top_logprobs {
            canonical.sampling.top_logprobs = Some(top_logprobs);
            canonical.commit_field("top_logprobs");
        }
        if let Some(parallel_tool_calls) = self.sampling.parallel_tool_calls {
            canonical.sampling.parallel_tool_calls = Some(parallel_tool_calls);
            canonical.commit_field("parallel_tool_calls");
        }
        if let Some(truncation) = &self.sampling.truncation {
            canonical.sampling.truncation = Some(truncation.clone());
            canonical.commit_field("truncation");
        }

        canonical.tools = self
            .tools
            .iter()
            .map(project_tool)
            .collect::<AdaptorResult<Vec<_>>>()?;
        if !canonical.tools.is_empty() {
            canonical.commit_field("tools");
        }

        if let Some(tool_choice) = &self.tool_choice {
            canonical.tool_choice = project_tool_choice(tool_choice);
            canonical.commit_field("tool_choice");
        }
        if let Some(response_format) = &self.response_format {
            canonical.response_format = Some(project_response_format(response_format));
            canonical.commit_field(if self.raw.value().get("text").is_some() {
                "text"
            } else {
                "response_format"
            });
        }
        if let Some(reasoning) = &self.reasoning {
            canonical.reasoning = Some(ReasoningOptions {
                value: reasoning.clone(),
            });
            canonical.commit_field("reasoning");
        }
        if let Some(previous_response_id) = &self.previous_response_id {
            canonical.previous_response_id = Some(previous_response_id.clone());
            canonical.commit_field("previous_response_id");
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
    if let Some(value) = object.get("metadata") {
        bag.push("metadata", value.clone());
    }
    if let Some(value) = object.get("stream") {
        bag.push("stream", value.clone());
    }
    if let Some(text) = object.get("text").and_then(JsonValue::as_object) {
        for (key, value) in text {
            if key != "format" {
                bag.push(FieldPath::new(["text", key.as_str()]), value.clone());
            }
        }
    }
    bag
}

fn response_format_value(object: &JsonMap<String, JsonValue>) -> Option<JsonValue> {
    object
        .get("text")
        .and_then(|text| text.get("format").cloned())
        .or_else(|| object.get("response_format").cloned())
}

fn project_input(value: &JsonValue) -> AdaptorResult<Input> {
    match value {
        JsonValue::String(text) => Ok(Input::Text(text.clone())),
        JsonValue::Array(items) => Ok(Input::Items(
            items
                .iter()
                .map(project_input_item)
                .collect::<AdaptorResult<Vec<_>>>()?,
        )),
        _ => Err(AdaptorError::invalid_request(
            "`input` must be a string or array",
        )),
    }
}

fn project_input_item(value: &JsonValue) -> AdaptorResult<InputItem> {
    let Some(object) = value.as_object() else {
        return Ok(InputItem::Raw(value.clone()));
    };
    let item_type = object
        .get("type")
        .and_then(JsonValue::as_str)
        .unwrap_or("message");
    match item_type {
        "message" => {
            let role = required_string(object, "role")?;
            let content = object
                .get("content")
                .ok_or_else(|| AdaptorError::invalid_request("message item missing `content`"))?;
            Ok(InputItem::Message(Message {
                role,
                content: project_content(content)?,
                name: optional_string(object, "name")?,
            }))
        }
        "function_call_output" => Ok(InputItem::ToolResult {
            call_id: required_string(object, "call_id")?,
            output: vec![ContentPart::Text {
                text: required_string(object, "output")?,
            }],
        }),
        "function_call" => Ok(InputItem::ToolCall {
            id: required_string(object, "call_id").or_else(|_| required_string(object, "id"))?,
            name: required_string(object, "name")?,
            arguments: object.get("arguments").cloned().unwrap_or(JsonValue::Null),
        }),
        _ => Ok(InputItem::Raw(value.clone())),
    }
}

fn project_content(value: &JsonValue) -> AdaptorResult<Vec<ContentPart>> {
    match value {
        JsonValue::String(text) => Ok(vec![ContentPart::Text { text: text.clone() }]),
        JsonValue::Array(parts) => parts.iter().map(project_content_part).collect(),
        _ => Ok(vec![ContentPart::Json(value.clone())]),
    }
}

fn project_content_part(value: &JsonValue) -> AdaptorResult<ContentPart> {
    let Some(object) = value.as_object() else {
        return Ok(ContentPart::Json(value.clone()));
    };
    match object.get("type").and_then(JsonValue::as_str) {
        Some("input_text" | "output_text" | "text") => Ok(ContentPart::Text {
            text: required_string(object, "text")?,
        }),
        Some("input_image" | "image_url") => Ok(ContentPart::Image {
            uri: image_url(object),
            media_type: None,
            data: None,
        }),
        Some("input_file" | "file") => Ok(ContentPart::File {
            file_id: optional_string(object, "file_id")?,
            filename: optional_string(object, "filename")?,
            data: optional_string(object, "file_data")?
                .or_else(|| optional_string(object, "data").ok().flatten()),
        }),
        _ => Ok(ContentPart::Json(value.clone())),
    }
}

fn image_url(object: &JsonMap<String, JsonValue>) -> Option<String> {
    object
        .get("image_url")
        .and_then(|value| {
            value.as_str().map(ToString::to_string).or_else(|| {
                value
                    .get("url")
                    .and_then(JsonValue::as_str)
                    .map(ToString::to_string)
            })
        })
        .or_else(|| {
            object
                .get("url")
                .and_then(JsonValue::as_str)
                .map(ToString::to_string)
        })
}

fn project_tool(value: &JsonValue) -> AdaptorResult<ToolSpec> {
    let object = value
        .as_object()
        .ok_or_else(|| AdaptorError::invalid_request("tool must be a JSON object"))?;
    let tool_type = required_string(object, "type")?;
    match tool_type.as_str() {
        "function" => Ok(ToolSpec {
            name: required_string(object, "name")?,
            description: optional_string(object, "description")?,
            parameters: object
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| json!({"type": "object"})),
            kind: ToolKind::Function,
            raw: value.clone(),
        }),
        other => Ok(ToolSpec {
            name: object
                .get("name")
                .and_then(JsonValue::as_str)
                .unwrap_or(other)
                .to_string(),
            description: optional_string(object, "description")?,
            parameters: JsonValue::Object(object.clone()),
            kind: ToolKind::BuiltIn(other.to_string()),
            raw: value.clone(),
        }),
    }
}

fn project_tool_choice(value: &JsonValue) -> ToolChoice {
    match value.as_str() {
        Some("auto") => ToolChoice::Auto,
        Some("none") => ToolChoice::None,
        Some("required") => ToolChoice::Required,
        _ => value
            .get("name")
            .and_then(JsonValue::as_str)
            .map(|name| ToolChoice::Tool {
                name: name.to_string(),
            })
            .unwrap_or_else(|| ToolChoice::Raw(value.clone())),
    }
}

fn project_response_format(value: &JsonValue) -> ResponseFormat {
    match value.get("type").and_then(JsonValue::as_str) {
        Some("text") => ResponseFormat::Text,
        Some("json_object") => ResponseFormat::JsonObject,
        Some("json_schema") => {
            let schema_object = value.get("json_schema").unwrap_or(value);
            ResponseFormat::JsonSchema {
                name: schema_object
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .map(ToString::to_string),
                schema: schema_object
                    .get("schema")
                    .cloned()
                    .unwrap_or_else(|| schema_object.clone()),
                strict: schema_object.get("strict").and_then(JsonValue::as_bool),
            }
        }
        _ => ResponseFormat::Raw(value.clone()),
    }
}

fn output_items_json(message_id: &str, output: &[OutputItem]) -> AdaptorResult<Vec<JsonValue>> {
    let mut text = String::new();
    let mut items = Vec::new();
    for item in output {
        match item {
            OutputItem::Text {
                text: part,
                channel: TextChannel::Output,
            } => text.push_str(part),
            OutputItem::Text {
                text: part,
                channel: TextChannel::Reasoning,
            } => items.push(json!({
                "id": format!("{message_id}_reasoning"),
                "type": "reasoning",
                "summary": [],
                "content": [{"type": "reasoning_text", "text": part}],
            })),
            OutputItem::ToolCall {
                id,
                name,
                arguments,
            } => items.push(json!({
                "id": id,
                "type": "function_call",
                "call_id": id,
                "name": name,
                "arguments": json_to_output_string(arguments),
                "status": "completed",
            })),
            OutputItem::StructuredJson(value) => text.push_str(&json_to_output_string(value)),
            OutputItem::Raw(value) => items.push(value.clone()),
        }
    }
    if !text.is_empty() || items.is_empty() {
        items.insert(
            0,
            message_item_json(message_id, "completed", vec![output_text_json(&text)]),
        );
    }
    Ok(items)
}

fn render_tool_call_delta(
    state: &mut ResponsesStreamState,
    delta: ToolCallDelta,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    Ok(vec![response_event(
        "response.function_call_arguments.delta",
        json!({
            "type": "response.function_call_arguments.delta",
            "sequence_number": next_sequence(state),
            "item_id": delta.id,
            "output_index": delta.index,
            "delta": delta.arguments_delta.unwrap_or_default(),
        }),
    )])
}

fn render_structured_delta(
    state: &mut ResponsesStreamState,
    delta: StructuredDelta,
) -> AdaptorResult<Vec<WireStreamEvent>> {
    let rendered = match delta {
        StructuredDelta::Text(text) => text,
        StructuredDelta::Json(value) => json_to_output_string(&value),
    };
    state.text.push_str(&rendered);
    Ok(vec![response_event(
        "response.output_text.delta",
        json!({
            "type": "response.output_text.delta",
            "sequence_number": next_sequence(state),
            "item_id": state.message_id,
            "output_index": 0,
            "content_index": 0,
            "delta": rendered,
        }),
    )])
}

fn response_status_event(
    state: &mut ResponsesStreamState,
    request: &ParsedResponseRequest,
    event_type: &str,
    status: &str,
    output: Vec<JsonValue>,
    usage: Option<Usage>,
) -> JsonValue {
    json!({
        "type": event_type,
        "sequence_number": next_sequence(state),
        "response": response_json(
            &state.response_id,
            state.created_at,
            &request.model,
            status,
            output,
            usage,
            state.provenance.as_ref(),
        ),
    })
}

fn response_json(
    response_id: &str,
    created_at: i64,
    model: &str,
    status: &str,
    output: Vec<JsonValue>,
    usage: Option<Usage>,
    provenance: Option<&crate::Provenance>,
) -> JsonValue {
    let mut object = json!({
        "id": response_id,
        "object": "response",
        "created_at": created_at,
        "status": status,
        "model": model,
        "output": output,
    });
    if let Some(usage) = usage {
        object["usage"] = usage_json(usage);
    }
    if let Some(provenance) = provenance.and_then(provenance_json) {
        object["hellas"] = provenance;
    }
    object
}

fn message_item_json(message_id: &str, status: &str, content: Vec<JsonValue>) -> JsonValue {
    json!({
        "id": message_id,
        "type": "message",
        "status": status,
        "role": "assistant",
        "content": content,
        "annotations": [],
    })
}

fn output_text_json(text: &str) -> JsonValue {
    json!({
        "type": "output_text",
        "text": text,
        "annotations": [],
    })
}

fn usage_json(usage: Usage) -> JsonValue {
    json!({
        "input_tokens": usage.input_tokens.unwrap_or(0),
        "output_tokens": usage.output_tokens.unwrap_or(0),
        "total_tokens": usage.total_tokens.unwrap_or_else(|| {
            usage.input_tokens.unwrap_or(0).saturating_add(usage.output_tokens.unwrap_or(0))
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
    if let Some(receipt) = &provenance.receipt_commitment {
        object.insert("receipt".to_string(), JsonValue::String(receipt.clone()));
    }
    (!object.is_empty()).then_some(JsonValue::Object(object))
}

fn response_event(name: &str, data: JsonValue) -> WireStreamEvent {
    WireStreamEvent::json(Some(name.to_string()), data)
}

fn next_sequence(state: &mut ResponsesStreamState) -> u64 {
    let current = state.sequence_number;
    state.sequence_number = state.sequence_number.saturating_add(1);
    current
}

fn json_to_output_string(value: &JsonValue) -> String {
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

fn optional_string(
    object: &JsonMap<String, JsonValue>,
    key: &str,
) -> AdaptorResult<Option<String>> {
    match object.get(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(ToString::to_string)
            .map(Some)
            .ok_or_else(|| AdaptorError::invalid_request(format!("`{key}` must be a string"))),
    }
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

fn optional_f32(object: &JsonMap<String, JsonValue>, key: &str) -> AdaptorResult<Option<f32>> {
    match object.get(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(value) => value
            .as_f64()
            .map(|value| value as f32)
            .map(Some)
            .ok_or_else(|| AdaptorError::invalid_request(format!("`{key}` must be a number"))),
    }
}

fn optional_array(
    object: &JsonMap<String, JsonValue>,
    key: &str,
) -> AdaptorResult<Option<Vec<JsonValue>>> {
    match object.get(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Array(values)) => Ok(Some(values.clone())),
        Some(_) => Err(AdaptorError::invalid_request(format!(
            "`{key}` must be an array"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Provenance, StopReason, WireEventData};

    fn adaptor() -> OpenAiResponsesAdaptor {
        OpenAiResponsesAdaptor
    }

    fn raw(value: JsonValue) -> RawRequest {
        RawRequest::from_value(value).unwrap()
    }

    fn sample_request() -> ParsedResponseRequest {
        adaptor()
            .parse(raw(json!({
                "model": "gpt-4.1-mini",
                "input": [
                    {
                        "type": "message",
                        "role": "user",
                        "content": [
                            {"type": "input_text", "text": "Describe this"},
                            {"type": "input_image", "image_url": {"url": "https://example.com/a.png"}}
                        ]
                    }
                ],
                "instructions": "Be brief.",
                "tools": [
                    {
                        "type": "function",
                        "name": "lookup",
                        "description": "Look up a value",
                        "parameters": {"type": "object"}
                    }
                ],
                "tool_choice": {"type": "function", "name": "lookup"},
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "answer",
                        "schema": {"type": "object"},
                        "strict": true
                    }
                },
                "reasoning": {"effort": "low"},
                "max_output_tokens": 64,
                "temperature": 0.2,
                "top_p": 0.9,
                "stream": true,
                "metadata": {"request_id": "r1"},
                "seed": 42
            })))
            .unwrap()
    }

    #[test]
    fn parse_preserves_raw_and_passthrough() {
        let parsed = sample_request();
        assert_eq!(parsed.model, "gpt-4.1-mini");
        assert_eq!(parsed.max_output_tokens, Some(64));
        assert_eq!(parsed.stream, Some(true));
        assert_eq!(parsed.passthrough.fields().len(), 3);
        assert!(
            parsed
                .passthrough
                .fields()
                .iter()
                .any(|field| field.path == FieldPath::from("metadata"))
        );
        assert!(
            parsed
                .passthrough
                .fields()
                .iter()
                .any(|field| field.path == FieldPath::from("stream"))
        );
        assert!(
            parsed
                .passthrough
                .fields()
                .iter()
                .any(|field| field.path == FieldPath::from("seed"))
        );
        assert!(parsed.raw.bytes().starts_with(b"{"));
    }

    #[test]
    fn projection_separates_committed_fields_from_passthrough() {
        let parsed = sample_request();
        let execution = adaptor().to_execution_request(&parsed).unwrap();
        assert_eq!(execution.canonical.model.name, "gpt-4.1-mini");
        assert!(
            execution
                .canonical
                .committed_fields
                .contains(&FieldPath::from("model"))
        );
        assert!(
            execution
                .canonical
                .committed_fields
                .contains(&FieldPath::from("input"))
        );
        assert!(
            execution
                .canonical
                .committed_fields
                .contains(&FieldPath::from("tools"))
        );
        assert!(
            execution
                .canonical
                .committed_fields
                .contains(&FieldPath::from("text"))
        );
        assert!(
            !execution
                .canonical
                .committed_fields
                .contains(&FieldPath::from("metadata"))
        );
        assert_eq!(execution.passthrough.fields().len(), 3);
    }

    #[test]
    fn projection_handles_string_input() {
        let parsed = adaptor()
            .parse(raw(json!({"model": "m", "input": "hello"})))
            .unwrap();
        let execution = adaptor().to_execution_request(&parsed).unwrap();
        assert_eq!(execution.canonical.input, Input::Text("hello".to_string()));
    }

    #[test]
    fn render_non_streaming_text_response() {
        let parsed = sample_request();
        let response = adaptor()
            .render_response(
                &parsed,
                ExecutionResult {
                    output: vec![OutputItem::Text {
                        text: "hello".to_string(),
                        channel: TextChannel::Output,
                    }],
                    usage: Some(Usage {
                        input_tokens: Some(5),
                        output_tokens: Some(1),
                        total_tokens: Some(6),
                    }),
                    stop_reason: StopReason::EndOfText,
                    provenance: Some(Provenance {
                        call_commitment: Some("aa".repeat(32)),
                        receipt_commitment: Some("bb".repeat(32)),
                    }),
                },
                RenderContext::new("resp_1", "msg_1", 123),
            )
            .unwrap();

        assert_eq!(response.status, 200);
        let body = match response.body {
            crate::WireBody::Json(body) => body,
            crate::WireBody::Bytes(_) => panic!("expected JSON response"),
        };
        assert_eq!(body["id"], "resp_1");
        assert_eq!(body["output"][0]["content"][0]["text"], "hello");
        assert_eq!(body["hellas"]["commitment"], "aa".repeat(32));
        assert_eq!(body["hellas"]["receipt"], "bb".repeat(32));
    }

    #[test]
    fn render_stream_text_sequence() {
        let parsed = sample_request();
        let mut state =
            adaptor().initial_state(&parsed, RenderContext::new("resp_1", "msg_1", 123));
        let mut events = adaptor().render_stream_start(&parsed, &mut state).unwrap();
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::TextDelta {
                        index: 0,
                        delta: "hel".to_string(),
                        channel: TextChannel::Output,
                    },
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::TextDelta {
                        index: 0,
                        delta: "lo".to_string(),
                        channel: TextChannel::Output,
                    },
                )
                .unwrap(),
        );
        events.extend(
            adaptor()
                .render_stream_event(
                    &parsed,
                    &mut state,
                    OutputEvent::Finished {
                        stop_reason: StopReason::EndOfText,
                        usage: Some(Usage {
                            input_tokens: Some(5),
                            output_tokens: Some(1),
                            total_tokens: Some(6),
                        }),
                    },
                )
                .unwrap(),
        );

        let names = events
            .iter()
            .map(|event| event.name.as_deref().unwrap_or(""))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "response.created",
                "response.in_progress",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );
        let completed = match &events.last().unwrap().data {
            WireEventData::Json(value) => value,
            _ => panic!("expected JSON event"),
        };
        assert_eq!(
            completed["response"]["output"][0]["content"][0]["text"],
            "hello"
        );
        assert_eq!(completed["response"]["usage"]["total_tokens"], 6);
    }
}
