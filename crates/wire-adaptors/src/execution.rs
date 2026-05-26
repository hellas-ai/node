use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{FieldPath, PassthroughBag};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRef {
    pub name: String,
    pub provider: Option<String>,
    pub revision: Option<String>,
}

impl ModelRef {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            provider: None,
            revision: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub canonical: CanonicalExecution,
    pub passthrough: PassthroughBag,
}

impl ExecutionRequest {
    pub fn new(canonical: CanonicalExecution, passthrough: PassthroughBag) -> Self {
        Self {
            canonical,
            passthrough,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalExecution {
    pub model: ModelRef,
    pub input: Input,
    pub instructions: Option<String>,
    pub sampling: SamplingOptions,
    pub tools: Vec<ToolSpec>,
    pub tool_choice: ToolChoice,
    pub response_format: Option<ResponseFormat>,
    pub reasoning: Option<ReasoningOptions>,
    pub previous_response_id: Option<String>,
    pub committed_fields: BTreeSet<FieldPath>,
}

impl CanonicalExecution {
    pub fn new(model: ModelRef, input: Input) -> Self {
        Self {
            model,
            input,
            instructions: None,
            sampling: SamplingOptions::default(),
            tools: Vec::new(),
            tool_choice: ToolChoice::Auto,
            response_format: None,
            reasoning: None,
            previous_response_id: None,
            committed_fields: BTreeSet::new(),
        }
    }

    pub fn commit_field(&mut self, path: impl Into<FieldPath>) {
        self.committed_fields.insert(path.into());
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Input {
    Text(String),
    Messages(Vec<Message>),
    Items(Vec<InputItem>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: Vec<ContentPart>,
    pub name: Option<String>,
}

impl Message {
    pub fn text(role: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: vec![ContentPart::Text { text: text.into() }],
            name: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum InputItem {
    Message(Message),
    ToolCall {
        id: String,
        name: String,
        arguments: JsonValue,
    },
    ToolResult {
        call_id: String,
        output: Vec<ContentPart>,
    },
    Raw(JsonValue),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ContentPart {
    Text {
        text: String,
    },
    Image {
        uri: Option<String>,
        media_type: Option<String>,
        data: Option<String>,
    },
    File {
        file_id: Option<String>,
        filename: Option<String>,
        data: Option<String>,
    },
    Json(JsonValue),
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SamplingOptions {
    pub max_output_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_logprobs: Option<u32>,
    pub parallel_tool_calls: Option<bool>,
    pub truncation: Option<String>,
    pub stop: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: Option<String>,
    pub parameters: JsonValue,
    pub kind: ToolKind,
    pub raw: JsonValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolKind {
    Function,
    BuiltIn(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ToolChoice {
    Auto,
    None,
    Required,
    Tool { name: String },
    Raw(JsonValue),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ResponseFormat {
    Text,
    JsonObject,
    JsonSchema {
        name: Option<String>,
        schema: JsonValue,
        strict: Option<bool>,
    },
    Raw(JsonValue),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReasoningOptions {
    pub value: JsonValue,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub output: Vec<OutputItem>,
    pub usage: Option<Usage>,
    pub stop_reason: StopReason,
    pub provenance: Option<Provenance>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum OutputItem {
    Text {
        text: String,
        channel: TextChannel,
    },
    ToolCall {
        id: String,
        name: String,
        arguments: JsonValue,
    },
    StructuredJson(JsonValue),
    Raw(JsonValue),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum OutputEvent {
    TextDelta {
        index: usize,
        delta: String,
        channel: TextChannel,
    },
    ToolCallStart(ToolCallStart),
    ToolCallArgumentsDelta(ToolCallArgumentsDelta),
    ToolCallEnd(ToolCallEnd),
    StructuredOutputDelta(StructuredDelta),
    Usage(Usage),
    Finished {
        stop_reason: StopReason,
        usage: Option<Usage>,
    },
    Error {
        message: String,
        code: Option<String>,
    },
    Provenance(Provenance),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextChannel {
    Output,
    Reasoning,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCallStart {
    pub index: usize,
    pub id: Option<String>,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCallArgumentsDelta {
    pub index: usize,
    pub delta: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCallEnd {
    pub index: usize,
    pub arguments: JsonValue,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum StructuredDelta {
    Text(String),
    Json(JsonValue),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopReason {
    EndOfText,
    MaxOutputTokens,
    StopSequence,
    ToolCall,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Lowercase hex commitment string ready for provider wire JSON.
    pub call_commitment: Option<String>,
    /// Lowercase hex receipt commitment string ready for provider wire JSON.
    pub receipt_commitment: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn execution_request_keeps_canonical_and_passthrough_separate() {
        let mut canonical =
            CanonicalExecution::new(ModelRef::new("model-a"), Input::Text("hello".to_string()));
        canonical.commit_field("model");
        canonical.commit_field("input");

        let mut passthrough = PassthroughBag::new();
        passthrough.push("metadata", json!({"trace_id": "abc"}));

        let request = ExecutionRequest::new(canonical, passthrough);

        assert!(
            request
                .canonical
                .committed_fields
                .contains(&FieldPath::from("model"))
        );
        assert_eq!(request.passthrough.fields().len(), 1);
        assert_eq!(
            request.passthrough.fields()[0].path,
            FieldPath::from("metadata")
        );
    }

    #[test]
    fn message_text_constructor_uses_content_parts() {
        let message = Message::text("user", "hi");
        assert_eq!(message.role, "user");
        assert_eq!(
            message.content,
            vec![ContentPart::Text {
                text: "hi".to_string()
            }]
        );
    }
}
