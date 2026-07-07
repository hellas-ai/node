//! Canonical streaming output vocabulary.
//!
//! These are the semantic events a producer commits to inside signed
//! output transcripts: [`crate::fetch`] encodes them as dag-cbor payloads
//! of [`crate::OutputEventEnvelope`]s, and the gateway renders provider
//! streams into and out of them. Because the encoded bytes are signed,
//! every field here is protocol surface; changing any shape is a payload
//! codec version change (see the codec strings in [`crate::fetch`]).

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

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
}
