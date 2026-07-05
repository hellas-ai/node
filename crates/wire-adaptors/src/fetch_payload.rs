use std::convert::Infallible;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error;

use crate::{
    OutputEvent, Provenance, StopReason, StructuredDelta, TextChannel, ToolCallArgumentsDelta,
    ToolCallEnd, ToolCallStart, Usage,
};

const EVENT_CODEC: &str = "hellas.fetch.output.event.v1";
const TERMINAL_CODEC: &str = "hellas.fetch.output.terminal.v1";

type EncodeError = serde_ipld_dagcbor::EncodeError<std::collections::TryReserveError>;
type DecodeError = serde_ipld_dagcbor::DecodeError<Infallible>;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FetchEventPayload {
    TextDelta {
        index: u64,
        delta: String,
        channel: TextChannel,
    },
    ToolCallStart {
        index: u64,
        id: Option<String>,
        name: String,
    },
    ToolCallArgumentsDelta {
        index: u64,
        delta: String,
    },
    ToolCallEnd {
        index: u64,
        arguments: JsonValue,
    },
    StructuredOutputDelta(StructuredDelta),
    Usage(Usage),
    Provenance(Provenance),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FetchTerminalPayload {
    Finished {
        stop_reason: StopReason,
        usage: Option<Usage>,
    },
    Failed {
        message: String,
        code: Option<String>,
    },
}

pub fn encode_fetch_event_payload(event: &OutputEvent) -> Result<Vec<u8>, FetchPayloadError> {
    let payload = FetchEventPayload::try_from(event)?;
    serde_ipld_dagcbor::to_vec(&(EVENT_CODEC, payload)).map_err(FetchPayloadError::Encode)
}

pub fn decode_fetch_event_payload(bytes: &[u8]) -> Result<OutputEvent, FetchPayloadError> {
    let (codec, payload): (String, FetchEventPayload) =
        serde_ipld_dagcbor::from_slice(bytes).map_err(FetchPayloadError::Decode)?;
    if codec != EVENT_CODEC {
        return Err(FetchPayloadError::CodecMismatch {
            expected: EVENT_CODEC,
            actual: codec,
        });
    }
    payload.try_into()
}

pub fn encode_fetch_terminal_payload(event: &OutputEvent) -> Result<Vec<u8>, FetchPayloadError> {
    let payload = FetchTerminalPayload::try_from(event)?;
    serde_ipld_dagcbor::to_vec(&(TERMINAL_CODEC, payload)).map_err(FetchPayloadError::Encode)
}

pub fn decode_fetch_terminal_payload(
    bytes: &[u8],
) -> Result<FetchTerminalPayload, FetchPayloadError> {
    let (codec, payload): (String, FetchTerminalPayload) =
        serde_ipld_dagcbor::from_slice(bytes).map_err(FetchPayloadError::Decode)?;
    if codec != TERMINAL_CODEC {
        return Err(FetchPayloadError::CodecMismatch {
            expected: TERMINAL_CODEC,
            actual: codec,
        });
    }
    Ok(payload)
}

impl FetchTerminalPayload {
    pub fn to_output_event(&self) -> OutputEvent {
        match self {
            Self::Finished { stop_reason, usage } => OutputEvent::Finished {
                stop_reason: *stop_reason,
                usage: *usage,
            },
            Self::Failed { message, code } => OutputEvent::Error {
                message: message.clone(),
                code: code.clone(),
            },
        }
    }
}

impl TryFrom<&OutputEvent> for FetchEventPayload {
    type Error = FetchPayloadError;

    fn try_from(event: &OutputEvent) -> Result<Self, Self::Error> {
        match event {
            OutputEvent::TextDelta {
                index,
                delta,
                channel,
            } => Ok(Self::TextDelta {
                index: (*index)
                    .try_into()
                    .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                delta: delta.clone(),
                channel: channel.clone(),
            }),
            OutputEvent::ToolCallStart(ToolCallStart { index, id, name }) => {
                Ok(Self::ToolCallStart {
                    index: (*index)
                        .try_into()
                        .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                    id: id.clone(),
                    name: name.clone(),
                })
            }
            OutputEvent::ToolCallArgumentsDelta(ToolCallArgumentsDelta { index, delta }) => {
                Ok(Self::ToolCallArgumentsDelta {
                    index: (*index)
                        .try_into()
                        .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                    delta: delta.clone(),
                })
            }
            OutputEvent::ToolCallEnd(ToolCallEnd { index, arguments }) => Ok(Self::ToolCallEnd {
                index: (*index)
                    .try_into()
                    .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                arguments: arguments.clone(),
            }),
            OutputEvent::StructuredOutputDelta(delta) => {
                Ok(Self::StructuredOutputDelta(delta.clone()))
            }
            OutputEvent::Usage(usage) => Ok(Self::Usage(*usage)),
            OutputEvent::Provenance(provenance) => Ok(Self::Provenance(provenance.clone())),
            OutputEvent::Finished { .. } | OutputEvent::Error { .. } => {
                Err(FetchPayloadError::TerminalAsEvent)
            }
        }
    }
}

impl TryFrom<FetchEventPayload> for OutputEvent {
    type Error = FetchPayloadError;

    fn try_from(payload: FetchEventPayload) -> Result<Self, FetchPayloadError> {
        match payload {
            FetchEventPayload::TextDelta {
                index,
                delta,
                channel,
            } => Ok(Self::TextDelta {
                index: usize::try_from(index).map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                delta,
                channel,
            }),
            FetchEventPayload::ToolCallStart { index, id, name } => {
                Ok(Self::ToolCallStart(ToolCallStart {
                    index: usize::try_from(index)
                        .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                    id,
                    name,
                }))
            }
            FetchEventPayload::ToolCallArgumentsDelta { index, delta } => {
                Ok(Self::ToolCallArgumentsDelta(ToolCallArgumentsDelta {
                    index: usize::try_from(index)
                        .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                    delta,
                }))
            }
            FetchEventPayload::ToolCallEnd { index, arguments } => {
                Ok(Self::ToolCallEnd(ToolCallEnd {
                    index: usize::try_from(index)
                        .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                    arguments,
                }))
            }
            FetchEventPayload::StructuredOutputDelta(delta) => {
                Ok(Self::StructuredOutputDelta(delta))
            }
            FetchEventPayload::Usage(usage) => Ok(Self::Usage(usage)),
            FetchEventPayload::Provenance(provenance) => Ok(Self::Provenance(provenance)),
        }
    }
}

impl TryFrom<&OutputEvent> for FetchTerminalPayload {
    type Error = FetchPayloadError;

    fn try_from(event: &OutputEvent) -> Result<Self, Self::Error> {
        match event {
            OutputEvent::Finished { stop_reason, usage } => Ok(Self::Finished {
                stop_reason: *stop_reason,
                usage: *usage,
            }),
            OutputEvent::Error { message, code } => Ok(Self::Failed {
                message: message.clone(),
                code: code.clone(),
            }),
            _ => Err(FetchPayloadError::NonTerminalAsTerminal),
        }
    }
}

#[derive(Debug, Error)]
pub enum FetchPayloadError {
    #[error("fetch payload encode failed: {0}")]
    Encode(#[from] EncodeError),
    #[error("fetch payload decode failed: {0}")]
    Decode(#[from] DecodeError),
    #[error("fetch payload codec mismatch: expected {expected}, got {actual}")]
    CodecMismatch {
        expected: &'static str,
        actual: String,
    },
    #[error("terminal fetch payload cannot be encoded as a stream event")]
    TerminalAsEvent,
    #[error("non-terminal fetch payload cannot be encoded as a terminal event")]
    NonTerminalAsTerminal,
    #[error("fetch payload index does not fit this platform")]
    IndexOutOfRange,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn event_payload_round_trip() {
        let event = OutputEvent::TextDelta {
            index: 2,
            delta: "hello".to_string(),
            channel: TextChannel::Reasoning,
        };

        let encoded = encode_fetch_event_payload(&event).unwrap();
        let decoded = decode_fetch_event_payload(&encoded).unwrap();

        assert_eq!(decoded, event);
    }

    #[test]
    fn terminal_payload_round_trip() {
        let event = OutputEvent::Finished {
            stop_reason: StopReason::MaxOutputTokens,
            usage: Some(Usage {
                input_tokens: Some(3),
                output_tokens: Some(4),
                total_tokens: Some(7),
            }),
        };

        let encoded = encode_fetch_terminal_payload(&event).unwrap();
        let decoded = decode_fetch_terminal_payload(&encoded).unwrap();

        assert_eq!(decoded.to_output_event(), event);
    }

    #[test]
    fn terminal_payload_is_not_event_payload() {
        let event = OutputEvent::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
        };

        assert!(matches!(
            encode_fetch_event_payload(&event).unwrap_err(),
            FetchPayloadError::TerminalAsEvent
        ));
    }

    #[test]
    fn event_payload_vector_is_pinned() {
        let event = OutputEvent::TextDelta {
            index: 0,
            delta: "hi".to_string(),
            channel: TextChannel::Output,
        };
        let actual = hex(&encode_fetch_event_payload(&event).unwrap());
        let expected = "82781c68656c6c61732e66657463682e6f75747075742e6576656e742e7631a1695465787444656c7461a36564656c746162686965696e64657800676368616e6e656c664f7574707574";
        assert_eq!(actual, expected);
    }
}
