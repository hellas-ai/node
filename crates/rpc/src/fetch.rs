use std::str;

use crate::{
    CanonicalizationId, InputCommitment, InputEventEnvelope, InputTranscriptBuilder, JsonBytes,
    OutputEventEnvelope, OutputTranscriptBuilder, ProducerSigningKey, PublicKey, SchemeId,
    StreamVerifyError, verify_input_event_envelopes, verify_output_event_envelopes,
};

const INPUT_CANONICALIZATION: &[u8] = b"hellas.fetch.input.v1";
const OUTPUT_CANONICALIZATION: &[u8] = b"hellas.fetch.output.v2";
const OUTPUT_EVENT_KIND: &str = "response.event";
const OUTPUT_TERMINAL_KIND: &str = "response.terminal";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchInput {
    pub input_commitment: InputCommitment,
    pub caller_key: PublicKey,
    pub service: String,
    pub method: String,
    pub body: JsonBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchOutput {
    pub producer_key: PublicKey,
    event_payloads: Vec<Vec<u8>>,
    terminal_payload: Vec<u8>,
}

impl FetchOutput {
    pub fn output_event_payloads(&self) -> (&[Vec<u8>], &[u8]) {
        (&self.event_payloads, &self.terminal_payload)
    }
}

pub fn input_canonicalization() -> CanonicalizationId {
    CanonicalizationId::from_bytes(INPUT_CANONICALIZATION)
}

pub fn output_canonicalization() -> CanonicalizationId {
    CanonicalizationId::from_bytes(OUTPUT_CANONICALIZATION)
}

pub fn build_input_events(
    service: &str,
    method: &str,
    payload: &[u8],
    key: &ProducerSigningKey,
) -> Result<Vec<InputEventEnvelope>, FetchProtocolError> {
    validate_non_empty_service_method(service, method)?;
    validate_json("request.body", payload)?;
    let mut builder = InputTranscriptBuilder::new(SchemeId::Fetch, key, input_canonicalization());
    builder.push("service", service.as_bytes().to_vec())?;
    builder.push("method", method.as_bytes().to_vec())?;
    builder.push("request.body", payload.to_vec())?;
    builder.push("input.end", Vec::new())?;
    let (events, _) = builder.finish()?;
    Ok(events)
}

pub fn build_output_events(
    input: InputCommitment,
    payload: &[u8],
    key: &ProducerSigningKey,
) -> Result<Vec<OutputEventEnvelope>, FetchProtocolError> {
    let mut builder =
        OutputTranscriptBuilder::new(SchemeId::Fetch, input, key, output_canonicalization());
    builder.push(OUTPUT_TERMINAL_KIND, payload.to_vec())?;
    let (events, _) = builder.finish()?;
    Ok(events)
}

pub struct FetchOutputTranscriptBuilder<'a> {
    inner: OutputTranscriptBuilder<'a>,
}

impl<'a> FetchOutputTranscriptBuilder<'a> {
    pub fn new(input: InputCommitment, key: &'a ProducerSigningKey) -> Self {
        Self {
            inner: OutputTranscriptBuilder::new(
                SchemeId::Fetch,
                input,
                key,
                output_canonicalization(),
            ),
        }
    }

    pub fn push_event(
        &mut self,
        payload: impl Into<Vec<u8>>,
    ) -> Result<OutputEventEnvelope, FetchProtocolError> {
        Ok(self.inner.push_envelope(OUTPUT_EVENT_KIND, payload)?)
    }

    pub fn finish(
        mut self,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Vec<OutputEventEnvelope>, FetchProtocolError> {
        self.inner.push(OUTPUT_TERMINAL_KIND, payload)?;
        let (events, _) = self.inner.finish()?;
        Ok(events)
    }
}

pub fn verify_input_events(
    events: &[InputEventEnvelope],
) -> Result<FetchInput, FetchProtocolError> {
    let caller_key = *events
        .first()
        .ok_or(FetchProtocolError::EmptyInputTranscript)?
        .event()
        .public_key();
    let input_commitment = verify_input_event_envelopes(SchemeId::Fetch, &caller_key, events)?;
    let (service, method, body) = input_parts(events)?;
    validate_non_empty_service_method(&service, &method)?;
    validate_json("request.body", body.as_bytes())?;
    Ok(FetchInput {
        input_commitment,
        caller_key,
        service,
        method,
        body,
    })
}

pub fn verify_output_events(
    input: InputCommitment,
    events: &[OutputEventEnvelope],
) -> Result<FetchOutput, FetchProtocolError> {
    let producer_key = *events
        .first()
        .ok_or(FetchProtocolError::EmptyOutputTranscript)?
        .event()
        .public_key();
    verify_output_event_envelopes(SchemeId::Fetch, input, &producer_key, events)?;
    let (event_payloads, terminal_payload) = output_payloads(events)?;
    Ok(FetchOutput {
        producer_key,
        event_payloads,
        terminal_payload,
    })
}

pub fn verify_terminal_continuation(
    streamed_prefix: &[OutputEventEnvelope],
    finished: &[OutputEventEnvelope],
) -> Result<(), FetchProtocolError> {
    if finished.is_empty() {
        return Err(FetchProtocolError::EmptyOutputTranscript);
    }
    if finished.len() < streamed_prefix.len() {
        return Err(FetchProtocolError::WrongOutputEventCount {
            actual: finished.len(),
        });
    }
    let first = finished
        .first()
        .ok_or(FetchProtocolError::EmptyOutputTranscript)?;
    let input = first.event().body().input();
    let producer_key = *first.event().public_key();
    verify_output_event_envelopes(SchemeId::Fetch, input, &producer_key, finished)?;
    output_payloads(finished)?;
    for (index, streamed) in streamed_prefix.iter().enumerate() {
        expect_output_event(streamed, index, OUTPUT_EVENT_KIND)?;
        let Some(finished_event) = finished.get(index) else {
            return Err(FetchProtocolError::WrongOutputEventCount {
                actual: finished.len(),
            });
        };
        if finished_event != streamed {
            return Err(FetchProtocolError::OutputPrefixMismatch { index });
        }
    }
    Ok(())
}

fn output_payloads(
    events: &[OutputEventEnvelope],
) -> Result<(Vec<Vec<u8>>, Vec<u8>), FetchProtocolError> {
    if events.is_empty() {
        return Err(FetchProtocolError::EmptyOutputTranscript);
    }
    let terminal_index = events.len() - 1;
    let mut payloads = Vec::with_capacity(terminal_index);
    for (index, event) in events[..terminal_index].iter().enumerate() {
        expect_output_event(event, index, OUTPUT_EVENT_KIND)?;
        payloads.push(event.payload().to_vec());
    }
    expect_output_event(
        &events[terminal_index],
        terminal_index,
        OUTPUT_TERMINAL_KIND,
    )?;
    Ok((payloads, events[terminal_index].payload().to_vec()))
}

fn input_parts(
    events: &[InputEventEnvelope],
) -> Result<(String, String, JsonBytes), FetchProtocolError> {
    if events.len() != 4 {
        return Err(FetchProtocolError::WrongInputEventCount {
            actual: events.len(),
        });
    }
    expect_input_event(&events[0], 0, "service")?;
    expect_input_event(&events[1], 1, "method")?;
    expect_input_event(&events[2], 2, "request.body")?;
    expect_input_event(&events[3], 3, "input.end")?;
    if !events[3].payload().is_empty() {
        return Err(FetchProtocolError::NonEmptyInputEnd);
    }
    let service =
        str::from_utf8(events[0].payload()).map_err(|source| FetchProtocolError::Utf8 {
            field: "service",
            source,
        })?;
    let method =
        str::from_utf8(events[1].payload()).map_err(|source| FetchProtocolError::Utf8 {
            field: "method",
            source,
        })?;
    Ok((
        service.to_string(),
        method.to_string(),
        JsonBytes::new(events[2].payload().to_vec()),
    ))
}

fn validate_non_empty_service_method(
    service: &str,
    method: &str,
) -> Result<(), FetchProtocolError> {
    if service.is_empty() {
        return Err(FetchProtocolError::EmptyService);
    }
    if method.is_empty() {
        return Err(FetchProtocolError::EmptyMethod);
    }
    Ok(())
}

fn validate_json(field: &'static str, bytes: &[u8]) -> Result<(), FetchProtocolError> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .map(|_| ())
        .map_err(|source| FetchProtocolError::Json { field, source })
}

fn expect_input_event(
    event: &InputEventEnvelope,
    index: usize,
    expected: &'static str,
) -> Result<(), FetchProtocolError> {
    if event.event().body().kind() == expected {
        if event.event().body().canonicalization() == input_canonicalization() {
            Ok(())
        } else {
            Err(FetchProtocolError::InputCanonicalizationMismatch { index })
        }
    } else {
        Err(FetchProtocolError::UnexpectedInputEvent {
            index,
            expected,
            actual: event.event().body().kind().to_string(),
        })
    }
}

fn expect_output_event(
    event: &OutputEventEnvelope,
    index: usize,
    expected: &'static str,
) -> Result<(), FetchProtocolError> {
    if event.event().body().kind() == expected {
        if event.event().body().canonicalization() == output_canonicalization() {
            Ok(())
        } else {
            Err(FetchProtocolError::OutputCanonicalizationMismatch { index })
        }
    } else {
        Err(FetchProtocolError::UnexpectedOutputEvent {
            index,
            expected,
            actual: event.event().body().kind().to_string(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchProtocolError {
    #[error("fetch service must not be empty")]
    EmptyService,
    #[error("fetch method must not be empty")]
    EmptyMethod,
    #[error("fetch input transcript is empty")]
    EmptyInputTranscript,
    #[error("fetch output transcript is empty")]
    EmptyOutputTranscript,
    #[error("fetch input transcript must contain exactly 4 events, got {actual}")]
    WrongInputEventCount { actual: usize },
    #[error("fetch output transcript must contain exactly one terminal event, got {actual} events")]
    WrongOutputEventCount { actual: usize },
    #[error("fetch input event {index} must be {expected}, got {actual}")]
    UnexpectedInputEvent {
        index: usize,
        expected: &'static str,
        actual: String,
    },
    #[error("fetch output event {index} must be {expected}, got {actual}")]
    UnexpectedOutputEvent {
        index: usize,
        expected: &'static str,
        actual: String,
    },
    #[error("fetch input event {index} must use the fetch input canonicalization")]
    InputCanonicalizationMismatch { index: usize },
    #[error("fetch output event {index} must use the fetch output canonicalization")]
    OutputCanonicalizationMismatch { index: usize },
    #[error("fetch input.end payload must be empty")]
    NonEmptyInputEnd,
    #[error("fetch streamed output event {index} does not match finished transcript")]
    OutputPrefixMismatch { index: usize },
    #[error("fetch {field} event is not UTF-8: {source}")]
    Utf8 {
        field: &'static str,
        #[source]
        source: str::Utf8Error,
    },
    #[error("fetch {field} must be UTF-8 JSON: {source}")]
    Json {
        field: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("fetch stream verification failed: {0}")]
    Stream(#[from] StreamVerifyError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
    }

    #[test]
    fn input_events_round_trip_through_shape_verifier() {
        let caller = key(1);
        let events =
            build_input_events("openai", "responses", br#"{"model":"gpt"}"#, &caller).unwrap();

        let input = verify_input_events(&events).unwrap();

        assert_eq!(input.caller_key, caller.public_key());
        assert_eq!(input.service, "openai");
        assert_eq!(input.method, "responses");
        assert_eq!(input.body.as_bytes(), br#"{"model":"gpt"}"#);
    }

    #[test]
    fn output_events_round_trip_through_shape_verifier() {
        let caller = key(1);
        let producer = key(2);
        let input = verify_input_events(
            &build_input_events("openai", "responses", br#"{"model":"gpt"}"#, &caller).unwrap(),
        )
        .unwrap()
        .input_commitment;
        let events = build_output_events(input, br#"{"id":"resp"}"#, &producer).unwrap();

        let output = verify_output_events(input, &events).unwrap();
        let (payloads, terminal) = output.output_event_payloads();

        assert_eq!(output.producer_key, producer.public_key());
        assert!(payloads.is_empty());
        assert_eq!(terminal, br#"{"id":"resp"}"#);
    }

    #[test]
    fn streaming_output_events_round_trip_through_shape_verifier() {
        let caller = key(1);
        let producer = key(2);
        let input = verify_input_events(
            &build_input_events("openai", "responses", br#"{"model":"gpt"}"#, &caller).unwrap(),
        )
        .unwrap()
        .input_commitment;
        let mut builder = FetchOutputTranscriptBuilder::new(input, &producer);
        let first = builder
            .push_event(b"semantic-output-event-1".to_vec())
            .unwrap();
        let second = builder
            .push_event(b"semantic-output-event-2".to_vec())
            .unwrap();
        let events = builder.finish(b"semantic-terminal".to_vec()).unwrap();

        assert_eq!(events[0], first);
        assert_eq!(events[1], second);
        let output = verify_output_events(input, &events).unwrap();
        let (payloads, terminal) = output.output_event_payloads();

        assert_eq!(output.producer_key, producer.public_key());
        assert_eq!(
            payloads,
            &[
                b"semantic-output-event-1".to_vec(),
                b"semantic-output-event-2".to_vec()
            ]
        );
        assert_eq!(terminal, b"semantic-terminal");
        verify_terminal_continuation(&events[..2], &events).unwrap();
    }

    #[test]
    fn terminal_continuation_rejects_divergent_valid_chain() {
        let caller = key(1);
        let producer = key(2);
        let input = verify_input_events(
            &build_input_events("openai", "responses", br#"{"model":"gpt"}"#, &caller).unwrap(),
        )
        .unwrap()
        .input_commitment;

        let mut streamed = FetchOutputTranscriptBuilder::new(input, &producer);
        let first_streamed = streamed.push_event(b"live-event".to_vec()).unwrap();
        let _streamed_finished = streamed.finish(b"terminal".to_vec()).unwrap();

        let mut divergent = FetchOutputTranscriptBuilder::new(input, &producer);
        divergent
            .push_event(b"different-live-event".to_vec())
            .unwrap();
        let divergent_finished = divergent.finish(b"terminal".to_vec()).unwrap();

        assert!(matches!(
            verify_terminal_continuation(&[first_streamed], &divergent_finished).unwrap_err(),
            FetchProtocolError::OutputPrefixMismatch { index: 0 }
        ));
    }

    #[test]
    fn input_rejects_empty_service() {
        let caller = key(1);
        let mut builder =
            InputTranscriptBuilder::new(SchemeId::Fetch, &caller, input_canonicalization());
        builder.push("service", Vec::new()).unwrap();
        builder.push("method", b"responses".to_vec()).unwrap();
        builder.push("request.body", br#"{}"#.to_vec()).unwrap();
        builder.push("input.end", Vec::new()).unwrap();
        let (events, _) = builder.finish().unwrap();

        assert!(matches!(
            verify_input_events(&events).unwrap_err(),
            FetchProtocolError::EmptyService
        ));
    }

    #[test]
    fn input_rejects_wrong_canonicalization() {
        let caller = key(1);
        let mut builder = InputTranscriptBuilder::new(
            SchemeId::Fetch,
            &caller,
            CanonicalizationId::from_bytes(b"wrong.input.v1"),
        );
        builder.push("service", b"openai".to_vec()).unwrap();
        builder.push("method", b"responses".to_vec()).unwrap();
        builder.push("request.body", br#"{}"#.to_vec()).unwrap();
        builder.push("input.end", Vec::new()).unwrap();
        let (events, _) = builder.finish().unwrap();

        assert!(matches!(
            verify_input_events(&events).unwrap_err(),
            FetchProtocolError::InputCanonicalizationMismatch { index: 0 }
        ));
    }

    #[test]
    fn output_rejects_unsigned_terminal_payload_change() {
        let caller = key(1);
        let producer = key(2);
        let input = verify_input_events(
            &build_input_events("openai", "responses", br#"{}"#, &caller).unwrap(),
        )
        .unwrap()
        .input_commitment;
        let events = build_output_events(input, br#"{"ok":true}"#, &producer).unwrap();

        assert!(matches!(
            OutputEventEnvelope::new(events[0].event().clone(), br#"{"ok":false}"#.to_vec(),)
                .unwrap_err(),
            StreamVerifyError::PayloadMismatch
        ));
    }

    #[test]
    fn output_rejects_wrong_canonicalization() {
        let caller = key(1);
        let producer = key(2);
        let input = verify_input_events(
            &build_input_events("openai", "responses", br#"{}"#, &caller).unwrap(),
        )
        .unwrap()
        .input_commitment;
        let mut builder = OutputTranscriptBuilder::new(
            SchemeId::Fetch,
            input,
            &producer,
            CanonicalizationId::from_bytes(b"wrong.output.v1"),
        );
        builder
            .push("response.terminal", br#"{}"#.to_vec())
            .unwrap();
        let (events, _) = builder.finish().unwrap();

        assert!(matches!(
            verify_output_events(input, &events).unwrap_err(),
            FetchProtocolError::OutputCanonicalizationMismatch { index: 0 }
        ));
    }
}

// ---------------------------------------------------------------------
// Payload semantics: the dag-cbor event language inside signed fetch
// output transcripts. `FetchOutput` above verifies envelope signatures
// and hands out raw payload bytes; these codecs give those bytes their
// meaning. The codec strings version the payload shapes independently
// of the transcript canonicalization.
//
// Ownership boundary: these signed-payload codecs live here, not in
// hellas-adaptors. The reciprocal — converting to/from provider wire
// formats (OpenAI, Anthropic, SSE) — is adaptors' job and must never
// appear in this crate. rpc does not depend on adaptors; the vocabulary
// (crate::output) flows the other way. Rule of thumb: signed bytes → rpc,
// vendor-HTTP bytes → adaptors.
// ---------------------------------------------------------------------

use std::collections::TryReserveError;
use std::convert::Infallible;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error;

use crate::output::{
    OutputEvent, Provenance, StopReason, StructuredDelta, TextChannel, ToolCallArgumentsDelta,
    ToolCallEnd, ToolCallStart, Usage,
};

type PayloadEncodeError = serde_ipld_dagcbor::EncodeError<TryReserveError>;
type PayloadDecodeError = serde_ipld_dagcbor::DecodeError<Infallible>;

const EVENT_CODEC: &str = "hellas.fetch.output.event.v1";
const TERMINAL_CODEC: &str = "hellas.fetch.output.terminal.v1";

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
    Encode(#[from] PayloadEncodeError),
    #[error("fetch payload decode failed: {0}")]
    Decode(#[from] PayloadDecodeError),
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
mod payload_tests {
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
