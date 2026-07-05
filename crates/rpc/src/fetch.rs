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
