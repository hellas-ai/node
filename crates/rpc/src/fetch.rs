use std::str;

use hellas_core::{
    CanonicalizationId, InputCommitment, InputEventEnvelope, InputTranscriptBuilder, JsonBytes,
    OutputEventEnvelope, OutputTranscriptBuilder, ProducerSigningKey, PublicKey, SchemeId,
    StreamVerifyError, verify_input_event_envelopes, verify_output_event_envelopes,
};

const INPUT_CANONICALIZATION: &[u8] = b"hellas.fetch.input.v1";
const OUTPUT_CANONICALIZATION: &[u8] = b"hellas.fetch.output.v1";

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
    pub body: JsonBytes,
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
    validate_json("response.body", payload)?;
    let mut builder =
        OutputTranscriptBuilder::new(SchemeId::Fetch, input, key, output_canonicalization());
    builder.push("response.body", payload.to_vec())?;
    builder.push("response.completed", Vec::new())?;
    let (events, _) = builder.finish()?;
    Ok(events)
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
    let body = output_body(events)?;
    Ok(FetchOutput { producer_key, body })
}

pub fn output_body(events: &[OutputEventEnvelope]) -> Result<JsonBytes, FetchProtocolError> {
    if events.len() != 2 {
        return Err(FetchProtocolError::WrongOutputEventCount {
            actual: events.len(),
        });
    }
    expect_output_event(&events[0], 0, "response.body")?;
    expect_output_event(&events[1], 1, "response.completed")?;
    if !events[1].payload().is_empty() {
        return Err(FetchProtocolError::NonEmptyOutputCompleted);
    }
    validate_json("response.body", events[0].payload())?;
    Ok(JsonBytes::new(events[0].payload().to_vec()))
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
    #[error("fetch output transcript must contain exactly 2 events, got {actual}")]
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
    #[error("fetch response.completed payload must be empty")]
    NonEmptyOutputCompleted,
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

        assert_eq!(output.producer_key, producer.public_key());
        assert_eq!(output.body.as_bytes(), br#"{"id":"resp"}"#);
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
        builder.push("response.body", br#"{}"#.to_vec()).unwrap();
        builder.push("response.completed", Vec::new()).unwrap();
        let (events, _) = builder.finish().unwrap();

        assert!(matches!(
            verify_output_events(input, &events).unwrap_err(),
            FetchProtocolError::OutputCanonicalizationMismatch { index: 0 }
        ));
    }
}
