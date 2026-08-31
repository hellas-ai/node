use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Assurance, CanonicalizationId, Digest, Evaluate, EvaluateRequest, InputCommitment, Operation,
    OutputEventEnvelope, OutputTranscriptBuilder, ProducerSigningKey, PublicKey, StreamVerifyError,
    decode_dag_cbor, encode_token_ids, scheme_id, verify_output_event_envelopes,
};
use crate::{DagCborDecodeError, DagCborEncodeError, canonical_dag_cbor};

const OUTPUT_CANONICALIZATION: &[u8] = b"hellas.evaluate.output.v4";
pub const TOKEN_DELTA_EVENT_KIND: &str = "evaluate.token_delta.v4";
pub const TERMINAL_EVENT_KIND: &str = "evaluate.terminal.v4";
const TOKEN_DELTA_CODEC: &str = "hellas.evaluate.output.token_delta.v4";
const TERMINAL_CODEC: &str = "hellas.evaluate.output.terminal.v4";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluateStopReason(u8);

impl EvaluateStopReason {
    /// Generation produced one of the caller-selected stop token IDs.
    pub const STOP_TOKEN: Self = Self(1);
    pub const MAX_OUTPUT: Self = Self(2);

    pub const fn as_u8(self) -> u8 {
        self.0
    }

    pub fn from_u8(value: u8) -> Result<Self, EvaluateProtocolError> {
        match value {
            1 => Ok(Self::STOP_TOKEN),
            2 => Ok(Self::MAX_OUTPUT),
            other => Err(EvaluateProtocolError::UnknownStopReason(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluateUsage {
    pub input_units: u64,
    pub output_units: u64,
}

impl EvaluateUsage {
    /// Evaluate bills prompt tokens plus generated tokens.
    pub fn billable_units(self) -> Result<u64, EvaluateProtocolError> {
        self.input_units
            .checked_add(self.output_units)
            .ok_or(EvaluateProtocolError::BillableUnitsOverflow)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluateTokenDelta {
    pub start_position: u64,
    pub token_ids: Vec<u32>,
}

impl EvaluateTokenDelta {
    pub fn end_position(&self) -> Result<u64, EvaluateProtocolError> {
        let len = u64::try_from(self.token_ids.len())
            .map_err(|_| EvaluateProtocolError::PositionOverflow)?;
        self.start_position
            .checked_add(len)
            .ok_or(EvaluateProtocolError::PositionOverflow)
    }

    pub fn token_bytes(&self) -> Vec<u8> {
        encode_token_ids(&self.token_ids)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluateTerminal {
    pub final_position: u64,
    pub stop_reason: EvaluateStopReason,
    /// The caller-selected token that stopped generation. Catena does not emit
    /// this token as output, so the signed terminal carries it explicitly.
    pub matched_stop_token_id: Option<u32>,
    pub text_artifact: Digest,
    pub usage: EvaluateUsage,
    pub billable_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluateOutput {
    pub producer_key: PublicKey,
    pub token_deltas: Vec<EvaluateTokenDelta>,
    pub terminal: EvaluateTerminal,
}

pub fn input_commitment(request: &EvaluateRequest) -> InputCommitment {
    InputCommitment::from_digest(Evaluate::commit_request(request).digest())
}

pub fn output_canonicalization() -> CanonicalizationId {
    CanonicalizationId::from_bytes(OUTPUT_CANONICALIZATION)
}

pub fn encode_token_delta_payload(
    payload: &EvaluateTokenDelta,
) -> Result<Vec<u8>, EvaluateProtocolError> {
    Ok(canonical_dag_cbor(&(TOKEN_DELTA_CODEC, payload))?)
}

pub fn decode_token_delta_payload(
    bytes: &[u8],
) -> Result<EvaluateTokenDelta, EvaluateProtocolError> {
    let (codec, payload): (String, EvaluateTokenDelta) = decode_dag_cbor(bytes)?;
    if codec != TOKEN_DELTA_CODEC {
        return Err(EvaluateProtocolError::CodecMismatch {
            expected: TOKEN_DELTA_CODEC,
            actual: codec,
        });
    }
    if payload.token_ids.is_empty() {
        return Err(EvaluateProtocolError::EmptyTokenDelta);
    }
    Ok(payload)
}

pub fn encode_terminal_payload(
    payload: &EvaluateTerminal,
) -> Result<Vec<u8>, EvaluateProtocolError> {
    Ok(canonical_dag_cbor(&(TERMINAL_CODEC, payload))?)
}

pub fn decode_terminal_payload(bytes: &[u8]) -> Result<EvaluateTerminal, EvaluateProtocolError> {
    let (codec, payload): (String, EvaluateTerminal) = decode_dag_cbor(bytes)?;
    if codec != TERMINAL_CODEC {
        return Err(EvaluateProtocolError::CodecMismatch {
            expected: TERMINAL_CODEC,
            actual: codec,
        });
    }
    validate_terminal(&payload)?;
    Ok(payload)
}

fn validate_terminal(terminal: &EvaluateTerminal) -> Result<(), EvaluateProtocolError> {
    validate_terminal_stop_witness(terminal)?;
    if terminal.usage.output_units != terminal.final_position {
        return Err(EvaluateProtocolError::UsagePositionMismatch);
    }
    let expected = terminal.usage.billable_units()?;
    if terminal.billable_units != expected {
        return Err(EvaluateProtocolError::BillableUnitsMismatch {
            expected,
            actual: terminal.billable_units,
        });
    }
    Ok(())
}

pub(crate) fn validate_terminal_stop_witness(
    terminal: &EvaluateTerminal,
) -> Result<(), EvaluateProtocolError> {
    EvaluateStopReason::from_u8(terminal.stop_reason.as_u8())?;
    match (terminal.stop_reason, terminal.matched_stop_token_id) {
        (EvaluateStopReason::STOP_TOKEN, None) => {
            return Err(EvaluateProtocolError::MissingMatchedStopTokenId);
        }
        (EvaluateStopReason::MAX_OUTPUT, Some(token_id)) => {
            return Err(EvaluateProtocolError::UnexpectedMatchedStopTokenId { token_id });
        }
        _ => {}
    }
    Ok(())
}

pub struct EvaluateOutputTranscriptBuilder<'a> {
    inner: OutputTranscriptBuilder<'a>,
    next_position: u64,
}

impl<'a> EvaluateOutputTranscriptBuilder<'a> {
    pub fn new(input: InputCommitment, assurance: Assurance, key: &'a ProducerSigningKey) -> Self {
        Self {
            inner: OutputTranscriptBuilder::new(
                scheme_id(Operation::Evaluate, assurance),
                input,
                key,
                output_canonicalization(),
            ),
            next_position: 0,
        }
    }

    pub fn resume_verified(
        input: InputCommitment,
        assurance: Assurance,
        key: &'a ProducerSigningKey,
        events: Vec<OutputEventEnvelope>,
    ) -> Result<Self, EvaluateProtocolError> {
        let public_key = key.public_key();
        if events.is_empty() {
            return Ok(Self::new(input, assurance, key));
        }
        let scheme = scheme_id(Operation::Evaluate, assurance);
        verify_output_event_envelopes(scheme, input, &public_key, &events)?;
        let next_position = verify_token_prefix(&events)?;
        if *events[0].event().public_key() != public_key {
            return Err(EvaluateProtocolError::ProducerKeyMismatch);
        }
        Ok(Self {
            inner: OutputTranscriptBuilder::resume_verified(
                scheme,
                input,
                key,
                output_canonicalization(),
                events,
            )?,
            next_position,
        })
    }

    pub fn push_token_delta(
        &mut self,
        token_ids: Vec<u32>,
    ) -> Result<OutputEventEnvelope, EvaluateProtocolError> {
        if token_ids.is_empty() {
            return Err(EvaluateProtocolError::EmptyTokenDelta);
        }
        let delta = EvaluateTokenDelta {
            start_position: self.next_position,
            token_ids,
        };
        self.next_position = delta.end_position()?;
        Ok(self
            .inner
            .push_envelope(TOKEN_DELTA_EVENT_KIND, encode_token_delta_payload(&delta)?)?)
    }

    pub fn finish(
        mut self,
        terminal: EvaluateTerminal,
    ) -> Result<Vec<OutputEventEnvelope>, EvaluateProtocolError> {
        if terminal.final_position != self.next_position {
            return Err(EvaluateProtocolError::TerminalPositionMismatch {
                expected: self.next_position,
                actual: terminal.final_position,
            });
        }
        validate_terminal(&terminal)?;
        self.inner
            .push(TERMINAL_EVENT_KIND, encode_terminal_payload(&terminal)?)?;
        let (events, _) = self.inner.finish()?;
        Ok(events)
    }
}

pub fn verify_output_events(
    input: InputCommitment,
    assurance: Assurance,
    events: &[OutputEventEnvelope],
) -> Result<EvaluateOutput, EvaluateProtocolError> {
    let producer_key = *events
        .first()
        .ok_or(EvaluateProtocolError::EmptyOutputTranscript)?
        .event()
        .public_key();
    verify_output_events_for_producer(input, assurance, &producer_key, events)
}

/// Verify an evaluate transcript against the producer identity selected by
/// the caller rather than trusting the key carried by the transcript itself.
pub fn verify_output_events_for_producer(
    input: InputCommitment,
    assurance: Assurance,
    producer_key: &PublicKey,
    events: &[OutputEventEnvelope],
) -> Result<EvaluateOutput, EvaluateProtocolError> {
    verify_output_event_envelopes(
        scheme_id(Operation::Evaluate, assurance),
        input,
        producer_key,
        events,
    )?;
    let (token_deltas, terminal) = output_payloads(events)?;
    Ok(EvaluateOutput {
        producer_key: *producer_key,
        token_deltas,
        terminal,
    })
}

fn verify_token_prefix(events: &[OutputEventEnvelope]) -> Result<u64, EvaluateProtocolError> {
    let mut next_position = 0;
    for (index, event) in events.iter().enumerate() {
        expect_output_event(event, index, TOKEN_DELTA_EVENT_KIND)?;
        let delta = decode_token_delta_payload(event.payload())?;
        if delta.start_position != next_position {
            return Err(EvaluateProtocolError::TokenPositionMismatch {
                expected: next_position,
                actual: delta.start_position,
            });
        }
        next_position = delta.end_position()?;
    }
    Ok(next_position)
}

fn output_payloads(
    events: &[OutputEventEnvelope],
) -> Result<(Vec<EvaluateTokenDelta>, EvaluateTerminal), EvaluateProtocolError> {
    let terminal_index = events
        .len()
        .checked_sub(1)
        .ok_or(EvaluateProtocolError::EmptyOutputTranscript)?;
    let mut token_deltas = Vec::with_capacity(terminal_index);
    let next_position = verify_token_prefix(&events[..terminal_index])?;
    for event in &events[..terminal_index] {
        token_deltas.push(decode_token_delta_payload(event.payload())?);
    }
    expect_output_event(&events[terminal_index], terminal_index, TERMINAL_EVENT_KIND)?;
    let terminal = decode_terminal_payload(events[terminal_index].payload())?;
    if terminal.final_position != next_position {
        return Err(EvaluateProtocolError::TerminalPositionMismatch {
            expected: next_position,
            actual: terminal.final_position,
        });
    }
    Ok((token_deltas, terminal))
}

fn expect_output_event(
    event: &OutputEventEnvelope,
    index: usize,
    expected_kind: &'static str,
) -> Result<(), EvaluateProtocolError> {
    let body = event.event().body();
    if body.canonicalization() != output_canonicalization() {
        return Err(EvaluateProtocolError::OutputCanonicalizationMismatch { index });
    }
    if body.kind() != expected_kind {
        return Err(EvaluateProtocolError::UnexpectedOutputEvent {
            index,
            expected: expected_kind,
            actual: body.kind().to_string(),
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum EvaluateProtocolError {
    #[error("evaluate payload encode failed: {0}")]
    Encode(#[from] DagCborEncodeError),
    #[error("evaluate payload decode failed: {0}")]
    Decode(#[from] DagCborDecodeError),
    #[error("evaluate payload codec mismatch: expected {expected}, got {actual}")]
    CodecMismatch {
        expected: &'static str,
        actual: String,
    },
    #[error("unknown evaluate stop reason byte 0x{0:02x}")]
    UnknownStopReason(u8),
    #[error("evaluate STOP_TOKEN terminal is missing its matched stop token ID")]
    MissingMatchedStopTokenId,
    #[error("evaluate MAX_OUTPUT terminal unexpectedly carries matched stop token ID {token_id}")]
    UnexpectedMatchedStopTokenId { token_id: u32 },
    #[error("evaluate stream verification failed: {0}")]
    Stream(#[from] StreamVerifyError),
    #[error("evaluate output transcript is empty")]
    EmptyOutputTranscript,
    #[error("evaluate token delta cannot be empty")]
    EmptyTokenDelta,
    #[error("evaluate token position mismatch: expected {expected}, got {actual}")]
    TokenPositionMismatch { expected: u64, actual: u64 },
    #[error("evaluate terminal position mismatch: expected {expected}, got {actual}")]
    TerminalPositionMismatch { expected: u64, actual: u64 },
    #[error("evaluate output event {index} canonicalization mismatch")]
    OutputCanonicalizationMismatch { index: usize },
    #[error("unexpected evaluate output event {index}: expected {expected}, got {actual}")]
    UnexpectedOutputEvent {
        index: usize,
        expected: &'static str,
        actual: String,
    },
    #[error("evaluate output transcript producer key does not match signing key")]
    ProducerKeyMismatch,
    #[error("evaluate output position exceeded u64 range")]
    PositionOverflow,
    #[error("evaluate usage output units do not match final position")]
    UsagePositionMismatch,
    #[error("evaluate billable units mismatch: expected {expected}, got {actual}")]
    BillableUnitsMismatch { expected: u64, actual: u64 },
    #[error("evaluate billable units exceed u64 range")]
    BillableUnitsOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ASSURANCE: Assurance = Assurance::ProducerSigned;
    use crate::ProducerSigningKey;

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn evaluate_v4_domains_and_first_event_commitment_are_pinned() {
        assert_eq!(OUTPUT_CANONICALIZATION, b"hellas.evaluate.output.v4");
        assert_eq!(TOKEN_DELTA_EVENT_KIND, "evaluate.token_delta.v4");
        assert_eq!(TERMINAL_EVENT_KIND, "evaluate.terminal.v4");
        assert_eq!(TOKEN_DELTA_CODEC, "hellas.evaluate.output.token_delta.v4");
        assert_eq!(TERMINAL_CODEC, "hellas.evaluate.output.terminal.v4");
        assert_eq!(
            scheme_id(Operation::Evaluate, Assurance::ProducerSigned).to_byte(),
            0x00
        );

        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([3; 32]));
        let event = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
            .push_token_delta(vec![10, 11])
            .unwrap();
        assert_eq!(
            hex(event.event_commitment().as_bytes()),
            "0fb828e10fa5cdffe684ff4028617384ee02f8b0f19a382a7cff386a28675883"
        );
    }

    #[test]
    fn decoded_token_delta_must_not_be_empty() {
        let bytes = encode_token_delta_payload(&EvaluateTokenDelta {
            start_position: 0,
            token_ids: Vec::new(),
        })
        .unwrap();

        assert!(matches!(
            decode_token_delta_payload(&bytes),
            Err(EvaluateProtocolError::EmptyTokenDelta)
        ));
    }

    #[test]
    fn output_events_round_trip_through_shape_verifier() {
        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([3; 32]));
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let first = builder.push_token_delta(vec![10, 11]).unwrap();
        let terminal = EvaluateTerminal {
            final_position: 2,
            stop_reason: EvaluateStopReason::STOP_TOKEN,
            matched_stop_token_id: Some(7),
            text_artifact: Digest::from_bytes([4; 32]),
            usage: EvaluateUsage {
                input_units: 7,
                output_units: 2,
            },
            billable_units: 9,
        };
        let events = builder.finish(terminal.clone()).unwrap();

        assert_eq!(events[0], first);
        let output = verify_output_events(input, TEST_ASSURANCE, &events).unwrap();
        assert_eq!(output.token_deltas.len(), 1);
        assert_eq!(output.token_deltas[0].token_ids, vec![10, 11]);
        assert_eq!(output.terminal, terminal);
    }

    #[test]
    fn resume_appends_terminal_without_resigning_prefix() {
        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([3; 32]));
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let prefix = vec![builder.push_token_delta(vec![10]).unwrap()];
        let resumed = EvaluateOutputTranscriptBuilder::resume_verified(
            input,
            TEST_ASSURANCE,
            &producer,
            prefix.clone(),
        )
        .unwrap();
        let events = resumed
            .finish(EvaluateTerminal {
                final_position: 1,
                stop_reason: EvaluateStopReason::MAX_OUTPUT,
                matched_stop_token_id: None,
                text_artifact: Digest::from_bytes([4; 32]),
                usage: EvaluateUsage {
                    input_units: 0,
                    output_units: 1,
                },
                billable_units: 1,
            })
            .unwrap();

        assert_eq!(events[0], prefix[0]);
        verify_output_events_for_producer(input, TEST_ASSURANCE, &producer.public_key(), &events)
            .unwrap();
    }

    #[test]
    fn terminal_position_must_match_token_deltas() {
        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([3; 32]));
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        builder.push_token_delta(vec![10]).unwrap();

        assert!(matches!(
            builder
                .finish(EvaluateTerminal {
                    final_position: 2,
                    stop_reason: EvaluateStopReason::STOP_TOKEN,
                    matched_stop_token_id: Some(7),
                    text_artifact: Digest::from_bytes([4; 32]),
                    usage: EvaluateUsage {
                        input_units: 0,
                        output_units: 2,
                    },
                    billable_units: 2,
                })
                .unwrap_err(),
            EvaluateProtocolError::TerminalPositionMismatch {
                expected: 1,
                actual: 2
            }
        ));
    }

    #[test]
    fn terminal_stop_reason_requires_exact_witness_shape() {
        let usage = EvaluateUsage {
            input_units: 0,
            output_units: 0,
        };
        let mut terminal = EvaluateTerminal {
            final_position: 0,
            stop_reason: EvaluateStopReason::STOP_TOKEN,
            matched_stop_token_id: None,
            text_artifact: Digest::from_bytes([4; 32]),
            usage,
            billable_units: 0,
        };
        assert!(matches!(
            validate_terminal(&terminal),
            Err(EvaluateProtocolError::MissingMatchedStopTokenId)
        ));

        terminal.stop_reason = EvaluateStopReason::MAX_OUTPUT;
        terminal.matched_stop_token_id = Some(7);
        assert!(matches!(
            validate_terminal(&terminal),
            Err(EvaluateProtocolError::UnexpectedMatchedStopTokenId { token_id: 7 })
        ));

        terminal.stop_reason = EvaluateStopReason::STOP_TOKEN;
        assert!(validate_terminal(&terminal).is_ok());
        terminal.stop_reason = EvaluateStopReason::MAX_OUTPUT;
        terminal.matched_stop_token_id = None;
        assert!(validate_terminal(&terminal).is_ok());
    }
}
