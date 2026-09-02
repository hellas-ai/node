use hellas_rpc::evaluate::{
    EvaluateOutput, EvaluateTokenDelta, TERMINAL_EVENT_KIND, TOKEN_DELTA_EVENT_KIND,
    decode_terminal_payload, decode_token_delta_payload, output_canonicalization,
};
use hellas_rpc::pb::execute::{WorkEvent, work_event};
use hellas_rpc::protocol::artifacts::{OutputAddressed, TextExecutionId, completed_text};
use hellas_rpc::stream::output_event_from_pb;
use hellas_rpc::{
    Assurance, Digest, EventCommitment, InputCommitment, Operation, OutputEventEnvelope, PublicKey,
    StreamId, normalize_stop_token_ids, output_genesis, scheme_id,
    verify_output_event_continuation,
};

use crate::{ClientError, ClientResult};

/// One verified observation from an evaluate execution stream.
#[derive(Debug, Clone)]
pub enum EvaluateExecutionEvent {
    Chunk {
        /// Cumulative token position after this chunk.
        position: u64,
        /// Little-endian `u32` token IDs for caller-selected local decoding.
        tokens: Vec<u8>,
    },
    Done(EvaluateOutcome),
}

/// Terminal result of a verified evaluate execution stream.
#[derive(Debug, Clone)]
pub enum EvaluateOutcome {
    Completed {
        output: EvaluateOutput,
        output_events: Vec<OutputEventEnvelope>,
    },
    Failed {
        position: u64,
        error: String,
    },
}

pub struct EvaluateChunkVerifier {
    input: InputCommitment,
    stream_id: StreamId,
    previous_event: EventCommitment,
    next_sequence: u64,
    next_position: u64,
    expected_producer_key: PublicKey,
    max_output_tokens: u64,
    vocabulary_size: u64,
    stop_token_ids: Vec<u32>,
    assurance: Assurance,
    events: Vec<OutputEventEnvelope>,
    generated_token_ids: Vec<u32>,
    text_artifact_expectation: Option<TextArtifactExpectation>,
    finalized: bool,
}

struct TextArtifactExpectation {
    execution: TextExecutionId,
    full_input_ids: Vec<u32>,
}

impl EvaluateChunkVerifier {
    pub fn new(
        input: InputCommitment,
        assurance: Assurance,
        expected_producer_key: PublicKey,
        max_output_tokens: u32,
        vocabulary_size: u64,
        mut stop_token_ids: Vec<u32>,
    ) -> Self {
        normalize_stop_token_ids(&mut stop_token_ids);
        let stream_id = StreamId::from_input_commitment(input);
        Self {
            input,
            stream_id,
            previous_event: output_genesis(input, stream_id),
            next_sequence: 0,
            next_position: 0,
            expected_producer_key,
            max_output_tokens: u64::from(max_output_tokens),
            vocabulary_size,
            stop_token_ids,
            assurance,
            events: Vec::new(),
            generated_token_ids: Vec::new(),
            text_artifact_expectation: None,
            finalized: false,
        }
    }

    /// Require the signed terminal artifact to be the canonical artifact
    /// derived from this text execution, its full input, and the verified
    /// streamed output tokens.
    #[must_use]
    pub fn with_text_artifact_expectation(
        mut self,
        execution: TextExecutionId,
        full_input_ids: Vec<u32>,
    ) -> Self {
        self.text_artifact_expectation = Some(TextArtifactExpectation {
            execution,
            full_input_ids,
        });
        self
    }

    pub const fn assurance(&self) -> Assurance {
        self.assurance
    }

    pub fn verify_chunk(
        &mut self,
        event: OutputEventEnvelope,
    ) -> ClientResult<(u64, EvaluateTokenDelta)> {
        self.ensure_active()?;
        let public_key = *event.event().public_key();
        if public_key != self.expected_producer_key {
            return Err(ClientError::protocol(
                "evaluate output chunk signed by the wrong producer key",
            ));
        }
        event
            .verify(&self.expected_producer_key)
            .map_err(|source| {
                ClientError::source(
                    "evaluate output chunk signature verification failed",
                    source,
                )
            })?;
        let body = event.event().body();
        if body.scheme() != scheme_id(Operation::Evaluate, self.assurance) {
            return Err(ClientError::protocol(
                "evaluate output chunk used the wrong scheme",
            ));
        }
        if body.input() != self.input {
            return Err(ClientError::protocol(
                "evaluate output chunk input commitment mismatch",
            ));
        }
        if body.stream_id() != self.stream_id {
            return Err(ClientError::protocol(
                "evaluate output chunk stream id mismatch",
            ));
        }
        if body.sequence() != self.next_sequence {
            return Err(ClientError::protocol(format!(
                "evaluate output chunk sequence mismatch: expected {}, got {}",
                self.next_sequence,
                body.sequence()
            )));
        }
        if body.previous_event() != self.previous_event {
            return Err(ClientError::protocol(
                "evaluate output chunk previous-event mismatch",
            ));
        }
        if body.kind() != TOKEN_DELTA_EVENT_KIND {
            return Err(ClientError::protocol(format!(
                "evaluate output chunk must be {TOKEN_DELTA_EVENT_KIND}, got {}",
                body.kind()
            )));
        }
        if body.canonicalization() != output_canonicalization() {
            return Err(ClientError::protocol(
                "evaluate output chunk canonicalization mismatch",
            ));
        }
        let delta = decode_token_delta_payload(event.payload())
            .map_err(|source| ClientError::EvaluateTranscript { source })?;
        if delta.start_position != self.next_position {
            return Err(ClientError::protocol(format!(
                "evaluate output chunk token position mismatch: expected {}, got {}",
                self.next_position, delta.start_position
            )));
        }
        if let Some(token_id) = delta
            .token_ids
            .iter()
            .copied()
            .find(|token_id| u64::from(*token_id) >= self.vocabulary_size)
        {
            return Err(ClientError::protocol(format!(
                "evaluate output token {token_id} is outside the committed vocabulary of {} tokens",
                self.vocabulary_size
            )));
        }
        let next_position = delta
            .end_position()
            .map_err(|source| ClientError::EvaluateTranscript { source })?;
        self.ensure_output_position(next_position)?;
        let next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            ClientError::protocol("evaluate output chunk sequence exceeds u64 range")
        })?;

        self.next_position = next_position;
        self.previous_event = event.event_commitment();
        self.next_sequence = next_sequence;
        self.generated_token_ids
            .extend(delta.token_ids.iter().copied());
        self.events.push(event);
        Ok((self.next_position, delta))
    }

    pub fn verify_terminal(
        &mut self,
        terminal: OutputEventEnvelope,
    ) -> ClientResult<EvaluateOutput> {
        self.ensure_active()?;
        if *terminal.event().public_key() != self.expected_producer_key {
            return Err(ClientError::protocol(
                "evaluate terminal event signed by the wrong producer key",
            ));
        }
        if terminal.event().body().input() != self.input {
            return Err(ClientError::protocol(
                "evaluate terminal event input commitment mismatch",
            ));
        }
        let expected_event_count = self.events.len().checked_add(1).ok_or_else(|| {
            ClientError::protocol("evaluate terminal transcript event count exceeds usize range")
        })?;
        let event_count = u64::try_from(expected_event_count).map_err(|_| {
            ClientError::protocol("evaluate terminal transcript event count exceeds u64 range")
        })?;
        let max_event_count = self.max_output_tokens + 1;
        if event_count > max_event_count {
            return Err(ClientError::protocol(format!(
                "evaluate terminal transcript has {event_count} events, exceeding the limit of {max_event_count}"
            )));
        }
        verify_output_event_continuation(
            scheme_id(Operation::Evaluate, self.assurance),
            self.input,
            &self.expected_producer_key,
            self.next_sequence,
            self.previous_event,
            &terminal,
        )
        .map_err(|source| ClientError::EvaluateTranscript {
            source: source.into(),
        })?;
        let body = terminal.event().body();
        if body.kind() != TERMINAL_EVENT_KIND {
            return Err(ClientError::protocol(format!(
                "evaluate terminal event must be {TERMINAL_EVENT_KIND}, got {}",
                body.kind()
            )));
        }
        if body.canonicalization() != output_canonicalization() {
            return Err(ClientError::protocol(
                "evaluate terminal event canonicalization mismatch",
            ));
        }
        let terminal_payload = decode_terminal_payload(terminal.payload())
            .map_err(|source| ClientError::EvaluateTranscript { source })?;
        if terminal_payload.final_position != self.next_position {
            return Err(ClientError::protocol(format!(
                "evaluate terminal position mismatch: expected {}, got {}",
                self.next_position, terminal_payload.final_position
            )));
        }
        let token_deltas = self
            .events
            .iter()
            .map(|event| decode_token_delta_payload(event.payload()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| ClientError::EvaluateTranscript { source })?;
        let output = EvaluateOutput {
            producer_key: self.expected_producer_key,
            token_deltas,
            terminal: terminal_payload,
        };
        self.ensure_output_position(output.terminal.final_position)?;
        if output.terminal.stop_reason == hellas_rpc::evaluate::EvaluateStopReason::MAX_OUTPUT
            && output.terminal.final_position != self.max_output_tokens
        {
            return Err(ClientError::protocol(format!(
                "evaluate MAX_OUTPUT terminal position must equal the requested maximum {}: got {}",
                self.max_output_tokens, output.terminal.final_position
            )));
        }
        if output.terminal.stop_reason == hellas_rpc::evaluate::EvaluateStopReason::STOP_TOKEN {
            if output.terminal.final_position >= self.max_output_tokens {
                return Err(ClientError::protocol(
                    "evaluate STOP_TOKEN terminal must occur before the requested maximum",
                ));
            }
            let matched = output.terminal.matched_stop_token_id.ok_or_else(|| {
                ClientError::protocol("evaluate STOP_TOKEN terminal is missing its matched token")
            })?;
            if self.stop_token_ids.binary_search(&matched).is_err() {
                return Err(ClientError::protocol(format!(
                    "evaluate STOP_TOKEN terminal matched uncommitted token {matched}"
                )));
            }
        }
        if let Some(expected) = &self.text_artifact_expectation {
            let input_units = u64::try_from(expected.full_input_ids.len()).map_err(|_| {
                ClientError::protocol("evaluate input token count exceeds u64 range")
            })?;
            if output.terminal.usage.input_units != input_units {
                return Err(ClientError::protocol(format!(
                    "evaluate terminal input usage mismatch: expected {input_units}, got {}",
                    output.terminal.usage.input_units
                )));
            }
            let derived = completed_text(
                expected.execution,
                &expected.full_input_ids,
                &self.generated_token_ids,
            )
            .artifact
            .output_id()
            .digest();
            if output.terminal.text_artifact != derived {
                return Err(ClientError::protocol(format!(
                    "evaluate terminal text artifact does not match the verified token stream: claimed {}, derived {derived}",
                    output.terminal.text_artifact
                )));
            }
        }
        self.events.push(terminal);
        self.finalized = true;
        Ok(output)
    }

    fn verify_failure(&mut self, position: u64) -> ClientResult<()> {
        self.ensure_active()?;
        self.ensure_output_position(position)?;
        if position != self.next_position {
            return Err(ClientError::protocol(format!(
                "evaluate failure position mismatch: expected {}, got {position}",
                self.next_position
            )));
        }
        self.finalized = true;
        Ok(())
    }

    fn ensure_active(&self) -> ClientResult<()> {
        if self.finalized {
            return Err(ClientError::protocol("evaluate stream already finalized"));
        }
        Ok(())
    }

    fn ensure_output_position(&self, position: u64) -> ClientResult<()> {
        if position > self.max_output_tokens {
            return Err(ClientError::protocol(format!(
                "evaluate output position {position} exceeds requested maximum {}",
                self.max_output_tokens
            )));
        }
        Ok(())
    }
}

pub fn evaluate_input_from_request_commitment(
    request_commitment: &[u8],
) -> ClientResult<InputCommitment> {
    let digest: [u8; 32] = request_commitment.try_into().map_err(|_| {
        ClientError::protocol(format!(
            "ticket request_commitment must be 32 bytes, got {}",
            request_commitment.len()
        ))
    })?;
    Ok(InputCommitment::from_digest(Digest::from_bytes(digest)))
}

/// Decode and verify one evaluate [`WorkEvent`].
///
/// This is transport-neutral: callers may obtain events through iroh,
/// WebSocket, an in-process executor, or any other Hellas `StreamTransport`.
pub fn verify_evaluate_work_event(
    verifier: &mut EvaluateChunkVerifier,
    event: WorkEvent,
    input_commitment: InputCommitment,
) -> ClientResult<EvaluateExecutionEvent> {
    if input_commitment != verifier.input {
        return Err(ClientError::protocol(
            "evaluate work verifier input commitment mismatch",
        ));
    }
    let Some(event) = event.kind else {
        return Err(ClientError::protocol("wire event with no body"));
    };
    verifier.ensure_active()?;
    match event {
        work_event::Kind::Chunk(chunk) => {
            let output_event = chunk.output_event.ok_or_else(|| {
                ClientError::protocol("evaluate work chunk missing signed output event")
            })?;
            let output_event = output_event_from_pb(output_event).map_err(|source| {
                ClientError::source("evaluate output event decode failed", source)
            })?;
            let (position, delta) = verifier.verify_chunk(output_event)?;
            Ok(EvaluateExecutionEvent::Chunk {
                position,
                tokens: delta.token_bytes(),
            })
        }
        work_event::Kind::Finished(finished) => {
            let terminal = finished.terminal_output_event.ok_or_else(|| {
                ClientError::protocol("evaluate WorkFinished missing signed terminal event")
            })?;
            let terminal = output_event_from_pb(terminal).map_err(|source| {
                ClientError::source("evaluate terminal event decode failed", source)
            })?;
            let output = verifier.verify_terminal(terminal)?;
            let output_events = std::mem::take(&mut verifier.events);
            Ok(EvaluateExecutionEvent::Done(EvaluateOutcome::Completed {
                output,
                output_events,
            }))
        }
        work_event::Kind::Failed(failed) => {
            verifier.verify_failure(failed.position)?;
            Ok(EvaluateExecutionEvent::Done(EvaluateOutcome::Failed {
                position: failed.position,
                error: failed.error,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::evaluate::{
        EvaluateOutputTranscriptBuilder, EvaluateProtocolError, EvaluateStopReason,
        EvaluateTerminal, EvaluateUsage, encode_terminal_payload, input_commitment,
    };
    use hellas_rpc::pb::execute::{WorkChunk, WorkEvent, WorkFailed, WorkFinished, work_event};
    use hellas_rpc::stream::output_event_to_pb;
    use hellas_rpc::{
        ContentId, EvaluateRequest, OutputTranscriptBuilder, ProducerSigningKey, Signature,
        SignedOutputEvent,
    };

    const TEST_ASSURANCE: Assurance = Assurance::ProducerSigned;

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
    }

    fn verifier(
        input: InputCommitment,
        producer_key: PublicKey,
        max_output_tokens: u32,
    ) -> EvaluateChunkVerifier {
        EvaluateChunkVerifier::new(
            input,
            TEST_ASSURANCE,
            producer_key,
            max_output_tokens,
            1_000,
            vec![7],
        )
    }

    fn corrupt_signature(event: &OutputEventEnvelope) -> OutputEventEnvelope {
        let signature = match *event.event().signature() {
            Signature::Secp256k1(mut bytes) => {
                bytes[7] ^= 0x01;
                Signature::Secp256k1(bytes)
            }
            _ => panic!("the fixture uses a secp256k1 producer key"),
        };
        let signed = SignedOutputEvent::from_parts(
            event.event().body().clone(),
            signature,
            *event.event().public_key(),
        )
        .unwrap();
        OutputEventEnvelope::new(signed, event.payload().to_vec()).unwrap()
    }

    fn terminal_event(events: &[OutputEventEnvelope]) -> OutputEventEnvelope {
        events.last().expect("fixture terminal event").clone()
    }

    fn signed_terminal_without_shape_validation(
        input: InputCommitment,
        producer: &ProducerSigningKey,
        terminal: &EvaluateTerminal,
    ) -> OutputEventEnvelope {
        let mut builder = OutputTranscriptBuilder::new(
            scheme_id(Operation::Evaluate, TEST_ASSURANCE),
            input,
            producer,
            output_canonicalization(),
        );
        builder
            .push(
                TERMINAL_EVENT_KIND,
                encode_terminal_payload(terminal).unwrap(),
            )
            .unwrap();
        builder.finish().unwrap().0.pop().unwrap()
    }

    fn finished(events: &[OutputEventEnvelope]) -> WorkFinished {
        WorkFinished {
            terminal_output_event: Some(output_event_to_pb(
                events.last().expect("fixture terminal event"),
            )),
            assurance_evidence: Vec::new(),
        }
    }

    #[test]
    fn rejected_producer_and_signature_do_not_advance_verifier_state() {
        let producer = key(2);
        let attacker = key(3);
        let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
        let valid = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
            .push_token_delta(vec![10])
            .unwrap();
        let attacker_event = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &attacker)
            .push_token_delta(vec![99])
            .unwrap();
        let invalid_signature = corrupt_signature(&valid);
        let mut verifier = verifier(input, producer.public_key(), 1);

        assert!(matches!(
            verifier.verify_chunk(attacker_event),
            Err(ClientError::Protocol(_))
        ));
        assert!(matches!(
            verifier.verify_chunk(invalid_signature),
            Err(ClientError::Source { .. })
        ));
        let (position, delta) = verifier.verify_chunk(valid).unwrap();
        assert_eq!(position, 1);
        assert_eq!(delta.token_ids, vec![10]);
    }

    #[test]
    fn output_position_cannot_exceed_requested_maximum() {
        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
        let oversized = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
            .push_token_delta(vec![10, 11, 12])
            .unwrap();
        let valid = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
            .push_token_delta(vec![10, 11])
            .unwrap();
        let mut verifier = verifier(input, producer.public_key(), 2);

        let error = verifier.verify_chunk(oversized).unwrap_err();
        assert!(error.to_string().contains("exceeds requested maximum 2"));
        assert_eq!(verifier.verify_chunk(valid).unwrap().0, 2);
    }

    #[test]
    fn out_of_vocabulary_chunk_rejection_is_transactional_across_a_split_retry() {
        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let first = builder.push_token_delta(vec![1]).unwrap();
        let invalid = builder.push_token_delta(vec![2, 10]).unwrap();
        let mut resumed = EvaluateOutputTranscriptBuilder::resume_verified(
            input,
            TEST_ASSURANCE,
            &producer,
            vec![first.clone()],
        )
        .unwrap();
        let retry = resumed.push_token_delta(vec![2, 9]).unwrap();
        let mut verifier = EvaluateChunkVerifier::new(
            input,
            TEST_ASSURANCE,
            producer.public_key(),
            3,
            10,
            Vec::new(),
        );

        assert_eq!(verifier.verify_chunk(first).unwrap().0, 1);
        let error = verifier.verify_chunk(invalid).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outside the committed vocabulary")
        );
        assert_eq!(verifier.verify_chunk(retry).unwrap().0, 3);
    }

    #[test]
    fn signed_terminal_requires_the_exact_stop_witness_shape() {
        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
        let usage = EvaluateUsage {
            input_units: 3,
            output_units: 0,
        };
        let missing = signed_terminal_without_shape_validation(
            input,
            &producer,
            &EvaluateTerminal {
                final_position: 0,
                stop_reason: EvaluateStopReason::STOP_TOKEN,
                matched_stop_token_id: None,
                text_artifact: Digest::from_bytes([5; 32]),
                usage,
                billable_units: 3,
            },
        );
        let extraneous = signed_terminal_without_shape_validation(
            input,
            &producer,
            &EvaluateTerminal {
                final_position: 0,
                stop_reason: EvaluateStopReason::MAX_OUTPUT,
                matched_stop_token_id: Some(7),
                text_artifact: Digest::from_bytes([5; 32]),
                usage,
                billable_units: 3,
            },
        );

        let missing_error = verifier(input, producer.public_key(), 1)
            .verify_terminal(missing)
            .unwrap_err();
        assert!(
            missing_error
                .to_string()
                .contains("missing its matched stop token ID")
        );
        let extraneous_error = verifier(input, producer.public_key(), 1)
            .verify_terminal(extraneous)
            .unwrap_err();
        assert!(
            extraneous_error
                .to_string()
                .contains("unexpectedly carries matched stop token ID 7")
        );
    }

    #[test]
    fn position_zero_stop_with_a_committed_witness_is_valid() {
        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
        let events = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
            .finish(EvaluateTerminal {
                final_position: 0,
                stop_reason: EvaluateStopReason::STOP_TOKEN,
                matched_stop_token_id: Some(7),
                text_artifact: Digest::from_bytes([5; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 0,
                },
                billable_units: 3,
            })
            .unwrap();

        let output = verifier(input, producer.public_key(), 1)
            .verify_terminal(terminal_event(&events))
            .unwrap();
        assert_eq!(output.terminal.matched_stop_token_id, Some(7));
    }

    #[test]
    fn terminal_first_transcript_checks_input_and_producer() {
        let producer = key(2);
        let other = key(3);
        let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
        let output_events = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
            .finish(EvaluateTerminal {
                final_position: 0,
                stop_reason: EvaluateStopReason::STOP_TOKEN,
                matched_stop_token_id: Some(7),
                text_artifact: Digest::from_bytes([5; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 0,
                },
                billable_units: 3,
            })
            .unwrap();

        let mut wrong_producer = verifier(input, other.public_key(), 2);
        assert!(
            wrong_producer
                .verify_terminal(terminal_event(&output_events))
                .unwrap_err()
                .to_string()
                .contains("wrong producer key")
        );

        let other_input = InputCommitment::from_digest(Digest::from_bytes([6; 32]));
        let mut wrong_input = verifier(other_input, producer.public_key(), 2);
        assert!(
            wrong_input
                .verify_terminal(terminal_event(&output_events))
                .unwrap_err()
                .to_string()
                .contains("input commitment mismatch")
        );

        let mut verifier = verifier(input, producer.public_key(), 2);
        assert_eq!(
            verifier
                .verify_terminal(terminal_event(&output_events))
                .unwrap()
                .terminal
                .final_position,
            0
        );
    }

    #[test]
    fn verifies_streamed_prefix_and_terminal() {
        let runner = key(1);
        let producer = key(2);
        let request = EvaluateRequest {
            text_execution: Digest::from_bytes([9; 32]),
            runner_public_key: runner.public_key(),
            execution_environment: ContentId::from_bytes([8; 32]),
            nonce: [7; 32],
            assurance: TEST_ASSURANCE,
            retain: true,
        };
        let input = input_commitment(&request);
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let token_event = builder.push_token_delta(vec![10, 11]).unwrap();
        let output_events = builder
            .finish(EvaluateTerminal {
                final_position: 2,
                stop_reason: EvaluateStopReason::STOP_TOKEN,
                matched_stop_token_id: Some(7),
                text_artifact: Digest::from_bytes([4; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 2,
                },
                billable_units: 5,
            })
            .unwrap();

        let mut verifier = verifier(input, producer.public_key(), 3);
        let (position, delta) = verifier.verify_chunk(token_event).unwrap();
        assert_eq!(position, 2);
        assert_eq!(delta.token_ids, vec![10, 11]);
        verifier
            .verify_terminal(terminal_event(&output_events))
            .unwrap();
    }

    #[test]
    fn terminal_cannot_hide_an_unstreamed_token_delta() {
        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let streamed = builder.push_token_delta(vec![10]).unwrap();
        builder.push_token_delta(vec![11]).unwrap();
        let output_events = builder
            .finish(EvaluateTerminal {
                final_position: 2,
                stop_reason: EvaluateStopReason::MAX_OUTPUT,
                matched_stop_token_id: None,
                text_artifact: Digest::from_bytes([5; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 2,
                },
                billable_units: 5,
            })
            .unwrap();
        let mut verifier = verifier(input, producer.public_key(), 2);
        verifier.verify_chunk(streamed).unwrap();

        let error = verifier
            .verify_terminal(terminal_event(&output_events))
            .unwrap_err();
        assert!(error.to_string().contains("sequence mismatch"));
    }

    #[test]
    fn terminal_artifact_must_match_verified_streamed_tokens() {
        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
        let execution = TextExecutionId::from_digest(Digest::from_bytes([6; 32]));
        let input_ids = vec![1, 2, 3];
        let forged_artifact = completed_text(execution, &input_ids, &[7])
            .artifact
            .output_id()
            .digest();
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let streamed = builder.push_token_delta(vec![9]).unwrap();
        let output_events = builder
            .finish(EvaluateTerminal {
                final_position: 1,
                stop_reason: EvaluateStopReason::MAX_OUTPUT,
                matched_stop_token_id: None,
                text_artifact: forged_artifact,
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 1,
                },
                billable_units: 4,
            })
            .unwrap();
        let mut verifier = verifier(input, producer.public_key(), 1)
            .with_text_artifact_expectation(execution, input_ids);
        verifier.verify_chunk(streamed).unwrap();

        let error = verifier
            .verify_terminal(terminal_event(&output_events))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match the verified token stream")
        );
    }

    #[test]
    fn stop_terminal_must_match_the_committed_stop_policy() {
        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
        let execution = TextExecutionId::from_digest(Digest::from_bytes([6; 32]));
        let input_ids = vec![1];
        let artifact = completed_text(execution, &input_ids, &[9])
            .artifact
            .output_id()
            .digest();
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let streamed = builder.push_token_delta(vec![9]).unwrap();
        let output_events = builder
            .finish(EvaluateTerminal {
                final_position: 1,
                stop_reason: EvaluateStopReason::STOP_TOKEN,
                matched_stop_token_id: Some(8),
                text_artifact: artifact,
                usage: EvaluateUsage {
                    input_units: 1,
                    output_units: 1,
                },
                billable_units: 2,
            })
            .unwrap();
        let mut verifier = verifier(input, producer.public_key(), 2)
            .with_text_artifact_expectation(execution, input_ids);
        verifier.verify_chunk(streamed).unwrap();

        let error = verifier
            .verify_terminal(terminal_event(&output_events))
            .unwrap_err();
        assert!(error.to_string().contains("uncommitted token 8"));
    }

    #[test]
    fn rejects_wrong_ticket_commitment_length() {
        assert!(matches!(
            evaluate_input_from_request_commitment(&[0; 31]),
            Err(ClientError::Protocol(_))
        ));
    }

    #[test]
    fn evaluate_protocol_error_remains_source_typed() {
        let error = ClientError::EvaluateTranscript {
            source: EvaluateProtocolError::UnknownStopReason(9),
        };
        assert!(error.to_string().contains("evaluate transcript"));
    }

    #[test]
    fn work_events_are_verified_end_to_end() {
        let runner = key(1);
        let producer = key(2);
        let request = EvaluateRequest {
            text_execution: Digest::from_bytes([9; 32]),
            runner_public_key: runner.public_key(),
            execution_environment: ContentId::from_bytes([8; 32]),
            nonce: [7; 32],
            assurance: TEST_ASSURANCE,
            retain: true,
        };
        let input = hellas_rpc::evaluate::input_commitment(&request);
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let chunk = builder.push_token_delta(vec![10, 11]).unwrap();
        let output_events = builder
            .finish(EvaluateTerminal {
                final_position: 2,
                stop_reason: EvaluateStopReason::STOP_TOKEN,
                matched_stop_token_id: Some(7),
                text_artifact: Digest::from_bytes([4; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 2,
                },
                billable_units: 5,
            })
            .unwrap();

        let mut verifier = verifier(input, producer.public_key(), 3);
        let event = verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Chunk(WorkChunk {
                    output_event: Some(output_event_to_pb(&chunk)),
                })),
            },
            input,
        )
        .unwrap();
        assert!(matches!(
            event,
            EvaluateExecutionEvent::Chunk {
                position: 2,
                ref tokens
            } if tokens.len() == 8
        ));

        let event = verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Finished(finished(&output_events))),
            },
            input,
        )
        .unwrap();
        assert!(matches!(
            event,
            EvaluateExecutionEvent::Done(EvaluateOutcome::Completed { .. })
        ));
    }

    #[test]
    fn finished_latch_is_atomic_and_rejects_later_events() {
        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let chunk = builder.push_token_delta(vec![10]).unwrap();
        let output_events = builder
            .finish(EvaluateTerminal {
                final_position: 1,
                stop_reason: EvaluateStopReason::MAX_OUTPUT,
                matched_stop_token_id: None,
                text_artifact: Digest::from_bytes([5; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 1,
                },
                billable_units: 4,
            })
            .unwrap();
        let mut verifier = verifier(input, producer.public_key(), 1);

        verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Chunk(WorkChunk {
                    output_event: Some(output_event_to_pb(&chunk)),
                })),
            },
            input,
        )
        .unwrap();

        let malformed = verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Finished(WorkFinished {
                    terminal_output_event: None,
                    assurance_evidence: Vec::new(),
                })),
            },
            input,
        )
        .unwrap_err();
        assert!(
            malformed
                .to_string()
                .contains("missing signed terminal event")
        );

        let completed = verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Finished(finished(&output_events))),
            },
            input,
        )
        .unwrap();
        assert!(matches!(
            completed,
            EvaluateExecutionEvent::Done(EvaluateOutcome::Completed { .. })
        ));

        let second_terminal = verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Finished(finished(&output_events))),
            },
            input,
        )
        .unwrap_err();
        assert!(second_terminal.to_string().contains("already finalized"));

        let later_chunk = verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Chunk(WorkChunk {
                    output_event: Some(output_event_to_pb(&chunk)),
                })),
            },
            input,
        )
        .unwrap_err();
        assert!(later_chunk.to_string().contains("already finalized"));
    }

    #[test]
    fn work_failed_position_must_match_prefix_and_consumes_terminal_latch() {
        let producer = key(2);
        let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
        let chunk = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
            .push_token_delta(vec![10])
            .unwrap();
        let mut verifier = verifier(input, producer.public_key(), 2);

        verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Chunk(WorkChunk {
                    output_event: Some(output_event_to_pb(&chunk)),
                })),
            },
            input,
        )
        .unwrap();

        let wrong_position = verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Failed(WorkFailed {
                    position: 0,
                    error: "wrong position".to_string(),
                })),
            },
            input,
        )
        .unwrap_err();
        assert!(wrong_position.to_string().contains("expected 1, got 0"));

        let over_limit = verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Failed(WorkFailed {
                    position: 3,
                    error: "over limit".to_string(),
                })),
            },
            input,
        )
        .unwrap_err();
        assert!(
            over_limit
                .to_string()
                .contains("exceeds requested maximum 2")
        );

        let failed = verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Failed(WorkFailed {
                    position: 1,
                    error: "worker stopped".to_string(),
                })),
            },
            input,
        )
        .unwrap();
        assert!(matches!(
            failed,
            EvaluateExecutionEvent::Done(EvaluateOutcome::Failed {
                position: 1,
                ref error
            }) if error == "worker stopped"
        ));

        let second_terminal = verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Finished(WorkFinished {
                    terminal_output_event: None,
                    assurance_evidence: Vec::new(),
                })),
            },
            input,
        )
        .unwrap_err();
        assert!(second_terminal.to_string().contains("already finalized"));
    }
}
