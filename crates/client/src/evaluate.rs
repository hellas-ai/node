use hellas_rpc::evaluate::{
    EvaluateOutput, EvaluateTokenDelta, TOKEN_DELTA_EVENT_KIND, decode_token_delta_payload,
    output_canonicalization, verify_terminal_continuation,
};
use hellas_rpc::pb::execute::{WorkEvent, work_event};
use hellas_rpc::stream::output_event_from_pb;
use hellas_rpc::{
    Assurance, Digest, EventCommitment, InputCommitment, Operation, OutputEventEnvelope, PublicKey,
    StreamId, output_genesis, scheme_id,
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
    assurance: Assurance,
    events: Vec<OutputEventEnvelope>,
    finalized: bool,
}

impl EvaluateChunkVerifier {
    pub fn new(
        input: InputCommitment,
        assurance: Assurance,
        expected_producer_key: PublicKey,
        max_output_tokens: u32,
    ) -> Self {
        let stream_id = StreamId::from_input_commitment(input);
        Self {
            input,
            stream_id,
            previous_event: output_genesis(input, stream_id),
            next_sequence: 0,
            next_position: 0,
            expected_producer_key,
            max_output_tokens: u64::from(max_output_tokens),
            assurance,
            events: Vec::new(),
            finalized: false,
        }
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
        self.events.push(event);
        Ok((self.next_position, delta))
    }

    pub fn verify_terminal(
        &mut self,
        output_events: &[OutputEventEnvelope],
    ) -> ClientResult<EvaluateOutput> {
        self.ensure_active()?;
        let first = output_events.first().ok_or_else(|| {
            ClientError::protocol("evaluate terminal transcript must not be empty")
        })?;
        if *first.event().public_key() != self.expected_producer_key {
            return Err(ClientError::protocol(
                "evaluate terminal transcript signed by the wrong producer key",
            ));
        }
        if first.event().body().input() != self.input {
            return Err(ClientError::protocol(
                "evaluate terminal transcript input commitment mismatch",
            ));
        }
        let event_count = u64::try_from(output_events.len()).map_err(|_| {
            ClientError::protocol("evaluate terminal transcript event count exceeds u64 range")
        })?;
        let max_event_count = self.max_output_tokens + 1;
        if event_count > max_event_count {
            return Err(ClientError::protocol(format!(
                "evaluate terminal transcript has {event_count} events, exceeding the limit of {max_event_count}"
            )));
        }
        let output = verify_terminal_continuation(
            self.input,
            self.assurance,
            &self.expected_producer_key,
            &self.events,
            output_events,
        )
        .map_err(|source| ClientError::EvaluateTranscript { source })?;
        self.ensure_output_position(output.terminal.final_position)?;
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
            let output_events = finished
                .output_events
                .into_iter()
                .map(output_event_from_pb)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| {
                    ClientError::source("evaluate output event decode failed", source)
                })?;
            let output = verifier.verify_terminal(&output_events)?;
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
        EvaluateTerminal, EvaluateUsage, input_commitment,
    };
    use hellas_rpc::pb::execute::{WorkChunk, WorkEvent, WorkFailed, WorkFinished, work_event};
    use hellas_rpc::stream::output_event_to_pb;
    use hellas_rpc::{
        ContentId, EvaluateRequest, ProducerSigningKey, Signature, SignedOutputEvent,
    };

    const TEST_ASSURANCE: Assurance = Assurance::ProducerSigned;

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
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
        let mut verifier =
            EvaluateChunkVerifier::new(input, TEST_ASSURANCE, producer.public_key(), 1);

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
        let mut verifier =
            EvaluateChunkVerifier::new(input, TEST_ASSURANCE, producer.public_key(), 2);

        let error = verifier.verify_chunk(oversized).unwrap_err();
        assert!(error.to_string().contains("exceeds requested maximum 2"));
        assert_eq!(verifier.verify_chunk(valid).unwrap().0, 2);
    }

    #[test]
    fn terminal_first_transcript_checks_input_producer_and_limit() {
        let producer = key(2);
        let other = key(3);
        let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        builder.push_token_delta(vec![10, 11]).unwrap();
        let output_events = builder
            .finish(EvaluateTerminal {
                final_position: 2,
                stop_reason: EvaluateStopReason::MAX_OUTPUT,
                text_artifact: Digest::from_bytes([5; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 2,
                },
                billable_units: 5,
            })
            .unwrap();

        let mut wrong_producer =
            EvaluateChunkVerifier::new(input, TEST_ASSURANCE, other.public_key(), 2);
        assert!(
            wrong_producer
                .verify_terminal(&output_events)
                .unwrap_err()
                .to_string()
                .contains("wrong producer key")
        );

        let other_input = InputCommitment::from_digest(Digest::from_bytes([6; 32]));
        let mut wrong_input =
            EvaluateChunkVerifier::new(other_input, TEST_ASSURANCE, producer.public_key(), 2);
        assert!(
            wrong_input
                .verify_terminal(&output_events)
                .unwrap_err()
                .to_string()
                .contains("input commitment mismatch")
        );

        let mut too_small =
            EvaluateChunkVerifier::new(input, TEST_ASSURANCE, producer.public_key(), 1);
        assert!(
            too_small
                .verify_terminal(&output_events)
                .unwrap_err()
                .to_string()
                .contains("exceeds requested maximum 1")
        );

        let mut verifier =
            EvaluateChunkVerifier::new(input, TEST_ASSURANCE, producer.public_key(), 2);
        assert_eq!(
            verifier
                .verify_terminal(&output_events)
                .unwrap()
                .terminal
                .final_position,
            2
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
                text_artifact: Digest::from_bytes([4; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 2,
                },
                billable_units: 5,
            })
            .unwrap();

        let mut verifier =
            EvaluateChunkVerifier::new(input, TEST_ASSURANCE, producer.public_key(), 2);
        let (position, delta) = verifier.verify_chunk(token_event).unwrap();
        assert_eq!(position, 2);
        assert_eq!(delta.token_ids, vec![10, 11]);
        verifier.verify_terminal(&output_events).unwrap();
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
                text_artifact: Digest::from_bytes([4; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 2,
                },
                billable_units: 5,
            })
            .unwrap();

        let mut verifier =
            EvaluateChunkVerifier::new(input, TEST_ASSURANCE, producer.public_key(), 2);
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
                kind: Some(work_event::Kind::Finished(WorkFinished {
                    output_events: output_events.iter().map(output_event_to_pb).collect(),
                    assurance_evidence: Vec::new(),
                })),
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
                text_artifact: Digest::from_bytes([5; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 1,
                },
                billable_units: 4,
            })
            .unwrap();
        let mut verifier =
            EvaluateChunkVerifier::new(input, TEST_ASSURANCE, producer.public_key(), 1);

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
                    output_events: Vec::new(),
                    assurance_evidence: Vec::new(),
                })),
            },
            input,
        )
        .unwrap_err();
        assert!(malformed.to_string().contains("must not be empty"));

        let completed = verify_evaluate_work_event(
            &mut verifier,
            WorkEvent {
                kind: Some(work_event::Kind::Finished(WorkFinished {
                    output_events: output_events.iter().map(output_event_to_pb).collect(),
                    assurance_evidence: Vec::new(),
                })),
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
                kind: Some(work_event::Kind::Finished(WorkFinished {
                    output_events: output_events.iter().map(output_event_to_pb).collect(),
                    assurance_evidence: Vec::new(),
                })),
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
        let mut verifier =
            EvaluateChunkVerifier::new(input, TEST_ASSURANCE, producer.public_key(), 2);

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
                    output_events: Vec::new(),
                    assurance_evidence: Vec::new(),
                })),
            },
            input,
        )
        .unwrap_err();
        assert!(second_terminal.to_string().contains("already finalized"));
    }
}
