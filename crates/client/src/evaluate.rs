use hellas_rpc::evaluate::{
    EvaluateOutput, EvaluateTokenDelta, TOKEN_DELTA_EVENT_KIND, decode_token_delta_payload,
    output_canonicalization, verify_output_events, verify_terminal_continuation,
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
        /// Little-endian `u32` token IDs, ready for `DecodeTokens`.
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
    producer_key: Option<PublicKey>,
    assurance: Assurance,
    events: Vec<OutputEventEnvelope>,
}

impl EvaluateChunkVerifier {
    pub fn new(input: InputCommitment, assurance: Assurance) -> Self {
        let stream_id = StreamId::from_input_commitment(input);
        Self {
            input,
            stream_id,
            previous_event: output_genesis(input, stream_id),
            next_sequence: 0,
            next_position: 0,
            producer_key: None,
            assurance,
            events: Vec::new(),
        }
    }

    pub const fn assurance(&self) -> Assurance {
        self.assurance
    }

    pub fn verify_chunk(
        &mut self,
        event: OutputEventEnvelope,
    ) -> ClientResult<(u64, EvaluateTokenDelta)> {
        let public_key = *event.event().public_key();
        match self.producer_key {
            Some(expected) if expected != public_key => {
                return Err(ClientError::protocol(
                    "evaluate output chunk producer key changed mid-stream",
                ));
            }
            Some(_) => {}
            None => self.producer_key = Some(public_key),
        }
        event.verify(&public_key).map_err(|source| {
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
        self.next_position = delta
            .end_position()
            .map_err(|source| ClientError::EvaluateTranscript { source })?;
        self.previous_event = event.event_commitment();
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.events.push(event);
        Ok((self.next_position, delta))
    }

    pub fn verify_terminal(&self, output_events: &[OutputEventEnvelope]) -> ClientResult<()> {
        if let Some(first) = output_events.first() {
            let first_key = *first.event().public_key();
            if let Some(pinned) = self.producer_key
                && pinned != first_key
            {
                return Err(ClientError::protocol(
                    "evaluate terminal transcript producer key does not match streamed chunks",
                ));
            }
        }
        verify_terminal_continuation(self.assurance, &self.events, output_events)
            .map_err(|source| ClientError::EvaluateTranscript { source })
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
    let Some(event) = event.kind else {
        return Err(ClientError::protocol("wire event with no body"));
    };
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
            verifier.verify_terminal(&output_events)?;
            let output = verify_output_events(input_commitment, &output_events)
                .map_err(|source| ClientError::EvaluateTranscript { source })?;
            Ok(EvaluateExecutionEvent::Done(EvaluateOutcome::Completed {
                output,
                output_events,
            }))
        }
        work_event::Kind::Failed(failed) => {
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
    use hellas_rpc::pb::execute::{WorkChunk, WorkEvent, WorkFinished, work_event};
    use hellas_rpc::stream::output_event_to_pb;
    use hellas_rpc::{ContentId, EvaluateRequest, ProducerSigningKey};

    const TEST_ASSURANCE: Assurance = Assurance::ProducerSigned;

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
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
                stop_reason: EvaluateStopReason::END_OF_SEQUENCE,
                text_artifact: Digest::from_bytes([4; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 2,
                },
                billable_units: 5,
            })
            .unwrap();

        let mut verifier = EvaluateChunkVerifier::new(input, TEST_ASSURANCE);
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
        };
        let input = hellas_rpc::evaluate::input_commitment(&request);
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, &producer);
        let chunk = builder.push_token_delta(vec![10, 11]).unwrap();
        let output_events = builder
            .finish(EvaluateTerminal {
                final_position: 2,
                stop_reason: EvaluateStopReason::END_OF_SEQUENCE,
                text_artifact: Digest::from_bytes([4; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 2,
                },
                billable_units: 5,
            })
            .unwrap();

        let mut verifier = EvaluateChunkVerifier::new(input);
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
}
