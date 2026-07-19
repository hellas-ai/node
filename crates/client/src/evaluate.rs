use hellas_rpc::evaluate::{
    EvaluateTokenDelta, TOKEN_DELTA_EVENT_KIND, decode_token_delta_payload,
    output_canonicalization, verify_terminal_continuation,
};
use hellas_rpc::{
    Digest, EventCommitment, InputCommitment, OutputEventEnvelope, PublicKey, SchemeId, StreamId,
    output_genesis,
};

use crate::{ClientError, ClientResult};

pub struct EvaluateChunkVerifier {
    input: InputCommitment,
    stream_id: StreamId,
    previous_event: EventCommitment,
    next_sequence: u64,
    next_position: u64,
    producer_key: Option<PublicKey>,
    events: Vec<OutputEventEnvelope>,
}

impl EvaluateChunkVerifier {
    pub fn new(input: InputCommitment) -> Self {
        let stream_id = StreamId::from_input_commitment(input);
        Self {
            input,
            stream_id,
            previous_event: output_genesis(input, stream_id),
            next_sequence: 0,
            next_position: 0,
            producer_key: None,
            events: Vec::new(),
        }
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
        if body.scheme() != SchemeId::Evaluate {
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
        verify_terminal_continuation(&self.events, output_events)
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

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::evaluate::{
        EvaluateOutputTranscriptBuilder, EvaluateProtocolError, EvaluateStopReason,
        EvaluateTerminal, EvaluateUsage, input_commitment,
    };
    use hellas_rpc::{ContentId, EvaluateRequest, ProducerSigningKey};

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
        };
        let input = input_commitment(&request);
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, &producer);
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

        let mut verifier = EvaluateChunkVerifier::new(input);
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
}
