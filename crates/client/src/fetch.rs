use std::sync::Arc;

use hellas_rpc::fetch::{
    FetchInput, FetchTerminalPayload, decode_fetch_event_payload, decode_fetch_terminal_payload,
    output_canonicalization, verify_input_events, verify_output_events,
};
use hellas_rpc::output::OutputEvent;
use hellas_rpc::pb::execute::{self as pb, Ticket, WorkEvent, WorkFinished, work_event};
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::stream::{input_event_from_pb, output_event_from_pb};
use hellas_rpc::{
    Assurance, EventCommitment, InputCommitment, Operation, OutputEventEnvelope, PublicKey,
    StreamId, output_genesis, scheme_id,
};

use crate::{ClientError, ClientResult};

// Stream items move once per chunk; boxing the envelope would trade a large
// move for a per-chunk allocation with no call-site benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum FetchExecutionEvent {
    Chunk {
        position: u64,
        output_event: OutputEventEnvelope,
        event: OutputEvent,
    },
    Done(FetchOutcome),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum DecodedFetchWireEvent {
    Chunk {
        output_event: OutputEventEnvelope,
        event: OutputEvent,
    },
    Done(FetchOutcome),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FetchOutcome {
    Completed {
        output_events: Vec<OutputEventEnvelope>,
        terminal: FetchTerminalPayload,
    },
    Failed {
        position: u64,
        error: String,
    },
}

/// Producer keys a fetch caller accepts signed output from.
#[derive(Clone, Debug)]
pub struct ProducerTrust {
    keys: Arc<Vec<PublicKey>>,
}

impl ProducerTrust {
    pub fn keys(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            keys: Arc::new(keys.into_iter().collect()),
        }
    }

    fn allows(&self, key: &PublicKey) -> bool {
        self.keys.contains(key)
    }
}

pub struct FetchChunkVerifier {
    input: InputCommitment,
    stream_id: StreamId,
    previous_event: EventCommitment,
    next_sequence: u64,
    next_position: u64,
    trust: ProducerTrust,
    producer_key: Option<PublicKey>,
    assurance: Assurance,
    events: Vec<OutputEventEnvelope>,
    finalized: bool,
}

impl FetchChunkVerifier {
    pub fn new(input: InputCommitment, assurance: Assurance, trust: ProducerTrust) -> Self {
        let stream_id = StreamId::from_input_commitment(input);
        Self {
            input,
            stream_id,
            previous_event: output_genesis(input, stream_id),
            next_sequence: 0,
            next_position: 0,
            trust,
            producer_key: None,
            assurance,
            events: Vec::new(),
            finalized: false,
        }
    }

    fn ensure_open(&self) -> ClientResult<()> {
        if self.finalized {
            Err(ClientError::protocol(
                "fetch stream emitted an event after its terminal outcome",
            ))
        } else {
            Ok(())
        }
    }

    pub fn verify_chunk(
        &mut self,
        event: OutputEventEnvelope,
    ) -> ClientResult<(u64, OutputEventEnvelope)> {
        self.ensure_open()?;
        let public_key = *event.event().public_key();
        match self.producer_key {
            Some(expected) if expected != public_key => {
                return Err(ClientError::protocol(
                    "fetch output chunk producer key changed mid-stream",
                ));
            }
            Some(_) => {}
            None => {
                if !self.trust.allows(&public_key) {
                    return Err(ClientError::protocol(
                        "fetch output chunk signed by untrusted producer key",
                    ));
                }
                self.producer_key = Some(public_key);
            }
        }
        event.verify(&public_key).map_err(|source| {
            ClientError::source("fetch output chunk signature verification failed", source)
        })?;
        let body = event.event().body();
        if body.scheme() != scheme_id(Operation::Fetch, self.assurance) {
            return Err(ClientError::protocol(
                "fetch output chunk used the wrong scheme",
            ));
        }
        if body.input() != self.input {
            return Err(ClientError::protocol(
                "fetch output chunk input commitment mismatch",
            ));
        }
        if body.stream_id() != self.stream_id {
            return Err(ClientError::protocol(
                "fetch output chunk stream id mismatch",
            ));
        }
        if body.sequence() != self.next_sequence {
            return Err(ClientError::protocol(format!(
                "fetch output chunk sequence mismatch: expected {}, got {}",
                self.next_sequence,
                body.sequence()
            )));
        }
        if body.previous_event() != self.previous_event {
            return Err(ClientError::protocol(
                "fetch output chunk previous-event mismatch",
            ));
        }
        if body.kind() != "response.event" {
            return Err(ClientError::protocol(format!(
                "fetch output chunk must be response.event, got {}",
                body.kind()
            )));
        }
        if body.canonicalization() != output_canonicalization() {
            return Err(ClientError::protocol(
                "fetch output chunk canonicalization mismatch",
            ));
        }
        let payload_len = u64::try_from(event.payload().len()).map_err(|_| {
            ClientError::protocol("fetch output chunk length exceeds u64 position range")
        })?;
        self.next_position = self.next_position.checked_add(payload_len).ok_or_else(|| {
            ClientError::protocol("fetch output position exceeds u64 position range")
        })?;
        self.previous_event = event.event_commitment();
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.events.push(event.clone());
        Ok((self.next_position, event))
    }

    pub fn verify_terminal(&mut self, output_events: &[OutputEventEnvelope]) -> ClientResult<()> {
        self.ensure_open()?;
        let expected_event_count = self.events.len().checked_add(1).ok_or_else(|| {
            ClientError::protocol("fetch terminal transcript event count exceeds usize range")
        })?;
        if output_events.len() != expected_event_count {
            return Err(ClientError::protocol(format!(
                "fetch terminal transcript must extend the streamed prefix by exactly one terminal event: expected {expected_event_count} events, got {}",
                output_events.len()
            )));
        }
        // `verify_terminal_continuation` checks every signature against the
        // first event's key, so binding that key here covers the transcript.
        if let Some(first) = output_events.first() {
            let first_key = *first.event().public_key();
            match self.producer_key {
                Some(pinned) if pinned != first_key => {
                    return Err(ClientError::protocol(
                        "fetch terminal transcript producer key does not match streamed chunks",
                    ));
                }
                Some(_) => {}
                None => {
                    if !self.trust.allows(&first_key) {
                        return Err(ClientError::protocol(
                            "fetch terminal transcript signed by untrusted producer key",
                        ));
                    }
                }
            }
        }
        hellas_rpc::fetch::verify_terminal_continuation(
            self.assurance,
            &self.events,
            output_events,
        )
        .map_err(|source| ClientError::FetchTranscript { source })?;
        self.finalized = true;
        Ok(())
    }

    fn verify_failed_terminal(&mut self) -> ClientResult<()> {
        self.ensure_open()?;
        self.finalized = true;
        Ok(())
    }
}

pub fn verify_fetch_work_event(
    verifier: &mut FetchChunkVerifier,
    event: WorkEvent,
    input_commitment: InputCommitment,
) -> ClientResult<FetchExecutionEvent> {
    match convert_fetch_wire_event(event, input_commitment, verifier.assurance)? {
        DecodedFetchWireEvent::Chunk {
            output_event,
            event,
        } => {
            let (position, output_event) = verifier.verify_chunk(output_event)?;
            Ok(FetchExecutionEvent::Chunk {
                position,
                output_event,
                event,
            })
        }
        DecodedFetchWireEvent::Done(outcome) => {
            match &outcome {
                FetchOutcome::Completed { output_events, .. } => {
                    verifier.verify_terminal(output_events)?;
                }
                FetchOutcome::Failed { .. } => verifier.verify_failed_terminal()?,
            }
            Ok(FetchExecutionEvent::Done(outcome))
        }
    }
}

fn convert_fetch_wire_event(
    event: WorkEvent,
    input_commitment: InputCommitment,
    assurance: Assurance,
) -> ClientResult<DecodedFetchWireEvent> {
    let Some(event) = event.kind else {
        return Err(ClientError::protocol("wire event with no body"));
    };
    match event {
        work_event::Kind::Chunk(chunk) => {
            let output_event = chunk.output_event.ok_or_else(|| {
                ClientError::protocol("fetch work chunk missing signed output event")
            })?;
            let output_event = output_event_from_pb(output_event)
                .map_err(|source| ClientError::FetchStreamEnvelope { source })?;
            let event = decode_fetch_event_payload(output_event.payload()).map_err(|source| {
                ClientError::source("fetch output event payload decode failed", source)
            })?;
            Ok(DecodedFetchWireEvent::Chunk {
                output_event,
                event,
            })
        }
        work_event::Kind::Finished(finished) => Ok(DecodedFetchWireEvent::Done(
            parse_fetch_finished(finished, input_commitment, assurance)?,
        )),
        work_event::Kind::Failed(failed) => Ok(DecodedFetchWireEvent::Done(FetchOutcome::Failed {
            position: failed.position,
            error: failed.error,
        })),
    }
}

pub fn parse_fetch_finished(
    finished: WorkFinished,
    input_commitment: InputCommitment,
    assurance: Assurance,
) -> ClientResult<FetchOutcome> {
    let output_events = finished
        .output_events
        .into_iter()
        .map(output_event_from_pb)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ClientError::FetchStreamEnvelope { source })?;
    let output = verify_output_events(input_commitment, assurance, &output_events)
        .map_err(|source| ClientError::FetchTranscript { source })?;
    let (_, terminal_payload) = output.output_event_payloads();
    let terminal = decode_fetch_terminal_payload(terminal_payload)
        .map_err(|source| ClientError::source("fetch terminal payload decode failed", source))?;
    Ok(FetchOutcome::Completed {
        output_events,
        terminal,
    })
}

pub fn verified_fetch_input(request: &FetchRequest) -> ClientResult<FetchInput> {
    let input = request
        .input
        .iter()
        .cloned()
        .map(input_event_from_pb)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ClientError::FetchStreamEnvelope { source })?;
    verify_input_events(&input).map_err(|source| ClientError::FetchTranscript { source })
}

pub fn validate_fetch_ticket(
    ticket: pb::Ticket,
    input_commitment: InputCommitment,
    assurance: Assurance,
) -> ClientResult<Ticket> {
    let request_commitment: [u8; 32] =
        ticket
            .request_commitment
            .as_slice()
            .try_into()
            .map_err(|_| {
                ClientError::protocol(format!(
                    "fetch ticket request_commitment must be 32 bytes, got {}",
                    ticket.request_commitment.len()
                ))
            })?;
    if request_commitment != *input_commitment.as_bytes() {
        return Err(ClientError::protocol(
            "fetch ticket request_commitment does not match signed input transcript",
        ));
    }
    let terms = hellas_rpc::run_ticket::job_terms_from_pb(&ticket)
        .map_err(|source| ClientError::source("invalid fetch ticket terms", source))?;
    if terms.assurance != assurance {
        return Err(ClientError::protocol(
            "fetch ticket assurance does not match signed input transcript",
        ));
    }
    Ok(ticket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::ProducerSigningKey;
    use hellas_rpc::fetch::{
        FetchOutputTranscriptBuilder, FetchProtocolError, build_input_events, build_output_events,
        encode_fetch_terminal_payload,
    };
    use hellas_rpc::output::{OutputEvent, StopReason};
    use hellas_rpc::stream::{input_event_to_pb, output_event_to_pb};
    use hellas_rpc::{ContentId, ProducerSigningKey as SigningKey};

    const TEST_ASSURANCE: Assurance = Assurance::ProducerSigned;

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
    }

    fn fetch_request(
        caller: &SigningKey,
        service: &str,
        method: &str,
        payload: &[u8],
    ) -> FetchRequest {
        let events = build_input_events(
            service,
            method,
            payload,
            ContentId::from_bytes([9; 32]),
            TEST_ASSURANCE,
            caller,
        )
        .unwrap();
        FetchRequest {
            input: events.iter().map(input_event_to_pb).collect(),
        }
    }

    fn finished_terminal_payload() -> Vec<u8> {
        encode_fetch_terminal_payload(&OutputEvent::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
        })
        .unwrap()
    }

    fn fetch_finished(
        request: &FetchRequest,
        producer: &SigningKey,
        terminal_payload: &[u8],
    ) -> WorkFinished {
        let input = verified_fetch_input(request).unwrap().input_commitment;
        let events =
            build_output_events(input, TEST_ASSURANCE, terminal_payload, producer).unwrap();
        WorkFinished {
            output_events: events.iter().map(output_event_to_pb).collect(),
            assurance_evidence: Vec::new(),
        }
    }

    fn trust_in(producers: &[&SigningKey]) -> ProducerTrust {
        ProducerTrust::keys(producers.iter().map(|key| key.public_key()))
    }

    fn input_commitment_for(request: &FetchRequest) -> InputCommitment {
        verified_fetch_input(request).unwrap().input_commitment
    }

    #[test]
    fn fetch_finished_verifies_signed_output_transcript() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let terminal_payload = finished_terminal_payload();
        let finished = fetch_finished(&request, &producer, &terminal_payload);

        let input = input_commitment_for(&request);
        let outcome = parse_fetch_finished(finished, input, TEST_ASSURANCE).unwrap();
        let FetchOutcome::Completed {
            terminal,
            output_events,
        } = outcome
        else {
            panic!("expected completed fetch outcome");
        };
        assert_eq!(
            terminal,
            FetchTerminalPayload::Finished {
                stop_reason: StopReason::EndOfText,
                usage: None,
                billable_units: 0,
            }
        );
        assert_eq!(output_events.len(), 1);
    }

    #[test]
    fn verify_chunk_rejects_untrusted_producer_key() {
        let caller = key(1);
        let producer = key(2);
        let trusted_producer = key(3);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let chunk = builder.push_event(br#"{"delta":"a"}"#.to_vec()).unwrap();

        let mut verifier =
            FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&trusted_producer]));
        let err = verifier.verify_chunk(chunk).unwrap_err();
        assert!(err.to_string().contains("untrusted producer key"));
    }

    #[test]
    fn verify_chunk_accepts_trusted_producer_key() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let chunk = builder.push_event(br#"{"delta":"a"}"#.to_vec()).unwrap();

        let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));
        verifier.verify_chunk(chunk).unwrap();
    }

    #[test]
    fn verifier_rejects_events_after_terminal_outcome() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));
        let failed = || WorkEvent {
            kind: Some(work_event::Kind::Failed(pb::WorkFailed {
                position: 0,
                error: "failed".to_string(),
            })),
        };

        assert!(matches!(
            verify_fetch_work_event(&mut verifier, failed(), input).unwrap(),
            FetchExecutionEvent::Done(FetchOutcome::Failed { .. })
        ));
        let error = verify_fetch_work_event(&mut verifier, failed(), input).unwrap_err();
        assert!(error.to_string().contains("after its terminal outcome"));
    }

    #[test]
    fn verify_terminal_rejects_untrusted_producer_without_streamed_chunks() {
        let caller = key(1);
        let producer = key(2);
        let trusted_producer = key(3);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let output_events = build_output_events(
            input,
            TEST_ASSURANCE,
            &finished_terminal_payload(),
            &producer,
        )
        .unwrap();

        let mut verifier =
            FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&trusted_producer]));
        let err = verifier.verify_terminal(&output_events).unwrap_err();
        assert!(err.to_string().contains("untrusted producer key"));
    }

    #[test]
    fn verify_terminal_accepts_trusted_producer_without_streamed_chunks() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let output_events = build_output_events(
            input,
            TEST_ASSURANCE,
            &finished_terminal_payload(),
            &producer,
        )
        .unwrap();

        let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));
        verifier.verify_terminal(&output_events).unwrap();
    }

    #[test]
    fn fetch_terminal_cannot_hide_an_unstreamed_response_event() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        builder
            .push_event(br#"{"delta":"hidden"}"#.to_vec())
            .unwrap();
        let output_events = builder.finish(finished_terminal_payload()).unwrap();
        let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));

        let error = verifier.verify_terminal(&output_events).unwrap_err();
        assert!(error.to_string().contains("exactly one terminal event"));
    }

    #[test]
    fn fetch_finished_rejects_tampered_output_event_payload() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let events = build_output_events(
            input,
            TEST_ASSURANCE,
            &finished_terminal_payload(),
            &producer,
        )
        .unwrap();
        let mut finished = WorkFinished {
            output_events: events.iter().map(output_event_to_pb).collect(),
            assurance_evidence: Vec::new(),
        };
        finished.output_events[0].payload = br#"{"x":2}"#.to_vec();

        assert!(matches!(
            parse_fetch_finished(finished, input, TEST_ASSURANCE).unwrap_err(),
            ClientError::FetchStreamEnvelope { .. } | ClientError::FetchTranscript { .. }
        ));
    }

    #[test]
    fn fetch_protocol_error_remains_source_typed() {
        let error = ClientError::FetchTranscript {
            source: FetchProtocolError::EmptyInputTranscript,
        };
        assert!(error.to_string().contains("fetch transcript"));
    }
}
