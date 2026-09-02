use std::sync::Arc;

#[cfg(test)]
use hellas_rpc::fetch::verify_output_events;
use hellas_rpc::fetch::{
    FetchInput, FetchTerminalPayload, MAX_FETCH_OUTPUT_EVENTS, MAX_FETCH_OUTPUT_PAYLOAD_BYTES,
    decode_fetch_event_payload, decode_fetch_terminal_payload, output_canonicalization,
    verify_input_events,
};
use hellas_rpc::output::OutputEvent;
use hellas_rpc::pb::execute::{self as pb, Ticket, WorkEvent, WorkFinished, work_event};
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::stream::{input_event_from_pb, output_event_from_pb};
use hellas_rpc::{
    Assurance, EventCommitment, InputCommitment, Operation, OutputEventEnvelope, PublicKey,
    StreamId, output_genesis, scheme_id, verify_output_event_continuation,
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
    Finished {
        terminal_output_event: OutputEventEnvelope,
    },
    Failed {
        position: u64,
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum FetchOutcome {
    /// A complete producer-signed output transcript.
    Completed {
        output_events: Vec<OutputEventEnvelope>,
        terminal: FetchTerminalPayload,
    },
    /// An unsigned RunTicket failure. Remote Fetch authenticates its source
    /// only through the retained verified transport; this is not transcript
    /// evidence and callers must surface it as failure.
    Failed { position: u64, error: String },
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
        let max_streamed_events = MAX_FETCH_OUTPUT_EVENTS
            .checked_sub(1)
            .expect("Fetch output limit includes one terminal event");
        if self.events.len() >= max_streamed_events {
            return Err(ClientError::protocol(format!(
                "fetch output stream exceeds the {max_streamed_events}-chunk limit"
            )));
        }
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
        let next_position = self.next_position.checked_add(payload_len).ok_or_else(|| {
            ClientError::protocol("fetch output position exceeds u64 position range")
        })?;
        if next_position > MAX_FETCH_OUTPUT_PAYLOAD_BYTES as u64 {
            return Err(ClientError::protocol(format!(
                "fetch output stream exceeds the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
            )));
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| ClientError::protocol("fetch output sequence exceeds u64 range"))?;
        self.next_position = next_position;
        self.previous_event = event.event_commitment();
        self.next_sequence = next_sequence;
        if self.producer_key.is_none() {
            self.producer_key = Some(public_key);
        }
        self.events.push(event.clone());
        Ok((self.next_position, event))
    }

    pub fn verify_terminal(
        &mut self,
        terminal: OutputEventEnvelope,
    ) -> ClientResult<FetchTerminalPayload> {
        self.ensure_open()?;
        let event_count = self.events.len().checked_add(1).ok_or_else(|| {
            ClientError::protocol("fetch terminal transcript event count exceeds usize range")
        })?;
        if event_count > MAX_FETCH_OUTPUT_EVENTS {
            return Err(ClientError::protocol(format!(
                "fetch output transcript exceeds the {MAX_FETCH_OUTPUT_EVENTS}-event limit"
            )));
        }
        if terminal.event().body().input() != self.input {
            return Err(ClientError::protocol(
                "fetch terminal event input commitment mismatch",
            ));
        }
        let terminal_key = *terminal.event().public_key();
        match self.producer_key {
            Some(pinned) if pinned != terminal_key => {
                return Err(ClientError::protocol(
                    "fetch terminal event producer key does not match streamed chunks",
                ));
            }
            Some(_) => {}
            None => {
                if !self.trust.allows(&terminal_key) {
                    return Err(ClientError::protocol(
                        "fetch terminal event signed by untrusted producer key",
                    ));
                }
            }
        }
        verify_output_event_continuation(
            scheme_id(Operation::Fetch, self.assurance),
            self.input,
            &terminal_key,
            self.next_sequence,
            self.previous_event,
            &terminal,
        )
        .map_err(|source| ClientError::FetchTranscript {
            source: source.into(),
        })?;
        let body = terminal.event().body();
        if body.kind() != "response.terminal" {
            return Err(ClientError::protocol(format!(
                "fetch terminal event must be response.terminal, got {}",
                body.kind()
            )));
        }
        if body.canonicalization() != output_canonicalization() {
            return Err(ClientError::protocol(
                "fetch terminal event canonicalization mismatch",
            ));
        }
        let terminal_payload_len = u64::try_from(terminal.payload().len()).map_err(|_| {
            ClientError::protocol("fetch terminal payload length exceeds u64 range")
        })?;
        let payload_bytes = self
            .next_position
            .checked_add(terminal_payload_len)
            .ok_or_else(|| {
                ClientError::protocol("fetch output payload length exceeds u64 range")
            })?;
        if payload_bytes > MAX_FETCH_OUTPUT_PAYLOAD_BYTES as u64 {
            return Err(ClientError::protocol(format!(
                "fetch output transcript exceeds the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
            )));
        }
        let terminal_payload =
            decode_fetch_terminal_payload(terminal.payload()).map_err(|source| {
                ClientError::source("fetch terminal payload decode failed", source)
            })?;
        self.events.push(terminal);
        self.finalized = true;
        Ok(terminal_payload)
    }

    fn verify_failed_terminal(&mut self, position: u64) -> ClientResult<()> {
        self.ensure_open()?;
        if position != self.next_position {
            return Err(ClientError::protocol(format!(
                "fetch failure position mismatch: expected {}, got {position}",
                self.next_position
            )));
        }
        self.finalized = true;
        Ok(())
    }
}

pub fn verify_fetch_work_event(
    verifier: &mut FetchChunkVerifier,
    event: WorkEvent,
) -> ClientResult<FetchExecutionEvent> {
    match convert_fetch_wire_event(event)? {
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
        DecodedFetchWireEvent::Finished {
            terminal_output_event,
        } => {
            let terminal = verifier.verify_terminal(terminal_output_event)?;
            let output_events = std::mem::take(&mut verifier.events);
            Ok(FetchExecutionEvent::Done(FetchOutcome::Completed {
                output_events,
                terminal,
            }))
        }
        DecodedFetchWireEvent::Failed { position, error } => {
            verifier.verify_failed_terminal(position)?;
            Ok(FetchExecutionEvent::Done(FetchOutcome::Failed {
                position,
                error,
            }))
        }
    }
}

fn convert_fetch_wire_event(event: WorkEvent) -> ClientResult<DecodedFetchWireEvent> {
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
        work_event::Kind::Finished(finished) => Ok(DecodedFetchWireEvent::Finished {
            terminal_output_event: decode_fetch_terminal(finished)?,
        }),
        work_event::Kind::Failed(failed) => Ok(DecodedFetchWireEvent::Failed {
            position: failed.position,
            error: failed.error,
        }),
    }
}

#[cfg(test)]
pub(crate) fn parse_fetch_finished(
    finished: WorkFinished,
    input_commitment: InputCommitment,
    assurance: Assurance,
) -> ClientResult<FetchOutcome> {
    let output_events = vec![decode_fetch_terminal(finished)?];
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

fn decode_fetch_terminal(finished: WorkFinished) -> ClientResult<OutputEventEnvelope> {
    let terminal = finished
        .terminal_output_event
        .ok_or_else(|| ClientError::protocol("fetch WorkFinished missing signed terminal event"))?;
    if terminal.payload.len() > MAX_FETCH_OUTPUT_PAYLOAD_BYTES {
        return Err(ClientError::protocol(format!(
            "fetch terminal event exceeds the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
        )));
    }
    output_event_from_pb(terminal).map_err(|source| ClientError::FetchStreamEnvelope { source })
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
    expected_provider_genesis: hellas_rpc::ContentId,
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
    if terms.provider_genesis != expected_provider_genesis {
        return Err(ClientError::protocol(
            "fetch ticket provider genesis does not match the pinned provider",
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
        encode_fetch_event_payload, encode_fetch_terminal_payload,
    };
    use hellas_rpc::output::{OutputEvent, StopReason, TextChannel};
    use hellas_rpc::stream::{input_event_to_pb, output_event_to_pb};
    use hellas_rpc::{ContentId, JobTerms, ProducerSigningKey as SigningKey, RequestCommitment};

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

    fn terminal_event(events: &[OutputEventEnvelope]) -> OutputEventEnvelope {
        events.last().expect("fixture terminal event").clone()
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
            terminal_output_event: events.last().map(output_event_to_pb),
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
    fn fetch_ticket_must_name_the_pinned_provider_genesis() {
        let caller = key(1);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let provider_genesis = b"provider enrollment".to_vec();
        let actual_provider = ContentId::hash(&provider_genesis);
        let ticket = hellas_rpc::run_ticket::ticket_to_pb(
            JobTerms {
                request: RequestCommitment::from_digest(input.digest()),
                provider_genesis: actual_provider,
                assurance: TEST_ASSURANCE,
                amount: 1,
                ttl_ms: 1_000,
            },
            provider_genesis,
        )
        .unwrap();

        let error = validate_fetch_ticket(
            ticket,
            input,
            TEST_ASSURANCE,
            ContentId::from_bytes([0x42; 32]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("pinned provider"));
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
    fn rejected_first_chunk_does_not_pin_its_producer() {
        let caller = key(1);
        let first_producer = key(2);
        let second_producer = key(3);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let other_request = fetch_request(&caller, "echo", "run", br#"{"x":2}"#);
        let input = input_commitment_for(&request);
        let other_input = input_commitment_for(&other_request);
        let invalid =
            FetchOutputTranscriptBuilder::new(other_input, TEST_ASSURANCE, &first_producer)
                .push_event(br#"{"delta":"wrong input"}"#.to_vec())
                .unwrap();
        let valid = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &second_producer)
            .push_event(br#"{"delta":"valid"}"#.to_vec())
            .unwrap();
        let mut verifier = FetchChunkVerifier::new(
            input,
            TEST_ASSURANCE,
            trust_in(&[&first_producer, &second_producer]),
        );

        assert!(
            verifier
                .verify_chunk(invalid)
                .unwrap_err()
                .to_string()
                .contains("input commitment mismatch")
        );
        verifier.verify_chunk(valid).unwrap();
        assert_eq!(verifier.producer_key, Some(second_producer.public_key()));
    }

    #[test]
    fn multi_event_replay_framing_verifies_end_to_end() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let mut streamed = Vec::new();
        for delta in ["one", "two"] {
            let payload = encode_fetch_event_payload(&OutputEvent::TextDelta {
                index: 0,
                delta: delta.to_string(),
                channel: TextChannel::Output,
            })
            .unwrap();
            streamed.push(builder.push_event(payload).unwrap());
        }
        let output_events = builder.finish(finished_terminal_payload()).unwrap();
        let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));
        let mut expected_position = 0_u64;

        for output_event in streamed {
            expected_position += output_event.payload().len() as u64;
            let wire = WorkEvent {
                kind: Some(work_event::Kind::Chunk(pb::WorkChunk {
                    output_event: Some(output_event_to_pb(&output_event)),
                })),
            };
            let FetchExecutionEvent::Chunk { position, .. } =
                verify_fetch_work_event(&mut verifier, wire).unwrap()
            else {
                panic!("replay prefix should decode as a chunk");
            };
            assert_eq!(position, expected_position);
        }

        let terminal = WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                terminal_output_event: output_events.last().map(output_event_to_pb),
                assurance_evidence: Vec::new(),
            })),
        };
        let FetchExecutionEvent::Done(FetchOutcome::Completed {
            output_events: verified,
            ..
        }) = verify_fetch_work_event(&mut verifier, terminal).unwrap()
        else {
            panic!("replay terminal should complete the transcript");
        };
        assert_eq!(verified, output_events);
    }

    #[test]
    fn verifier_bounds_retained_streamed_event_count() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));

        for _ in 0..MAX_FETCH_OUTPUT_EVENTS - 1 {
            verifier
                .verify_chunk(builder.push_event(Vec::new()).unwrap())
                .unwrap();
        }
        let error = verifier
            .verify_chunk(builder.push_event(Vec::new()).unwrap())
            .unwrap_err();

        assert!(error.to_string().contains("4095-chunk limit"));
        assert_eq!(verifier.events.len(), MAX_FETCH_OUTPUT_EVENTS - 1);
    }

    #[test]
    fn verifier_bounds_retained_streamed_payload_bytes() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));

        verifier
            .verify_chunk(
                builder
                    .push_event(vec![0; MAX_FETCH_OUTPUT_PAYLOAD_BYTES])
                    .unwrap(),
            )
            .unwrap();
        let error = verifier
            .verify_chunk(builder.push_event(vec![1]).unwrap())
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("2097152-byte signed payload limit")
        );
        assert_eq!(verifier.events.len(), 1);
        assert_eq!(
            verifier.next_position,
            MAX_FETCH_OUTPUT_PAYLOAD_BYTES as u64
        );
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
            verify_fetch_work_event(&mut verifier, failed()).unwrap(),
            FetchExecutionEvent::Done(FetchOutcome::Failed { .. })
        ));
        let error = verify_fetch_work_event(&mut verifier, failed()).unwrap_err();
        assert!(error.to_string().contains("after its terminal outcome"));
    }

    #[test]
    fn failure_position_must_match_verified_signed_prefix() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
        let chunk = builder.push_event(b"prefix".to_vec()).unwrap();
        let expected_position = chunk.payload().len() as u64;
        let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));
        verifier.verify_chunk(chunk).unwrap();

        let failed = |position| WorkEvent {
            kind: Some(work_event::Kind::Failed(pb::WorkFailed {
                position,
                error: "failed".to_string(),
            })),
        };
        let error = verify_fetch_work_event(&mut verifier, failed(0)).unwrap_err();
        assert!(error.to_string().contains("failure position mismatch"));
        assert!(matches!(
            verify_fetch_work_event(&mut verifier, failed(expected_position)).unwrap(),
            FetchExecutionEvent::Done(FetchOutcome::Failed { .. })
        ));
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
        let err = verifier
            .verify_terminal(terminal_event(&output_events))
            .unwrap_err();
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
        verifier
            .verify_terminal(terminal_event(&output_events))
            .unwrap();
    }

    #[test]
    fn malformed_terminal_payload_does_not_finalize_the_verifier() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let input = input_commitment_for(&request);
        let malformed =
            build_output_events(input, TEST_ASSURANCE, b"not DAG-CBOR", &producer).unwrap();
        let valid = build_output_events(
            input,
            TEST_ASSURANCE,
            &finished_terminal_payload(),
            &producer,
        )
        .unwrap();
        let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));

        assert!(
            verifier
                .verify_terminal(terminal_event(&malformed))
                .unwrap_err()
                .to_string()
                .contains("terminal payload decode failed")
        );
        verifier.verify_terminal(terminal_event(&valid)).unwrap();
    }

    #[test]
    fn verify_terminal_rejects_a_transcript_for_a_different_input() {
        let caller = key(1);
        let producer = key(2);
        let expected_request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let other_request = fetch_request(&caller, "echo", "run", br#"{"x":2}"#);
        let expected_input = input_commitment_for(&expected_request);
        let other_input = input_commitment_for(&other_request);
        let output_events = build_output_events(
            other_input,
            TEST_ASSURANCE,
            &finished_terminal_payload(),
            &producer,
        )
        .unwrap();
        let mut verifier =
            FetchChunkVerifier::new(expected_input, TEST_ASSURANCE, trust_in(&[&producer]));

        let error = verifier
            .verify_terminal(terminal_event(&output_events))
            .unwrap_err();

        assert!(error.to_string().contains("input commitment mismatch"));
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

        let error = verifier
            .verify_terminal(terminal_event(&output_events))
            .unwrap_err();
        assert!(error.to_string().contains("sequence mismatch"));
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
            terminal_output_event: events.last().map(output_event_to_pb),
            assurance_evidence: Vec::new(),
        };
        finished
            .terminal_output_event
            .as_mut()
            .expect("fixture terminal event")
            .payload = br#"{"x":2}"#.to_vec();

        assert!(matches!(
            parse_fetch_finished(finished, input, TEST_ASSURANCE).unwrap_err(),
            ClientError::FetchStreamEnvelope { .. } | ClientError::FetchTranscript { .. }
        ));
    }

    #[test]
    fn fetch_protocol_error_remains_source_typed() {
        let error = ClientError::FetchTranscript {
            source: FetchProtocolError::WrongInputEventCount { actual: 0 },
        };
        assert!(error.to_string().contains("fetch transcript"));
    }
}
