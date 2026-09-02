//! The provider's real execution backend, behind the paid gate.
//!
//! # What this is
//!
//! One implementation of [`PaidEvaluateBackend`], over this crate's own
//! Evaluate engine. The gate that decides whether a backend may be
//! called at all is [`hellas_rpc::work::run_accepted_work`]'s, and it is
//! not here: it belongs beside the journal that records the decision,
//! and a second copy of it in front of one backend would be a second
//! opinion about when a paid job may run.
//!
//! So what is here is exactly the seam. A request that this endpoint
//! rebuilt from its own journal goes in; the complete signed transcript
//! of one invocation comes back, or a fault does.
//!
//! # Invoked once
//!
//! Not by anything in this file. This starts the engine every time it is
//! called, and that is the honest shape for it: what makes a second call
//! not come is the running marker the gate journaled, and nothing here
//! can see one.
//!
//! Which is also to say what this is not: a paid gate on the executor's
//! own front door. An owner of the [`ExecutorHandle`] can call it
//! directly and get an execution for nothing, because the handle is held
//! in-process and no RPC route exposes it.
//!
//! One thing this file must not do, and deliberately does not: consult
//! the engine's completed-execution map. That map is keyed by request
//! commitment, so a second paid job carrying the same request would be
//! answered out of the first one's transcript, with nothing invoked and
//! a price charged. `EvaluateEngine::start_prepared_input` instead creates
//! one fresh invocation and hands it to the actor's owed FIFO exactly once.
//!
//! # What is not covered by a test here
//!
//! That the exact Catena environment, given this request, produces that
//! transcript. Running it needs a compatible GPU and the committed content,
//! so the ordinary unit suite does not execute this path end to end; the ROCm
//! integration test does. What the gate does with a transcript, and how many
//! times it asks for one, is tested against a counting double at this trait in
//! `hellas-rpc`.

use crate::ExecutorError;
use crate::executor::{ExecutorHandle, ExecutorOwedRequest};
use hellas_rpc::OutputEventEnvelope;
use hellas_rpc::work::{BackendFault, PaidEvaluateBackend, PreparedEvaluateInput};

impl ExecutorHandle {
    /// Runs one already-authorized paid job to its terminal.
    ///
    /// The receiver is owned by this future, not by a transport. A
    /// caller that disconnects mid-generation therefore detaches its own
    /// reader and nothing else — the invocation is not cancelled by the
    /// wire, because the wire never held it.
    ///
    /// # Errors
    ///
    /// [`ExecutorError`] when the engine will not start the request,
    /// when the stream ends without a terminal, when the execution
    /// failed, or when an event does not decode.
    pub async fn run_paid_evaluate(
        &self,
        input: PreparedEvaluateInput,
    ) -> Result<Vec<OutputEventEnvelope>, ExecutorError> {
        // The actor admits this durable obligation exactly once. If the GPU
        // worker is occupied, EvaluateEngine retains it in its owed FIFO and
        // dispatches it ahead of peer-admitted work.
        let outcome = self
            .send_owed(|reply| ExecutorOwedRequest::RunPaidEvaluate {
                input: Box::new(input),
                reply,
            })
            .await?;
        drain_transcript(outcome).await
    }
}

/// Reads one execution's events to its end, and returns the transcript
/// it finished with.
///
/// A failure and a stream that simply stops are two different faults and
/// are reported as two: the first is what the engine said went wrong,
/// the second is that it never said anything.
async fn drain_transcript(
    outcome: crate::executor::ExecuteOutcome,
) -> Result<Vec<OutputEventEnvelope>, ExecutorError> {
    use hellas_rpc::pb::execute::work_event;

    let mut events = outcome.events;
    let mut transcript = Vec::new();
    let mut terminal_seen = false;
    while let Some(event) = events.recv().await {
        if terminal_seen {
            return Err(ExecutorError::Execution(
                "paid evaluate stream emitted an item after its terminal outcome".to_string(),
            ));
        }
        let event = event.map_err(|status| {
            ExecutorError::Execution(format!("paid evaluate stream failed: {status}"))
        })?;
        match event.kind {
            Some(work_event::Kind::Chunk(chunk)) => {
                let event = chunk.output_event.ok_or_else(|| {
                    ExecutorError::Execution(
                        "paid evaluate chunk is missing its signed output event".to_string(),
                    )
                })?;
                transcript.push(hellas_rpc::stream::output_event_from_pb(event).map_err(
                    |err| ExecutorError::Execution(format!("paid evaluate output event: {err}")),
                )?);
            }
            Some(work_event::Kind::Finished(finished)) => {
                let event = finished.terminal_output_event.ok_or_else(|| {
                    ExecutorError::Execution(
                        "paid evaluate completion is missing its signed terminal event".to_string(),
                    )
                })?;
                transcript.push(hellas_rpc::stream::output_event_from_pb(event).map_err(
                    |err| ExecutorError::Execution(format!("paid evaluate terminal event: {err}")),
                )?);
                terminal_seen = true;
            }
            Some(work_event::Kind::Failed(failed)) => {
                return Err(ExecutorError::Execution(format!(
                    "paid evaluate failed at position {}: {}",
                    failed.position, failed.error
                )));
            }
            None => {
                return Err(ExecutorError::Execution(
                    "paid evaluate stream event has no body".to_string(),
                ));
            }
        }
    }
    if terminal_seen {
        Ok(transcript)
    } else {
        Err(ExecutorError::Execution(
            "paid evaluate stream ended without a terminal".to_string(),
        ))
    }
}

impl PaidEvaluateBackend for ExecutorHandle {
    async fn evaluate(
        &self,
        input: PreparedEvaluateInput,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        self.run_paid_evaluate(input)
            .await
            .map_err(|error| BackendFault::new(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hellas_rpc::evaluate::{
        EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
        input_commitment,
    };
    use hellas_rpc::pb::execute::{WorkChunk, WorkEvent, WorkFailed, WorkFinished, work_event};
    use hellas_rpc::provenance::ExecutionProvenance;
    use hellas_rpc::stream::output_event_to_pb;
    use hellas_rpc::{
        Assurance, ContentId, Digest, EvaluateRequest, ProducerSigningKey, Retention,
    };
    use tokio::sync::mpsc;

    use crate::executor::ExecuteOutcome;

    fn key() -> ProducerSigningKey {
        match ProducerSigningKey::from_secret_bytes([0x22; 32]) {
            Ok(key) => key,
            Err(error) => panic!("a fixed scalar is a producer key: {error}"),
        }
    }

    fn request() -> EvaluateRequest {
        EvaluateRequest {
            text_execution: Digest::from_bytes([0x31; 32]),
            runner_public_key: key().public_key(),
            execution_environment: ContentId::from_bytes([0x32; 32]),
            nonce: [0x33; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
        }
    }

    /// One complete signed transcript for [`request`].
    fn transcript() -> Vec<OutputEventEnvelope> {
        let request = request();
        let signer = key();
        let mut builder = EvaluateOutputTranscriptBuilder::new(
            input_commitment(&request),
            request.assurance,
            &signer,
        );
        if let Err(error) = builder.push_token_delta(vec![7, 8]) {
            panic!("a non-empty delta pushes: {error}");
        }
        let usage = EvaluateUsage {
            input_units: 3,
            output_units: 2,
        };
        let terminal = EvaluateTerminal {
            final_position: 2,
            stop_reason: EvaluateStopReason::STOP_TOKEN,
            matched_stop_token_id: Some(1),
            text_artifact: Digest::from_bytes([0x77; 32]),
            usage,
            billable_units: 5,
        };
        match builder.finish(terminal) {
            Ok(events) => events,
            Err(error) => panic!("the fixture transcript finishes: {error}"),
        }
    }

    /// An execution whose stream is exactly `events`, already ended.
    fn outcome_items(events: Vec<Result<WorkEvent, hellas_wire::WireStatus>>) -> ExecuteOutcome {
        let (sender, receiver) = mpsc::channel(events.len().max(1));
        for event in events {
            if sender.try_send(event).is_err() {
                panic!("the fixture channel takes its own events");
            }
        }
        drop(sender);
        ExecuteOutcome {
            provenance: ExecutionProvenance {
                commitment_id: [0; 32],
            },
            events: receiver,
        }
    }

    fn outcome(events: Vec<WorkEvent>) -> ExecuteOutcome {
        outcome_items(events.into_iter().map(Ok).collect())
    }

    fn finished(transcript: &[OutputEventEnvelope]) -> WorkEvent {
        let terminal = transcript.last().expect("fixture terminal event");
        WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                terminal_output_event: Some(output_event_to_pb(terminal)),
                assurance_evidence: Vec::new(),
            })),
        }
    }

    /// One streamed token-delta chunk, carrying a real signed event, as
    /// the worker emits during generation.
    fn chunk() -> WorkEvent {
        let Some(first) = transcript().first().map(output_event_to_pb) else {
            panic!("the fixture transcript has a first event");
        };
        WorkEvent {
            kind: Some(work_event::Kind::Chunk(WorkChunk {
                output_event: Some(first),
            })),
        }
    }

    /// Prefix chunks and the singular terminal frame reconstruct one transcript.
    #[tokio::test]
    async fn the_answer_combines_prefix_chunks_and_terminal() {
        let expected = transcript();
        let events = vec![chunk(), finished(&expected)];
        match drain_transcript(outcome(events)).await {
            Ok(drained) => assert_eq!(drained, expected),
            Err(error) => panic!("a finished execution has a transcript: {error}"),
        }
    }

    #[tokio::test]
    async fn a_post_terminal_event_is_a_protocol_fault() {
        let transcript = transcript();
        for suffix in [chunk(), finished(&transcript)] {
            let events = vec![chunk(), finished(&transcript), suffix];
            let error = drain_transcript(outcome(events))
                .await
                .expect_err("an event after WorkFinished must be rejected");
            assert!(error.to_string().contains("after its terminal outcome"));
        }
    }

    #[tokio::test]
    async fn a_post_terminal_stream_error_is_a_protocol_fault() {
        let transcript = transcript();
        let events = vec![
            Ok(chunk()),
            Ok(finished(&transcript)),
            Err(hellas_wire::WireStatus::internal("late transport failure")),
        ];
        let error = drain_transcript(outcome_items(events))
            .await
            .expect_err("an error after WorkFinished must be rejected");
        assert!(error.to_string().contains("after its terminal outcome"));
    }

    /// A failed execution is a fault, not an empty answer.
    ///
    /// The difference matters to the gate above: a fault ends the job
    /// and charges the client nothing, while an empty transcript would
    /// be offered to `terminal_result` as if the provider had computed
    /// something.
    #[tokio::test]
    async fn a_failed_execution_is_a_fault() {
        let events = vec![
            chunk(),
            WorkEvent {
                kind: Some(work_event::Kind::Failed(WorkFailed {
                    position: 4,
                    error: "the Catena environment did not run".to_string(),
                })),
            },
        ];
        let Err(error) = drain_transcript(outcome(events)).await else {
            panic!("a failed execution has no transcript");
        };
        let text = error.to_string();
        assert!(
            text.contains("the Catena environment did not run"),
            "{text}"
        );
        assert!(text.contains('4'), "{text}");
    }

    /// A stream that stops without saying anything is a fault too.
    #[tokio::test]
    async fn a_stream_without_a_terminal_is_a_fault() {
        for events in [Vec::new(), vec![chunk()]] {
            let Err(error) = drain_transcript(outcome(events)).await else {
                panic!("a stream with no terminal has no transcript");
            };
            assert!(error.to_string().contains("without a terminal"), "{error}",);
        }
    }

    /// Retention is a field of the request, not a gate on this seam.
    ///
    /// A `retain=false` request is drained here exactly as a retained one
    /// is, and the transcript that comes back is complete — which is
    /// what the paid endpoint needs, because the evidence it journals is
    /// the signed result and not a stored artifact. Nothing here reads
    /// the artifact store, so nothing here can suppress the answer.
    ///
    /// It says nothing about artifact publication. The evaluate engine
    /// computes an ephemeral result without publishing its token graph.
    #[tokio::test]
    async fn an_unretained_request_still_yields_its_transcript() {
        let mut unretained = request();
        unretained.retain = false;
        assert_eq!(unretained.retention(), Retention::Ephemeral);
        assert_eq!(
            unretained.text_execution,
            request().text_execution,
            "retention is the only thing varied",
        );

        let signer = key();
        let mut builder = EvaluateOutputTranscriptBuilder::new(
            input_commitment(&unretained),
            unretained.assurance,
            &signer,
        );
        if let Err(error) = builder.push_token_delta(vec![7, 8]) {
            panic!("a non-empty delta pushes: {error}");
        }
        let events = match builder.finish(EvaluateTerminal {
            final_position: 2,
            stop_reason: EvaluateStopReason::STOP_TOKEN,
            matched_stop_token_id: Some(1),
            text_artifact: Digest::from_bytes([0x77; 32]),
            usage: EvaluateUsage {
                input_units: 3,
                output_units: 2,
            },
            billable_units: 5,
        }) {
            Ok(events) => events,
            Err(error) => panic!("the fixture transcript finishes: {error}"),
        };

        let prefix = WorkEvent {
            kind: Some(work_event::Kind::Chunk(WorkChunk {
                output_event: events.first().map(output_event_to_pb),
            })),
        };
        match drain_transcript(outcome(vec![prefix, finished(&events)])).await {
            Ok(drained) => assert_eq!(drained, events),
            Err(error) => panic!("an ephemeral request still has a transcript: {error}"),
        }

        // And it is a different transcript than the retained request's,
        // because the request commitment binds retention.
        assert_ne!(events, transcript());
    }
}
