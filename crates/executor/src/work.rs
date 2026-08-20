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
//! Not by anything in this file. This calls the engine every time it is
//! called, and that is the honest shape for it: the caller has already
//! journaled a running marker for this `work_id`, and it is that marker
//! — not any restraint here — which means no second call will come.
//!
//! One thing this file must not do, and deliberately does not: consult
//! the engine's completed-execution map. That map is keyed by request
//! commitment, so a second paid job carrying the same request would be
//! answered out of the first one's transcript, with nothing invoked and
//! a price charged. `SchemeEngine::start_request` starts.
//!
//! # What is not covered by a test here
//!
//! That the Candle backend, given this request, produces that
//! transcript. Running it needs model weights, so no check in this
//! repository executes this path end to end; what the gate does with a
//! transcript, and how many times it asks for one, is tested against a
//! counting double at this trait in `hellas-rpc`.

use hellas_rpc::work::{BackendFault, PaidEvaluateBackend};
use hellas_rpc::{EvaluateRequest, OutputEventEnvelope};

use crate::ExecutorError;
use crate::executor::{ExecutorHandle, ExecutorMessage};

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
        request: EvaluateRequest,
    ) -> Result<Vec<OutputEventEnvelope>, ExecutorError> {
        let outcome = self
            .send(|reply| ExecutorMessage::RunPaidEvaluate { request, reply })
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
    while let Some(event) = events.recv().await {
        let event = event.map_err(|status| {
            ExecutorError::WeightsError(format!("paid evaluate stream failed: {status}"))
        })?;
        match event.kind {
            Some(work_event::Kind::Finished(finished)) => {
                let mut transcript = Vec::with_capacity(finished.output_events.len());
                for event in finished.output_events {
                    transcript.push(hellas_rpc::stream::output_event_from_pb(event).map_err(
                        |err| {
                            ExecutorError::WeightsError(format!(
                                "paid evaluate terminal event: {err}"
                            ))
                        },
                    )?);
                }
                return Ok(transcript);
            }
            Some(work_event::Kind::Failed(failed)) => {
                return Err(ExecutorError::WeightsError(format!(
                    "paid evaluate failed at position {}: {}",
                    failed.position, failed.error
                )));
            }
            // Token chunks are the streaming half of the unpaid path.
            // The paid answer is the signed transcript the terminal
            // carries, so these are read past rather than served: this
            // milestone releases no plaintext before the terminal is
            // durable, and there is nothing here to release it to.
            _ => {}
        }
    }
    Err(ExecutorError::WeightsError(
        "paid evaluate stream ended without a terminal".to_string(),
    ))
}

impl PaidEvaluateBackend for ExecutorHandle {
    async fn evaluate(
        &self,
        request: EvaluateRequest,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        self.run_paid_evaluate(request)
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
    use hellas_rpc::{Assurance, ContentId, Digest, ProducerSigningKey, Retention};
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
            stop_reason: EvaluateStopReason::END_OF_SEQUENCE,
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
    fn outcome(events: Vec<WorkEvent>) -> ExecuteOutcome {
        let (sender, receiver) = mpsc::channel(events.len().max(1));
        for event in events {
            if sender.try_send(Ok(event)).is_err() {
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

    fn finished(transcript: &[OutputEventEnvelope]) -> WorkEvent {
        WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                output_events: transcript.iter().map(output_event_to_pb).collect(),
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

    /// The answer is the transcript the terminal carries, and the token
    /// chunks that streamed past it are not part of it.
    #[tokio::test]
    async fn the_answer_is_the_terminals_transcript_and_not_the_chunks() {
        let expected = transcript();
        let events = vec![chunk(), chunk(), finished(&expected)];
        match drain_transcript(outcome(events)).await {
            Ok(drained) => assert_eq!(drained, expected),
            Err(error) => panic!("a finished execution has a transcript: {error}"),
        }
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
                    error: "the weights did not load".to_string(),
                })),
            },
        ];
        let Err(error) = drain_transcript(outcome(events)).await else {
            panic!("a failed execution has no transcript");
        };
        let text = error.to_string();
        assert!(text.contains("the weights did not load"), "{text}");
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

    /// Retention is the user's artifact policy and not the protocol's
    /// evidence policy.
    ///
    /// A `retain=false` request is the one whose transcript the artifact
    /// store will not keep, and it is drained here exactly as a retained
    /// one is: what the paid endpoint journals is the signed result, and
    /// this seam never consults the store that retention governs.
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
            stop_reason: EvaluateStopReason::END_OF_SEQUENCE,
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

        match drain_transcript(outcome(vec![finished(&events)])).await {
            Ok(drained) => assert_eq!(drained, events),
            Err(error) => panic!("an ephemeral request still has a transcript: {error}"),
        }

        // And it is a different transcript than the retained request's,
        // because the request commitment binds retention.
        assert_ne!(events, transcript());
    }
}
