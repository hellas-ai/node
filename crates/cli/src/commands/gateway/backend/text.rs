use async_stream::try_stream;
use futures::StreamExt;
use hellas_adaptors::{BackendError, OutputEvent, TextChannel};

use crate::execution::Outcome;

use super::super::state::PreparedGeneration;
use super::generation::{GenerationEvent, generation_stream};
use super::provenance::{provenance_from_execution, stop_reason_from_runtime, usage};

pub(super) fn text_events(
    prepared: PreparedGeneration,
) -> impl futures::Stream<Item = Result<OutputEvent, BackendError>> + Send {
    try_stream! {
        let prompt_tokens = prepared.prompt_tokens;
        let stream_provenance = prepared.provenance.clone();
        let deadline = prepared.deadline();
        let inner = generation_stream(prepared);
        tokio::pin!(inner);

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Delta(delta)))) => {
                    yield OutputEvent::TextDelta {
                        index: 0,
                        delta,
                        channel: TextChannel::Output,
                    };
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Completed {
                    total_tokens,
                    stop_reason,
                    text_artifact,
                    ..
                })))) => {
                    info!(
                        %text_artifact,
                        provenance = ?stream_provenance,
                        total_tokens,
                        ?stop_reason,
                        "gateway stream ready"
                    );
                    if let Some(provenance) = stream_provenance.as_ref().map(provenance_from_execution) {
                        yield OutputEvent::Provenance(provenance);
                    }
                    yield OutputEvent::Finished {
                        stop_reason: stop_reason_from_runtime(stop_reason),
                        usage: Some(usage(prompt_tokens, total_tokens)),
                    };
                    return;
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Failed { error, .. })))) => {
                    Err(BackendError::failed(format!("Inference error: {error}")))?;
                }
                Ok(Some(Err(err))) => Err(err)?,
                Ok(None) => Err(BackendError::failed("execution stream ended without terminal outcome"))?,
                Err(_) => Err(BackendError::failed(format!(
                    "inference timed out after {}s",
                    super::super::timeout_secs_until(deadline)
                )))?,
            }
        }
    }
}
