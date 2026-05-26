use async_stream::try_stream;
use futures::StreamExt;
use hellas_wire_adaptors::{BackendError, ExecutionResult, OutputEvent, OutputItem, TextChannel};

use crate::execution::Outcome;

use super::super::state::PreparedGeneration;
use super::generation::{GenerationEvent, TextGenerationError, collect_text, generation_stream};
use super::provenance::{
    provenance_from_execution, provenance_from_parts, stop_reason_from_runtime, usage,
};

pub(super) async fn execute_text(
    prepared: PreparedGeneration,
    ready_message: &'static str,
) -> Result<ExecutionResult, BackendError> {
    let prompt_tokens = prepared.prompt_tokens;
    let completed = collect_text(prepared)
        .await
        .map_err(text_generation_error)?;
    info!(
        receipt_commitment = %completed.receipt_commitment,
        provenance = ?completed.provenance,
        total_tokens = completed.total_tokens,
        stop_reason = ?completed.stop_reason,
        message = ready_message,
        "gateway response ready"
    );
    Ok(ExecutionResult {
        output: vec![OutputItem::Text {
            text: completed.text,
            channel: TextChannel::Output,
        }],
        usage: Some(usage(prompt_tokens, completed.total_tokens)),
        stop_reason: stop_reason_from_runtime(completed.stop_reason),
        provenance: provenance_from_parts(
            completed.provenance.as_ref(),
            Some(&completed.receipt_commitment),
        ),
    })
}

pub(super) fn text_events(
    prepared: PreparedGeneration,
    ready_message: &'static str,
) -> impl futures::Stream<Item = Result<OutputEvent, BackendError>> + Send {
    try_stream! {
        let prompt_tokens = prepared.prompt_tokens;
        let mut stream_provenance = prepared.provenance.clone();
        let deadline = prepared.deadline();
        let inner = generation_stream(prepared);
        tokio::pin!(inner);

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Provenance(prov)))) => {
                    let should_emit = stream_provenance.is_none();
                    stream_provenance = Some(prov.clone());
                    if should_emit {
                        yield OutputEvent::Provenance(provenance_from_execution(&prov));
                    }
                }
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
                    receipt_commitment,
                })))) => {
                    info!(
                        %receipt_commitment,
                        provenance = ?stream_provenance,
                        total_tokens,
                        ?stop_reason,
                        message = ready_message,
                        "gateway stream ready"
                    );
                    if let Some(provenance) = provenance_from_parts(
                        stream_provenance.as_ref(),
                        Some(&receipt_commitment),
                    ) {
                        yield OutputEvent::Provenance(provenance);
                    }
                    yield OutputEvent::Finished {
                        stop_reason: stop_reason_from_runtime(stop_reason),
                        usage: Some(usage(prompt_tokens, total_tokens)),
                    };
                    return;
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Failed { error, .. })))) => {
                    Err(BackendError::execution(format!("Inference error: {error}")))?;
                }
                Ok(Some(Err(err))) => Err(BackendError::execution(format!("Inference error: {err:#}")))?,
                Ok(None) => Err(BackendError::execution("execution stream ended without terminal outcome"))?,
                Err(_) => Err(BackendError::execution(format!(
                    "inference timed out after {}s",
                    super::super::timeout_secs_until(deadline)
                )))?,
            }
        }
    }
}

fn text_generation_error(error: TextGenerationError) -> BackendError {
    match error {
        TextGenerationError::Failed { position, error } => {
            warn!(position, %error, "gateway request failed");
            BackendError::execution(format!("Inference error: {error}"))
        }
        TextGenerationError::Stream(message) => BackendError::execution(message),
    }
}
