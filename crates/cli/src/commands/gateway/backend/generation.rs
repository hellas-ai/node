use async_stream::try_stream;
use futures::StreamExt;

use crate::execution::{Outcome, StopReason};
use crate::text_output::TextOutputDecoder;

use super::super::state::PreparedGeneration;

#[derive(Debug, Clone)]
pub(super) enum GenerationEvent {
    Delta(String),
    Done(Outcome),
}

pub(super) struct CompletedTextGeneration {
    pub(super) text: String,
    pub(super) provenance: Option<hellas_rpc::provenance::ExecutionProvenance>,
    pub(super) total_tokens: u64,
    pub(super) stop_reason: StopReason,
    pub(super) receipt: crate::execution::ReceiptArtifact,
}

pub(super) enum TextGenerationError {
    Failed { position: u64, error: String },
    Stream(String),
}

pub(super) fn generation_stream(
    generation: PreparedGeneration,
) -> impl futures::Stream<Item = anyhow::Result<GenerationEvent>> + Send {
    let PreparedGeneration {
        prepared,
        assets,
        stop_token_ids,
        ..
    } = generation;
    try_stream! {
        let mut decoder = TextOutputDecoder::new(assets, &stop_token_ids);
        let inner = prepared.stream();
        tokio::pin!(inner);
        while let Some(event) = inner.next().await {
            match event? {
                crate::execution::ExecutionEvent::Chunk { tokens, .. } => {
                    let delta = decoder.push_bytes(&tokens)?;
                    if !delta.is_empty() {
                        yield GenerationEvent::Delta(delta);
                    }
                }
                crate::execution::ExecutionEvent::Done(outcome) => {
                    yield GenerationEvent::Done(outcome);
                    return;
                }
            }
        }
        Err(anyhow::anyhow!("execution stream ended without terminal outcome"))?;
    }
}

pub(super) async fn collect_text(
    generation: PreparedGeneration,
) -> Result<CompletedTextGeneration, TextGenerationError> {
    let deadline = generation.deadline();
    let provenance = generation.provenance.clone();
    let stream = generation_stream(generation);
    tokio::pin!(stream);
    let mut text = String::new();
    loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(GenerationEvent::Delta(delta)))) => text.push_str(&delta),
            Ok(Some(Ok(GenerationEvent::Done(Outcome::Completed {
                total_tokens,
                stop_reason,
                receipt,
            })))) => {
                return Ok(CompletedTextGeneration {
                    text,
                    provenance,
                    total_tokens,
                    stop_reason,
                    receipt,
                });
            }
            Ok(Some(Ok(GenerationEvent::Done(Outcome::Failed { position, error })))) => {
                return Err(TextGenerationError::Failed { position, error });
            }
            Ok(Some(Err(err))) => {
                return Err(TextGenerationError::Stream(format!(
                    "Inference error: {err:#}"
                )));
            }
            Ok(None) => {
                return Err(TextGenerationError::Stream(
                    "execution stream ended without terminal outcome".to_string(),
                ));
            }
            Err(_) => {
                return Err(TextGenerationError::Stream(format!(
                    "inference timed out after {}s",
                    super::super::timeout_secs_until(deadline)
                )));
            }
        }
    }
}
