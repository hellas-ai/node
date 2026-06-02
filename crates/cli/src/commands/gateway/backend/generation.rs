use async_stream::try_stream;
use futures::StreamExt;

use crate::execution::Outcome;
use hellas_rpc::model::TextOutputDecoder;

use super::super::state::PreparedGeneration;

#[derive(Debug, Clone)]
pub(super) enum GenerationEvent {
    Delta(String),
    Done(Outcome),
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
