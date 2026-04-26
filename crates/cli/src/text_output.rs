use anyhow::{Context, anyhow};
use catgrad_llm::{Detokenizer, LLMError};
use hellas_rpc::decode_token_ids;
use hellas_rpc::model::ModelAssets;
use std::sync::Arc;

/// Streaming detokenizer. Stateful — buffers partial UTF-8 sequences
/// across `push_bytes` calls so multi-byte glyphs aren't split mid-stream.
pub struct TextOutputDecoder {
    decoder: Detokenizer<'static>,
}

impl TextOutputDecoder {
    pub fn new(assets: Arc<ModelAssets>, stop_token_ids: &[i32]) -> Self {
        let decoder = Detokenizer::new(
            move |token_ids| {
                let token_ids: Vec<u32> = token_ids
                    .iter()
                    .map(|&token| {
                        u32::try_from(token).map_err(|_| {
                            LLMError::TokenizerError(format!(
                                "negative token id {token} cannot be decoded"
                            ))
                        })
                    })
                    .collect::<catgrad_llm::Result<_>>()?;
                assets
                    .decode_tokens(&token_ids)
                    .map_err(|err| LLMError::TokenizerError(err.to_string()))
            },
            stop_token_ids,
        );
        Self { decoder }
    }

    /// Push a chunk of token bytes; returns the incremental text delta.
    /// May return an empty string if the chunk only contained the leading
    /// bytes of a multi-byte UTF-8 character.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<String> {
        let token_ids: Vec<i32> = decode_token_ids(bytes)
            .context("failed to decode streamed output batch")?
            .into_iter()
            .map(|token| {
                i32::try_from(token)
                    .map_err(|_| anyhow!("output token id {token} exceeds i32 range"))
            })
            .collect::<Result<_, _>>()?;
        self.decoder
            .push_tokens(&token_ids)
            .context("failed to detokenize streamed output batch")
    }
}
