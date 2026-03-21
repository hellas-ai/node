use crate::execution::ExecutionOutput;
use anyhow::{anyhow, Context};
use catgrad_llm::{Detokenizer, LLMError};
use hellas_executor::ModelAssets;
use hellas_rpc::decode_token_ids;
use std::sync::Arc;

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

    pub fn decode_output(assets: &ModelAssets, output: &ExecutionOutput) -> anyhow::Result<String> {
        let token_ids = decode_token_ids(&output.output)
            .map_err(|err| anyhow!("failed to decode output token payload: {err}"))?;
        assets
            .decode_tokens(&token_ids)
            .context("failed to decode output text")
    }

    pub fn push_output(&mut self, output: &[u8]) -> anyhow::Result<String> {
        let token_ids: Vec<i32> = decode_token_ids(output)
            .map_err(|err| anyhow!("failed to decode streamed output batch: {err}"))?
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
