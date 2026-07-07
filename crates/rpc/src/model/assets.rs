use std::sync::Arc;

use crate::Dtype;
use catgrad_llm::utils::{get_model, get_model_architecture, get_model_chat_template};
use catgrad_llm::{Detokenizer, LLMError};
use chatgrad::types::Message;
use chatgrad::{PreparedPrompt, RenderChatTemplateOptions};
use serde_json::Value;
use tokenizers::Tokenizer;

use super::config::encode_i32_tokens;
use super::hf::get_model_metadata_files;
use super::{ModelAssetsError, Result};
use crate::{decode_token_ids, spec::ModelSpec};

/// Model-domain result of preparing a prompt for a quote: everything the
/// model layer contributes to a `QuotePreparedTextRequest`, minus the
/// protocol framing (start marker, runner key) the caller adds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedQuote {
    pub huggingface_model_id: String,
    pub huggingface_revision: String,
    pub prompt_token_ids: Vec<u32>,
    pub stop_token_ids: Vec<u32>,
    pub accept_dtype: String,
}

pub struct ModelAssets {
    model: ModelSpec,
    config: Value,
    tokenizer: Arc<Tokenizer>,
    tokenizer_config: Arc<Value>,
    chat_template: Option<Arc<str>>,
    stop_token_ids: Arc<[i32]>,
    dtype: Dtype,
}

impl ModelAssets {
    pub fn load(model_name: &str, dtype: Dtype) -> Result<Self> {
        let model = ModelSpec::parse(model_name)?;
        let (config_path, tokenizer_path, tokenizer_config_path) =
            get_model_metadata_files(&model)?;
        let config_bytes =
            std::fs::read(&config_path).map_err(|source| ModelAssetsError::ReadModelConfig {
                path: config_path.clone(),
                source,
            })?;
        let config: Value = serde_json::from_slice(&config_bytes)
            .map_err(|source| ModelAssetsError::ParseModelConfig { source })?;
        let tokenizer_config_bytes = std::fs::read(&tokenizer_config_path).map_err(|source| {
            ModelAssetsError::ReadModelConfig {
                path: tokenizer_config_path.clone(),
                source,
            }
        })?;
        let tokenizer_config: Value = serde_json::from_slice(&tokenizer_config_bytes)
            .map_err(|source| ModelAssetsError::ParseModelConfig { source })?;

        let graph_model = get_model(&config, 1, None, to_catgrad_dtype(dtype))
            .map_err(|source| ModelAssetsError::ConstructModelConfig { source })?;
        let stop_token_ids: Vec<i32> = graph_model.config().get_eos_token_ids();

        let tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(|source| {
            ModelAssetsError::LoadTokenizer {
                path: tokenizer_path,
                source,
            }
        })?;

        let chat_template = get_model_chat_template(&model.id, &model.revision)
            .ok()
            .map(Arc::<str>::from);

        Ok(Self {
            model,
            config,
            tokenizer: Arc::new(tokenizer),
            tokenizer_config: Arc::new(tokenizer_config),
            chat_template,
            stop_token_ids: Arc::from(stop_token_ids.as_slice()),
            dtype,
        })
    }

    /// Encode a prepared prompt into the model-domain pieces of a quote:
    /// model identity, validated token streams, and the model's dtype.
    /// Assembling the wire `QuotePreparedTextRequest` (start marker,
    /// runner key) is the caller's job — the model layer owns no protocol
    /// shape.
    pub fn prepare_quote(&self, prepared_prompt: &PreparedPrompt) -> Result<PreparedQuote> {
        let prompt_token_ids = encode_i32_tokens(&prepared_prompt.input_ids, |token| {
            ModelAssetsError::NegativePromptTokenId { token }
        })?;
        let stop_token_ids = encode_i32_tokens(&prepared_prompt.stop_token_ids, |token| {
            ModelAssetsError::NegativeStopTokenId { token }
        })?;
        Ok(PreparedQuote {
            huggingface_model_id: self.model.id.clone(),
            huggingface_revision: self.model.revision.clone(),
            prompt_token_ids,
            stop_token_ids,
            accept_dtype: self.dtype.as_wire().to_string(),
        })
    }

    pub fn has_chat_template(&self) -> bool {
        self.chat_template.is_some()
    }

    pub fn prepare_chat(&self, messages: &[Message]) -> Result<PreparedPrompt> {
        let template = self.chat_template.as_deref().ok_or_else(|| {
            ModelAssetsError::PreparePromptRequest {
                source: LLMError::InvalidModelConfig("model has no chat template".to_string()),
            }
        })?;
        PreparedPrompt::from_messages(
            self.tokenizer.as_ref(),
            template,
            &self.tokenizer_config,
            messages,
            &self.stop_token_ids,
        )
        .map_err(|source| ModelAssetsError::PreparePromptRequest { source })
    }

    pub fn prepare_chat_with_options(
        &self,
        messages: &[Message],
        tools: Option<&[serde_json::Value]>,
        enable_thinking: bool,
    ) -> Result<PreparedPrompt> {
        let template = self.chat_template.as_deref().ok_or_else(|| {
            ModelAssetsError::PreparePromptRequest {
                source: LLMError::InvalidModelConfig("model has no chat template".to_string()),
            }
        })?;
        PreparedPrompt::from_messages_with_options(
            self.tokenizer.as_ref(),
            template,
            &self.tokenizer_config,
            messages,
            &self.stop_token_ids,
            RenderChatTemplateOptions {
                enable_thinking,
                tools,
            },
        )
        .map_err(|source| ModelAssetsError::PreparePromptRequest { source })
    }

    pub fn prepare_plain(&self, prompt: &str) -> Result<PreparedPrompt> {
        PreparedPrompt::from_prompt(self.tokenizer.as_ref(), prompt, &self.stop_token_ids)
            .map_err(|source| ModelAssetsError::PreparePromptRequest { source })
    }

    pub fn decode_tokens(&self, token_ids: &[u32]) -> Result<String> {
        self.tokenizer
            .decode(token_ids, false)
            .map_err(|source| ModelAssetsError::DecodeTokens { source })
    }

    pub fn stop_token_ids(&self) -> &[i32] {
        &self.stop_token_ids
    }

    pub fn architecture(&self) -> Result<String> {
        get_model_architecture(&self.config)
            .map(str::to_string)
            .map_err(|source| ModelAssetsError::PreparePromptRequest { source })
    }
}

/// Stateful decoder for streamed token batches.
///
/// The decoder preserves detokenizer state across chunks, including partial
/// byte sequences and stop-token handling.
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

    pub fn for_model(assets: Arc<ModelAssets>) -> Self {
        let stop_token_ids = assets.stop_token_ids().to_vec();
        Self::new(assets, &stop_token_ids)
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<String> {
        let token_ids: Vec<i32> = decode_token_ids(bytes)?
            .into_iter()
            .map(|token| {
                i32::try_from(token).map_err(|_| ModelAssetsError::OutputTokenOutOfRange { token })
            })
            .collect::<std::result::Result<_, _>>()?;
        self.decoder
            .push_tokens(&token_ids)
            .map_err(|source| ModelAssetsError::Detokenize { source })
    }
}

pub fn to_catgrad_dtype(dtype: Dtype) -> catgrad::prelude::Dtype {
    match dtype {
        Dtype::F32 => catgrad::prelude::Dtype::F32,
        Dtype::F16 => catgrad::prelude::Dtype::F16,
        Dtype::BF16 => catgrad::prelude::Dtype::BF16,
        Dtype::F8 => catgrad::prelude::Dtype::F8,
        Dtype::U32 => catgrad::prelude::Dtype::U32,
    }
}
