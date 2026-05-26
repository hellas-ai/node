use std::sync::Arc;

use crate::pb::courtesy::{
    QuotePreparedTextRequest, SymbolicGenesisStart, SymbolicStart, symbolic_start,
};
use catgrad::prelude::Dtype;
use catgrad_llm::LLMError;
use catgrad_llm::utils::{get_model, get_model_architecture, get_model_chat_template};
use chatgrad::types::Message;
use chatgrad::{PreparedPrompt, RenderChatTemplateOptions};
use serde_json::Value;
use tokenizers::Tokenizer;

use super::config::encode_i32_tokens;
use super::hf::get_model_metadata_files;
use super::{ModelAssetsError, Result};
use crate::spec::ModelSpec;

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

        let graph_model = get_model(&config, 1, None, dtype)
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

    pub fn build_quote_prepared_text_request(
        &self,
        prepared_prompt: &PreparedPrompt,
        max_seq: u32,
    ) -> Result<QuotePreparedTextRequest> {
        let input_ids = encode_i32_tokens(&prepared_prompt.input_ids, |token| {
            ModelAssetsError::NegativePromptTokenId { token }
        })?;
        let stop_token_ids = encode_i32_tokens(&prepared_prompt.stop_token_ids, |token| {
            ModelAssetsError::NegativeStopTokenId { token }
        })?;

        Ok(QuotePreparedTextRequest {
            huggingface_model_id: self.model.id.clone(),
            huggingface_revision: self.model.revision.clone(),
            prompt_token_ids: input_ids,
            max_new_tokens: max_seq,
            stop_token_ids,
            start: Some(SymbolicStart {
                kind: Some(symbolic_start::Kind::Genesis(SymbolicGenesisStart {})),
            }),
            accept_dtypes: vec![dtype_to_wire(self.dtype).to_string()],
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
            &self.tokenizer,
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
            &self.tokenizer,
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
        PreparedPrompt::from_prompt(&self.tokenizer, prompt, &self.stop_token_ids)
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

fn dtype_to_wire(dtype: Dtype) -> &'static str {
    match dtype {
        Dtype::F32 => "f32",
        Dtype::F16 => "f16",
        Dtype::BF16 => "bf16",
        Dtype::F8 => "f8",
        Dtype::U32 => "u32",
    }
}
