use std::sync::Arc;

use crate::encode_token_ids;
use crate::pb::hellas::GetQuoteRequest;
use catgrad::prelude::Dtype;
use catgrad_llm::runtime::chat::{ChatOptions, ChatTurn, ToolDirectory};
use catgrad_llm::types::Message;
use catgrad_llm::utils::{get_model, get_model_architecture, get_model_chat_template};
use catgrad_llm::{LLMError, PreparedPrompt};
use serde_json::Value;
use tokenizers::Tokenizer;

use super::config::{build_program_bytes, encode_i32_tokens};
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

    pub fn build_quote_request(
        &self,
        prepared_prompt: &PreparedPrompt,
        max_seq: u32,
    ) -> Result<GetQuoteRequest> {
        let max_sequence_length = prepared_prompt.input_ids.len() + max_seq as usize;
        let program = build_program_bytes(&self.config, max_sequence_length, self.dtype)?;
        let input_ids = encode_i32_tokens(&prepared_prompt.input_ids, |token| {
            ModelAssetsError::NegativePromptTokenId { token }
        })?;
        let stop_token_ids = encode_i32_tokens(&prepared_prompt.stop_token_ids, |token| {
            ModelAssetsError::NegativeStopTokenId { token }
        })?;

        Ok(GetQuoteRequest {
            huggingface_model_id: self.model.id.clone(),
            huggingface_revision: self.model.revision.clone(),
            program,
            input: encode_token_ids(&input_ids),
            prompt_tokens: prepared_prompt.input_ids.len() as u32,
            max_new_tokens: max_seq,
            stop_token_ids,
        })
    }

    pub fn has_chat_template(&self) -> bool {
        self.chat_template.is_some()
    }

    pub fn prepare_chat(&self, messages: &[Message]) -> Result<PreparedPrompt> {
        let template = self
            .chat_template
            .as_deref()
            .ok_or_else(|| ModelAssetsError::PreparePromptRequest {
                source: LLMError::InvalidModelConfig("model has no chat template".to_string()),
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

    pub fn prepare_plain(&self, prompt: &str) -> Result<PreparedPrompt> {
        PreparedPrompt::from_prompt(&self.tokenizer, prompt, &self.stop_token_ids)
            .map_err(|source| ModelAssetsError::PreparePromptRequest { source })
    }

    pub fn decode_tokens(&self, token_ids: &[u32]) -> Result<String> {
        self.tokenizer
            .decode(token_ids, false)
            .map_err(|source| ModelAssetsError::DecodeTokens { source })
    }

    /// Build a `ChatTurn` for one chat-completion request.
    ///
    /// The caller supplies an already-built [`ToolDirectory`] (or
    /// `None` for no tools) — wire-shape conversion happens at the
    /// gateway edge via `ToolDirectory::from_openai_tools` /
    /// `ToolDirectory::from_anthropic_tools`. This keeps `ModelAssets`
    /// independent of any one wire surface.
    ///
    /// Errors:
    /// - `PreparePromptRequest` if the model has no chat template or
    ///   the architecture string can't be extracted.
    /// - `ChatTurnConfig` if `ChatTurn::new` rejects the binding
    ///   (e.g. tools bound for an arch with no tool-call protocol) —
    ///   the variant carries the typed catgrad-llm error and the
    ///   gateway maps to HTTP 400.
    pub fn chat_turn(
        &self,
        tools: Option<Arc<ToolDirectory>>,
        options: ChatOptions,
    ) -> Result<ChatTurn> {
        let chat_template = self
            .chat_template
            .as_ref()
            .ok_or_else(|| ModelAssetsError::PreparePromptRequest {
                source: LLMError::InvalidModelConfig("model has no chat template".to_string()),
            })?
            .clone();

        let arch = get_model_architecture(&self.config)
            .map_err(|source| ModelAssetsError::PreparePromptRequest { source })?
            .to_string();

        Ok(ChatTurn::new(
            arch,
            chat_template,
            Arc::clone(&self.tokenizer),
            Arc::clone(&self.tokenizer_config),
            Arc::clone(&self.stop_token_ids),
            tools,
            options,
        )?)
    }
}
