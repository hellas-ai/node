use catgrad_llm::types::Message;
use catgrad_llm::utils::{get_model, get_model_chat_template};
use catgrad_llm::{Detokenizer, PreparedPrompt};
use hellas_rpc::encode_token_ids;
use hellas_rpc::pb::hellas::GetQuoteRequest;
use serde_json::Value;
use tokenizers::Tokenizer;

use super::config::{build_graph_bytes, encode_i32_tokens, validate_prefill_prompt_length};
use super::hf::get_model_metadata_files;
use super::spec::ModelSpec;
use super::{ModelAssetsError, Result};

pub struct ModelAssets {
    model: ModelSpec,
    config: Value,
    model_config_json: Vec<u8>,
    tokenizer: Tokenizer,
    chat_template: Option<String>,
    stop_token_ids: Vec<i32>,
}

impl ModelAssets {
    pub fn load(model_name: &str) -> Result<Self> {
        let model = ModelSpec::parse(model_name)?;
        let (config_path, tokenizer_path) = get_model_metadata_files(&model)?;
        let model_config_json =
            std::fs::read(&config_path).map_err(|source| ModelAssetsError::ReadModelConfig {
                path: config_path.clone(),
                source,
            })?;
        let config: Value = serde_json::from_slice(&model_config_json)
            .map_err(|source| ModelAssetsError::ParseModelConfig { source })?;

        let graph_model = get_model(&config, 1)
            .map_err(|source| ModelAssetsError::ConstructModelConfig { source })?;
        let stop_token_ids = graph_model.config().get_eos_token_ids();

        let tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(|source| {
            ModelAssetsError::LoadTokenizer {
                path: tokenizer_path,
                source,
            }
        })?;

        let chat_template = match get_model_chat_template(&model.id, &model.revision) {
            Ok(template) => Some(
                template
                    .replace("{% generation %}", "")
                    .replace("{% endgeneration %}", ""),
            ),
            Err(_) => None,
        };

        Ok(Self {
            model,
            config,
            model_config_json,
            tokenizer,
            chat_template,
            stop_token_ids,
        })
    }

    pub fn build_quote_request(
        &self,
        prepared_prompt: &PreparedPrompt,
        max_seq: u32,
    ) -> Result<GetQuoteRequest> {
        validate_prefill_prompt_length(&self.config, prepared_prompt.input_ids.len())?;
        let max_sequence_length = prepared_prompt.input_ids.len() + max_seq as usize;
        let graph = build_graph_bytes(&self.config, max_sequence_length)?;
        let input_ids = encode_i32_tokens(&prepared_prompt.input_ids, |token| {
            ModelAssetsError::NegativePromptTokenId { token }
        })?;
        let stop_token_ids = encode_i32_tokens(&prepared_prompt.stop_token_ids, |token| {
            ModelAssetsError::NegativeStopTokenId { token }
        })?;

        Ok(GetQuoteRequest {
            huggingface_model_id: self.model.id.clone(),
            huggingface_revision: self.model.revision.clone(),
            model_config_json: self.model_config_json.clone(),
            graph,
            input: encode_token_ids(&input_ids),
            prompt_tokens: prepared_prompt.input_ids.len() as u32,
            max_new_tokens: max_seq,
            stop_token_ids,
        })
    }

    pub fn prepare_plain_prompt(&self, prompt: &str) -> Result<PreparedPrompt> {
        PreparedPrompt::from_prompt(&self.tokenizer, prompt, &self.stop_token_ids)
            .map_err(|source| ModelAssetsError::PreparePlainPrompt { source })
    }

    pub fn prepare_messages(&self, messages: &[Message]) -> Result<PreparedPrompt> {
        let chat_template = self
            .chat_template
            .as_ref()
            .ok_or(ModelAssetsError::MissingChatTemplate)?;
        PreparedPrompt::from_messages(
            &self.tokenizer,
            chat_template,
            messages,
            &self.stop_token_ids,
        )
        .map_err(|source| ModelAssetsError::PrepareMessages { source })
    }

    pub fn create_detokenizer<'a>(&'a self, stop_token_ids: &[i32]) -> Detokenizer<'a> {
        Detokenizer::from_tokenizer(&self.tokenizer, stop_token_ids)
    }

    pub fn decode_tokens(&self, token_ids: &[u32]) -> Result<String> {
        self.tokenizer
            .decode(token_ids, false)
            .map_err(|source| ModelAssetsError::DecodeTokens { source })
    }
}
