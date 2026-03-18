use std::path::PathBuf;

use catgrad_llm::helpers::GATED_DELTA_CHUNK_SIZE;
use catgrad_llm::types::Message;
use catgrad_llm::utils::{get_model, get_model_chat_template};
use catgrad_llm::{Detokenizer, LLMError, PreparedPrompt};
use hellas_rpc::encode_token_ids;
use hellas_rpc::pb::hellas::GetQuoteRequest;
use hf_hub::api::sync::{ApiBuilder, ApiError};
use hf_hub::{Repo, RepoType};
use serde_json::Value;
use thiserror::Error;
use tokenizers::{Error as TokenizerError, Tokenizer};

use crate::weights::DEFAULT_REF;

type Result<T> = std::result::Result<T, ModelAssetsError>;

#[derive(Debug, Error)]
pub enum ModelAssetsError {
    #[error("model id is empty")]
    EmptyModelId,
    #[error("model revision is empty")]
    EmptyModelRevision,
    #[error("failed to initialize Hugging Face API")]
    BuildHfApi {
        #[source]
        source: ApiError,
    },
    #[error("failed to fetch {file} for {model_id}@{revision}")]
    FetchModelMetadata {
        model_id: String,
        revision: String,
        file: &'static str,
        #[source]
        source: ApiError,
    },
    #[error("failed to read model config {path:?}")]
    ReadModelConfig {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse model config JSON")]
    ParseModelConfig {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to construct model config")]
    ConstructModelConfig {
        #[source]
        source: LLMError,
    },
    #[error("failed to load tokenizer {path:?}")]
    LoadTokenizer {
        path: PathBuf,
        #[source]
        source: TokenizerError,
    },
    #[error("model does not expose a chat template")]
    MissingChatTemplate,
    #[error("failed to prepare plain prompt")]
    PreparePlainPrompt {
        #[source]
        source: LLMError,
    },
    #[error("failed to prepare chat messages")]
    PrepareMessages {
        #[source]
        source: LLMError,
    },
    #[error("negative prompt token id {token} cannot be encoded")]
    NegativePromptTokenId { token: i32 },
    #[error("negative stop token id {token} cannot be encoded")]
    NegativeStopTokenId { token: i32 },
    #[error("failed to build graph model")]
    BuildGraphModel {
        #[source]
        source: LLMError,
    },
    #[error("failed to construct typed graph term")]
    MissingTypedGraphTerm,
    #[error("failed to serialize graph")]
    SerializeGraph {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to decode tokens")]
    DecodeTokens {
        #[source]
        source: TokenizerError,
    },
    #[error(
        "prompt too long for current catgrad prefill on {architecture}: {prompt_tokens} tokens exceeds limit {limit}"
    )]
    PromptTooLong {
        architecture: String,
        prompt_tokens: usize,
        limit: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ModelSpec {
    id: String,
    revision: String,
}

impl ModelSpec {
    fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(ModelAssetsError::EmptyModelId);
        }

        let (id, revision) = match raw.rsplit_once('@') {
            Some((id, revision)) => {
                let id = id.trim();
                let revision = revision.trim();
                if id.is_empty() {
                    return Err(ModelAssetsError::EmptyModelId);
                }
                if revision.is_empty() {
                    return Err(ModelAssetsError::EmptyModelRevision);
                }
                (id.to_string(), revision.to_string())
            }
            None => (raw.to_string(), DEFAULT_REF.to_string()),
        };

        Ok(Self { id, revision })
    }
}

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

pub fn validate_execution_config(
    model_config_json: &[u8],
    prompt_tokens: usize,
    max_new_tokens: u32,
) -> Result<()> {
    let config: Value = serde_json::from_slice(model_config_json)
        .map_err(|source| ModelAssetsError::ParseModelConfig { source })?;
    validate_prefill_prompt_length(&config, prompt_tokens)?;
    let max_sequence_length = prompt_tokens.saturating_add(max_new_tokens as usize);
    let _ = get_model(&config, max_sequence_length)
        .map_err(|source| ModelAssetsError::ConstructModelConfig { source })?;
    Ok(())
}

fn encode_i32_tokens(
    token_ids: &[i32],
    make_error: impl Fn(i32) -> ModelAssetsError,
) -> Result<Vec<u32>> {
    token_ids
        .iter()
        .map(|&token| u32::try_from(token).map_err(|_| make_error(token)))
        .collect()
}

fn get_model_metadata_files(model: &ModelSpec) -> Result<(PathBuf, PathBuf)> {
    let mut builder = ApiBuilder::from_env();
    let env_token = std::env::var("HF_TOKEN")
        .ok()
        .or_else(|| std::env::var("HUGGING_FACE_HUB_TOKEN").ok())
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty());
    if let Some(token) = env_token {
        builder = builder.with_token(Some(token));
    }

    let api = builder
        .build()
        .map_err(|source| ModelAssetsError::BuildHfApi { source })?;
    let repo = api.repo(Repo::with_revision(
        model.id.clone(),
        RepoType::Model,
        model.revision.clone(),
    ));

    let config =
        repo.get("config.json")
            .map_err(|source| ModelAssetsError::FetchModelMetadata {
                model_id: model.id.clone(),
                revision: model.revision.clone(),
                file: "config.json",
                source,
            })?;
    let tokenizer =
        repo.get("tokenizer.json")
            .map_err(|source| ModelAssetsError::FetchModelMetadata {
                model_id: model.id.clone(),
                revision: model.revision.clone(),
                file: "tokenizer.json",
                source,
            })?;

    Ok((config, tokenizer))
}

fn build_graph_bytes(config: &Value, max_sequence_length: usize) -> Result<Vec<u8>> {
    let model = get_model(config, max_sequence_length)
        .map_err(|source| ModelAssetsError::BuildGraphModel { source })?;
    let typed_term = model
        .term()
        .ok_or(ModelAssetsError::MissingTypedGraphTerm)?;
    serde_json::to_vec(&typed_term).map_err(|source| ModelAssetsError::SerializeGraph { source })
}

fn validate_prefill_prompt_length(config: &Value, prompt_tokens: usize) -> Result<()> {
    let Some((architecture, limit)) = prefill_prompt_limit(config) else {
        return Ok(());
    };

    if prompt_tokens > limit {
        return Err(ModelAssetsError::PromptTooLong {
            architecture: architecture.to_string(),
            prompt_tokens,
            limit,
        });
    }

    Ok(())
}

fn prefill_prompt_limit(config: &Value) -> Option<(&str, usize)> {
    let architecture = config.get("architectures")?.get(0)?.as_str()?;
    match architecture {
        "Qwen3_5ForConditionalGeneration" | "OlmoHybridForCausalLM" => {
            Some((architecture, GATED_DELTA_CHUNK_SIZE))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::ModelSpec;
    use crate::weights::DEFAULT_REF;
    use catgrad_llm::helpers::GATED_DELTA_CHUNK_SIZE;
    use serde_json::json;

    #[test]
    fn parses_default_revision_when_not_specified() {
        let spec = ModelSpec::parse("HuggingFaceTB/SmolLM2-135M-Instruct").unwrap();
        assert_eq!(spec.id, "HuggingFaceTB/SmolLM2-135M-Instruct");
        assert_eq!(spec.revision, DEFAULT_REF);
    }

    #[test]
    fn parses_explicit_revision_suffix() {
        let spec = ModelSpec::parse("foo/bar@refs/pr/7").unwrap();
        assert_eq!(spec.id, "foo/bar");
        assert_eq!(spec.revision, "refs/pr/7");
    }

    #[test]
    fn rejects_empty_revision_suffix() {
        let err = ModelSpec::parse("foo/bar@").unwrap_err();
        assert!(err.to_string().contains("revision"));
    }

    #[test]
    fn rejects_qwen3_5_prefill_over_chunk_limit() {
        let config = json!({
            "architectures": ["Qwen3_5ForConditionalGeneration"]
        });

        let err = super::validate_prefill_prompt_length(&config, GATED_DELTA_CHUNK_SIZE + 1)
            .unwrap_err();
        assert!(matches!(
            err,
            super::ModelAssetsError::PromptTooLong { limit, .. } if limit == GATED_DELTA_CHUNK_SIZE
        ));
    }

    #[test]
    fn rejects_olmo_hybrid_prefill_over_chunk_limit() {
        let config = json!({
            "architectures": ["OlmoHybridForCausalLM"]
        });

        let err = super::validate_prefill_prompt_length(&config, GATED_DELTA_CHUNK_SIZE + 1)
            .unwrap_err();
        assert!(matches!(
            err,
            super::ModelAssetsError::PromptTooLong { limit, .. } if limit == GATED_DELTA_CHUNK_SIZE
        ));
    }

    #[test]
    fn allows_long_prefill_for_non_chunked_models() {
        let config = json!({
            "architectures": ["Qwen3ForCausalLM"]
        });

        super::validate_prefill_prompt_length(&config, GATED_DELTA_CHUNK_SIZE + 1).unwrap();
    }
}
