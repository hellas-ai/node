mod assets;
mod config;
mod hf;
mod spec;

use std::path::PathBuf;

use catgrad_llm::LLMError;
use hf_hub::api::sync::ApiError;
use thiserror::Error;
use tokenizers::Error as TokenizerError;

pub use assets::ModelAssets;
pub(crate) use config::validate_execution_config;
pub(crate) use spec::DEFAULT_MODEL_REVISION;

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
