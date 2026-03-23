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
pub(crate) use spec::{DEFAULT_MODEL_REVISION, ModelSpec};

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
    #[error("failed to prepare prompt request")]
    PreparePromptRequest {
        #[source]
        source: LLMError,
    },
    #[error("negative prompt token id {token} cannot be encoded")]
    NegativePromptTokenId { token: i32 },
    #[error("negative stop token id {token} cannot be encoded")]
    NegativeStopTokenId { token: i32 },
    #[error("failed to build program model")]
    BuildProgramModel {
        #[source]
        source: LLMError,
    },
    #[error("failed to serialize program")]
    SerializeProgram {
        #[source]
        source: LLMError,
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
