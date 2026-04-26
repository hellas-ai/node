mod assets;
mod config;
mod hf;

use std::path::PathBuf;

use catgrad_llm::LLMError;
use hf_hub::api::sync::ApiError;
use thiserror::Error;
use tokenizers::Error as TokenizerError;

use crate::spec::ModelSpecError;

pub use assets::ModelAssets;

type Result<T> = std::result::Result<T, ModelAssetsError>;

#[derive(Debug, Error)]
pub enum ModelAssetsError {
    #[error(transparent)]
    Spec(#[from] ModelSpecError),
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
    /// One of the offered tool schemas is malformed (not a valid
    /// JSON Schema, duplicate name, or a tool entry that doesn't fit
    /// the expected wire shape). Gateway maps this to a request error
    /// (HTTP 400 / OpenAI invalid_request) — the tools themselves are
    /// bad, the model never ran.
    #[error("invalid tool directory")]
    InvalidToolDirectory {
        #[source]
        source: LLMError,
    },
    /// Caller asked for tools but the model architecture has no
    /// registered tool-call protocol. Gateway maps this to a request
    /// error (HTTP 400) with a "model X does not support tool calling"
    /// message — the model is incapable, the request shouldn't have
    /// been made.
    #[error("model `{arch}` does not support tool calling")]
    ToolsUnsupportedForModel { arch: String },
}
