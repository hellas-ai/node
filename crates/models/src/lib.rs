//! Model assets: HuggingFace download, tokenizer, and text decoding.
//!
//! The model domain layer. Depends on `hellas-rpc` for protocol
//! primitives (`Dtype`, `ModelSpec`, token codecs) but owns no protocol
//! shape itself — it hands callers domain results and leaves wire
//! assembly to them.

mod assets;
mod config;
mod hf;

use std::path::PathBuf;

use catgrad_llm::LLMError;
use hf_hub::api::sync::ApiError;
use thiserror::Error;
use tokenizers::Error as TokenizerError;

use hellas_rpc::{TokenBytesError, spec::ModelSpecError};

pub use assets::{
    ModelAssets, PreparedQuote, TextOutputDecoder, program_manifest, to_catgrad_dtype,
};

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
        source: serde_json::Error,
    },
    #[error("program graph does not match its declared type")]
    InvalidProgramGraph,
    #[error("failed to read manifest asset {path:?}")]
    ReadManifestAsset {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("model cache path has no immutable revision")]
    UnresolvedRevision,
    #[error("failed to decode tokens")]
    DecodeTokens {
        #[source]
        source: TokenizerError,
    },
    #[error("failed to decode token byte payload")]
    TokenBytes {
        #[from]
        source: TokenBytesError,
    },
    #[error("output token id {token} exceeds i32 range")]
    OutputTokenOutOfRange { token: u32 },
    #[error("failed to detokenize streamed output")]
    Detokenize {
        #[source]
        source: LLMError,
    },
}

mod wire;
pub use wire::model_assets_wire_code;
