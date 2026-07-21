//! Model assets: HuggingFace download, tokenizer, and text decoding.
//!
//! The model domain layer. Depends on `hellas-rpc` for protocol
//! primitives (`Dtype`, `ModelSpec`, token codecs) but owns no protocol
//! shape itself — it hands callers domain results and leaves wire
//! assembly to them.

mod assets;
mod hf;
mod prompt;

use std::path::PathBuf;

use catgrad_llm_models::ModelError;
use hf_hub::api::sync::ApiError;
use thiserror::Error;
use tokenizers::Error as TokenizerError;

use hellas_rpc::{TokenBytesError, spec::ModelSpecError};

pub use assets::{
    ChatMessage, ModelAssets, PreparedPrompt, PreparedQuote, TextOutputDecoder, program_manifest,
    to_catgrad_dtype,
};

type Result<T> = std::result::Result<T, ModelAssetsError>;

#[derive(Debug, Error)]
pub enum ModelAssetsError {
    #[error(transparent)]
    Spec(#[from] ModelSpecError),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("failed to initialize Hugging Face API")]
    BuildHfApi {
        #[source]
        source: ApiError,
    },
    #[error("failed to fetch {file} for {model_id}@{revision}")]
    FetchModelAsset {
        model_id: String,
        revision: String,
        file: String,
        #[source]
        source: ApiError,
    },
    #[error("failed to read model asset {path:?}")]
    ReadAsset {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse model metadata JSON")]
    ParseModelMetadata {
        #[source]
        source: serde_json::Error,
    },
    #[error("model.safetensors.index.json has no valid weight_map")]
    InvalidModelIndex,
    #[error("failed to load tokenizer {path:?}")]
    LoadTokenizer {
        path: PathBuf,
        #[source]
        source: TokenizerError,
    },
    #[error("model has no chat template")]
    MissingChatTemplate,
    #[error("failed to render model chat template")]
    RenderChatTemplate {
        #[source]
        source: minijinja::Error,
    },
    #[error("failed to tokenize prompt")]
    TokenizePrompt {
        #[source]
        source: TokenizerError,
    },
    #[error("negative stop token id {token} cannot be encoded")]
    NegativeStopTokenId { token: i32 },
    #[error("failed to serialize program")]
    SerializeProgram {
        #[source]
        source: serde_json::Error,
    },
    #[error("program graph does not match its declared type")]
    InvalidProgramGraph,
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
}

mod wire;
pub use wire::model_assets_wire_code;
