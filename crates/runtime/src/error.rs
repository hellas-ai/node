use thiserror::Error;

#[derive(Debug, Error)]
pub enum LLMError {
    #[error(transparent)]
    Upstream(#[from] catgrad_llm::LLMError),

    #[error(transparent)]
    Model(#[from] catgrad_llm_models::ModelError),

    #[error(transparent)]
    Runtime(#[from] crate::graph::RuntimeError),

    #[error("invalid text session state: {0}")]
    InvalidTextSessionState(String),

    #[error("invalid model config: {0}")]
    InvalidModelConfig(String),

    #[error("failed to decode JSON at path `{path}`: {source}")]
    JsonError {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("tokenizer error: {0}")]
    TokenizerError(String),
}

impl From<tokenizers::Error> for LLMError {
    fn from(err: tokenizers::Error) -> Self {
        Self::TokenizerError(err.to_string())
    }
}

impl From<serde_json::Error> for LLMError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonError {
            path: "$".to_string(),
            source: err,
        }
    }
}

pub type Result<T, E = LLMError> = std::result::Result<T, E>;
