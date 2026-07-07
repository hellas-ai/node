use thiserror::Error;

pub type AdaptorResult<T> = Result<T, AdaptorError>;

#[derive(Debug, Error)]
pub enum AdaptorError {
    #[error("invalid JSON request: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("unsupported wire feature: {0}")]
    Unsupported(String),
    #[error("execution projection failed: {0}")]
    Projection(String),
    #[error("invalid wire response: {0}")]
    InvalidResponse(String),
    #[error("response rendering failed: {0}")]
    Render(String),
}

impl AdaptorError {
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::InvalidRequest(message.into())
    }

    pub fn unsupported(feature: impl Into<String>) -> Self {
        Self::Unsupported(feature.into())
    }

    pub fn projection(message: impl Into<String>) -> Self {
        Self::Projection(message.into())
    }

    pub fn invalid_response(message: impl Into<String>) -> Self {
        Self::InvalidResponse(message.into())
    }

    pub fn render(message: impl Into<String>) -> Self {
        Self::Render(message.into())
    }
}
