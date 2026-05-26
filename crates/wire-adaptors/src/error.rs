use thiserror::Error;

pub type AdaptorResult<T> = Result<T, AdaptorError>;

#[derive(Debug, Error)]
pub enum AdaptorError {
    #[error("invalid JSON request: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid request: {message}")]
    InvalidRequest { message: String },
    #[error("unsupported wire feature: {feature}")]
    Unsupported { feature: String },
    #[error("execution projection failed: {message}")]
    Projection { message: String },
    #[error("response rendering failed: {message}")]
    Render { message: String },
}

impl AdaptorError {
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::InvalidRequest {
            message: message.into(),
        }
    }

    pub fn unsupported(feature: impl Into<String>) -> Self {
        Self::Unsupported {
            feature: feature.into(),
        }
    }

    pub fn projection(message: impl Into<String>) -> Self {
        Self::Projection {
            message: message.into(),
        }
    }

    pub fn render(message: impl Into<String>) -> Self {
        Self::Render {
            message: message.into(),
        }
    }
}
