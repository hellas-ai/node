use catgrad_llm::LLMError;
use hellas_wire::{WireCode, WireStatus};
use thiserror::Error;

use crate::TokenBytesError;
use crate::model::ModelAssetsError;

/// Error returned when the backend fails to initialize.
#[derive(Clone, Debug, Error)]
#[error("{message}")]
pub struct BackendInitError {
    pub message: String,
}

impl BackendInitError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Errors from the in-memory quote/execution state machine.
#[derive(Debug, Error)]
pub enum StateError {
    #[error("quote not found: {0}")]
    QuoteNotFound(String),
    #[error("quote expired: {0}")]
    QuoteExpired(String),
}

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("executor channel closed")]
    ChannelClosed,
    #[error("execution queue is full (capacity {capacity})")]
    QueueFull { capacity: usize },
    #[error("invalid quote request: {0}")]
    InvalidQuoteRequest(String),
    #[error(transparent)]
    BackendInit(#[from] BackendInitError),
    #[error(transparent)]
    ModelAssets(#[from] ModelAssetsError),
    #[error("LLM error: {0}")]
    Llm(#[from] LLMError),
    #[error("weights not ready for {0}")]
    WeightsNotReady(String),
    #[error("weights error: {0}")]
    WeightsError(String),
    #[error("artifact not found: {0}")]
    ArtifactNotFound(String),
    #[error("artifact store error: {0}")]
    ArtifactStore(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("invalid token payload: {0}")]
    InvalidTokenPayload(String),
    #[error(transparent)]
    TokenBytes(#[from] TokenBytesError),
    #[error(
        "program was built for dtype {request:?} but this executor only supports {supported:?}; rebuild the program at one of the supported dtypes or run an executor with --dtype {request:?} in its supported set"
    )]
    DtypeNotSupported {
        request: catgrad::prelude::Dtype,
        supported: Vec<catgrad::prelude::Dtype>,
    },
    #[error(transparent)]
    State(#[from] StateError),
}

fn model_assets_wire_code(err: &ModelAssetsError) -> WireCode {
    match err {
        ModelAssetsError::Spec(_)
        | ModelAssetsError::ParseModelConfig { .. }
        | ModelAssetsError::ConstructModelConfig { .. }
        | ModelAssetsError::NegativePromptTokenId { .. }
        | ModelAssetsError::NegativeStopTokenId { .. } => WireCode::InvalidArgument,
        _ => WireCode::Internal,
    }
}

fn executor_wire_code(err: &ExecutorError) -> WireCode {
    match err {
        ExecutorError::QueueFull { .. } => WireCode::ResourceExhausted,
        ExecutorError::InvalidQuoteRequest(_)
        | ExecutorError::InvalidTokenPayload(_)
        | ExecutorError::TokenBytes(_) => WireCode::InvalidArgument,
        ExecutorError::DtypeNotSupported { .. } => WireCode::FailedPrecondition,
        ExecutorError::ModelAssets(model_err) => model_assets_wire_code(model_err),
        ExecutorError::WeightsNotReady(_) | ExecutorError::State(StateError::QuoteExpired(_)) => {
            WireCode::FailedPrecondition
        }
        ExecutorError::PolicyDenied(_) => WireCode::PermissionDenied,
        ExecutorError::ArtifactNotFound(_) | ExecutorError::State(StateError::QuoteNotFound(_)) => {
            WireCode::NotFound
        }
        ExecutorError::ChannelClosed
        | ExecutorError::BackendInit(_)
        | ExecutorError::Llm(_)
        | ExecutorError::WeightsError(_)
        | ExecutorError::ArtifactStore(_) => WireCode::Internal,
    }
}

impl From<ModelAssetsError> for WireStatus {
    fn from(err: ModelAssetsError) -> Self {
        WireStatus::new(model_assets_wire_code(&err), err.to_string())
    }
}

impl From<ExecutorError> for WireStatus {
    fn from(err: ExecutorError) -> Self {
        WireStatus::new(executor_wire_code(&err), err.to_string())
    }
}
