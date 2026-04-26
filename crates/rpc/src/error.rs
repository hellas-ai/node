use crate::model::ModelAssetsError;
use catgrad_llm::LLMError;
use thiserror::Error;
use tonic::Status;

/// Error returned when the backend fails to initialize.
///
/// Defined here (rather than alongside the concrete backend) so that
/// `ExecutorError` — which the CLI carries across feature configurations —
/// stays in a single backend-free crate.
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
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("invalid token payload: {0}")]
    InvalidTokenPayload(String),
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

impl From<ExecutorError> for Status {
    fn from(err: ExecutorError) -> Self {
        let code = match &err {
            ExecutorError::QueueFull { .. } => tonic::Code::ResourceExhausted,

            ExecutorError::InvalidQuoteRequest(_) | ExecutorError::InvalidTokenPayload(_) => {
                tonic::Code::InvalidArgument
            }

            ExecutorError::DtypeNotSupported { .. } => tonic::Code::FailedPrecondition,

            ExecutorError::ModelAssets(model_err) => match model_err {
                ModelAssetsError::Spec(_)
                | ModelAssetsError::ParseModelConfig { .. }
                | ModelAssetsError::ConstructModelConfig { .. }
                | ModelAssetsError::NegativePromptTokenId { .. }
                | ModelAssetsError::NegativeStopTokenId { .. } => tonic::Code::InvalidArgument,
                _ => tonic::Code::Internal,
            },

            ExecutorError::WeightsNotReady(_)
            | ExecutorError::State(StateError::QuoteExpired(_)) => tonic::Code::FailedPrecondition,

            ExecutorError::PolicyDenied(_) => tonic::Code::PermissionDenied,

            ExecutorError::State(StateError::QuoteNotFound(_)) => tonic::Code::NotFound,

            ExecutorError::ChannelClosed
            | ExecutorError::BackendInit(_)
            | ExecutorError::Llm(_)
            | ExecutorError::WeightsError(_) => tonic::Code::Internal,
        };
        Status::new(code, err.to_string())
    }
}
