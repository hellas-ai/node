use crate::backend::BackendInitError;
use crate::model::ModelAssetsError;
use crate::state::StateError;
use catgrad::abstract_interpreter::types::InterpreterError;
use catgrad::interpreter::backend::BackendError;
use catgrad_llm::LLMError;
use thiserror::Error;
use tonic::Status;

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
    #[error("invalid catgrad graph: {0}")]
    InvalidGraph(#[from] serde_json::Error),
    #[error("LLM error: {0}")]
    Llm(#[from] LLMError),
    #[error("interpreter error: {0}")]
    Interpreter(#[from] InterpreterError),
    #[error("backend error: {0:?}")]
    Backend(BackendError),
    #[error("weights not ready for {0}")]
    WeightsNotReady(String),
    #[error("weights error: {0}")]
    WeightsError(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("invalid token payload: {0}")]
    InvalidTokenPayload(String),
    #[error("no output from graph")]
    NoOutput,
    #[error("unexpected output value")]
    UnexpectedOutput,
    #[error(transparent)]
    State(#[from] StateError),
}

impl From<ExecutorError> for Status {
    fn from(err: ExecutorError) -> Self {
        let code = match &err {
            ExecutorError::QueueFull { .. } => tonic::Code::ResourceExhausted,

            ExecutorError::InvalidQuoteRequest(_)
            | ExecutorError::InvalidGraph(_)
            | ExecutorError::InvalidTokenPayload(_) => tonic::Code::InvalidArgument,

            ExecutorError::ModelAssets(model_err) => match model_err {
                ModelAssetsError::EmptyModelId
                | ModelAssetsError::EmptyModelRevision
                | ModelAssetsError::ParseModelConfig { .. }
                | ModelAssetsError::ConstructModelConfig { .. }
                | ModelAssetsError::NegativePromptTokenId { .. }
                | ModelAssetsError::NegativeStopTokenId { .. }
                | ModelAssetsError::PromptTooLong { .. } => tonic::Code::InvalidArgument,
                _ => tonic::Code::Internal,
            },

            ExecutorError::WeightsNotReady(_)
            | ExecutorError::State(StateError::OutputNotAvailable(_)) => {
                tonic::Code::FailedPrecondition
            }

            ExecutorError::PolicyDenied(_) => tonic::Code::PermissionDenied,

            ExecutorError::State(
                StateError::QuoteNotFound(_) | StateError::ExecutionNotFound(_),
            ) => tonic::Code::NotFound,

            ExecutorError::ChannelClosed
            | ExecutorError::BackendInit(_)
            | ExecutorError::Llm(_)
            | ExecutorError::Interpreter(_)
            | ExecutorError::Backend(_)
            | ExecutorError::WeightsError(_)
            | ExecutorError::NoOutput
            | ExecutorError::UnexpectedOutput => tonic::Code::Internal,
        };
        Status::new(code, err.to_string())
    }
}
