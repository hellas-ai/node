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
    #[error("executor is busy")]
    Busy,
    #[error("invalid catgrad graph: {0}")]
    InvalidGraph(#[from] serde_json::Error),
    #[error("LLM error: {0}")]
    Llm(#[from] LLMError),
    #[error("interpreter error: {0}")]
    Interpreter(#[from] InterpreterError),
    #[error("backend error: {0:?}")]
    Backend(BackendError),
    #[error("failed to construct model term for {0}")]
    ModelConstruction(String),
    #[error("missing quote payload")]
    MissingPayload,
    #[error("missing weights hint model id")]
    MissingWeightsHint,
    #[error("weights not ready for model {0}")]
    WeightsNotReady(String),
    #[error("weights error: {0}")]
    WeightsError(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("no output from graph")]
    NoOutput,
    #[error("unexpected output value")]
    UnexpectedOutput,
    #[error(transparent)]
    State(#[from] StateError),
}

impl From<ExecutorError> for Status {
    fn from(err: ExecutorError) -> Self {
        match &err {
            ExecutorError::ChannelClosed => Status::internal(err.to_string()),
            ExecutorError::Busy => Status::resource_exhausted(err.to_string()),
            ExecutorError::InvalidGraph(_) => Status::invalid_argument(err.to_string()),
            ExecutorError::Llm(_) => Status::internal(err.to_string()),
            ExecutorError::Interpreter(_) => Status::internal(err.to_string()),
            ExecutorError::Backend(_) => Status::internal(err.to_string()),
            ExecutorError::ModelConstruction(_) => Status::internal(err.to_string()),
            ExecutorError::MissingPayload => Status::invalid_argument(err.to_string()),
            ExecutorError::MissingWeightsHint => Status::invalid_argument(err.to_string()),
            ExecutorError::WeightsNotReady(_) => Status::failed_precondition(err.to_string()),
            ExecutorError::WeightsError(_) => Status::internal(err.to_string()),
            ExecutorError::PolicyDenied(_) => Status::permission_denied(err.to_string()),
            ExecutorError::NoOutput => Status::internal(err.to_string()),
            ExecutorError::UnexpectedOutput => Status::internal(err.to_string()),
            ExecutorError::State(StateError::QuoteNotFound(_)) => {
                Status::not_found(err.to_string())
            }
            ExecutorError::State(StateError::ExecutionNotFound(_)) => {
                Status::not_found(err.to_string())
            }
        }
    }
}
