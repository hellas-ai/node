use crate::state::StateError;
use thiserror::Error;
use tonic::Status;

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("executor channel closed")]
    ChannelClosed,
    #[error(transparent)]
    State(#[from] StateError),
}

impl From<ExecutorError> for Status {
    fn from(err: ExecutorError) -> Self {
        match &err {
            ExecutorError::ChannelClosed => Status::internal(err.to_string()),
            ExecutorError::State(StateError::QuoteNotFound(_)) => {
                Status::not_found(err.to_string())
            }
            ExecutorError::State(StateError::ExecutionNotFound(_)) => {
                Status::not_found(err.to_string())
            }
        }
    }
}
