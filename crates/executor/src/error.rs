use thiserror::Error;
use tonic::Status;

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("executor channel closed")]
    ChannelClosed,
}

impl From<ExecutorError> for Status {
    fn from(err: ExecutorError) -> Self {
        match err {
            ExecutorError::ChannelClosed => Status::internal(err.to_string()),
        }
    }
}
