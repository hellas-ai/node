use hellas_wire::{WireCode, WireStatus};
use thiserror::Error;

use hellas_rpc::TokenBytesError;

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
    #[error("{0}")]
    ResourceExhausted(String),
    #[error("invalid quote request: {0}")]
    InvalidQuoteRequest(String),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("artifact not found: {0}")]
    ArtifactNotFound(String),
    #[error("artifact store error: {0}")]
    ArtifactStore(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("{message}")]
    QuotaExceeded {
        retry_after_ms: Option<u64>,
        message: String,
    },
    #[error("invalid token payload: {0}")]
    InvalidTokenPayload(String),
    #[error(transparent)]
    TokenBytes(#[from] TokenBytesError),
    #[error(transparent)]
    State(#[from] StateError),
}

fn executor_wire_code(err: &ExecutorError) -> WireCode {
    match err {
        ExecutorError::QueueFull { .. }
        | ExecutorError::ResourceExhausted(_)
        | ExecutorError::QuotaExceeded { .. } => WireCode::ResourceExhausted,
        ExecutorError::InvalidQuoteRequest(_)
        | ExecutorError::InvalidTokenPayload(_)
        | ExecutorError::TokenBytes(_) => WireCode::InvalidArgument,
        ExecutorError::State(StateError::QuoteExpired(_)) => WireCode::FailedPrecondition,
        ExecutorError::PolicyDenied(_) => WireCode::PermissionDenied,
        ExecutorError::ArtifactNotFound(_) | ExecutorError::State(StateError::QuoteNotFound(_)) => {
            WireCode::NotFound
        }
        ExecutorError::ChannelClosed
        | ExecutorError::Execution(_)
        | ExecutorError::ArtifactStore(_) => WireCode::Internal,
    }
}

impl From<ExecutorError> for WireStatus {
    fn from(err: ExecutorError) -> Self {
        WireStatus::new(executor_wire_code(&err), err.to_string())
    }
}
