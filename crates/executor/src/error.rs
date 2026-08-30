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
    #[error("invalid quote request: {0}")]
    InvalidQuoteRequest(String),
    #[error("invalid Catena package source: {0}")]
    InvalidPackageSource(String),
    #[error("Catena package load failed: {0}")]
    PackageLoad(String),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("artifact not found: {0}")]
    ArtifactNotFound(String),
    #[error("artifact store error: {0}")]
    ArtifactStore(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    /// Deliberately not [`ExecutorError::PolicyDenied`]: the caller is
    /// permitted to ask, and the answer would be a price if this node
    /// had the package loaded. It does not, and a quote may not load
    /// one. What the client hears is "not here yet", which is the thing
    /// an operator can fix.
    #[error("Catena package is not loaded: {0}")]
    PackageNotLoaded(String),
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
        ExecutorError::QueueFull { .. } | ExecutorError::QuotaExceeded { .. } => {
            WireCode::ResourceExhausted
        }
        ExecutorError::InvalidQuoteRequest(_)
        | ExecutorError::InvalidPackageSource(_)
        | ExecutorError::InvalidTokenPayload(_)
        | ExecutorError::TokenBytes(_) => WireCode::InvalidArgument,
        ExecutorError::PackageNotLoaded(_) => WireCode::FailedPrecondition,
        ExecutorError::State(StateError::QuoteExpired(_)) => WireCode::FailedPrecondition,
        ExecutorError::PolicyDenied(_) => WireCode::PermissionDenied,
        ExecutorError::ArtifactNotFound(_) | ExecutorError::State(StateError::QuoteNotFound(_)) => {
            WireCode::NotFound
        }
        ExecutorError::ChannelClosed
        | ExecutorError::PackageLoad(_)
        | ExecutorError::Execution(_)
        | ExecutorError::ArtifactStore(_) => WireCode::Internal,
    }
}

impl From<ExecutorError> for WireStatus {
    fn from(err: ExecutorError) -> Self {
        WireStatus::new(executor_wire_code(&err), err.to_string())
    }
}
