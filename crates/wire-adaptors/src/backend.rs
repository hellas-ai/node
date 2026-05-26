use std::future::Future;
use std::pin::Pin;

use futures_core::Stream;
use thiserror::Error;

use crate::{ExecutionRequest, ExecutionResult, OutputEvent, RawRequest};

pub type BackendResult<T> = Result<T, BackendError>;
pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = BackendResult<T>> + Send + 'a>>;
pub type OutputEventStream = Pin<Box<dyn Stream<Item = BackendResult<OutputEvent>> + Send>>;

#[derive(Clone, Debug, PartialEq)]
pub struct BackendRequest {
    pub execution: ExecutionRequest,
    pub raw: RawRequest,
}

impl BackendRequest {
    pub fn new(execution: ExecutionRequest, raw: RawRequest) -> Self {
        Self { execution, raw }
    }
}

pub trait ExecutionBackend {
    fn execute<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, ExecutionResult>;

    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream>;
}

pub struct BackendStream {
    pub events: OutputEventStream,
    pub initial_provenance: Option<crate::Provenance>,
}

impl BackendStream {
    pub fn new(
        events: impl Stream<Item = BackendResult<OutputEvent>> + Send + 'static,
        initial_provenance: Option<crate::Provenance>,
    ) -> Self {
        Self {
            events: Box::pin(events),
            initial_provenance,
        }
    }
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("backend rejected request: {message}")]
    Rejected { message: String },
    #[error("backend execution failed: {message}")]
    Execution { message: String },
    #[error("backend stream failed: {message}")]
    Stream { message: String },
}

impl BackendError {
    pub fn rejected(message: impl Into<String>) -> Self {
        Self::Rejected {
            message: message.into(),
        }
    }

    pub fn execution(message: impl Into<String>) -> Self {
        Self::Execution {
            message: message.into(),
        }
    }

    pub fn stream(message: impl Into<String>) -> Self {
        Self::Stream {
            message: message.into(),
        }
    }
}
