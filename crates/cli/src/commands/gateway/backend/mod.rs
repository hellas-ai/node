use std::sync::Arc;

use hellas_wire_adaptors::{
    BackendError, BackendFuture, BackendRequest, BackendStream, ExecutionBackend, ExecutionResult,
};

mod generation;
mod provenance;
mod text;

use self::text::{execute_text, text_events};
use super::state::{GatewayState, PreparedGeneration};

#[derive(Clone)]
pub(super) struct GatewayBackend {
    state: Arc<GatewayState>,
}

impl GatewayBackend {
    pub(super) fn new(state: Arc<GatewayState>) -> Self {
        Self { state }
    }

    async fn prepare(&self, request: &BackendRequest) -> Result<PreparedGeneration, BackendError> {
        self.state
            .prepare_wire_execution(&request.execution)
            .await
            .map_err(|err| {
                if err.status.is_client_error() {
                    BackendError::rejected(err.message)
                } else {
                    BackendError::execution(err.message)
                }
            })
    }
}

impl ExecutionBackend for GatewayBackend {
    fn execute<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, ExecutionResult> {
        Box::pin(async move {
            let prepared = self.prepare(&request).await?;
            execute_text(prepared).await
        })
    }

    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream> {
        Box::pin(async move {
            let prepared = self.prepare(&request).await?;
            let initial_provenance = prepared
                .provenance
                .as_ref()
                .map(self::provenance::provenance_from_execution);
            Ok(BackendStream::new(
                text_events(prepared),
                initial_provenance,
            ))
        })
    }
}
