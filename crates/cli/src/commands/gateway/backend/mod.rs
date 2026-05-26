use std::sync::Arc;

use hellas_wire_adaptors::{
    BackendError, BackendFuture, BackendRequest, BackendStream, ExecutionBackend, ExecutionResult,
};

mod chat;
mod generation;
mod provenance;
mod text;

use self::chat::{chat_events, execute_chat};
use self::provenance::provenance_from_execution;
use self::text::{execute_text, text_events};
use super::state::{GatewayState, PreparedGeneration};

#[derive(Clone)]
pub(super) struct GatewayBackend {
    state: Arc<GatewayState>,
    surface: GatewaySurface,
}

#[derive(Clone, Copy)]
pub(super) enum GatewaySurface {
    Responses,
    Completion,
    OpenAiChat,
    Anthropic,
}

impl GatewayBackend {
    pub(super) fn new(state: Arc<GatewayState>, surface: GatewaySurface) -> Self {
        Self { state, surface }
    }

    async fn prepare(&self, request: &BackendRequest) -> Result<PreparedGeneration, BackendError> {
        let result = match self.surface {
            GatewaySurface::Responses => {
                self.state
                    .prepare_responses_execution(&request.execution)
                    .await
            }
            GatewaySurface::Completion => {
                self.state.prepare_plain_execution(&request.execution).await
            }
            GatewaySurface::OpenAiChat => {
                self.state
                    .prepare_openai_chat_execution(&request.execution)
                    .await
            }
            GatewaySurface::Anthropic => {
                self.state
                    .prepare_anthropic_execution(&request.execution)
                    .await
            }
        };
        result.map_err(|err| {
            if err.status.is_client_error() {
                BackendError::rejected(err.message)
            } else {
                BackendError::execution(err.message)
            }
        })
    }

    fn tool_call_id_prefix(&self) -> &'static str {
        match self.surface {
            GatewaySurface::Anthropic => "toolu",
            GatewaySurface::OpenAiChat => "call",
            GatewaySurface::Responses | GatewaySurface::Completion => "call",
        }
    }

    fn ready_message(&self) -> &'static str {
        match self.surface {
            GatewaySurface::Responses => "openai response ready",
            GatewaySurface::Completion => "completion request ready",
            GatewaySurface::OpenAiChat => "openai chat completion ready",
            GatewaySurface::Anthropic => "anthropic message completion ready",
        }
    }
}

impl ExecutionBackend for GatewayBackend {
    fn execute<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, ExecutionResult> {
        Box::pin(async move {
            let prepared = self.prepare(&request).await?;
            match self.surface {
                GatewaySurface::Responses | GatewaySurface::Completion => {
                    execute_text(prepared, self.ready_message()).await
                }
                GatewaySurface::OpenAiChat | GatewaySurface::Anthropic => {
                    execute_chat(prepared, self.tool_call_id_prefix(), self.ready_message()).await
                }
            }
        })
    }

    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream<'static>> {
        Box::pin(async move {
            let prepared = self.prepare(&request).await?;
            let initial_provenance = prepared
                .provenance
                .as_ref()
                .and_then(provenance_from_execution);
            let stream = match self.surface {
                GatewaySurface::Responses | GatewaySurface::Completion => BackendStream::new(
                    text_events(prepared, self.ready_message()),
                    initial_provenance,
                ),
                GatewaySurface::OpenAiChat | GatewaySurface::Anthropic => BackendStream::new(
                    chat_events(prepared, self.tool_call_id_prefix(), self.ready_message()),
                    initial_provenance,
                ),
            };
            Ok(stream)
        })
    }
}
