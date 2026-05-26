use super::backend::{GatewayBackend, GatewaySurface};
use super::state::GatewayState;
use super::wire_adaptor::{backend_response, backend_stream_response, parse_backend_request};
use super::{next_id, now_unix};
use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;
use hellas_wire_adaptors::RenderContext;
use hellas_wire_adaptors::openai::chat_completions::OpenAiChatCompletionsAdaptor;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let adaptor = OpenAiChatCompletionsAdaptor;
    let (mut parsed, mut request) =
        match parse_backend_request(&adaptor, &body, "OpenAI Chat Completions") {
            Ok(request) => request,
            Err(response) => return *response,
        };
    let stream = parsed.stream == Some(true);
    if let Some(model) = state.force_model.as_ref() {
        parsed.model = model.clone();
        request.execution.canonical.model.name = model.clone();
    }
    let backend = GatewayBackend::new(state, GatewaySurface::OpenAiChat);
    if stream {
        backend_stream_response(
            adaptor,
            parsed,
            backend,
            request,
            render_context(),
            "OpenAI Chat Completions",
        )
        .await
    } else {
        backend_response(
            adaptor,
            parsed,
            backend,
            request,
            render_context(),
            "OpenAI Chat Completions",
        )
        .await
    }
}

fn render_context() -> RenderContext {
    RenderContext::new(next_id("chatcmpl"), next_id("msg"), now_unix())
}
