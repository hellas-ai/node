use super::backend::{GatewayBackend, GatewaySurface};
use super::next_id;
use super::state::GatewayState;
use super::wire_adaptor::{backend_response, backend_stream_response, parse_backend_request};
use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;
use hellas_wire_adaptors::RenderContext;
use hellas_wire_adaptors::anthropic::AnthropicMessagesAdaptor;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let adaptor = AnthropicMessagesAdaptor;
    let (mut parsed, mut request) =
        match parse_backend_request(&adaptor, &body, "Anthropic Messages") {
            Ok(request) => request,
            Err(response) => return response,
        };
    let stream = parsed.stream == Some(true);
    if let Some(model) = state.force_model.as_ref() {
        parsed.model = model.clone();
        request.execution.canonical.model.name = model.clone();
    }
    let backend = GatewayBackend::new(state, GatewaySurface::Anthropic);
    if stream {
        backend_stream_response(
            adaptor,
            parsed,
            backend,
            request,
            render_context(),
            "Anthropic Messages",
        )
        .await
    } else {
        backend_response(
            adaptor,
            parsed,
            backend,
            request,
            render_context(),
            "Anthropic Messages",
        )
        .await
    }
}

fn render_context() -> RenderContext {
    RenderContext::new(next_id("msg"), next_id("unused"), 0)
}
