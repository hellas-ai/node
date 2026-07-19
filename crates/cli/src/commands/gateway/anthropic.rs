use super::backend::GatewayBackend;
use super::next_id;
use super::state::GatewayState;
use super::dispatch::{backend_wire_response, parse_backend_request};
use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;
use hellas_adaptors::RenderContext;
use hellas_adaptors::anthropic::AnthropicMessagesAdaptor;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let adaptor = AnthropicMessagesAdaptor;
    let (mut parsed, mut request) =
        match parse_backend_request(&adaptor, &body, "Anthropic Messages") {
            Ok(request) => request,
            Err(response) => return *response,
        };
    let stream = parsed.stream == Some(true);
    if let Some(model) = state.force_model.as_ref() {
        parsed.model = model.clone();
        request.execution.canonical.model.name = model.clone();
    }
    let backend = GatewayBackend::new(state);
    backend_wire_response(
        stream,
        adaptor,
        parsed,
        backend,
        request,
        render_context(),
        "Anthropic Messages",
    )
    .await
}

fn render_context() -> RenderContext {
    let id = next_id("msg");
    RenderContext::new(id.clone(), id, 0)
}
