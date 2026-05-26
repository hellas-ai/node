use super::backend::GatewayBackend;
use super::state::GatewayState;
use super::wire_adaptor::{backend_response, backend_stream_response, parse_backend_request};
use super::{next_id, now_unix};
use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;
use hellas_wire_adaptors::RenderContext;
use hellas_wire_adaptors::openai::completions::OpenAiCompletionsAdaptor;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let adaptor = OpenAiCompletionsAdaptor;
    let (mut parsed, mut request) =
        match parse_backend_request(&adaptor, &body, "OpenAI Completions") {
            Ok(request) => request,
            Err(response) => return *response,
        };
    let stream_response_flag = parsed.stream == Some(true);
    if let Some(model) = state.force_model.as_ref() {
        parsed.model = model.clone();
        request.execution.canonical.model.name = model.clone();
    }
    let backend = GatewayBackend::new(state);
    if stream_response_flag {
        backend_stream_response(
            adaptor,
            parsed,
            backend,
            request,
            render_context(),
            "OpenAI Completions",
        )
        .await
    } else {
        backend_response(
            adaptor,
            parsed,
            backend,
            request,
            render_context(),
            "OpenAI Completions",
        )
        .await
    }
}

fn render_context() -> RenderContext {
    RenderContext::new(next_id("cmpl"), next_id("unused"), now_unix())
}
