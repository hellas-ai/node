use super::backend::GatewayBackend;
use super::state::GatewayState;
use super::wire_adaptor::{backend_response, backend_stream_response, parse_backend_request};
use super::{next_id, now_unix};
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use hellas_wire_adaptors::openai::responses::OpenAiResponsesAdaptor;
use hellas_wire_adaptors::openai::responses::ParsedResponseRequest;
use hellas_wire_adaptors::{BackendRequest, RenderContext};
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let adaptor = OpenAiResponsesAdaptor;
    let (mut parsed, mut request) = match parse_backend_request(&adaptor, &body, "OpenAI Responses")
    {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let stream = parsed.stream.unwrap_or(false);
    if let Some(model) = state.force_model.as_ref() {
        apply_model_override(&mut parsed, &mut request, model);
    }

    if let Some(proxy) = state.responses_proxy.as_ref() {
        if stream {
            return match proxy.forward_request(request).await {
                Ok(response) => response,
                Err(err) => err.into_response(),
            };
        }
        return backend_response(
            adaptor,
            parsed,
            proxy.as_ref().clone(),
            request,
            render_context(),
            "OpenAI Responses",
        )
        .await;
    }

    let backend = GatewayBackend::new(state);
    if stream {
        backend_stream_response(
            adaptor,
            parsed,
            backend,
            request,
            render_context(),
            "OpenAI Responses",
        )
        .await
    } else {
        backend_response(
            adaptor,
            parsed,
            backend,
            request,
            render_context(),
            "OpenAI Responses",
        )
        .await
    }
}

fn apply_model_override(
    parsed: &mut ParsedResponseRequest,
    request: &mut BackendRequest,
    model: &str,
) {
    parsed.model = model.to_string();
    request.execution.canonical.model.name = model.to_string();
}

fn render_context() -> RenderContext {
    RenderContext::new(next_id("resp"), next_id("msg"), now_unix())
}
