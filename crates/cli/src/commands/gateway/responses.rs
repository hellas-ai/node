use super::state::{GatewayState, PreparedGeneration};
use super::wire_adaptor::{parse_execution_request, text_response, text_stream_response};
use super::{next_id, now_unix};
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use hellas_wire_adaptors::RenderContext;
use hellas_wire_adaptors::openai::responses::{OpenAiResponsesAdaptor, ParsedResponseRequest};
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    if let Some(proxy) = state.responses_proxy.as_ref() {
        return match proxy.forward(body).await {
            Ok(response) => response,
            Err(err) => err.into_response(),
        };
    }

    let adaptor = OpenAiResponsesAdaptor;
    let (parsed, execution) = match parse_execution_request(&adaptor, &body, "OpenAI Responses") {
        Ok(request) => request,
        Err(response) => return response,
    };
    let stream = parsed.stream.unwrap_or(false);
    let prepared = match state.prepare_wire_execution(&execution).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream {
        stream_response(adaptor, parsed, prepared)
    } else {
        respond(adaptor, parsed, prepared).await
    }
}

async fn respond(
    adaptor: OpenAiResponsesAdaptor,
    mut parsed: ParsedResponseRequest,
    prepared: PreparedGeneration,
) -> Response {
    parsed.model = prepared.model.clone();
    text_response(
        adaptor,
        parsed,
        prepared,
        render_context(),
        "OpenAI Responses",
        "openai response ready",
    )
    .await
}

fn stream_response(
    adaptor: OpenAiResponsesAdaptor,
    mut parsed: ParsedResponseRequest,
    prepared: PreparedGeneration,
) -> Response {
    parsed.model = prepared.model.clone();
    text_stream_response(
        adaptor,
        parsed,
        prepared,
        render_context(),
        "openai response ready",
    )
}

fn render_context() -> RenderContext {
    RenderContext::new(next_id("resp"), next_id("msg"), now_unix())
}
