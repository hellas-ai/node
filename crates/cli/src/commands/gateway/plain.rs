use super::state::{GatewayState, PreparedGeneration};
use super::wire_adaptor::{parse_execution_request, text_response, text_stream_response};
use super::{next_id, now_unix};
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use hellas_wire_adaptors::RenderContext;
use hellas_wire_adaptors::openai::completions::{
    OpenAiCompletionsAdaptor, ParsedCompletionRequest,
};
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let adaptor = OpenAiCompletionsAdaptor;
    let (parsed, execution) = match parse_execution_request(&adaptor, &body, "OpenAI Completions") {
        Ok(request) => request,
        Err(response) => return response,
    };
    let stream_response_flag = parsed.stream == Some(true);
    let prepared = match state.prepare_plain_execution(&execution).await {
        Ok(prepared) => prepared,
        Err(err) => return err.into_response(),
    };

    if stream_response_flag {
        return stream_response(adaptor, parsed, prepared);
    }
    respond(adaptor, parsed, prepared).await
}

fn stream_response(
    adaptor: OpenAiCompletionsAdaptor,
    mut parsed: ParsedCompletionRequest,
    prepared: PreparedGeneration,
) -> Response {
    parsed.model = prepared.model.clone();
    text_stream_response(
        adaptor,
        parsed,
        prepared,
        RenderContext::new(next_id("cmpl"), next_id("unused"), now_unix()),
        "completion request ready",
    )
}

async fn respond(
    adaptor: OpenAiCompletionsAdaptor,
    mut parsed: ParsedCompletionRequest,
    prepared: PreparedGeneration,
) -> Response {
    parsed.model = prepared.model.clone();
    text_response(
        adaptor,
        parsed,
        prepared,
        RenderContext::new(next_id("cmpl"), next_id("unused"), now_unix()),
        "OpenAI Completions",
        "completion request ready",
    )
    .await
}
