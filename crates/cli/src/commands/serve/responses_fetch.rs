use futures::StreamExt;
use hellas_executor::{FetchProviderError, FetchProviderRequest};
use hellas_wire_adaptors::openai::responses::{OpenAiResponsesAdaptor, ParsedResponseRequest};
use hellas_wire_adaptors::{
    BackendStream, RawRequest, RenderContext, WireAdaptor, WireBody, WireIngress,
};
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};

use crate::commands::openai_responses_stream::ResponsesSseProjector;

pub(super) fn parsed_streaming_request(
    request: &FetchProviderRequest,
) -> Result<ParsedResponseRequest, FetchProviderError> {
    let adaptor = OpenAiResponsesAdaptor;
    let raw = RawRequest::from_slice(request.body.as_bytes()).map_err(|err| {
        FetchProviderError::Rejected(format!("invalid OpenAI Responses request: {err}"))
    })?;
    let parsed = adaptor.parse(raw).map_err(|err| {
        FetchProviderError::Rejected(format!("invalid OpenAI Responses request: {err}"))
    })?;
    if parsed.stream != Some(true) {
        return Err(FetchProviderError::Rejected(
            "OpenAI Responses fetch requests must set stream=true".to_string(),
        ));
    }
    Ok(parsed)
}

pub(super) async fn execute_responses_request(
    client: &reqwest::Client,
    endpoint: Url,
    bearer_token: &str,
    body: Vec<u8>,
    parsed: ParsedResponseRequest,
    fallback_context: RenderContext,
    label: &str,
) -> Result<Vec<u8>, FetchProviderError> {
    let upstream = client
        .post(endpoint)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {bearer_token}"))
        .body(body)
        .send()
        .await
        .map_err(|source| {
            FetchProviderError::Failed(format!("{label} request failed: {source}"))
        })?;

    let status = upstream.status();
    if !status.is_success() {
        let body = upstream.text().await.unwrap_or_default();
        return Err(FetchProviderError::Failed(format!(
            "{label} returned HTTP {status}: {body}"
        )));
    }

    let adaptor = OpenAiResponsesAdaptor;
    if parsed.stream == Some(true) || is_event_stream(&upstream) {
        collect_sse_response(upstream, adaptor, parsed, fallback_context).await
    } else {
        let body = upstream.bytes().await.map_err(|source| {
            FetchProviderError::Failed(format!("{label} body read failed: {source}"))
        })?;
        adaptor.decode_response(&parsed, &body).map_err(|err| {
            FetchProviderError::Failed(format!("invalid {label} response body: {err}"))
        })?;
        Ok(body.to_vec())
    }
}

async fn collect_sse_response(
    upstream: reqwest::Response,
    adaptor: OpenAiResponsesAdaptor,
    parsed: ParsedResponseRequest,
    fallback_context: RenderContext,
) -> Result<Vec<u8>, FetchProviderError> {
    let mut chunks = upstream.bytes_stream();
    let mut projector = ResponsesSseProjector::new(parsed.clone());
    let mut events = Vec::new();

    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|source| {
            FetchProviderError::Failed(format!("Responses stream failed: {source}"))
        })?;
        events.extend(
            projector
                .push(&chunk)
                .map_err(|err| FetchProviderError::Failed(err.to_string()))?,
        );
    }
    events.extend(
        projector
            .finish()
            .map_err(|err| FetchProviderError::Failed(err.to_string()))?,
    );

    let result = BackendStream::new(futures::stream::iter(events.into_iter().map(Ok)), None)
        .collect()
        .await
        .map_err(|err| FetchProviderError::Failed(err.to_string()))?;
    let response = adaptor
        .render_response(&parsed, result, projector.render_context(fallback_context))
        .map_err(|err| FetchProviderError::Failed(err.to_string()))?;
    match response.body {
        WireBody::Json(value) => serde_json::to_vec(&value).map_err(|source| {
            FetchProviderError::Failed(format!("JSON encoding failed: {source}"))
        }),
        WireBody::Bytes(bytes) => Ok(bytes),
    }
}

fn is_event_stream(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .any(|part| part.trim().eq_ignore_ascii_case("text/event-stream"))
        })
}
