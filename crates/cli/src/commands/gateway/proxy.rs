use axum::body::{Body, Bytes};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use futures::TryStreamExt;
use hellas_wire_adaptors::{
    BackendError, BackendFuture, BackendRequest, ExecutionBackend, ExecutionResult,
    OutputEventStream, OutputItem, StopReason, TextChannel, Usage,
};
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderName as ReqwestHeaderName};
use serde_json::Value as JsonValue;

use super::state::HttpError;

#[derive(Clone)]
pub(super) struct ResponsesProxy {
    client: reqwest::Client,
    endpoint: Url,
    bearer_token: Option<String>,
}

impl ResponsesProxy {
    pub(super) fn new(endpoint: &str, api_key_env: &str) -> anyhow::Result<Self> {
        let endpoint = Url::parse(endpoint)?;
        let bearer_token = std::env::var(api_key_env)
            .ok()
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty());
        Ok(Self::from_parts(endpoint, bearer_token))
    }

    fn from_parts(endpoint: Url, bearer_token: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint,
            bearer_token,
        }
    }

    pub(super) async fn forward(&self, body: Bytes) -> Result<Response, HttpError> {
        let upstream = self.send_raw(body).await?;
        proxy_response(upstream)
    }

    async fn send_raw(&self, body: Bytes) -> Result<reqwest::Response, HttpError> {
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(body);

        if let Some(token) = &self.bearer_token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }

        let upstream = request.send().await.map_err(|source| HttpError {
            status: StatusCode::BAD_GATEWAY,
            message: format!("Responses proxy request failed: {source}"),
        })?;
        Ok(upstream)
    }
}

impl ExecutionBackend for ResponsesProxy {
    fn execute<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, ExecutionResult> {
        Box::pin(async move {
            let upstream = self
                .send_raw(Bytes::from(request.raw.bytes().to_vec()))
                .await
                .map_err(|err| BackendError::execution(err.message))?;
            let status = upstream.status();
            if !status.is_success() {
                return Err(BackendError::execution(format!(
                    "Responses proxy returned HTTP {status}"
                )));
            }
            let body = upstream
                .bytes()
                .await
                .map_err(|source| BackendError::execution(source.to_string()))?;
            responses_execution_result(&body)
        })
    }

    fn stream<'a>(&'a self, _request: BackendRequest) -> BackendFuture<'a, OutputEventStream<'a>> {
        Box::pin(async move {
            Err(BackendError::stream(
                "Responses proxy streaming is forwarded at the HTTP response layer",
            ))
        })
    }
}

fn proxy_response(upstream: reqwest::Response) -> Result<Response, HttpError> {
    let status = StatusCode::from_u16(upstream.status().as_u16()).map_err(|source| HttpError {
        status: StatusCode::BAD_GATEWAY,
        message: format!("Responses proxy returned invalid status: {source}"),
    })?;

    let mut builder = Response::builder().status(status);
    for (name, value) in upstream.headers() {
        if !is_forwarded_response_header(name) {
            continue;
        }
        let Ok(header_name) = HeaderName::from_bytes(name.as_str().as_bytes()) else {
            continue;
        };
        let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) else {
            continue;
        };
        builder = builder.header(header_name, header_value);
    }

    let body = Body::from_stream(upstream.bytes_stream().map_err(std::io::Error::other));
    builder.body(body).map_err(|source| HttpError {
        status: StatusCode::BAD_GATEWAY,
        message: format!("Responses proxy response failed: {source}"),
    })
}

fn is_forwarded_response_header(name: &ReqwestHeaderName) -> bool {
    !matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn responses_execution_result(bytes: &[u8]) -> Result<ExecutionResult, BackendError> {
    let value: JsonValue = serde_json::from_slice(bytes)
        .map_err(|source| BackendError::execution(format!("invalid Responses JSON: {source}")))?;
    let output = value
        .get("output")
        .and_then(JsonValue::as_array)
        .map(|items| output_items(items))
        .unwrap_or_else(|| {
            value
                .get("output_text")
                .and_then(JsonValue::as_str)
                .map(|text| {
                    vec![OutputItem::Text {
                        text: text.to_string(),
                        channel: TextChannel::Output,
                    }]
                })
                .unwrap_or_default()
        });

    Ok(ExecutionResult {
        output,
        usage: value.get("usage").map(usage_from_json),
        stop_reason: stop_reason_from_response(&value),
        provenance: None,
    })
}

fn output_items(items: &[JsonValue]) -> Vec<OutputItem> {
    items.iter().flat_map(output_item).collect()
}

fn output_item(item: &JsonValue) -> Vec<OutputItem> {
    match item.get("type").and_then(JsonValue::as_str) {
        Some("message") => item
            .get("content")
            .and_then(JsonValue::as_array)
            .map(|parts| parts.iter().map(message_content_part).collect())
            .unwrap_or_default(),
        Some("function_call") => vec![OutputItem::ToolCall {
            id: item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            name: item
                .get("name")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            arguments: parse_arguments(item.get("arguments")),
        }],
        _ => vec![OutputItem::Raw(item.clone())],
    }
}

fn message_content_part(part: &JsonValue) -> OutputItem {
    match part.get("type").and_then(JsonValue::as_str) {
        Some("output_text" | "text") => OutputItem::Text {
            text: part
                .get("text")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            channel: TextChannel::Output,
        },
        Some("reasoning_text") => OutputItem::Text {
            text: part
                .get("text")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            channel: TextChannel::Reasoning,
        },
        _ => OutputItem::Raw(part.clone()),
    }
}

fn parse_arguments(arguments: Option<&JsonValue>) -> JsonValue {
    match arguments {
        Some(JsonValue::String(value)) => {
            serde_json::from_str(value).unwrap_or_else(|_| JsonValue::String(value.clone()))
        }
        Some(value) => value.clone(),
        None => JsonValue::Null,
    }
}

fn usage_from_json(value: &JsonValue) -> Usage {
    Usage {
        input_tokens: value.get("input_tokens").and_then(JsonValue::as_u64),
        output_tokens: value.get("output_tokens").and_then(JsonValue::as_u64),
        total_tokens: value.get("total_tokens").and_then(JsonValue::as_u64),
    }
}

fn stop_reason_from_response(value: &JsonValue) -> StopReason {
    match value.get("status").and_then(JsonValue::as_str) {
        Some("incomplete")
            if value
                .get("incomplete_details")
                .and_then(|details| details.get("reason"))
                .and_then(JsonValue::as_str)
                == Some("max_output_tokens") =>
        {
            StopReason::MaxOutputTokens
        }
        Some("cancelled") => StopReason::Cancelled,
        _ => StopReason::EndOfText,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::to_bytes;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    #[derive(Clone)]
    struct Capture {
        tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<(Option<String>, Bytes)>>>>,
    }

    async fn capture(
        State(capture): State<Capture>,
        headers: HeaderMap,
        body: Bytes,
    ) -> &'static str {
        let auth = headers
            .get(AUTHORIZATION.as_str())
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        if let Some(tx) = capture.tx.lock().await.take() {
            let _ = tx.send((auth, body));
        }
        r#"{"ok":true}"#
    }

    async fn capture_responses_json(
        State(capture): State<Capture>,
        headers: HeaderMap,
        body: Bytes,
    ) -> &'static str {
        let auth = headers
            .get(AUTHORIZATION.as_str())
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        if let Some(tx) = capture.tx.lock().await.take() {
            let _ = tx.send((auth, body));
        }
        r#"{
            "id": "resp_test",
            "object": "response",
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "content": [
                        {"type": "output_text", "text": "done"}
                    ]
                },
                {
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "lookup",
                    "arguments": "{\"query\":\"tea\"}"
                }
            ],
            "usage": {
                "input_tokens": 3,
                "output_tokens": 2,
                "total_tokens": 5
            }
        }"#
    }

    #[tokio::test]
    async fn forwards_raw_body_and_bearer_token() {
        let (tx, rx) = oneshot::channel();
        let captured = Capture {
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
        };
        let app = Router::new()
            .route("/v1/responses", post(capture))
            .with_state(captured);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let proxy = ResponsesProxy::from_parts(
            Url::parse(&format!("http://{addr}/v1/responses")).unwrap(),
            Some("test-key".to_string()),
        );
        let response = proxy
            .forward(Bytes::from_static(
                br#"{"model":"m","input":"hello","seed":7}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let response_body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(response_body, Bytes::from_static(br#"{"ok":true}"#));

        let (auth, body) = rx.await.unwrap();
        assert_eq!(auth.as_deref(), Some("Bearer test-key"));
        assert_eq!(
            body,
            Bytes::from_static(br#"{"model":"m","input":"hello","seed":7}"#)
        );
    }

    #[tokio::test]
    async fn execution_backend_forwards_raw_request_and_projects_response() {
        use hellas_wire_adaptors::openai::responses::OpenAiResponsesAdaptor;
        use hellas_wire_adaptors::{RawRequest, WireAdaptor};

        let (tx, rx) = oneshot::channel();
        let captured = Capture {
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
        };
        let app = Router::new()
            .route("/v1/responses", post(capture_responses_json))
            .with_state(captured);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let body =
            Bytes::from_static(br#"{"model":"m","input":"hello","metadata":{"trace":"abc"}}"#);
        let raw = RawRequest::from_slice(&body).unwrap();
        let adaptor = OpenAiResponsesAdaptor;
        let parsed = adaptor.parse(raw.clone()).unwrap();
        let execution = adaptor.to_execution_request(&parsed).unwrap();
        let proxy = ResponsesProxy::from_parts(
            Url::parse(&format!("http://{addr}/v1/responses")).unwrap(),
            Some("test-key".to_string()),
        );

        let result = proxy
            .execute(BackendRequest::new(execution, raw))
            .await
            .unwrap();

        let (auth, forwarded_body) = rx.await.unwrap();
        assert_eq!(auth.as_deref(), Some("Bearer test-key"));
        assert_eq!(forwarded_body, body);
        assert_eq!(result.usage.unwrap().total_tokens, Some(5));
        assert_eq!(result.stop_reason, StopReason::EndOfText);
        assert_eq!(
            result.output,
            vec![
                OutputItem::Text {
                    text: "done".to_string(),
                    channel: TextChannel::Output,
                },
                OutputItem::ToolCall {
                    id: "call_1".to_string(),
                    name: "lookup".to_string(),
                    arguments: serde_json::json!({"query": "tea"}),
                }
            ]
        );
    }
}
