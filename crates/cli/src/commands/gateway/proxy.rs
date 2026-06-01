use axum::body::Bytes;
use axum::http::StatusCode;
use futures::StreamExt;
use hellas_wire_adaptors::openai::responses::{
    OpenAiResponsesAdaptor, ParsedResponseRequest, ResponsesIngressState,
};
use hellas_wire_adaptors::{
    BackendError, BackendFuture, BackendRequest, BackendStream, ExecutionBackend, ExecutionResult,
    OutputEvent, SseDecoder, WireAdaptor, WireIngress, WireStreamEvent,
};
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::{Map as JsonMap, Value as JsonValue};

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
        Self::with_client(reqwest::Client::new(), endpoint, bearer_token)
    }

    fn with_client(client: reqwest::Client, endpoint: Url, bearer_token: Option<String>) -> Self {
        Self {
            client,
            endpoint,
            bearer_token,
        }
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
            let adaptor = OpenAiResponsesAdaptor;
            let parsed = adaptor
                .parse(request.raw.clone())
                .map_err(|err| BackendError::rejected(err.to_string()))?;
            let upstream = self
                .send_raw(forwarded_body(&request).map_err(BackendError::rejected)?)
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
            adaptor
                .decode_response(&parsed, &body)
                .map_err(|err| BackendError::execution(err.to_string()))
        })
    }

    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream> {
        Box::pin(async move {
            let adaptor = OpenAiResponsesAdaptor;
            let parsed = adaptor
                .parse(request.raw.clone())
                .map_err(|err| BackendError::rejected(err.to_string()))?;
            let upstream = self
                .send_raw(forwarded_body(&request).map_err(BackendError::rejected)?)
                .await
                .map_err(|err| BackendError::execution(err.message))?;
            let status = upstream.status();
            if !status.is_success() {
                return Err(BackendError::execution(format!(
                    "Responses proxy returned HTTP {status}"
                )));
            }
            Ok(BackendStream::new(
                responses_event_stream(upstream, adaptor, parsed),
                None,
            ))
        })
    }
}

fn forwarded_body(request: &BackendRequest) -> Result<Bytes, String> {
    let upstream_model = request.execution.canonical.model.name.as_str();
    let raw_model = request.raw.value().get("model").and_then(JsonValue::as_str);
    if raw_model == Some(upstream_model) {
        return Ok(Bytes::copy_from_slice(request.raw.bytes()));
    }

    let JsonValue::Object(mut object) = request.raw.value().clone() else {
        return Err("Responses proxy request body must be a JSON object".to_string());
    };
    object.insert(
        "model".to_string(),
        JsonValue::String(upstream_model.to_string()),
    );
    encode_json_object(object)
}

fn encode_json_object(object: JsonMap<String, JsonValue>) -> Result<Bytes, String> {
    serde_json::to_vec(&JsonValue::Object(object))
        .map(Bytes::from)
        .map_err(|source| format!("failed to encode Responses proxy request: {source}"))
}

fn responses_event_stream(
    upstream: reqwest::Response,
    adaptor: OpenAiResponsesAdaptor,
    parsed: ParsedResponseRequest,
) -> impl futures::Stream<Item = Result<OutputEvent, BackendError>> + Send + 'static {
    async_stream::stream! {
        let mut chunks = upstream.bytes_stream();
        let mut decoder = SseDecoder::new();
        let mut state = adaptor.initial_ingress_state(&parsed);

        while let Some(chunk) = chunks.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(source) => {
                    yield Err(BackendError::stream(format!("Responses proxy stream failed: {source}")));
                    return;
                }
            };
            let frames = match decoder.push(&chunk) {
                Ok(frames) => decode_sse_frames(&adaptor, &parsed, &mut state, frames),
                Err(err) => {
                    yield Err(BackendError::stream(err.to_string()));
                    return;
                }
            };
            let events = match frames {
                Ok(events) => events,
                Err(err) => {
                    yield Err(err);
                    return;
                }
            };
            for event in events {
                yield Ok(event);
            }
        }

        let frames = match decoder.finish() {
            Ok(frames) => decode_sse_frames(&adaptor, &parsed, &mut state, frames),
            Err(err) => {
                yield Err(BackendError::stream(err.to_string()));
                return;
            }
        };
        let events = match frames {
            Ok(events) => events,
            Err(err) => {
                yield Err(err);
                return;
            }
        };
        for event in events {
            yield Ok(event);
        }
    }
}

fn decode_sse_frames(
    adaptor: &OpenAiResponsesAdaptor,
    parsed: &ParsedResponseRequest,
    state: &mut ResponsesIngressState,
    frames: Vec<WireStreamEvent>,
) -> Result<Vec<OutputEvent>, BackendError> {
    let mut output = Vec::new();
    for frame in frames {
        output.extend(
            adaptor
                .decode_stream_event(parsed, state, frame)
                .map_err(|err| BackendError::stream(err.to_string()))?,
        );
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::response::Response;
    use axum::routing::post;
    use hellas_wire_adaptors::openai::responses::OpenAiResponsesAdaptor;
    use hellas_wire_adaptors::{
        OutputEvent, OutputItem, RawRequest, StopReason, TextChannel, Usage, WireAdaptor,
    };
    use std::sync::Arc;
    use tokio::sync::oneshot;

    type CapturedRequest = (Option<String>, Bytes);
    type CaptureSender = oneshot::Sender<CapturedRequest>;
    type SharedCaptureSender = Arc<tokio::sync::Mutex<Option<CaptureSender>>>;

    #[derive(Clone)]
    struct Capture {
        tx: SharedCaptureSender,
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

    async fn capture_responses_sse(
        State(capture): State<Capture>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let auth = headers
            .get(AUTHORIZATION.as_str())
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        if let Some(tx) = capture.tx.lock().await.take() {
            let _ = tx.send((auth, body));
        }
        Response::builder()
            .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from(
                r#"event: response.output_item.added
data: {"type":"response.output_item.added","item":{"content":[],"id":"msg_1","role":"assistant","status":"in_progress","type":"message"}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_1","delta":"hel"}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_1","delta":"lo"}

event: response.output_text.done
data: {"type":"response.output_text.done","item_id":"msg_1","text":"hello"}

event: response.completed
data: {"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}

"#,
            ))
            .unwrap()
    }

    fn backend_request(body: Bytes) -> BackendRequest {
        let raw = RawRequest::from_slice(&body).unwrap();
        let adaptor = OpenAiResponsesAdaptor;
        let parsed = adaptor.parse(raw.clone()).unwrap();
        let execution = adaptor.to_execution_request(&parsed).unwrap();
        BackendRequest::new(execution, raw)
    }

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .tls_certs_only(std::iter::empty::<reqwest::Certificate>())
            .build()
            .unwrap()
    }

    fn test_proxy(addr: std::net::SocketAddr, bearer_token: Option<String>) -> ResponsesProxy {
        ResponsesProxy::with_client(
            test_client(),
            Url::parse(&format!("http://{addr}/v1/responses")).unwrap(),
            bearer_token,
        )
    }

    #[tokio::test]
    async fn execution_backend_forwards_request_body_and_bearer_token() {
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

        let proxy = test_proxy(addr, Some("test-key".to_string()));
        let body = Bytes::from_static(br#"{"model":"m","input":"hello","seed":7}"#);
        let result = proxy.execute(backend_request(body.clone())).await.unwrap();

        let (auth, body) = rx.await.unwrap();
        assert_eq!(auth.as_deref(), Some("Bearer test-key"));
        assert_eq!(
            body,
            Bytes::from_static(br#"{"model":"m","input":"hello","seed":7}"#)
        );
        assert_eq!(result.output, Vec::new());
    }

    #[tokio::test]
    async fn rewrites_model_when_execution_model_changes() {
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

        let proxy = test_proxy(addr, None);
        let body = Bytes::from_static(br#"{"model":"public","input":"hello","seed":7}"#);
        let mut request = backend_request(body);
        request.execution.canonical.model.name = "upstream".to_string();

        let result = proxy.execute(request).await.unwrap();

        let (_auth, forwarded_body) = rx.await.unwrap();
        let forwarded: JsonValue = serde_json::from_slice(&forwarded_body).unwrap();
        assert_eq!(forwarded["model"], "upstream");
        assert_eq!(forwarded["input"], "hello");
        assert_eq!(forwarded["seed"], 7);
        assert_eq!(result.output, Vec::new());
    }

    #[tokio::test]
    async fn execution_backend_forwards_request_and_projects_response() {
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
        let proxy = test_proxy(addr, Some("test-key".to_string()));

        let result = proxy.execute(backend_request(body.clone())).await.unwrap();

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

    #[tokio::test]
    async fn streaming_backend_projects_responses_sse() {
        let (tx, rx) = oneshot::channel();
        let captured = Capture {
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
        };
        let app = Router::new()
            .route("/v1/responses", post(capture_responses_sse))
            .with_state(captured);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let body = Bytes::from_static(br#"{"model":"m","input":"hello","stream":true}"#);
        let proxy = test_proxy(addr, Some("test-key".to_string()));
        let stream = proxy.stream(backend_request(body.clone())).await.unwrap();
        let events = stream
            .events
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let (auth, forwarded_body) = rx.await.unwrap();
        assert_eq!(auth.as_deref(), Some("Bearer test-key"));
        assert_eq!(forwarded_body, body);
        assert_eq!(
            events,
            vec![
                OutputEvent::TextDelta {
                    index: 0,
                    delta: "hel".to_string(),
                    channel: TextChannel::Output,
                },
                OutputEvent::TextDelta {
                    index: 0,
                    delta: "lo".to_string(),
                    channel: TextChannel::Output,
                },
                OutputEvent::Finished {
                    stop_reason: StopReason::EndOfText,
                    usage: Some(Usage {
                        input_tokens: Some(3),
                        output_tokens: Some(2),
                        total_tokens: Some(5),
                    }),
                },
            ]
        );
    }
}
