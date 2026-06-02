use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use futures::stream;
use hellas_executor::{
    FetchProvider, FetchProviderError, FetchProviderFuture, FetchProviderRequest,
    FetchProviderStream,
};
use hellas_wire_adaptors::RenderContext;
use reqwest::Url;

use super::responses_fetch::{execute_responses_request, parsed_streaming_request};

const SERVICE_OPENAI: &str = "openai";
const METHOD_RESPONSES: &str = "responses";

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub(super) struct OpenAiResponsesFetchProvider {
    client: reqwest::Client,
    endpoint: Url,
    bearer_token: String,
}

impl OpenAiResponsesFetchProvider {
    pub(super) fn new(endpoint: &str, api_key_env: &str) -> anyhow::Result<Self> {
        let endpoint = Url::parse(endpoint)
            .with_context(|| format!("invalid OpenAI Responses endpoint: {endpoint}"))?;
        let bearer_token = std::env::var(api_key_env)
            .with_context(|| format!("environment variable {api_key_env} is not set"))?;
        let bearer_token = bearer_token.trim().to_string();
        if bearer_token.is_empty() {
            bail!("environment variable {api_key_env} is empty");
        }
        Ok(Self::with_client(
            reqwest::Client::new(),
            endpoint,
            bearer_token,
        ))
    }

    fn with_client(client: reqwest::Client, endpoint: Url, bearer_token: String) -> Self {
        Self {
            client,
            endpoint,
            bearer_token,
        }
    }

    async fn execute(&self, request: FetchProviderRequest) -> Result<Vec<u8>, FetchProviderError> {
        if request.service != SERVICE_OPENAI || request.method != METHOD_RESPONSES {
            return Err(FetchProviderError::Rejected(format!(
                "unsupported fetch route {}/{}",
                request.service, request.method
            )));
        }

        let parsed = parsed_streaming_request(&request)?;
        execute_responses_request(
            &self.client,
            self.endpoint.clone(),
            &self.bearer_token,
            request.body.as_bytes().to_vec(),
            parsed,
            render_context(),
            "OpenAI Responses",
        )
        .await
    }
}

impl FetchProvider for OpenAiResponsesFetchProvider {
    fn run(&self, request: FetchProviderRequest) -> FetchProviderFuture<'_> {
        Box::pin(async move {
            let body = self.execute(request).await?;
            Ok(Box::pin(stream::once(async move { Ok(body) })) as FetchProviderStream)
        })
    }
}

fn render_context() -> RenderContext {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    RenderContext::new(
        format!("resp_fetch_{id}"),
        format!("msg_fetch_{id}"),
        now_unix(),
    )
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::{Body, Bytes};
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::response::Response;
    use axum::routing::post;
    use futures::StreamExt;
    use hellas_core::JsonBytes;
    use reqwest::header::AUTHORIZATION;
    use serde_json::Value as JsonValue;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    type CapturedRequest = (Option<String>, Bytes);
    type CaptureSender = oneshot::Sender<CapturedRequest>;
    type SharedCaptureSender = Arc<tokio::sync::Mutex<Option<CaptureSender>>>;

    #[derive(Clone)]
    struct Capture {
        tx: SharedCaptureSender,
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
                r#"event: response.created
data: {"type":"response.created","response":{"id":"resp_up","object":"response","created_at":42,"status":"in_progress"}}

event: response.output_item.added
data: {"type":"response.output_item.added","item":{"content":[],"id":"msg_up","role":"assistant","status":"in_progress","type":"message"}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_up","delta":"hel"}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_up","delta":"lo"}

event: response.completed
data: {"type":"response.completed","response":{"id":"resp_up","object":"response","created_at":42,"status":"completed","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}

"#,
            ))
            .unwrap()
    }

    fn provider(addr: std::net::SocketAddr) -> OpenAiResponsesFetchProvider {
        OpenAiResponsesFetchProvider::with_client(
            reqwest::Client::new(),
            Url::parse(&format!("http://{addr}/v1/responses")).unwrap(),
            "test-key".to_string(),
        )
    }

    fn request(body: &[u8]) -> FetchProviderRequest {
        FetchProviderRequest::new(
            SERVICE_OPENAI,
            METHOD_RESPONSES,
            JsonBytes::new(body.to_vec()),
        )
    }

    async fn collect(provider: &OpenAiResponsesFetchProvider, body: &[u8]) -> Vec<u8> {
        let mut stream = provider.run(request(body)).await.unwrap();
        let mut output = Vec::new();
        while let Some(chunk) = stream.next().await {
            output.extend(chunk.unwrap());
        }
        output
    }

    #[tokio::test]
    async fn forwards_streaming_request_and_projects_terminal_json() {
        let (tx, rx) = oneshot::channel();
        let app = Router::new()
            .route("/v1/responses", post(capture_responses_sse))
            .with_state(Capture {
                tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let body = br#"{"model":"m","input":"hello","stream":true,"metadata":{"trace":"abc"}}"#;
        let output = collect(&provider(addr), body).await;

        let (auth, forwarded_body) = rx.await.unwrap();
        assert_eq!(auth.as_deref(), Some("Bearer test-key"));
        assert_eq!(forwarded_body.as_ref(), body);

        let json: JsonValue = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["id"], "resp_up");
        assert_eq!(json["created_at"], 42);
        assert_eq!(json["model"], "m");
        assert_eq!(json["metadata"]["trace"], "abc");
        assert_eq!(json["usage"]["total_tokens"], 5);
        assert_eq!(json["output"][0]["id"], "msg_up");
        assert_eq!(json["output"][0]["content"][0]["text"], "hello");
    }

    #[tokio::test]
    async fn rejects_non_streaming_responses_requests() {
        let provider = OpenAiResponsesFetchProvider::with_client(
            reqwest::Client::new(),
            Url::parse("http://127.0.0.1:9/v1/responses").unwrap(),
            "test-key".to_string(),
        );
        let result = provider
            .run(request(br#"{"model":"m","input":"hello"}"#))
            .await;
        let Err(FetchProviderError::Rejected(message)) = result else {
            panic!("expected rejection");
        };
        assert!(message.contains("stream=true"));
    }
}
