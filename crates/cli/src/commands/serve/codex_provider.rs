use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use hellas_executor::{
    FetchProvider, FetchProviderError, FetchProviderFuture, FetchProviderRequest,
    FetchProviderStream,
};
use reqwest::Url;

use crate::commands::codex_auth::CodexAuthStore;
use crate::commands::http_client;

use super::DEFAULT_CODEX_BASE_URL;
use super::responses_fetch::execute_responses_request;

#[derive(Clone)]
pub(super) struct CodexResponsesFetchProvider {
    client: reqwest::Client,
    auth: CodexAuthStore,
    base_url: Url,
}

impl CodexResponsesFetchProvider {
    pub(super) fn new(base_url: &str, auth_path: Option<&Path>) -> anyhow::Result<Self> {
        let base_url = if base_url.trim().is_empty() {
            DEFAULT_CODEX_BASE_URL
        } else {
            base_url.trim()
        };
        let base_url = Url::parse(base_url)
            .with_context(|| format!("invalid Codex Responses base URL: {base_url}"))?;
        Ok(Self {
            client: http_client(Duration::from_secs(20 * 60)),
            auth: CodexAuthStore::new(auth_path)?,
            base_url,
        })
    }

    #[cfg(test)]
    fn with_store(client: reqwest::Client, base_url: Url, auth: CodexAuthStore) -> Self {
        Self {
            client,
            auth,
            base_url,
        }
    }

    async fn execute(
        &self,
        request: FetchProviderRequest,
    ) -> Result<FetchProviderStream, FetchProviderError> {
        let access_token = self.auth.access_token().await.map_err(|err| {
            FetchProviderError::failed(format!("Codex authentication failed: {err}"))
        })?;
        let endpoint = responses_endpoint(&self.base_url);
        execute_responses_request(
            &self.client,
            endpoint,
            &access_token,
            request.body.as_bytes().to_vec(),
            &request.idempotency_key(),
            "Codex Responses",
        )
        .await
    }
}

impl FetchProvider for CodexResponsesFetchProvider {
    fn run(&self, request: FetchProviderRequest) -> FetchProviderFuture<'_> {
        Box::pin(async move { self.execute(request).await })
    }
}

fn responses_endpoint(base_url: &Url) -> Url {
    let mut base = base_url.clone();
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path().trim_end_matches('/'));
        base.set_path(&path);
    }
    base.join("responses").expect("valid Codex Responses URL")
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
    use base64::Engine;
    use futures::StreamExt;
    use hellas_rpc::JsonBytes;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    type CapturedRequest = (Option<String>, Option<String>, Bytes);

    #[derive(Clone)]
    struct Capture {
        tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<CapturedRequest>>>>,
    }

    async fn capture_responses_sse(
        State(capture): State<Capture>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let auth = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let idempotency_key = headers
            .get("Idempotency-Key")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        if let Some(tx) = capture.tx.lock().await.take() {
            let _ = tx.send((auth, idempotency_key, body));
        }
        Response::builder()
            .body(Body::from(
                r#"event: response.created
data: {"type":"response.created","response":{"id":"resp_codex_up","object":"response","created_at":42,"status":"in_progress"}}

event: response.output_item.added
data: {"type":"response.output_item.added","item":{"content":[],"id":"msg_codex_up","role":"assistant","status":"in_progress","type":"message"}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_codex_up","delta":"ok"}

event: response.completed
data: {"type":"response.completed","response":{"id":"resp_codex_up","object":"response","created_at":42,"status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}

"#,
            ))
            .unwrap()
    }

    fn request(body: &[u8]) -> FetchProviderRequest {
        FetchProviderRequest::new(
            "codex",
            "responses",
            JsonBytes::new(body.to_vec()),
            hellas_rpc::InputCommitment::from_digest(hellas_rpc::Digest::from_bytes([7; 32])),
        )
    }

    #[tokio::test]
    async fn forwards_streaming_request_with_codex_token() {
        let (tx, rx) = oneshot::channel();
        let app = Router::new()
            .route("/codex/responses", post(capture_responses_sse))
            .with_state(Capture {
                tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let dir = tempfile::tempdir().unwrap();
        let auth = CodexAuthStore::with_token_url(
            dir.path().join("codex-auth.json"),
            Url::parse("http://127.0.0.1/token").unwrap(),
        );
        let access_token = non_expiring_token();
        auth.save(&crate::commands::codex_auth::CodexAuthState::new(
            crate::commands::codex_auth::test_tokens(&access_token, "refresh"),
            None,
        ))
        .unwrap();
        let provider = CodexResponsesFetchProvider::with_store(
            reqwest::Client::new(),
            Url::parse(&format!("http://{addr}/codex")).unwrap(),
            auth,
        );

        let body = br#"{"model":"gpt-5.5-codex","input":"hello","stream":true}"#;
        let mut stream = provider.run(request(body)).await.unwrap();
        let mut output = Vec::new();
        while let Some(event) = stream.next().await {
            output.push(event.unwrap());
        }
        let (auth, idempotency_key, forwarded_body) = rx.await.unwrap();

        assert_eq!(auth, Some(format!("Bearer {access_token}")));
        assert_eq!(idempotency_key, Some(request(body).idempotency_key()));
        assert_eq!(forwarded_body.as_ref(), body);
        let joined = String::from_utf8(output.concat()).unwrap();
        assert!(joined.contains("event: response.created"));
        assert!(joined.contains(r#""id":"resp_codex_up""#));
        assert!(joined.contains(r#""delta":"ok""#));
        assert!(joined.contains("event: response.completed"));
    }

    #[test]
    fn joins_responses_endpoint_to_codex_base_url() {
        assert_eq!(
            responses_endpoint(&Url::parse("https://chatgpt.com/backend-api/codex").unwrap())
                .as_str(),
            "https://chatgpt.com/backend-api/codex/responses"
        );
    }

    fn non_expiring_token() -> String {
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":4102444800}"#);
        format!("header.{payload}.signature")
    }
}
