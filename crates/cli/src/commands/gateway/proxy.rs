use axum::body::{Body, Bytes};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use futures::TryStreamExt;
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderName as ReqwestHeaderName};

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

        proxy_response(upstream)
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
}
