use futures::StreamExt;
use hellas_adaptors::MAX_SSE_RESPONSE_BYTES;
use hellas_executor::{FetchProviderError, FetchProviderResponse, FetchProviderResponseHead};
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use std::time::Duration;

/// Maximum diagnostic prefix retained from an unsuccessful HTTP response.
const MAX_FETCH_ERROR_BODY_BYTES: usize = 2 * 1024;
/// A total request deadline bounds the whole call; this independent idle
/// deadline prevents a peer that stops producing SSE bytes from occupying a
/// Fetch execution slot for that entire window. Ordinary SSE keepalives count
/// as activity and reset it. Error bodies are diagnostic only, so the same
/// duration bounds their entire prefix read without renewal.
const FETCH_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// HTTP client for attested Fetch egress. Redirects are disabled because the
/// exact HTTPS destination is part of the quoted Fetch environment.
pub(super) fn responses_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20 * 60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Fetch HTTP client configuration is valid")
}

pub(super) async fn execute_responses_request(
    client: &reqwest::Client,
    endpoint: Url,
    bearer_token: &str,
    body: Vec<u8>,
    // Derived from the input transcript commitment, so a re-issued call for
    // the same ticket dedupes at the provider billing boundary where the
    // provider honors the header.
    idempotency_key: &str,
    label: &str,
) -> Result<FetchProviderResponse, FetchProviderError> {
    let upstream = client
        .post(endpoint)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {bearer_token}"))
        .header("Idempotency-Key", idempotency_key)
        .body(body)
        .send()
        .await
        .map_err(|source| {
            FetchProviderError::failed(format!("{label} request failed: {source}"))
        })?;

    let status = upstream.status();
    if !status.is_success() {
        let diagnostic = error_body_prefix(upstream).await;
        tracing::warn!(
            provider = label,
            upstream_status = status.as_u16(),
            upstream_diagnostic = %diagnostic,
            "upstream Fetch request failed; response details are omitted from the caller error"
        );
        return Err(FetchProviderError::failed(format!(
            "{label} upstream rejected the request (HTTP {})",
            status.as_u16()
        )));
    }

    let content_type = upstream
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !content_type.is_some_and(|value| value.eq_ignore_ascii_case("text/event-stream")) {
        return Err(FetchProviderError::failed(format!(
            "{label} returned successful HTTP {status} without text/event-stream content"
        )));
    }

    let head = FetchProviderResponseHead {
        effective_model: effective_model_from_headers(upstream.headers())?,
    };
    Ok(FetchProviderResponse {
        head,
        stream: Box::pin(stream_response(upstream, label.to_string())),
    })
}

/// Codex currently reads the standard `openai-model` response header. The
/// `x-openai-model` spelling is accepted as its compatibility fallback; the
/// standard spelling therefore wins when both are present. Repeated values of
/// either spelling are hostile unless they agree exactly.
fn effective_model_from_headers(
    headers: &reqwest::header::HeaderMap,
) -> Result<Option<String>, FetchProviderError> {
    let standard = unique_model_header(headers, "openai-model")?;
    let compatibility = unique_model_header(headers, "x-openai-model")?;
    Ok(standard.or(compatibility))
}

fn unique_model_header(
    headers: &reqwest::header::HeaderMap,
    name: &'static str,
) -> Result<Option<String>, FetchProviderError> {
    let mut value: Option<String> = None;
    for raw in headers.get_all(name) {
        let text = raw.to_str().map_err(|_| {
            FetchProviderError::failed(format!("{name} response header is not valid UTF-8"))
        })?;
        if text.is_empty() || text.len() > 256 {
            return Err(FetchProviderError::failed(format!(
                "{name} response header must contain 1..=256 UTF-8 bytes"
            )));
        }
        if value.as_deref().is_some_and(|existing| existing != text) {
            return Err(FetchProviderError::failed(format!(
                "conflicting duplicate {name} response headers"
            )));
        }
        value = Some(text.to_owned());
    }
    Ok(value)
}

async fn error_body_prefix(upstream: reqwest::Response) -> String {
    error_body_prefix_with_deadline(upstream, FETCH_STREAM_IDLE_TIMEOUT).await
}

async fn error_body_prefix_with_deadline(
    upstream: reqwest::Response,
    read_timeout: Duration,
) -> String {
    let mut body = Vec::new();
    let mut chunks = upstream.bytes_stream();
    let deadline = tokio::time::Instant::now() + read_timeout;

    while body.len() < MAX_FETCH_ERROR_BODY_BYTES {
        let next = match tokio::time::timeout_at(deadline, chunks.next()).await {
            Ok(next) => next,
            Err(_) => {
                let excerpt = diagnostic_excerpt(&body);
                let note = format!(
                    "[error body read timed out after {} seconds]",
                    read_timeout.as_secs_f64()
                );
                return if excerpt.is_empty() {
                    note
                } else {
                    format!("{excerpt} {note}")
                };
            }
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(source) => {
                let excerpt = diagnostic_excerpt(&body);
                let note = format!("[error body read failed: {source}]");
                return if excerpt.is_empty() {
                    note
                } else {
                    format!("{excerpt} {note}")
                };
            }
        };
        let remaining = MAX_FETCH_ERROR_BODY_BYTES - body.len();
        let retained = remaining.min(chunk.len());
        body.extend_from_slice(&chunk[..retained]);
        if retained < chunk.len() {
            break;
        }
    }

    let limited = body.len() == MAX_FETCH_ERROR_BODY_BYTES;
    let body = diagnostic_excerpt(&body);
    if limited {
        format!("{body} [body prefix limited to {MAX_FETCH_ERROR_BODY_BYTES} bytes]")
    } else {
        body
    }
}

fn diagnostic_excerpt(body: &[u8]) -> String {
    String::from_utf8_lossy(body)
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn stream_response(
    upstream: reqwest::Response,
    label: String,
) -> impl futures::Stream<Item = Result<Vec<u8>, FetchProviderError>> + Send + 'static {
    stream_response_with_idle_timeout(upstream, label, FETCH_STREAM_IDLE_TIMEOUT)
}

fn stream_response_with_idle_timeout(
    upstream: reqwest::Response,
    label: String,
    idle_timeout: Duration,
) -> impl futures::Stream<Item = Result<Vec<u8>, FetchProviderError>> + Send + 'static {
    async_stream::try_stream! {
        let mut chunks = upstream.bytes_stream();
        let mut received = 0_usize;

        loop {
            let next = tokio::time::timeout(idle_timeout, chunks.next())
                .await
                .map_err(|_| FetchProviderError::failed(format!(
                    "{label} stream produced no bytes for {} seconds",
                    idle_timeout.as_secs_f64()
                )))?;
            let Some(chunk) = next else {
                break;
            };
            let chunk = chunk.map_err(|source| {
                FetchProviderError::failed(format!("{label} stream failed: {source}"))
            })?;
            let next_received = received.checked_add(chunk.len()).ok_or_else(|| {
                FetchProviderError::failed(format!(
                    "{label} stream exceeded the {MAX_SSE_RESPONSE_BYTES}-byte limit"
                ))
            })?;
            if next_received > MAX_SSE_RESPONSE_BYTES {
                Err(FetchProviderError::failed(format!(
                    "{label} stream exceeded the {MAX_SSE_RESPONSE_BYTES}-byte limit"
                )))?;
            }
            received = next_received;
            yield chunk.to_vec();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::{Body, Bytes};
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::{Redirect, Response};
    use axum::routing::post;
    use futures::stream;
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn redirect() -> Redirect {
        Redirect::temporary("/sink")
    }

    async fn sink(State(hits): State<Arc<AtomicUsize>>) {
        hits.fetch_add(1, Ordering::SeqCst);
    }

    async fn json_success() -> Response {
        Response::builder()
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"ok":true}"#))
            .unwrap()
    }

    async fn oversized_error() -> Response {
        let mut body = vec![b'x'; MAX_FETCH_ERROR_BODY_BYTES];
        body.extend_from_slice(b"SECRET_AFTER_LIMIT");
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(body))
            .unwrap()
    }

    async fn sensitive_error() -> Response {
        Response::builder()
            .status(StatusCode::UNPROCESSABLE_ENTITY)
            .body(Body::from("UPSTREAM_PRIVATE_SENTINEL"))
            .unwrap()
    }

    async fn oversized_event_stream() -> Response {
        let chunk = vec![b'x'; MAX_SSE_RESPONSE_BYTES / 3];
        let chunks = stream::iter([
            Ok::<_, Infallible>(Bytes::from(chunk.clone())),
            Ok(Bytes::from(chunk.clone())),
            Ok(Bytes::from(chunk)),
            Ok(Bytes::from_static(b"x")),
        ]);
        Response::builder()
            .header(
                axum::http::header::CONTENT_TYPE,
                "text/event-stream; charset=utf-8",
            )
            .body(Body::from_stream(chunks))
            .unwrap()
    }

    fn stalled_error_before_first_byte() -> reqwest::Response {
        axum::http::Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(reqwest::Body::wrap_stream(stream::pending::<
                Result<Bytes, Infallible>,
            >()))
            .unwrap()
            .into()
    }

    fn stalled_error_after_partial_body() -> reqwest::Response {
        let chunks =
            stream::once(async { Ok::<_, Infallible>(Bytes::from_static(b"useful diagnostic")) })
                .chain(stream::pending());
        axum::http::Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(reqwest::Body::wrap_stream(chunks))
            .unwrap()
            .into()
    }

    fn promptly_streamed_error() -> reqwest::Response {
        let chunks = stream::iter([
            Bytes::from_static(b"useful "),
            Bytes::from_static(b"diagnostic"),
        ])
        .then(|chunk| async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok::<_, Infallible>(chunk)
        });
        axum::http::Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(reqwest::Body::wrap_stream(chunks))
            .unwrap()
            .into()
    }

    async fn test_endpoint(app: Router, path: &str) -> Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Url::parse(&format!(
            "http://{}{}",
            listener.local_addr().unwrap(),
            path
        ))
        .unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        endpoint
    }

    async fn execute_test_request(
        endpoint: Url,
    ) -> Result<FetchProviderResponse, FetchProviderError> {
        execute_responses_request(
            &responses_http_client(),
            endpoint,
            "secret",
            br#"{"model":"m","input":"hi","stream":true}"#.to_vec(),
            "idempotency",
            "test",
        )
        .await
    }

    #[tokio::test]
    async fn attested_fetch_client_never_follows_redirects() {
        let hits = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/origin", post(redirect))
            .route("/sink", post(sink))
            .with_state(hits.clone());
        let endpoint = test_endpoint(app, "/origin").await;

        let result = execute_test_request(endpoint).await;
        let Err(error) = result else {
            panic!("redirect unexpectedly reached an upstream success response");
        };

        assert!(error.to_string().contains("HTTP 307"));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn successful_fetch_requires_event_stream_content_type() {
        let endpoint = test_endpoint(
            Router::new().route("/responses", post(json_success)),
            "/responses",
        )
        .await;

        let Err(error) = execute_test_request(endpoint).await else {
            panic!("JSON success unexpectedly passed the SSE content-type check");
        };

        assert!(error.to_string().contains("without text/event-stream"));
    }

    #[tokio::test]
    async fn provider_local_error_diagnostic_retains_only_a_bounded_body_prefix() {
        let endpoint = test_endpoint(
            Router::new().route("/responses", post(oversized_error)),
            "/responses",
        )
        .await;

        let response = responses_http_client().post(endpoint).send().await.unwrap();
        let diagnostic = error_body_prefix(response).await;

        assert!(diagnostic.contains(&format!(
            "body prefix limited to {MAX_FETCH_ERROR_BODY_BYTES} bytes"
        )));
        assert!(!diagnostic.contains("SECRET_AFTER_LIMIT"));
        assert!(diagnostic.len() < MAX_FETCH_ERROR_BODY_BYTES + 256);
    }

    #[tokio::test]
    async fn unsuccessful_fetch_never_forwards_the_upstream_body_to_the_caller() {
        let endpoint = test_endpoint(
            Router::new().route("/responses", post(sensitive_error)),
            "/responses",
        )
        .await;

        let Err(error) = execute_test_request(endpoint).await else {
            panic!("HTTP error unexpectedly passed");
        };
        let message = error.to_string();

        assert_eq!(
            message,
            "fetch provider failed: test upstream rejected the request (HTTP 422)"
        );
        assert!(!message.contains("UPSTREAM_PRIVATE_SENTINEL"));
    }

    #[tokio::test(start_paused = true)]
    async fn error_body_stalled_before_first_byte_hits_the_read_deadline() {
        let upstream = stalled_error_before_first_byte();
        let read_timeout = Duration::from_secs(5);
        let started = tokio::time::Instant::now();

        let diagnostic = error_body_prefix_with_deadline(upstream, read_timeout).await;

        assert_eq!(started.elapsed(), read_timeout);
        assert_eq!(diagnostic, "[error body read timed out after 5 seconds]");
    }

    #[tokio::test(start_paused = true)]
    async fn partial_error_body_is_retained_when_the_read_deadline_expires() {
        let upstream = stalled_error_after_partial_body();
        let read_timeout = Duration::from_secs(5);
        let started = tokio::time::Instant::now();

        let diagnostic = error_body_prefix_with_deadline(upstream, read_timeout).await;

        assert_eq!(started.elapsed(), read_timeout);
        assert_eq!(
            diagnostic,
            "useful diagnostic [error body read timed out after 5 seconds]"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn promptly_streamed_error_body_completes_within_the_read_deadline() {
        let upstream = promptly_streamed_error();
        let read_timeout = Duration::from_secs(5);
        let started = tokio::time::Instant::now();

        let diagnostic = error_body_prefix_with_deadline(upstream, read_timeout).await;

        assert_eq!(started.elapsed(), Duration::from_secs(2));
        assert_eq!(diagnostic, "useful diagnostic");
    }

    #[tokio::test]
    async fn stalled_sse_body_hits_the_idle_deadline() {
        async fn stalled() -> Response {
            let chunks =
                stream::once(async { Ok::<_, Infallible>(Bytes::from_static(b"data: first\n\n")) })
                    .chain(stream::pending());
            Response::builder()
                .header(CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(chunks))
                .unwrap()
        }

        let app = Router::new().route("/stalled", post(stalled));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let response = responses_http_client()
            .post(format!("http://{addr}/stalled"))
            .send()
            .await
            .unwrap();
        let stream = stream_response_with_idle_timeout(
            response,
            "test".to_string(),
            Duration::from_millis(10),
        );
        futures::pin_mut!(stream);

        assert_eq!(stream.next().await.unwrap().unwrap(), b"data: first\n\n");
        let error = stream.next().await.unwrap().unwrap_err().to_string();
        assert!(error.contains("produced no bytes"), "{error}");
    }

    #[tokio::test]
    async fn successful_fetch_caps_cumulative_upstream_bytes() {
        let endpoint = test_endpoint(
            Router::new().route("/responses", post(oversized_event_stream)),
            "/responses",
        )
        .await;
        let mut stream = execute_test_request(endpoint).await.unwrap().stream;
        let mut accepted = 0_usize;
        let error = loop {
            match stream.next().await {
                Some(Ok(chunk)) => accepted = accepted.checked_add(chunk.len()).unwrap(),
                Some(Err(error)) => break error,
                None => panic!("oversized upstream stream ended without a limit error"),
            }
        };

        assert!(accepted <= MAX_SSE_RESPONSE_BYTES);
        assert!(
            error
                .to_string()
                .contains("stream exceeded the 3145728-byte limit")
        );
    }

    #[test]
    fn effective_model_uses_standard_header_and_rejects_ambiguous_duplicates() {
        let mut headers = HeaderMap::new();
        headers.append("x-openai-model", HeaderValue::from_static("fallback"));
        headers.append("openai-model", HeaderValue::from_static("official"));
        assert_eq!(
            effective_model_from_headers(&headers).unwrap().as_deref(),
            Some("official")
        );

        headers.append("openai-model", HeaderValue::from_static("conflict"));
        assert!(
            effective_model_from_headers(&headers)
                .unwrap_err()
                .to_string()
                .contains("conflicting duplicate openai-model")
        );

        let mut malformed = HeaderMap::new();
        malformed.append(
            "openai-model",
            HeaderValue::from_bytes(b"\xff").expect("opaque HTTP header value"),
        );
        assert!(
            effective_model_from_headers(&malformed)
                .unwrap_err()
                .to_string()
                .contains("not valid UTF-8")
        );
    }
}
