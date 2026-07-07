//! Tower middleware that lifts `ExecutionProvenance` from response extensions
//! into `x-hellas-*` HTTP response headers.
//!
//! Handlers stay free of header-attachment boilerplate: they insert the
//! typed values into `response.extensions_mut()` and this layer renders
//! them as headers on the way out. SSE bodies emit the same data as
//! in-band events for browser EventSource consumers — those are still
//! produced by the handlers themselves (the layer can't see into the
//! body's stream).

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request, Response};
use futures::future::BoxFuture;
use hellas_rpc::provenance::{
    COMMITMENT_KEY as COMMITMENT_HEADER, ExecutionProvenance, encode_hex,
};
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Clone, Default)]
pub(super) struct ProvenanceLayer;

impl<S> Layer<S> for ProvenanceLayer {
    type Service = ProvenanceService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProvenanceService { inner }
    }
}

#[derive(Clone)]
pub(super) struct ProvenanceService<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for ProvenanceService<S>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response<Body>, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        // Standard tower/axum cloning idiom: own a "ready" clone of the
        // inner service for the spawned future, leave the original behind.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let mut response = inner.call(request).await?;
            apply_provenance_headers(&mut response);
            Ok(response)
        })
    }
}

fn apply_provenance_headers(response: &mut Response<Body>) {
    let extensions = response.extensions().clone();
    if let Some(prov) = extensions.get::<ExecutionProvenance>() {
        response
            .headers_mut()
            .insert(commitment_header(), header_value(&prov.commitment_id));
    }
}

fn commitment_header() -> HeaderName {
    HeaderName::from_static(COMMITMENT_HEADER)
}

fn header_value(bytes: &[u8; 32]) -> HeaderValue {
    HeaderValue::from_str(&encode_hex(bytes))
        .expect("64-char lowercase hex is always a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    fn build_response_with_extensions(prov: Option<ExecutionProvenance>) -> Response<Body> {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();
        if let Some(prov) = prov {
            response.extensions_mut().insert(prov);
        }
        response
    }

    #[test]
    fn applies_commitment_header_when_present() {
        let prov = ExecutionProvenance {
            commitment_id: [0xab; 32],
        };
        let mut response = build_response_with_extensions(Some(prov.clone()));
        apply_provenance_headers(&mut response);
        assert_eq!(
            response
                .headers()
                .get(COMMITMENT_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("ab".repeat(32).as_str())
        );
    }

    #[test]
    fn no_extensions_yields_no_headers() {
        let mut response = build_response_with_extensions(None);
        apply_provenance_headers(&mut response);
        assert!(!response.headers().contains_key(COMMITMENT_HEADER));
    }

    /// End-to-end: dispatch a request through an axum `Router` wrapped with
    /// `ProvenanceLayer` and confirm the layer lifts the handler-set
    /// extensions into the outgoing response headers.
    #[tokio::test]
    async fn router_layer_lifts_extensions_to_headers() {
        use axum::Router;
        use axum::body::Body;
        use axum::routing::get;
        use tower::ServiceExt;

        async fn handler() -> Response<Body> {
            let prov = ExecutionProvenance {
                commitment_id: [0x12; 32],
            };
            let mut response = Response::new(Body::empty());
            response.extensions_mut().insert(prov);
            response
        }

        let app = Router::new()
            .route("/", get(handler))
            .layer(ProvenanceLayer);

        let request = Request::builder().uri("/").body(Body::empty()).unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.headers().get(COMMITMENT_HEADER).unwrap(),
            &"12".repeat(32)
        );
    }
}
