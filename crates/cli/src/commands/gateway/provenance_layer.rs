//! Tower middleware that lifts catnix provenance from response
//! extensions into the `x-hellas-*` HTTP response headers.
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
    CATNIX_COMMITMENT_HEADER, CATNIX_RECEIPT_HEADER, CatnixCallCommitment, CatnixReceiptCommitment,
    ExecutionProvenance, encode_hex,
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
    if let Some(call) = extensions.get::<CatnixCallCommitment>() {
        response
            .headers_mut()
            .insert(catnix_commitment_header(), header_value(&call.0));
    } else if let Some(prov) = extensions.get::<ExecutionProvenance>() {
        if let Some(catnix) = &prov.catnix_call_commitment {
            response
                .headers_mut()
                .insert(catnix_commitment_header(), header_value(catnix));
        }
    }
    if let Some(catnix_receipt) = extensions.get::<CatnixReceiptCommitment>() {
        response
            .headers_mut()
            .insert(catnix_receipt_header(), header_value(&catnix_receipt.0));
    }
}

fn catnix_commitment_header() -> HeaderName {
    HeaderName::from_static(CATNIX_COMMITMENT_HEADER)
}

fn catnix_receipt_header() -> HeaderName {
    HeaderName::from_static(CATNIX_RECEIPT_HEADER)
}

fn header_value(bytes: &[u8; 32]) -> HeaderValue {
    HeaderValue::from_str(&encode_hex(bytes))
        .expect("64-char lowercase hex is always a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use hellas_rpc::provenance::{COMMITMENT_HEADER, RECEIPT_HEADER};
    use hellas_runtime::cid::Cid;
    use hellas_runtime::runtime::TextReceipt;

    fn build_response_with_extensions(
        prov: Option<ExecutionProvenance>,
        receipt: Option<Cid<TextReceipt>>,
        catnix_receipt: Option<CatnixReceiptCommitment>,
    ) -> Response<Body> {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();
        if let Some(prov) = prov {
            response.extensions_mut().insert(prov);
        }
        if let Some(receipt) = receipt {
            response.extensions_mut().insert(receipt);
        }
        if let Some(catnix_receipt) = catnix_receipt {
            response.extensions_mut().insert(catnix_receipt);
        }
        response
    }

    #[test]
    fn ignores_runtime_receipt_extensions() {
        let prov = ExecutionProvenance {
            commitment_id: [0xab; 32],
            catnix_call_commitment: None,
        };
        let receipt = Cid::<TextReceipt>::from_bytes([0xef; 32]);
        let mut response = build_response_with_extensions(Some(prov), Some(receipt), None);
        apply_provenance_headers(&mut response);
        assert!(!response.headers().contains_key(COMMITMENT_HEADER));
        assert!(!response.headers().contains_key(RECEIPT_HEADER));
    }

    #[test]
    fn skips_headers_when_catnix_commitment_absent() {
        let prov = ExecutionProvenance {
            commitment_id: [1; 32],
            catnix_call_commitment: None,
        };
        let mut response = build_response_with_extensions(Some(prov), None, None);
        apply_provenance_headers(&mut response);
        assert!(!response.headers().contains_key(CATNIX_COMMITMENT_HEADER));
        assert!(!response.headers().contains_key(COMMITMENT_HEADER));
        assert!(!response.headers().contains_key(RECEIPT_HEADER));
    }

    #[test]
    fn no_extensions_yields_no_headers() {
        let mut response = build_response_with_extensions(None, None, None);
        apply_provenance_headers(&mut response);
        assert!(!response.headers().contains_key(CATNIX_COMMITMENT_HEADER));
        assert!(!response.headers().contains_key(CATNIX_RECEIPT_HEADER));
        assert!(!response.headers().contains_key(COMMITMENT_HEADER));
        assert!(!response.headers().contains_key(RECEIPT_HEADER));
    }

    /// End-to-end: dispatch a request through an axum `Router` wrapped with
    /// `ProvenanceLayer` and confirm the layer lifts the handler-set
    /// extensions into the outgoing response headers.
    #[test]
    fn applies_catnix_header_when_present() {
        let prov = ExecutionProvenance {
            commitment_id: [0xab; 32],
            catnix_call_commitment: Some([0xcd; 32]),
        };
        let mut response = build_response_with_extensions(Some(prov), None, None);
        apply_provenance_headers(&mut response);
        assert_eq!(
            response
                .headers()
                .get(CATNIX_COMMITMENT_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("cd".repeat(32).as_str())
        );
        assert!(!response.headers().contains_key(COMMITMENT_HEADER));
    }

    #[test]
    fn applies_typed_catnix_call_header_when_present() {
        let mut response = build_response_with_extensions(None, None, None);
        response
            .extensions_mut()
            .insert(CatnixCallCommitment([0xcd; 32]));
        apply_provenance_headers(&mut response);
        assert_eq!(
            response
                .headers()
                .get(CATNIX_COMMITMENT_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("cd".repeat(32).as_str())
        );
    }

    #[test]
    fn skips_catnix_header_when_absent() {
        let prov = ExecutionProvenance {
            commitment_id: [1; 32],
            catnix_call_commitment: None,
        };
        let mut response = build_response_with_extensions(Some(prov), None, None);
        apply_provenance_headers(&mut response);
        assert!(!response.headers().contains_key(CATNIX_COMMITMENT_HEADER));
    }

    /// Terminal catnix receipt commitment surfaces as `x-hellas-receipt`
    /// when the handler attaches a `CatnixReceiptCommitment` extension.
    #[test]
    fn applies_catnix_receipt_header_when_present() {
        let receipt = Cid::<TextReceipt>::from_bytes([0xef; 32]);
        let catnix = CatnixReceiptCommitment([0x77; 32]);
        let mut response = build_response_with_extensions(None, Some(receipt), Some(catnix));
        apply_provenance_headers(&mut response);
        assert_eq!(
            response
                .headers()
                .get(CATNIX_RECEIPT_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("77".repeat(32).as_str())
        );
        assert!(!response.headers().contains_key(RECEIPT_HEADER));
    }

    #[test]
    fn skips_catnix_receipt_header_when_absent() {
        let receipt = Cid::<TextReceipt>::from_bytes([0xef; 32]);
        let mut response = build_response_with_extensions(None, Some(receipt), None);
        apply_provenance_headers(&mut response);
        assert!(!response.headers().contains_key(RECEIPT_HEADER));
        assert!(!response.headers().contains_key(CATNIX_RECEIPT_HEADER));
    }

    #[tokio::test]
    async fn router_layer_lifts_extensions_to_headers() {
        use axum::Router;
        use axum::body::Body;
        use axum::routing::get;
        use tower::ServiceExt;

        async fn handler() -> Response<Body> {
            let prov = ExecutionProvenance {
                commitment_id: [0x12; 32],
                catnix_call_commitment: Some([0xab; 32]),
            };
            let receipt = Cid::<TextReceipt>::from_bytes([0x56; 32]);
            let catnix_receipt = CatnixReceiptCommitment([0x78; 32]);
            let mut response = Response::new(Body::empty());
            response.extensions_mut().insert(prov);
            response.extensions_mut().insert(receipt);
            response.extensions_mut().insert(catnix_receipt);
            response
        }

        let app = Router::new()
            .route("/", get(handler))
            .layer(ProvenanceLayer);

        let request = Request::builder().uri("/").body(Body::empty()).unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.headers().get(CATNIX_COMMITMENT_HEADER).unwrap(),
            &"ab".repeat(32)
        );
        assert_eq!(
            response.headers().get(CATNIX_RECEIPT_HEADER).unwrap(),
            &"78".repeat(32)
        );
        assert!(!response.headers().contains_key(COMMITMENT_HEADER));
        assert!(!response.headers().contains_key(RECEIPT_HEADER));
    }
}
