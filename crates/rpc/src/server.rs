//! Server-side admission middleware for tonic services.
//!
//! `ManagedServer<S, Inner, E>` is a `tower::Service` wrapper that sits in
//! front of a tonic-generated server (`Inner`) and runs admission for every
//! inbound request against a [`PeerDirectory`]. The dispatch is fully typed:
//! the codegen-emitted [`RpcServiceSpec`] impl on `S` converts the gRPC path
//! string into a typed `InboundRequestPolicy`, and a [`PeerExtractor`] (`E`)
//! converts the incoming `http::Request` into a peer observation. Application
//! service impls no longer call `observe_inbound_request` themselves.
//!
//! Wire shape mirrors `tonic::service::interceptor::InterceptedService`: the
//! response body is wrapped so we can emit either the inner service's body
//! (request passed) or an empty body alongside a gRPC status (request
//! rejected). Pin-projected future variants avoid boxing on the happy path.

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project::pin_project;

use crate::peers::{PeerDirectory, PeerExtractor, RpcService, RpcServiceSpec};

/// Pin-projected tower::Service wrapper around a tonic-generated server.
///
/// Construct with [`ManagedServer::new`]. The service type parameter `S`
/// (the codegen marker like `CourtesyService`) selects which generated
/// `RpcServiceSpec::inbound_policy` is consulted; the `Inner` service is
/// the tonic-generated server (e.g. `CourtesyServer<MyImpl>`); `E` is the
/// transport-side [`PeerExtractor`].
pub struct ManagedServer<S, Inner, E> {
    inner: Inner,
    directory: PeerDirectory,
    extractor: E,
    _service: PhantomData<fn() -> S>,
}

impl<S, Inner, E> ManagedServer<S, Inner, E>
where
    S: RpcServiceSpec,
    Inner: tonic::server::NamedService,
{
    pub fn new(inner: Inner, directory: PeerDirectory, extractor: E) -> Self {
        // Catch wiring mistakes where the spec marker `S` and the tonic
        // server `Inner` disagree on which service this is. The path
        // dispatch comes from `S::inbound_policy`, but `Inner` is what
        // actually serves bytes — if they're crossed, every request would
        // hit `UNIMPLEMENTED` on the inner side while the policy lookup
        // either silently misclassifies or misses entirely. This is purely
        // a developer-error tripwire, so debug-only.
        debug_assert_eq!(
            <S as RpcService>::NAME,
            Inner::NAME,
            "ManagedServer spec/server mismatch: spec={} inner={}",
            <S as RpcService>::NAME,
            Inner::NAME,
        );
        Self {
            inner,
            directory,
            extractor,
            _service: PhantomData,
        }
    }
}

impl<S, Inner: Clone, E: Clone> Clone for ManagedServer<S, Inner, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            directory: self.directory.clone(),
            extractor: self.extractor.clone(),
            _service: PhantomData,
        }
    }
}

impl<S, Inner: std::fmt::Debug, E: std::fmt::Debug> std::fmt::Debug for ManagedServer<S, Inner, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedServer")
            .field("service", &std::any::type_name::<S>())
            .field("inner", &self.inner)
            .field("extractor", &self.extractor)
            .finish_non_exhaustive()
    }
}

// Delegate NamedService so `TransportBuilder::add_rpc` picks the right ALPN.
impl<S, Inner, E> tonic::server::NamedService for ManagedServer<S, Inner, E>
where
    Inner: tonic::server::NamedService,
{
    const NAME: &'static str = Inner::NAME;
}

impl<S, Inner, E, ReqBody, ResBody> tower_service::Service<http::Request<ReqBody>>
    for ManagedServer<S, Inner, E>
where
    S: RpcServiceSpec,
    Inner: tower_service::Service<http::Request<ReqBody>, Response = http::Response<ResBody>>,
    E: PeerExtractor,
{
    type Response = http::Response<ManagedBody<ResBody>>;
    type Error = Inner::Error;
    type Future = ManagedFuture<Inner::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<ReqBody>) -> Self::Future {
        let Some(policy) = S::inbound_policy(req.uri().path()) else {
            // Path doesn't belong to this service — pass through to the
            // inner tonic dispatcher (which replies UNIMPLEMENTED), but
            // first record the invalid-request hit against the peer so a
            // hostile peer spamming unknown paths on a valid ALPN still
            // shows up in the registry's counters.
            if let Some(observation) = self.extractor.extract(&req) {
                let _ = self
                    .directory
                    .manager()
                    .observe_invalid_request(observation.peer);
            }
            return ManagedFuture::pass(self.inner.call(req));
        };

        let Some(observation) = self.extractor.extract(&req) else {
            // No peer context available — surface as unauthenticated.
            // (iroh inbound requests always carry IrohContext, so this only
            // fires for transports that haven't installed an extractor.)
            return ManagedFuture::status(tonic::Status::unauthenticated("missing peer context"));
        };

        match self
            .directory
            .observe_inbound_request(observation.peer, observation.rtt_ms, policy)
        {
            Ok(admission) if admission.allow => {
                // Stash the typed admission decision so handlers that care
                // about its `disclosure_limit` (e.g. GetKnownPeers) don't
                // have to re-observe — that would double-bill the bucket.
                req.extensions_mut().insert(admission);
                ManagedFuture::pass(self.inner.call(req))
            }
            Ok(_) => ManagedFuture::status(tonic::Status::resource_exhausted("rate limited")),
            Err(_) => ManagedFuture::status(tonic::Status::internal("peer directory unavailable")),
        }
    }
}

#[pin_project]
pub struct ManagedFuture<F> {
    #[pin]
    kind: ManagedFutureKind<F>,
}

#[pin_project(project = ManagedFutureKindProj)]
enum ManagedFutureKind<F> {
    Pass(#[pin] F),
    Status(Option<tonic::Status>),
}

impl<F> ManagedFuture<F> {
    fn pass(future: F) -> Self {
        Self {
            kind: ManagedFutureKind::Pass(future),
        }
    }

    fn status(status: tonic::Status) -> Self {
        Self {
            kind: ManagedFutureKind::Status(Some(status)),
        }
    }
}

impl<F, E, B> Future for ManagedFuture<F>
where
    F: Future<Output = Result<http::Response<B>, E>>,
{
    type Output = Result<http::Response<ManagedBody<B>>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project().kind.project() {
            ManagedFutureKindProj::Pass(inner) => {
                inner.poll(cx).map_ok(|resp| resp.map(ManagedBody::pass))
            }
            ManagedFutureKindProj::Status(slot) => {
                let status = slot.take().expect("ManagedFuture polled after completion");
                let (parts, ()) = status.into_http::<()>().into_parts();
                Poll::Ready(Ok(http::Response::from_parts(parts, ManagedBody::empty())))
            }
        }
    }
}

#[pin_project]
pub struct ManagedBody<B> {
    #[pin]
    kind: ManagedBodyKind<B>,
}

#[pin_project(project = ManagedBodyKindProj)]
enum ManagedBodyKind<B> {
    Empty,
    Pass(#[pin] B),
}

impl<B> ManagedBody<B> {
    fn pass(body: B) -> Self {
        Self {
            kind: ManagedBodyKind::Pass(body),
        }
    }

    fn empty() -> Self {
        Self {
            kind: ManagedBodyKind::Empty,
        }
    }
}

impl<B: http_body::Body> http_body::Body for ManagedBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.project().kind.project() {
            ManagedBodyKindProj::Empty => Poll::Ready(None),
            ManagedBodyKindProj::Pass(body) => body.poll_frame(cx),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.kind {
            ManagedBodyKind::Empty => http_body::SizeHint::with_exact(0),
            ManagedBodyKind::Pass(body) => body.size_hint(),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.kind {
            ManagedBodyKind::Empty => true,
            ManagedBodyKind::Pass(body) => body.is_end_stream(),
        }
    }
}

#[cfg(all(test, feature = "swarm"))]
mod tests {
    use std::convert::Infallible;
    use std::future::{Future, Ready, ready};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    use http_body::Body as _;
    use tower_service::Service as _;

    use super::*;
    use crate::peers::{
        InboundPeerObservation, PeerDirectory, PeerDirectoryConfig, PeerId, PeerRegistryConfig,
    };
    use crate::service::NodeService;

    /// Body placeholder: never yields a frame. Sufficient for the response
    /// path because denial replaces it with `ManagedBody::Empty`, and for
    /// the request path because the inner service isn't invoked.
    struct EmptyBody;

    impl http_body::Body for EmptyBody {
        type Data = prost::bytes::Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<prost::bytes::Bytes>, Infallible>>> {
            Poll::Ready(None)
        }
    }

    #[derive(Clone)]
    struct CountingInner {
        called: Arc<AtomicBool>,
    }

    impl tonic::server::NamedService for CountingInner {
        const NAME: &'static str = <NodeService as crate::peers::RpcService>::NAME;
    }

    impl tower_service::Service<http::Request<EmptyBody>> for CountingInner {
        type Response = http::Response<EmptyBody>;
        type Error = Infallible;
        type Future = Ready<Result<http::Response<EmptyBody>, Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: http::Request<EmptyBody>) -> Self::Future {
            self.called.store(true, Ordering::SeqCst);
            ready(Ok(http::Response::new(EmptyBody)))
        }
    }

    /// PeerExtractor returning a fixed peer for every request.
    #[derive(Clone, Copy)]
    struct FixedExtractor(PeerId);

    impl PeerExtractor for FixedExtractor {
        fn extract<B>(&self, _req: &http::Request<B>) -> Option<InboundPeerObservation> {
            Some(InboundPeerObservation {
                peer: self.0,
                rtt_ms: None,
            })
        }
    }

    fn drained_directory() -> PeerDirectory {
        // A bucket whose capacity is below one token can never admit a
        // rate-limited request — `try_take` short-circuits with Err(None).
        // This is the cheapest way to force the denial branch without
        // spinning a real clock.
        let config = PeerDirectoryConfig {
            registry: PeerRegistryConfig {
                max_peers: 8,
                max_in_flight_per_peer: 4,
                max_in_flight_total: 16,
                bucket_capacity: 0.0,
                bucket_refill_per_sec: 0.0,
                ..PeerRegistryConfig::default()
            },
            global_known_peers_bucket_capacity: 0.0,
            global_known_peers_bucket_refill_per_sec: 0.0,
            ..PeerDirectoryConfig::default()
        };
        PeerDirectory::with_config(PeerId::from([0u8; 32]), config)
    }

    fn rate_limited_path() -> &'static str {
        <crate::service::methods::GetKnownPeers as crate::peers::RpcMethod>::GRPC_PATH
    }

    fn unary_request(path: &str) -> http::Request<EmptyBody> {
        http::Request::builder()
            .method("POST")
            .uri(format!("http://example.com{path}"))
            .body(EmptyBody)
            .unwrap()
    }

    fn block_on<F: Future>(fut: F) -> F::Output {
        // The futures we drive here never park, so a single poll resolves
        // them; using tokio for one assertion is overkill.
        let mut fut = Box::pin(fut);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(&waker);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("test future returned Pending unexpectedly"),
        }
    }

    #[test]
    fn denied_request_skips_inner_and_returns_resource_exhausted() {
        let directory = drained_directory();
        let called = Arc::new(AtomicBool::new(false));
        let inner = CountingInner {
            called: called.clone(),
        };
        let extractor = FixedExtractor(PeerId::from([1u8; 32]));

        let mut server: ManagedServer<NodeService, CountingInner, FixedExtractor> =
            ManagedServer::new(inner, directory, extractor);

        let response = block_on(server.call(unary_request(rate_limited_path())))
            .expect("denial path is infallible");

        assert!(
            !called.load(Ordering::SeqCst),
            "inner service must not be invoked when admission denies"
        );

        let status = tonic::Status::from_header_map(response.headers())
            .expect("denied response carries a gRPC status in headers");
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);

        // The body wrapper switches to Empty on denial, so size_hint
        // reports zero and is_end_stream is true immediately.
        let body = response.into_body();
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
    }

    #[test]
    fn unknown_path_passes_through_and_records_invalid_request() {
        // Unknown method paths fall through to the inner tonic dispatcher
        // (which will reply UNIMPLEMENTED), but the extractor's peer is
        // still bookkept so a hostile peer spamming nonsense paths shows
        // up in the registry's invalid_request_count.
        let directory = PeerDirectory::new(PeerId::from([0u8; 32]));
        let peer = PeerId::from([2u8; 32]);
        let called = Arc::new(AtomicBool::new(false));
        let inner = CountingInner {
            called: called.clone(),
        };
        let extractor = FixedExtractor(peer);

        let mut server: ManagedServer<NodeService, CountingInner, FixedExtractor> =
            ManagedServer::new(inner, directory.clone(), extractor);

        let _ = block_on(server.call(unary_request("/no.such.Service/Method")));

        assert!(
            called.load(Ordering::SeqCst),
            "inner must be invoked for unknown paths so tonic replies UNIMPLEMENTED"
        );
        let snapshot = directory
            .manager()
            .snapshot()
            .expect("registry readable");
        let entry = snapshot.get(peer).expect("peer recorded by extractor");
        assert_eq!(entry.invalid_request_count, 1);
    }

}
