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

use crate::peers::{PeerDirectory, PeerExtractor, PeerManagerError, RpcServiceSpec};

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

impl<S, Inner, E> ManagedServer<S, Inner, E> {
    pub fn new(inner: Inner, directory: PeerDirectory, extractor: E) -> Self {
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

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        let Some(policy) = S::inbound_policy(req.uri().path()) else {
            // Path doesn't belong to this service — pass through, the inner
            // tonic dispatcher will reply with UNIMPLEMENTED.
            return ManagedFuture::pass(self.inner.call(req));
        };

        match self.extractor.extract(&req) {
            None => {
                // No peer context available — surface as unauthenticated.
                // (Iroh inbound requests always carry IrohContext, so this
                // is reserved for unauthenticated transports.)
                return ManagedFuture::status(tonic::Status::unauthenticated(
                    "missing peer context",
                ));
            }
            Some(observation) => {
                match self.directory.observe_inbound_request(
                    observation.peer,
                    observation.rtt_ms,
                    policy,
                ) {
                    Ok(_) => ManagedFuture::pass(self.inner.call(req)),
                    Err(PeerManagerError::Admission(_)) => ManagedFuture::status(
                        tonic::Status::resource_exhausted("rate limited"),
                    ),
                    Err(PeerManagerError::Unavailable) => ManagedFuture::status(
                        tonic::Status::internal("peer directory unavailable"),
                    ),
                }
            }
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
