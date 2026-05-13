//! Typed RPC call builders.
//!
//! Each call shape is a distinct type so the `IntoFuture::Output` is fully
//! determined by `M: RpcMethod` alone — no second public generic for the
//! response shape. Codegen-emitted extension traits (e.g. `CourtesyClient`)
//! pick the right call type per method based on `M::REQUEST_STREAMING` and
//! `M::RESPONSE_STREAMING`:
//!
//! | request | response   | type                       | output                                  |
//! |---------|------------|----------------------------|-----------------------------------------|
//! | unary   | unary      | `UnaryCall<M>`             | `M::Response`                           |
//! | unary   | streaming  | `ServerStreamingCall<M>`   | `ManagedStreaming<M::Response>`         |
//! | stream  | unary      | `ClientStreamingCall<M>`   | `M::Response`                           |
//! | stream  | streaming  | `BidiStreamingCall<M>`     | `ManagedStreaming<M::Response>`         |
//!
//! All four hold an `IrohPeerHandle` and dial through `IrohRpcPool<S>` on
//! `.await`. The `Permit` is acquired before the dial and consumed on
//! response — connect failures call `finish_connect_err`, status failures
//! call `finish_err`, success calls `finish_ok`. Drop while in-flight
//! records `Cancelled` via the `RpcPermitGuard` Drop impl.
//!
//! Builder methods (`with_timeout`, eventually `with_deadline`, etc.) consume
//! `self` and return `Self`; the actual call is executed when the value is
//! awaited (via `IntoFuture`). This mirrors the modern Rust idiom used by
//! `reqwest::RequestBuilder` and `sqlx::query::Query`.

use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::time::Duration;

use thiserror::Error;

use crate::iroh_client::{IrohClientError, ManagedStreaming};
use crate::peers::{IrohPeerHandle, IrohRpcPoolError, PeerManagerError, RpcMethod, RpcService};

// On wasm the iroh transport's response futures are `!Send` (single-threaded
// runtime). Off wasm, we keep the `Send` bound so callers can drive these
// futures on multi-threaded runtimes. The request-side `RequestStream` stays
// `Send` everywhere — tonic's `Grpc::{client,bidi}_streaming` require it,
// and user-supplied streams (e.g. wrapping a `Vec<T: Send>`) satisfy that
// on wasm too.
#[cfg(target_family = "wasm")]
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
#[cfg(not(target_family = "wasm"))]
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

type RequestStream<T> = Pin<Box<dyn futures_core::Stream<Item = T> + Send + 'static>>;

/// Wire-agnostic error type returned by the typed call builders.
///
/// `tonic::Status` is not exposed at the API boundary — callers see typed
/// variants. The internal `IrohRpcPoolError` and `tonic::Status` map in via
/// `From` impls; new transports add their own conversions as they land.
#[derive(Debug, Error)]
pub enum RpcError {
    /// Admission denied before any I/O — rate limit, in-flight cap, etc.
    #[error("admission rejected: {0}")]
    Admission(PeerManagerError),
    /// The transport couldn't establish a channel to the peer.
    #[error("connect for {method}: {message}")]
    Connect {
        method: &'static str,
        message: String,
    },
    /// The remote returned a gRPC status. `code` is the gRPC code; `message`
    /// is the remote's status message.
    #[error("{method}: {code:?}: {message}")]
    Failed {
        method: &'static str,
        code: tonic::Code,
        message: String,
    },
    /// Transport-layer error reading or writing the wire.
    #[error("transport ({method}): {message}")]
    Transport {
        method: &'static str,
        message: String,
    },
}

impl RpcError {
    pub(crate) fn from_pool(method: &'static str, err: IrohRpcPoolError) -> Self {
        match err {
            IrohRpcPoolError::Peer(e) => Self::Admission(e),
            IrohRpcPoolError::Connect { source, .. } => Self::Connect {
                method,
                message: source.to_string(),
            },
        }
    }

    pub(crate) fn from_status(method: &'static str, status: tonic::Status) -> Self {
        Self::Failed {
            method,
            code: status.code(),
            message: status.message().to_owned(),
        }
    }

    pub(crate) fn from_client(err: IrohClientError) -> Self {
        match err {
            IrohClientError::Pool(e) => Self::from_pool("rpc", e),
            IrohClientError::Status { method, source } => Self::from_status(method, source),
        }
    }
}

// Helpers — these stay private; only the four call types use them.

async fn open_grpc<M: RpcMethod>(
    handle: &IrohPeerHandle,
) -> Result<
    (
        tonic::client::Grpc<tonic_iroh_transport::IrohChannel>,
        crate::peers::RpcPermitGuard,
    ),
    RpcError,
> {
    let pool = handle.pool::<M::Service>();
    let (channel, mut permit) = pool
        .channel::<M>(handle.peer_id())
        .await
        .map_err(|e| RpcError::from_pool(M::NAME, e))?;
    let mut grpc = tonic::client::Grpc::new(channel)
        // Match the GRPC_MESSAGE_LIMIT applied by the existing low-level
        // tonic clients (`hellas-pb` / `cli::commands::artifact`). Without
        // this, typed callers fall back to tonic's ~4 MB default and large
        // responses (artifacts, model assets) silently get truncated.
        .max_decoding_message_size(crate::GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(crate::GRPC_MESSAGE_LIMIT);
    if let Err(e) = grpc.ready().await {
        // Mark the permit explicitly as a transport error — otherwise
        // dropping the local guard would record `Cancelled`, masking a real
        // failure as a user-driven abort.
        let message = format!("service was not ready: {e}");
        permit.finish_err(message.clone());
        return Err(RpcError::Transport {
            method: M::NAME,
            message,
        });
    }
    Ok((grpc, permit))
}

fn stamp_request<M: RpcMethod, T>(request: tonic::Request<T>) -> tonic::Request<T> {
    let mut request = request;
    request.extensions_mut().insert(tonic::codegen::GrpcMethod::new(
        <M::Service as RpcService>::NAME,
        M::NAME,
    ));
    request
}

fn path_for<M: RpcMethod>() -> tonic::codegen::http::uri::PathAndQuery {
    tonic::codegen::http::uri::PathAndQuery::from_static(M::GRPC_PATH)
}

// ---------------------------------------------------------------------------
// UnaryCall<M> — unary request, unary response
// ---------------------------------------------------------------------------

pub struct UnaryCall<M: RpcMethod> {
    handle: IrohPeerHandle,
    request: tonic::Request<M::Request>,
    timeout: Option<Duration>,
}

impl<M: RpcMethod> UnaryCall<M> {
    pub fn new(handle: IrohPeerHandle, request: impl tonic::IntoRequest<M::Request>) -> Self {
        Self {
            handle,
            request: request.into_request(),
            timeout: None,
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl<M> IntoFuture for UnaryCall<M>
where
    M: RpcMethod + 'static,
{
    type Output = Result<tonic::Response<M::Response>, RpcError>;
    type IntoFuture = BoxFuture<'static, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        let Self {
            handle,
            request,
            timeout,
        } = self;
        Box::pin(async move {
            let (mut grpc, mut permit) = open_grpc::<M>(&handle).await?;
            let codec = tonic_prost::ProstCodec::<M::Request, M::Response>::default();
            let path = path_for::<M>();
            let mut request = stamp_request::<M, _>(request);
            if let Some(timeout) = timeout {
                request.set_timeout(timeout);
            }
            match grpc.unary(request, path, codec).await {
                Ok(resp) => {
                    permit.finish_ok();
                    Ok(resp)
                }
                Err(status) => {
                    permit.finish_err(format!("{}: {status}", M::NAME));
                    Err(RpcError::from_status(M::NAME, status))
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// ServerStreamingCall<M> — unary request, streaming response
// ---------------------------------------------------------------------------

pub struct ServerStreamingCall<M: RpcMethod> {
    handle: IrohPeerHandle,
    request: tonic::Request<M::Request>,
    timeout: Option<Duration>,
}

impl<M: RpcMethod> ServerStreamingCall<M> {
    pub fn new(handle: IrohPeerHandle, request: impl tonic::IntoRequest<M::Request>) -> Self {
        Self {
            handle,
            request: request.into_request(),
            timeout: None,
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl<M> IntoFuture for ServerStreamingCall<M>
where
    M: RpcMethod + 'static,
{
    type Output = Result<tonic::Response<ManagedStreaming<M::Response>>, RpcError>;
    type IntoFuture = BoxFuture<'static, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        let Self {
            handle,
            request,
            timeout,
        } = self;
        Box::pin(async move {
            let (mut grpc, permit) = open_grpc::<M>(&handle).await?;
            let codec = tonic_prost::ProstCodec::<M::Request, M::Response>::default();
            let path = path_for::<M>();
            let mut request = stamp_request::<M, _>(request);
            if let Some(timeout) = timeout {
                request.set_timeout(timeout);
            }
            let result = grpc.server_streaming(request, path, codec).await;
            crate::iroh_client::finish_streaming::<M, _>(permit, result)
                .map(|resp| {
                    let (meta, body, ext) = resp.into_parts();
                    tonic::Response::from_parts(meta, body, ext)
                })
                .map_err(RpcError::from_client)
        })
    }
}

// ---------------------------------------------------------------------------
// ClientStreamingCall<M> — streaming request, unary response
// ---------------------------------------------------------------------------

pub struct ClientStreamingCall<M: RpcMethod> {
    handle: IrohPeerHandle,
    request: tonic::Request<RequestStream<M::Request>>,
    timeout: Option<Duration>,
}

impl<M: RpcMethod> ClientStreamingCall<M> {
    pub fn new(
        handle: IrohPeerHandle,
        request: impl tonic::IntoStreamingRequest<Message = M::Request>,
    ) -> Self {
        let request = request.into_streaming_request();
        let (metadata, extensions, body) = request.into_parts();
        let body: RequestStream<M::Request> = Box::pin(body);
        let request = tonic::Request::from_parts(metadata, extensions, body);
        Self {
            handle,
            request,
            timeout: None,
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl<M> IntoFuture for ClientStreamingCall<M>
where
    M: RpcMethod + 'static,
{
    type Output = Result<tonic::Response<M::Response>, RpcError>;
    type IntoFuture = BoxFuture<'static, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        let Self {
            handle,
            request,
            timeout,
        } = self;
        Box::pin(async move {
            let (mut grpc, mut permit) = open_grpc::<M>(&handle).await?;
            let codec = tonic_prost::ProstCodec::<M::Request, M::Response>::default();
            let path = path_for::<M>();
            let mut request = stamp_request::<M, _>(request);
            if let Some(timeout) = timeout {
                request.set_timeout(timeout);
            }
            match grpc.client_streaming(request, path, codec).await {
                Ok(resp) => {
                    permit.finish_ok();
                    Ok(resp)
                }
                Err(status) => {
                    permit.finish_err(format!("{}: {status}", M::NAME));
                    Err(RpcError::from_status(M::NAME, status))
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// BidiStreamingCall<M> — streaming request, streaming response
// ---------------------------------------------------------------------------

pub struct BidiStreamingCall<M: RpcMethod> {
    handle: IrohPeerHandle,
    request: tonic::Request<RequestStream<M::Request>>,
    timeout: Option<Duration>,
}

impl<M: RpcMethod> BidiStreamingCall<M> {
    pub fn new(
        handle: IrohPeerHandle,
        request: impl tonic::IntoStreamingRequest<Message = M::Request>,
    ) -> Self {
        let request = request.into_streaming_request();
        let (metadata, extensions, body) = request.into_parts();
        let body: RequestStream<M::Request> = Box::pin(body);
        let request = tonic::Request::from_parts(metadata, extensions, body);
        Self {
            handle,
            request,
            timeout: None,
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl<M> IntoFuture for BidiStreamingCall<M>
where
    M: RpcMethod + 'static,
{
    type Output = Result<tonic::Response<ManagedStreaming<M::Response>>, RpcError>;
    type IntoFuture = BoxFuture<'static, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        let Self {
            handle,
            request,
            timeout,
        } = self;
        Box::pin(async move {
            let (mut grpc, permit) = open_grpc::<M>(&handle).await?;
            let codec = tonic_prost::ProstCodec::<M::Request, M::Response>::default();
            let path = path_for::<M>();
            let mut request = stamp_request::<M, _>(request);
            if let Some(timeout) = timeout {
                request.set_timeout(timeout);
            }
            let result = grpc.streaming(request, path, codec).await;
            crate::iroh_client::finish_streaming::<M, _>(permit, result)
                .map(|resp| {
                    let (meta, body, ext) = resp.into_parts();
                    tonic::Response::from_parts(meta, body, ext)
                })
                .map_err(RpcError::from_client)
        })
    }
}
