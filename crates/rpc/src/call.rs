//! Generic RPC helpers used by codegen-emitted client trait impls.
//!
//! The codegen produces typed client traits like `ExecuteClient<T>` with one
//! async method per RPC. Each method body delegates to one of the helpers
//! below, parameterised by a `MethodMarker` so prost type info is at the
//! type level — no string method names at call sites.

use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use prost::Message;

use hellas_wire::TransportError;
use hellas_wire::metadata::{Metadata, Trailer};
use hellas_wire::status::{WireCode, WireStatus};
use hellas_wire::transport::{
    MethodMarker, RecvHalf, SendHalf, Stream as WireStream, StreamTransport,
};

/// Unary call: send one request, receive one response.
pub async fn unary<T, M>(
    transport: &T,
    request: M::Request,
    headers: Metadata,
) -> Result<M::Response, WireStatus>
where
    T: StreamTransport + Sync,
    M: MethodMarker,
    M::Request: Message,
    M::Response: Message + Default,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    unary_with_trailer::<T, M>(transport, request, headers)
        .await
        .map(|wt| wt.response)
}

/// Unary call returning both the response and the terminal trailer
/// metadata. Server-side handlers populate the trailer via
/// `WithTrailer<R>`; this surfaces those bytes to the client so it
/// can read `x-hellas-commitment-bin` / OTel response context.
pub async fn unary_with_trailer<T, M>(
    transport: &T,
    request: M::Request,
    headers: Metadata,
) -> Result<WithTrailer<M::Response>, WireStatus>
where
    T: StreamTransport + Sync,
    M: MethodMarker,
    M::Request: Message,
    M::Response: Message + Default,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let stream = transport
        .open(M::METHOD_ID, headers)
        .await
        .map_err(transport_to_status)?;
    let (mut send, recv) = WireStream::split(stream);
    let mut recv = Box::pin(recv);

    let mut buf = BytesMut::with_capacity(request.encoded_len());
    request
        .encode(&mut buf)
        .map_err(|e| WireStatus::internal(format!("prost encode: {e}")))?;
    send.send_body(buf.freeze())
        .await
        .map_err(|e| WireStatus::internal(format!("send: {e}")))?;
    send.close_send(None)
        .await
        .map_err(|e| WireStatus::internal(format!("close_send: {e}")))?;

    // Unary protocol shape: exactly one body chunk, then EOF, then a
    // terminal trailer. Anything else is a server-side bug and must
    // surface as Internal rather than be silently swallowed.
    let chunk = match recv.next().await {
        Some(Ok(b)) => b,
        Some(Err(e)) => return Err(WireStatus::internal(format!("recv: {e}"))),
        None => {
            // No body — must be a terminal-trailer-only error response.
            // Drain to populate the trailer and surface it.
            while recv.next().await.is_some() {}
            return Err(match recv.trailer() {
                Some(t) if t.status != WireCode::Ok => trailer_to_status(t),
                Some(_) => WireStatus::internal("unary handler returned no body but Ok trailer"),
                None => WireStatus::internal("unary handler returned no body and no trailer"),
            });
        }
    };
    // We got the body; next() must be None next. An extra body is a
    // handler-protocol bug, not noise to swallow.
    match recv.next().await {
        None => {}
        Some(Ok(_)) => {
            return Err(WireStatus::internal(
                "unary handler emitted more than one body",
            ));
        }
        Some(Err(e)) => return Err(WireStatus::internal(format!("recv after body: {e}"))),
    }
    let trailer = recv
        .trailer()
        .ok_or_else(|| WireStatus::internal("unary call ended without terminal trailer"))?;
    if trailer.status != WireCode::Ok {
        return Err(trailer_to_status(trailer));
    }
    let response = M::Response::decode(&chunk[..])
        .map_err(|e| WireStatus::internal(format!("prost decode: {e}")))?;
    Ok(WithTrailer::with_metadata(
        response,
        trailer.metadata.clone(),
    ))
}

fn trailer_to_status(t: &Trailer) -> WireStatus {
    WireStatus {
        code: t.status,
        message: t.message.clone(),
        details: Bytes::new(),
        metadata: t.metadata.clone(),
    }
}

/// Server-streaming call: send one request, receive a stream of responses
/// + a terminal trailer.
///
/// Returns a [`StreamingCall`]: the consumer iterates body chunks via the
/// `Stream` impl and MUST call [`StreamingCall::finish`] after the stream
/// EOFs to surface the terminal trailer (or error).
pub async fn server_streaming<T, M>(
    transport: &T,
    request: M::Request,
    headers: Metadata,
) -> Result<StreamingCall<M::Response>, WireStatus>
where
    T: StreamTransport + Sync,
    M: MethodMarker,
    M::Request: Message,
    M::Response: Message + Default + Send + 'static,
    T::Stream: 'static,
    <T::Stream as WireStream>::RecvHalf: Unpin + 'static,
    <T::Stream as WireStream>::SendHalf: 'static,
    <<T::Stream as WireStream>::RecvHalf as RecvHalf>::Error:
        std::error::Error + Send + Sync + 'static,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let stream = transport
        .open(M::METHOD_ID, headers)
        .await
        .map_err(transport_to_status)?;
    let (mut send, recv) = WireStream::split(stream);

    let mut buf = BytesMut::with_capacity(request.encoded_len());
    request
        .encode(&mut buf)
        .map_err(|e| WireStatus::internal(format!("prost encode: {e}")))?;
    send.send_body(buf.freeze())
        .await
        .map_err(|e| WireStatus::internal(format!("send: {e}")))?;
    send.close_send(None)
        .await
        .map_err(|e| WireStatus::internal(format!("close_send: {e}")))?;

    Ok(StreamingCall::new(recv))
}

/// Bidirectional streaming call: open a request/response stream and let
/// the caller drive both halves.
pub async fn bidi_streaming<T, M>(
    transport: &T,
    headers: Metadata,
) -> Result<BidiStreamingCall<M::Request, M::Response>, WireStatus>
where
    T: StreamTransport + Sync,
    M: MethodMarker,
    M::Request: Message,
    M::Response: Message + Default + Send + 'static,
    T::Stream: 'static,
    <T::Stream as WireStream>::RecvHalf: Unpin + 'static,
    <T::Stream as WireStream>::SendHalf: 'static,
    <<T::Stream as WireStream>::RecvHalf as RecvHalf>::Error:
        std::error::Error + Send + Sync + 'static,
    <<T::Stream as WireStream>::SendHalf as SendHalf>::Error:
        std::error::Error + Send + Sync + 'static,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let stream = transport
        .open(M::METHOD_ID, headers)
        .await
        .map_err(transport_to_status)?;
    let (send, recv) = WireStream::split(stream);
    Ok(BidiStreamingCall::new(send, recv))
}

fn transport_to_status<E: std::error::Error>(err: E) -> WireStatus {
    WireStatus::new(WireCode::Unavailable, err.to_string())
}

// -- Streaming response surface ---------------------------------------------

/// A streaming-response call: yields decoded body chunks via its
/// `Stream` impl, then surfaces the terminal trailer via [`finish`].
///
/// Owns the recv-half directly (type-erased through a private trait
/// so consumers don't need to thread the transport type all the way
/// through). The protocol invariant *"0+ bodies, then exactly one
/// terminal trailer"* maps to the API surface as *"0+ next() calls,
/// then exactly one finish() call"* — sequenced by ownership, no
/// invalid states representable.
///
/// [`finish`]: StreamingCall::finish
#[must_use = "streaming calls carry a terminal trailer; ignoring it discards the server-side status"]
pub struct StreamingCall<R> {
    inner: Pin<Box<dyn ErasedRecv + Send>>,
    eof: bool,
    _r: PhantomData<R>,
}

// The `Pin<Box<...>>` field is already heap-pinned; the outer struct
// only carries a `bool` and `PhantomData`, so it is safe to move the
// outer struct around.
impl<R> Unpin for StreamingCall<R> {}

/// Object-safe view onto a recv-half. Adapts the transport-specific
/// `RecvHalf::Error` to a `WireStatus` and exposes the trailer as an
/// owned `Trailer` so `finish` can move out.
trait ErasedRecv {
    fn poll_chunk(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, WireStatus>>>;
    fn take_trailer(&self) -> Option<Trailer>;
}

trait ErasedSend {
    fn send_body<'a>(
        self: Pin<&'a mut Self>,
        payload: Bytes,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), WireStatus>> + Send + 'a>>;

    fn close_send<'a>(
        self: Pin<&'a mut Self>,
        trailer: Option<Trailer>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), WireStatus>> + Send + 'a>>;

    fn reset(self: Pin<&mut Self>, code: WireCode);
}

struct RecvAdapter<R: RecvHalf + Unpin> {
    recv: R,
}

struct SendAdapter<S: SendHalf> {
    send: S,
}

impl<S: SendHalf> Unpin for SendAdapter<S> {}

impl<R: RecvHalf + Unpin> ErasedRecv for RecvAdapter<R>
where
    R::Error: std::error::Error + Send + Sync + 'static,
{
    fn poll_chunk(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, WireStatus>>> {
        match Pin::new(&mut self.recv).poll_next(cx) {
            Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(b))),
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Some(Err(WireStatus::internal(format!("recv: {e}")))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
    fn take_trailer(&self) -> Option<Trailer> {
        self.recv.trailer().cloned()
    }
}

impl<S: SendHalf> ErasedSend for SendAdapter<S>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    fn send_body<'a>(
        self: Pin<&'a mut Self>,
        payload: Bytes,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), WireStatus>> + Send + 'a>> {
        let this = self.get_mut();
        Box::pin(async move {
            this.send
                .send_body(payload)
                .await
                .map_err(|e| WireStatus::internal(format!("send: {e}")))
        })
    }

    fn close_send<'a>(
        self: Pin<&'a mut Self>,
        trailer: Option<Trailer>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), WireStatus>> + Send + 'a>> {
        let this = self.get_mut();
        Box::pin(async move {
            this.send
                .close_send(trailer)
                .await
                .map_err(|e| WireStatus::internal(format!("close_send: {e}")))
        })
    }

    fn reset(self: Pin<&mut Self>, code: WireCode) {
        self.get_mut().send.reset(code);
    }
}

impl<R> StreamingCall<R> {
    fn new<H>(recv: H) -> Self
    where
        H: RecvHalf + Unpin + Send + 'static,
        H::Error: std::error::Error + Send + Sync + 'static,
    {
        Self {
            inner: Box::pin(RecvAdapter { recv }),
            eof: false,
            _r: PhantomData,
        }
    }

    /// Consume the call and return the terminal trailer.
    ///
    /// Must be called after the `Stream` impl returns `None`. Returns
    /// the trailer if its `status == Ok`; otherwise returns the
    /// trailer reified as a `WireStatus` error. A missing trailer is
    /// treated as `Internal` — the server emitted an EOF with no
    /// terminal frame, which is itself a protocol bug.
    pub fn finish(self) -> Result<Trailer, WireStatus> {
        assert!(
            self.eof,
            "StreamingCall::finish() called before the Stream returned None"
        );
        match self.inner.take_trailer() {
            Some(t) if t.status == WireCode::Ok => Ok(t),
            Some(t) => Err(trailer_to_status(&t)),
            None => Err(WireStatus::internal(
                "stream ended without terminal trailer",
            )),
        }
    }
}

impl<R: Message + Default> futures_core::Stream for StreamingCall<R> {
    type Item = Result<R, WireStatus>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.eof {
            return Poll::Ready(None);
        }
        match self.inner.as_mut().poll_chunk(cx) {
            Poll::Ready(Some(Ok(bytes))) => match R::decode(&bytes[..]) {
                Ok(msg) => Poll::Ready(Some(Ok(msg))),
                Err(e) => Poll::Ready(Some(Err(WireStatus::internal(format!(
                    "prost decode: {e}"
                ))))),
            },
            Poll::Ready(Some(Err(s))) => Poll::Ready(Some(Err(s))),
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Send half of a client request stream.
#[must_use = "request streams must be closed to let the server finish the RPC"]
pub struct StreamingSink<Q> {
    inner: Pin<Box<dyn ErasedSend + Send>>,
    closed: bool,
    _q: PhantomData<Q>,
}

impl<Q> Unpin for StreamingSink<Q> {}

impl<Q> StreamingSink<Q> {
    fn new<S>(send: S) -> Self
    where
        S: SendHalf + 'static,
        S::Error: std::error::Error + Send + Sync + 'static,
    {
        Self {
            inner: Box::pin(SendAdapter { send }),
            closed: false,
            _q: PhantomData,
        }
    }

    pub fn reset(&mut self, code: WireCode) {
        self.closed = true;
        self.inner.as_mut().reset(code);
    }
}

impl<Q: Message> StreamingSink<Q> {
    pub async fn send(&mut self, request: Q) -> Result<(), WireStatus> {
        if self.closed {
            return Err(WireStatus::new(
                WireCode::FailedPrecondition,
                "request stream is already closed",
            ));
        }
        let mut buf = BytesMut::with_capacity(request.encoded_len());
        request
            .encode(&mut buf)
            .map_err(|e| WireStatus::internal(format!("prost encode: {e}")))?;
        self.inner.as_mut().send_body(buf.freeze()).await
    }

    pub async fn close(&mut self) -> Result<(), WireStatus> {
        if self.closed {
            return Ok(());
        }
        self.inner.as_mut().close_send(None).await?;
        self.closed = true;
        Ok(())
    }
}

impl<Q> Drop for StreamingSink<Q> {
    fn drop(&mut self) {
        if !self.closed {
            self.inner.as_mut().reset(WireCode::Cancelled);
        }
    }
}

/// Bidirectional streaming call. Use [`split`] when send and receive need
/// to be driven concurrently.
///
/// [`split`]: BidiStreamingCall::split
#[must_use = "streaming calls carry a terminal trailer; ignoring it discards the server-side status"]
pub struct BidiStreamingCall<Q, R> {
    sink: StreamingSink<Q>,
    responses: StreamingCall<R>,
}

impl<Q, R> Unpin for BidiStreamingCall<Q, R> {}

impl<Q, R> BidiStreamingCall<Q, R> {
    fn new<S, H>(send: S, recv: H) -> Self
    where
        S: SendHalf + 'static,
        S::Error: std::error::Error + Send + Sync + 'static,
        H: RecvHalf + Unpin + Send + 'static,
        H::Error: std::error::Error + Send + Sync + 'static,
    {
        Self {
            sink: StreamingSink::new(send),
            responses: StreamingCall::new(recv),
        }
    }

    pub fn split(self) -> (StreamingSink<Q>, StreamingCall<R>) {
        (self.sink, self.responses)
    }

    pub fn finish(self) -> Result<Trailer, WireStatus> {
        self.responses.finish()
    }
}

impl<Q: Message, R> BidiStreamingCall<Q, R> {
    pub async fn send(&mut self, request: Q) -> Result<(), WireStatus> {
        self.sink.send(request).await
    }

    pub async fn close(&mut self) -> Result<(), WireStatus> {
        self.sink.close().await
    }
}

impl<Q, R: Message + Default> futures_core::Stream for BidiStreamingCall<Q, R> {
    type Item = Result<R, WireStatus>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().responses).poll_next(cx)
    }
}

/// A successful unary response plus any trailer metadata the handler
/// wants to emit (commitments, OTel span context, ...).
#[derive(Debug)]
pub struct WithTrailer<R> {
    pub response: R,
    pub metadata: hellas_wire::Metadata,
}

impl<R> WithTrailer<R> {
    pub fn new(response: R) -> Self {
        Self {
            response,
            metadata: hellas_wire::Metadata::new(),
        }
    }

    pub fn with_metadata(response: R, metadata: hellas_wire::Metadata) -> Self {
        Self { response, metadata }
    }
}

impl<R> From<R> for WithTrailer<R> {
    fn from(response: R) -> Self {
        Self::new(response)
    }
}

/// Server-side helper: decode a single prost message off the recv stream,
/// emit a single response, then close with an Ok trailer (optionally
/// carrying provenance metadata via `WithTrailer`).
pub async fn dispatch_unary<T, M, F, Fut, RespOrTrailer>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default,
    M::Response: Message,
    F: FnOnce(M::Request) -> Fut + Send,
    Fut: std::future::Future<Output = Result<RespOrTrailer, WireStatus>> + Send,
    RespOrTrailer: Into<WithTrailer<M::Response>>,
{
    dispatch_unary_with_context_and_limit::<T, M, _, _, _>(inbound, None, |request, _context| {
        handler(request)
    })
    .await
}

/// Server-side unary dispatch with a raw request-body limit checked before
/// prost decoding.
pub async fn dispatch_unary_bounded<T, M, F, Fut, RespOrTrailer>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    max_request_bytes: usize,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default,
    M::Response: Message,
    F: FnOnce(M::Request) -> Fut + Send,
    Fut: std::future::Future<Output = Result<RespOrTrailer, WireStatus>> + Send,
    RespOrTrailer: Into<WithTrailer<M::Response>>,
{
    dispatch_unary_with_context_and_limit::<T, M, _, _, _>(
        inbound,
        Some(max_request_bytes),
        |request, _context| handler(request),
    )
    .await
}

/// Context-aware unary dispatch. This is used by connection-bound protocols
/// such as confidential open; the exporter remains transport-provided and is
/// never decoded from request bytes.
pub async fn dispatch_unary_with_context<T, M, F, Fut, RespOrTrailer>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default,
    M::Response: Message,
    F: FnOnce(M::Request, hellas_wire::TransportContext) -> Fut + Send,
    Fut: std::future::Future<Output = Result<RespOrTrailer, WireStatus>> + Send,
    RespOrTrailer: Into<WithTrailer<M::Response>>,
{
    dispatch_unary_with_context_and_limit::<T, M, _, _, _>(inbound, None, handler).await
}

fn raw_request_limit_status(len: usize, max: Option<usize>) -> Option<WireStatus> {
    let max = max?;
    (len > max).then(|| {
        WireStatus::new(
            WireCode::InvalidArgument,
            format!("raw unary request exceeds {max} bytes"),
        )
    })
}

async fn dispatch_unary_with_context_and_limit<T, M, F, Fut, RespOrTrailer>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    max_request_bytes: Option<usize>,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default,
    M::Response: Message,
    F: FnOnce(M::Request, hellas_wire::TransportContext) -> Fut + Send,
    Fut: std::future::Future<Output = Result<RespOrTrailer, WireStatus>> + Send,
    RespOrTrailer: Into<WithTrailer<M::Response>>,
{
    let context = inbound.context;
    let (mut send, recv) = WireStream::split(inbound.stream);
    let mut recv = Box::pin(recv);
    let req_bytes = match recv.next().await {
        Some(Ok(b)) => b,
        Some(Err(e)) => return Err(TransportError::Io(format!("recv: {e}"))),
        None => return Err(TransportError::Protocol("empty unary request".into())),
    };
    if let Some(status) = raw_request_limit_status(req_bytes.len(), max_request_bytes) {
        send.close_send(Some(status.into()))
            .await
            .map_err(|e| TransportError::Io(format!("close-with-status: {e}")))?;
        return Ok(());
    }
    let request = M::Request::decode(&req_bytes[..])
        .map_err(|e| TransportError::Protocol(format!("prost decode: {e}")))?;

    match handler(request, context).await {
        Ok(result) => {
            let WithTrailer { response, metadata } = result.into();
            let mut buf = BytesMut::with_capacity(response.encoded_len());
            response
                .encode(&mut buf)
                .map_err(|e| TransportError::Protocol(format!("prost encode: {e}")))?;
            send.send_body(buf.freeze())
                .await
                .map_err(|e| TransportError::Io(format!("send: {e}")))?;
            let trailer = if metadata.is_empty() {
                Trailer::ok()
            } else {
                Trailer {
                    status: WireCode::Ok,
                    message: smol_str::SmolStr::new_static(""),
                    metadata,
                }
            };
            send.close_send(Some(trailer))
                .await
                .map_err(|e| TransportError::Io(format!("close: {e}")))?;
        }
        Err(status) => {
            send.close_send(Some(status.into()))
                .await
                .map_err(|e| TransportError::Io(format!("close-with-status: {e}")))?;
        }
    }
    Ok(())
}

/// Server-side helper for server-streaming methods: decode the single
/// request frame, invoke the handler, then forward each yielded
/// response back over the wire.
pub async fn dispatch_server_streaming<T, M, F, Fut, S>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default,
    M::Response: Message + Send + 'static,
    F: FnOnce(M::Request) -> Fut + Send,
    Fut: std::future::Future<Output = Result<S, WireStatus>> + Send,
    S: futures_util::Stream<Item = Result<M::Response, WireStatus>> + Send + Unpin,
{
    let (mut send, recv) = WireStream::split(inbound.stream);
    let mut recv = Box::pin(recv);
    let req_bytes = match recv.next().await {
        Some(Ok(b)) => b,
        Some(Err(e)) => return Err(TransportError::Io(format!("recv: {e}"))),
        None => return Err(TransportError::Protocol("empty stream request".into())),
    };
    let request = M::Request::decode(&req_bytes[..])
        .map_err(|e| TransportError::Protocol(format!("prost decode: {e}")))?;

    let mut stream = match handler(request).await {
        Ok(s) => s,
        Err(status) => {
            send.close_send(Some(status.into()))
                .await
                .map_err(|e| TransportError::Io(format!("close-with-status: {e}")))?;
            return Ok(());
        }
    };

    while let Some(item) = stream.next().await {
        match item {
            Ok(response) => {
                let mut buf = BytesMut::with_capacity(response.encoded_len());
                response
                    .encode(&mut buf)
                    .map_err(|e| TransportError::Protocol(format!("prost encode: {e}")))?;
                send.send_body(buf.freeze())
                    .await
                    .map_err(|e| TransportError::Io(format!("send: {e}")))?;
            }
            Err(status) => {
                send.close_send(Some(Trailer {
                    status: status.code,
                    message: status.message,
                    metadata: status.metadata,
                }))
                .await
                .map_err(|e| TransportError::Io(format!("close-with-status: {e}")))?;
                return Ok(());
            }
        }
    }

    send.close_send(Some(Trailer::ok()))
        .await
        .map_err(|e| TransportError::Io(format!("close: {e}")))?;
    Ok(())
}

/// Server-side helper for bidirectional streaming methods.
pub async fn dispatch_bidi_streaming<T, M, F, Fut, S>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default + Send + 'static,
    M::Response: Message + Send + 'static,
    F: FnOnce(RequestStream<M::Request>) -> Fut + Send,
    Fut: std::future::Future<Output = Result<S, WireStatus>> + Send,
    S: futures_util::Stream<Item = Result<M::Response, WireStatus>> + Send + Unpin,
    <T::Stream as WireStream>::RecvHalf: Unpin + Send + 'static,
    <<T::Stream as WireStream>::RecvHalf as RecvHalf>::Error:
        std::error::Error + Send + Sync + 'static,
{
    let (mut send, recv) = WireStream::split(inbound.stream);
    let requests = RequestStream::new(recv);
    let mut stream = match handler(requests).await {
        Ok(s) => s,
        Err(status) => {
            send.close_send(Some(status.into()))
                .await
                .map_err(|e| TransportError::Io(format!("close-with-status: {e}")))?;
            return Ok(());
        }
    };

    while let Some(item) = stream.next().await {
        match item {
            Ok(response) => {
                let mut buf = BytesMut::with_capacity(response.encoded_len());
                response
                    .encode(&mut buf)
                    .map_err(|e| TransportError::Protocol(format!("prost encode: {e}")))?;
                send.send_body(buf.freeze())
                    .await
                    .map_err(|e| TransportError::Io(format!("send: {e}")))?;
            }
            Err(status) => {
                send.close_send(Some(Trailer {
                    status: status.code,
                    message: status.message,
                    metadata: status.metadata,
                }))
                .await
                .map_err(|e| TransportError::Io(format!("close-with-status: {e}")))?;
                return Ok(());
            }
        }
    }

    send.close_send(Some(Trailer::ok()))
        .await
        .map_err(|e| TransportError::Io(format!("close: {e}")))?;
    Ok(())
}

/// Decoded request stream passed to bidirectional server handlers.
pub struct RequestStream<Q> {
    inner: Pin<Box<dyn ErasedRecv + Send>>,
    eof: bool,
    _q: PhantomData<Q>,
}

impl<Q> Unpin for RequestStream<Q> {}

impl<Q> RequestStream<Q> {
    fn new<H>(recv: H) -> Self
    where
        H: RecvHalf + Unpin + Send + 'static,
        H::Error: std::error::Error + Send + Sync + 'static,
    {
        Self {
            inner: Box::pin(RecvAdapter { recv }),
            eof: false,
            _q: PhantomData,
        }
    }
}

impl<Q: Message + Default> futures_core::Stream for RequestStream<Q> {
    type Item = Result<Q, WireStatus>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.eof {
            return Poll::Ready(None);
        }
        match this.inner.as_mut().poll_chunk(cx) {
            Poll::Ready(Some(Ok(bytes))) => match Q::decode(&bytes[..]) {
                Ok(msg) => Poll::Ready(Some(Ok(msg))),
                Err(e) => Poll::Ready(Some(Err(WireStatus::internal(format!(
                    "prost decode: {e}"
                ))))),
            },
            Poll::Ready(Some(Err(s))) => Poll::Ready(Some(Err(s))),
            Poll::Ready(None) => {
                this.eof = true;
                match this.inner.take_trailer() {
                    Some(t) if t.status == WireCode::Ok => Poll::Ready(None),
                    Some(t) => Poll::Ready(Some(Err(trailer_to_status(&t)))),
                    None => Poll::Ready(Some(Err(WireStatus::internal(
                        "request stream ended without terminal trailer",
                    )))),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod streaming_call_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, PartialEq, ::prost::Message)]
    struct U32Msg {
        #[prost(uint32, tag = "1")]
        x: u32,
    }

    /// Synthetic recv: pre-loaded chunks + optional trailer.
    struct MockRecv {
        chunks: VecDeque<Result<Bytes, WireStatus>>,
        trailer: Option<Trailer>,
    }

    impl ErasedRecv for MockRecv {
        fn poll_chunk(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Bytes, WireStatus>>> {
            Poll::Ready(self.chunks.pop_front())
        }
        fn take_trailer(&self) -> Option<Trailer> {
            self.trailer.clone()
        }
    }

    fn call(
        chunks: Vec<Result<Bytes, WireStatus>>,
        trailer: Option<Trailer>,
    ) -> StreamingCall<U32Msg> {
        StreamingCall {
            inner: Box::pin(MockRecv {
                chunks: chunks.into(),
                trailer,
            }),
            eof: false,
            _r: PhantomData,
        }
    }

    fn body(v: u32) -> Bytes {
        let mut b = bytes::BytesMut::new();
        prost::Message::encode(&U32Msg { x: v }, &mut b).unwrap();
        b.freeze()
    }

    #[derive(Clone, Default)]
    struct MockSendState {
        bodies: Arc<Mutex<Vec<Bytes>>>,
        close: Arc<Mutex<Option<Option<Trailer>>>>,
        reset: Arc<Mutex<Option<WireCode>>>,
    }

    struct MockSend {
        state: MockSendState,
    }

    impl SendHalf for MockSend {
        type Error = std::io::Error;

        async fn send_body(&mut self, payload: Bytes) -> Result<(), Self::Error> {
            self.state.bodies.lock().unwrap().push(payload);
            Ok(())
        }

        async fn close_send(&mut self, trailer: Option<Trailer>) -> Result<(), Self::Error> {
            *self.state.close.lock().unwrap() = Some(trailer);
            Ok(())
        }

        fn reset(&mut self, code: WireCode) {
            *self.state.reset.lock().unwrap() = Some(code);
        }
    }

    #[tokio::test]
    async fn happy_path_then_ok_trailer() {
        let mut c = call(vec![Ok(body(7)), Ok(body(13))], Some(Trailer::ok()));
        assert_eq!(c.next().await.unwrap().unwrap().x, 7);
        assert_eq!(c.next().await.unwrap().unwrap().x, 13);
        assert!(c.next().await.is_none());
        assert_eq!(c.finish().unwrap().status, WireCode::Ok);
    }

    #[tokio::test]
    async fn non_ok_trailer_surfaces_via_finish() {
        let mut c = call(
            vec![Ok(body(1))],
            Some(Trailer::from_status(WireCode::Cancelled, "abort")),
        );
        let _ = c.next().await;
        let _ = c.next().await; // drain to EOF
        let err = c.finish().unwrap_err();
        assert_eq!(err.code, WireCode::Cancelled);
        assert_eq!(err.message.as_str(), "abort");
    }

    #[tokio::test]
    async fn missing_trailer_is_internal() {
        let mut c = call(vec![Ok(body(1))], None);
        let _ = c.next().await;
        let _ = c.next().await;
        assert_eq!(c.finish().unwrap_err().code, WireCode::Internal);
    }

    #[tokio::test]
    async fn per_item_error_propagates() {
        let mut c = call(
            vec![Ok(body(1)), Err(WireStatus::new(WireCode::DataLoss, "mid"))],
            Some(Trailer::ok()),
        );
        assert_eq!(c.next().await.unwrap().unwrap().x, 1);
        assert_eq!(
            c.next().await.unwrap().unwrap_err().code,
            WireCode::DataLoss,
        );
    }

    #[tokio::test]
    #[should_panic(expected = "before the Stream returned None")]
    async fn finish_before_eof_panics() {
        let _ = call(vec![Ok(body(1))], Some(Trailer::ok())).finish();
    }

    #[tokio::test]
    async fn request_stream_decodes_body_frames() {
        let mut stream = RequestStream {
            inner: Box::pin(MockRecv {
                chunks: vec![Ok(body(21))].into(),
                trailer: Some(Trailer::ok()),
            }),
            eof: false,
            _q: PhantomData::<U32Msg>,
        };

        assert_eq!(stream.next().await.unwrap().unwrap().x, 21);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn request_stream_surfaces_terminal_error() {
        let mut stream = RequestStream {
            inner: Box::pin(MockRecv {
                chunks: VecDeque::new(),
                trailer: Some(Trailer::from_status(WireCode::Cancelled, "client closed")),
            }),
            eof: false,
            _q: PhantomData::<U32Msg>,
        };

        let err = stream.next().await.unwrap().unwrap_err();
        assert_eq!(err.code, WireCode::Cancelled);
        assert_eq!(err.message.as_str(), "client closed");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn streaming_sink_encodes_requests_and_closes() {
        let state = MockSendState::default();
        let mut sink = StreamingSink::<U32Msg>::new(MockSend {
            state: state.clone(),
        });

        sink.send(U32Msg { x: 34 }).await.unwrap();
        sink.close().await.unwrap();

        let bodies = state.bodies.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        assert_eq!(U32Msg::decode(&bodies[0][..]).unwrap().x, 34);
        assert!(state.close.lock().unwrap().is_some());
        assert!(state.reset.lock().unwrap().is_none());
    }

    #[test]
    fn raw_unary_limit_is_inclusive_and_rejects_before_decode() {
        assert!(raw_request_limit_status(65_540, Some(65_540)).is_none());
        let status = raw_request_limit_status(65_541, Some(65_540))
            .expect("one byte over the raw cap is rejected");
        assert_eq!(status.code(), WireCode::InvalidArgument);
    }
}
