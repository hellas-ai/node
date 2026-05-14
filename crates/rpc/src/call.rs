//! Generic RPC helpers used by codegen-emitted client trait impls.
//!
//! The codegen produces typed client traits like `ExecuteClient<T>` with one
//! async method per RPC. Each method body delegates to one of the helpers
//! below, parameterised by a `MethodMarker` so prost type info is at the
//! type level — no string method names at call sites.

use std::pin::Pin;

use bytes::BytesMut;
use futures_util::StreamExt;
use prost::Message;

use hellas_wire::metadata::{Metadata, Trailer};
use hellas_wire::status::{WireCode, WireStatus};
use hellas_wire::transport::{
    MethodMarker, RecvHalf, SendHalf, Stream as WireStream, StreamTransport,
};
use hellas_wire::TransportError;

/// Pin-boxed receive stream for server-streaming responses.
pub type ResponseStream<R> =
    Pin<Box<dyn futures_core::Stream<Item = Result<R, WireStatus>> + Send>>;

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
/// can read `x-hellas-commitment-bin` / receipts / OTel response
/// context.
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

    let chunk_opt = match recv.next().await {
        Some(Ok(b)) => Some(b),
        Some(Err(e)) => return Err(WireStatus::internal(format!("recv: {e}"))),
        None => None,
    };
    // Drain to terminal so the trailer is populated.
    while recv.next().await.is_some() {}
    // If the server emitted an error trailer, surface it as the call
    // result — don't conflate "no body" with "Internal".
    if let Some(trailer) = recv.trailer() {
        if trailer.status != WireCode::Ok {
            return Err(WireStatus {
                code: trailer.status,
                message: trailer.message.clone(),
                details: bytes::Bytes::new(),
                metadata: trailer.metadata.clone(),
            });
        }
    }
    let chunk = chunk_opt.ok_or_else(|| {
        WireStatus::new(
            WireCode::Internal,
            "empty unary response with Ok trailer",
        )
    })?;
    let response = M::Response::decode(&chunk[..])
        .map_err(|e| WireStatus::internal(format!("prost decode: {e}")))?;
    let metadata = recv.trailer().map(|t| t.metadata.clone()).unwrap_or_default();
    Ok(WithTrailer::with_metadata(response, metadata))
}

/// Server-streaming call: send one request, receive a stream of responses.
pub async fn server_streaming<T, M>(
    transport: &T,
    request: M::Request,
    headers: Metadata,
) -> Result<ResponseStream<M::Response>, WireStatus>
where
    T: StreamTransport + Sync,
    M: MethodMarker,
    M::Request: Message,
    M::Response: Message + Default + Send + 'static,
    T::Stream: 'static,
    <T::Stream as WireStream>::RecvHalf: 'static,
    <T::Stream as WireStream>::SendHalf: 'static,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let stream = transport
        .open(M::METHOD_ID, headers)
        .await
        .map_err(transport_to_status)?;
    let (mut send, recv) = WireStream::split(stream);
    let recv = Box::pin(recv);

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

    // The send-half is dropped here; the recv-half drives response decoding.
    let decoded =
        recv.map(|chunk| -> Result<M::Response, WireStatus> {
            let bytes = chunk.map_err(|e| {
                WireStatus::internal(format!("recv: {e}"))
            })?;
            M::Response::decode(&bytes[..])
                .map_err(|e| WireStatus::internal(format!("prost decode: {e}")))
        });
    Ok(Box::pin(decoded))
}

fn transport_to_status<E: std::error::Error>(err: E) -> WireStatus {
    WireStatus::new(WireCode::Unavailable, err.to_string())
}

/// A successful unary response plus any trailer metadata the handler
/// wants to emit (commitments, receipts, OTel span context, …).
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
/// carrying provenance/receipt metadata via `WithTrailer`).
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
    let (mut send, recv) = WireStream::split(inbound.stream);
    let mut recv = Box::pin(recv);
    let req_bytes = match recv.next().await {
        Some(Ok(b)) => b,
        Some(Err(e)) => return Err(TransportError::Io(format!("recv: {e}"))),
        None => return Err(TransportError::Protocol("empty unary request".into())),
    };
    let request = M::Request::decode(&req_bytes[..])
        .map_err(|e| TransportError::Protocol(format!("prost decode: {e}")))?;

    match handler(request).await {
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
            send.close_send(Some(Trailer {
                status: status.code,
                message: status.message,
                metadata: status.metadata,
            }))
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
            send.close_send(Some(Trailer {
                status: status.code,
                message: status.message,
                metadata: status.metadata,
            }))
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
