//! Native WebSocket transport via `tokio-tungstenite`.
//!
//! The WebSocket layer is message-oriented: each binary WS message is
//! exactly one mux keyed frame ("one Frame = one WebSocket message"
//! invariant from the wire plan). All non-binary control frames
//! (Ping/Pong/Text) are dropped — keepalives are handled by the
//! WebSocket layer itself, and we don't emit text.

use std::error::Error as StdError;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::clock::DefaultClock;
use crate::mux::{MessagePipe, MuxConfig, MuxTransport, Role};
use crate::transport::PeerIdentity;

use super::WsTransport;

/// Mux slot capacity for native ws connections. Native is typically
/// the relay end of a browser ↔ relay link, so we size for the
/// browser's footprint.
const NATIVE_MUX_N: usize = 128;

/// Errors surfaced by the WS adapter. Wrap tungstenite's error type
/// (which is not `Send + Sync + 'static` by accident — it is) so the
/// `MessagePipe` associated-error bounds are satisfied.
#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("websocket: {0}")]
    Ws(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("connect: {0}")]
    Connect(String),
}

/// `MessagePipe` adapter over a tokio-tungstenite `WebSocketStream`.
///
/// Generic over the underlying byte stream so the same pipe works for
/// `connect_async` (which yields `MaybeTlsStream<TcpStream>`) and for
/// upgraded server sockets (`hyper::upgrade::Upgraded`, plain
/// `TcpStream`, etc.).
pub struct WsPipe<S> {
    ws: WebSocketStream<S>,
}

impl<S> WsPipe<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self { ws }
    }

    pub fn into_inner(self) -> WebSocketStream<S> {
        self.ws
    }
}

impl<S> MessagePipe for WsPipe<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type SendError = WsError;
    type RecvError = WsError;

    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        self.ws.send(Message::Binary(bytes)).await?;
        Ok(())
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        while let Some(msg) = self.ws.next().await {
            match msg? {
                Message::Binary(data) => return Ok(Some(data)),
                // Control frames + text: skip silently. tungstenite
                // auto-replies to pings, so we only see the trace.
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Text(_) => continue,
                Message::Frame(_) => continue,
                Message::Close(_) => return Ok(None),
            }
        }
        Ok(None)
    }
}

/// Dial a WebSocket URL and bring up a `WsTransport` (== `MuxTransport`)
/// in client role. The caller polls `transport.open(...)` / `accept()`
/// as usual; the mux's spawned I/O loop drives the WebSocket.
pub async fn connect(url: &str) -> Result<WsTransport, WsError> {
    let (ws, _resp) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| WsError::Connect(format!("{e}")))?;
    let pipe = WsPipe::new(ws);
    let transport = MuxTransport::spawn::<NATIVE_MUX_N, DefaultClock, _>(
        Role::Client,
        DefaultClock,
        MuxConfig::default(),
        pipe,
        None,
    );
    Ok(transport)
}

/// Wrap an already-upgraded `WebSocketStream` as a server-side
/// `WsTransport`. The caller is responsible for performing the
/// HTTP/1.1 → WebSocket handshake (e.g. via `hyper`'s upgrade machinery
/// + `tokio_tungstenite::WebSocketStream::from_raw_socket(_, Server, _)`
/// or by accepting on a listener with `tokio_tungstenite::accept_async`).
///
/// `peer` is the optional transport-vouched identity (e.g. extracted
/// from a TLS client cert or an upstream auth header); pass `None` if
/// the transport itself has nothing to vouch for.
pub fn accept_upgraded<S>(
    ws: WebSocketStream<S>,
    peer: Option<PeerIdentity>,
) -> WsTransport
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let pipe = WsPipe::new(ws);
    MuxTransport::spawn::<NATIVE_MUX_N, DefaultClock, _>(
        Role::Server,
        DefaultClock,
        MuxConfig::default(),
        pipe,
        peer,
    )
}

// Compile-time assertion: keep our error type compatible with the
// `MessagePipe::*Error` bounds (Send + Sync + 'static + Error).
const _: fn() = || {
    fn assert_pipe_error<T: StdError + Send + Sync + 'static>() {}
    assert_pipe_error::<WsError>();
};
