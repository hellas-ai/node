//! Transport-trait surface.
//!
//! `StreamTransport` is the per-connection abstraction (open new
//! streams, accept inbound). `Stream` / `SendHalf` / `RecvHalf` are the
//! per-RPC view.

use std::future::Future;

use bytes::Bytes;
use futures_core::Stream as FuturesStream;
use smol_str::SmolStr;

use crate::metadata::{Metadata, Trailer};
use crate::status::WireCode;

/// Peer identity. Transports that have a real identity (iroh QUIC cert,
/// mTLS subject, …) populate this. Transports that don't (browser WS,
/// CF DO inbound) leave it `None`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PeerIdentity(pub SmolStr);

/// What kind of authentication the transport itself vouches for. Apps
/// layer their own auth on top via metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AuthLevel {
    /// Transport offers no identity (browser WS).
    #[default]
    None,
    /// Transport-vouched identity (iroh NodeId, mTLS subject).
    Vouched,
}

/// Transport-provided context for an inbound stream.
#[derive(Clone, Debug, Default)]
pub struct TransportContext {
    pub peer: Option<PeerIdentity>,
    pub rtt_ms: Option<f64>,
    pub auth_level: AuthLevel,
}

pub struct Inbound<S> {
    pub method_id: u32,
    pub headers: Metadata,
    pub stream: S,
    pub context: TransportContext,
}

/// Per-connection transport abstraction.
pub trait StreamTransport {
    type Stream: Stream;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Open a new outbound stream for this method. Headers go on the
    /// `OpenFrame`; body follows via `SendHalf::send_body`.
    fn open(
        &self,
        method_id: u32,
        headers: Metadata,
    ) -> impl Future<Output = Result<Self::Stream, Self::Error>> + Send;

    /// Accept the next inbound stream. Returns `None` when the
    /// transport is closed.
    fn accept(
        &self,
    ) -> impl Future<Output = Result<Option<Inbound<Self::Stream>>, Self::Error>> + Send;
}

/// Per-RPC bidi handle. Split into send/recv halves for concurrent use.
pub trait Stream: Send {
    type SendError: std::error::Error + Send + Sync + 'static;
    type RecvError: std::error::Error + Send + Sync + 'static;

    type SendHalf: SendHalf<Error = Self::SendError>;
    type RecvHalf: RecvHalf<Error = Self::RecvError>;

    /// Consume into independent halves. Both halves carry a shared
    /// reset capability (see `SendHalf::reset` / `RecvHalf::reset`).
    fn split(self) -> (Self::SendHalf, Self::RecvHalf);

    /// Cancel both directions. Idempotent.
    fn reset(&mut self, code: WireCode);
}

/// Send half. `Sink<Bytes>` ergonomics; single-frame internal buffer so
/// callers manage their own outbound queue if they want to coalesce.
pub trait SendHalf: Send {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Send a body chunk. Resolves when the chunk has been handed off
    /// to the transport (not necessarily flushed to the wire).
    fn send_body(
        &mut self,
        payload: Bytes,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Close the send direction, optionally with a trailer.
    fn close_send(
        &mut self,
        trailer: Option<Trailer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Cancel both directions of the underlying stream. Idempotent.
    fn reset(&mut self, code: WireCode);
}

/// Recv half. Yields body chunks; trailer is available after the
/// stream terminates.
pub trait RecvHalf: FuturesStream<Item = Result<Bytes, <Self as RecvHalf>::Error>> + Send {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Available after `next()` has returned `None`. Carries the
    /// terminal status (Ok / reset code / etc.).
    fn trailer(&self) -> Option<&Trailer>;

    /// Cancel both directions of the underlying stream. Idempotent.
    fn reset(&mut self, code: WireCode);
}
