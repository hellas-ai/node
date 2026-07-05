//! Common transport error type used as the default `Error` associated
//! type when a transport doesn't supply its own.

use crate::status::WireCode;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("transport closed")]
    Closed,
    #[error("at capacity")]
    AtCapacity,
    #[error("frame decode: {0}")]
    Frame(#[from] crate::frame::FrameError),
    #[error("status: {0:?}")]
    Status(WireCode),
    #[error("i/o: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}
