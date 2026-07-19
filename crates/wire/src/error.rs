//! Common transport error type used as the default `Error` associated
//! type when a transport doesn't supply its own.

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("i/o: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}
