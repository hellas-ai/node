//! Iroh transport: one StreamTransport per iroh `Connection`.
//! Iroh substreams ARE the streams; no mux involved.

mod stream;
mod transport;

pub use stream::{IrohRecvHalf, IrohSendHalf, IrohStream};
pub use transport::{IrohTransport, IrohTransportError};
