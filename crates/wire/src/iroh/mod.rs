//! Iroh transport: one StreamTransport per iroh `Connection`.
//! Iroh substreams ARE the streams; no mux involved.

mod stream;
mod transport;

pub mod pool;
pub mod swarm;

pub use pool::{Pool, PoolError, PoolOptions};
pub use stream::{IrohRecvHalf, IrohSendHalf, IrohStream};
pub use swarm::{
    DiscoveredPeer, Discovery, Peer, PeerExchangeBackend, ServiceRegistry, StaticBackend,
};
pub use transport::{IrohTransport, IrohTransportError, OPEN_EXPORTER_LABEL, OPEN_EXPORTER_LEN};
