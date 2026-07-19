//! `hellas-wire` — transport-agnostic RPC wire layer.

pub mod canonical;
pub mod clock;
pub mod error;
pub mod frame;
pub mod latency;
pub mod metadata;
pub mod schema;
pub mod status;
pub mod transport;

#[cfg(feature = "mux")]
pub mod mux;

#[cfg(feature = "iroh")]
pub mod iroh;

#[cfg(any(feature = "ws", feature = "ws-wasm"))]
pub mod ws;

pub use crate::canonical::{Encode, Writer};
pub use crate::clock::{Clock, DefaultClock};
pub use crate::error::TransportError;
pub use crate::frame::{
    CreditFrame, EndFrame, Frame, FrameError, FrameKind, OpenFrame, ResetFrame,
};
pub use crate::latency::{EwmaLatency, LatencyEstimator};
pub use crate::metadata::{Metadata, MetadataValue, Trailer};
pub use crate::schema::{
    FieldSchema, METHOD_DOMAIN, MessageSchema, MethodSchema, PrimKind, SERVICE_DOMAIN,
    ServiceSchema, TypeSchema,
};
pub use crate::status::{WireCode, WireStatus};
pub use crate::transport::{
    AuthLevel, Dispatcher, Inbound, MethodMarker, PeerIdentity, RecvHalf, SendHalf, ServiceMarker,
    Stream, StreamTransport, TransportContext,
};
