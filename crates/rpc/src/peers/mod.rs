//! Sans-io peer registry and admission policy primitives.
//!
//! This module intentionally has no transport or runtime dependencies. Callers
//! feed it observations before and after they perform I/O, and the registry
//! returns pure admission decisions plus derived peer state.

mod admission;
mod id;
mod registry;
mod security;

pub use admission::{AcquireDenied, Outcome, Permit, RequestKind};
pub use id::PeerId;
pub use registry::{
    DiscoverySource, PeerChange, PeerEntry, PeerEvent, PeerRegistry, PeerRegistryConfig,
    ServiceObservation, ServiceState, ServiceStatus,
};
pub use security::{AuthLevel, TransportSecurity};
