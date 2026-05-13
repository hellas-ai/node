//! Sans-io peer registry and admission policy primitives.
//!
//! This module is the pure state engine for peer facts. It intentionally has no
//! transport, runtime, clock, or storage dependencies. Callers pass timestamps
//! and observations in, and the registry returns deterministic state changes and
//! admission decisions.
//!
//! Most application code should use [`PeerManager`] instead of calling
//! [`PeerRegistry::apply`] directly. The intended layering is:
//!
//! - a transport/discovery driver owns discovery streams and records facts here
//!   before notifying application code;
//! - generated or hand-written RPC clients acquire/release request permits here
//!   around actual RPC calls;
//! - RPC servers record inbound calls with `observe_inbound_request` for
//!   accounting and admission, but do not infer service capabilities from those
//!   calls;
//! - application code queries the current registry view, usually through a
//!   manager snapshot/view API, rather than hand-feeding events.
//!
//! In other words, the registry is the source of truth, not the discovery task
//! and not an event stream. Events are useful for notification, but polling
//! events should never be required to keep peer state correct.
//!
//! Querying from the pure registry returns borrowed entries:
//!
//! ```ignore
//! if let Some(peer) = registry.get(peer_id) {
//!     if let Some(courtesy) = peer.service::<CourtesyService>() {
//!         println!("courtesy status: {:?}", courtesy.status);
//!     }
//! }
//! ```
//!
//! `PeerManager` exposes snapshots and closure-based reads instead of long-lived
//! `Arc<PeerEntry>` handles, so callers do not accidentally hold locks or
//! depend on stale mutable state.

mod admission;
mod id;
mod manager;
mod registry;
mod security;

pub use admission::{AcquireDenied, Outcome, Permit, RequestKind};
pub use id::PeerId;
pub use manager::{PeerManager, PeerManagerError, RpcObservation, RpcPermitGuard};
pub use registry::{
    DiscoverySource, PeerChange, PeerEntry, PeerEvent, PeerRegistry, PeerRegistryConfig,
    ServiceObservation, ServiceState, ServiceStatus,
};
pub use security::{AuthLevel, TransportSecurity};

/// Type-level service identity used by typed peer queries and request kinds.
pub trait ServiceKey {
    const NAME: &'static str;
}
