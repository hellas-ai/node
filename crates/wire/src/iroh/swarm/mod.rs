//! Swarm: unified peer discovery and connection racing.
//!
//! - Pluggable peer feeds via the [`Discovery`] trait
//! - Per-feed priority, trust, and scope
//! - Merged, deduped stream consumed by the [`ServiceRegistry`]
//!
//! ## Backend status
//!
//! * `StaticBackend` and `PeerExchangeBackend` — fully implemented.
//! * `MdnsBackend` (`discovery-mdns`) and `DhtBackend` (`discovery-dht`)
//!   are scope-deferred for the wire v1 cutover; the modules exist as
//!   empty stubs behind their feature flags so future work can land
//!   without churning consumers.

pub mod discovery;
pub mod engine;
pub mod peers;
pub mod registry;

#[cfg(feature = "discovery-dht")]
pub mod dht;
#[cfg(feature = "discovery-mdns")]
pub mod mdns;

pub use discovery::{DiscoveredPeer, Discovery, Peer, PeerExchangeBackend, StaticBackend};
pub use engine::SwarmEngine;
pub use peers::{PeerFeed, PeerFeedSpec, Scope};
pub use registry::ServiceRegistry;
