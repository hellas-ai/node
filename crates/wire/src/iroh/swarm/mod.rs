//! Swarm: unified peer discovery and connection racing.
//!
//! - Pluggable peer feeds via the [`Discovery`] trait
//! - Per-feed priority, trust, and scope
//! - Merged, deduped stream consumed by the [`ServiceRegistry`]
//!
//! ## Backends
//!
//! * `StaticBackend` and `PeerExchangeBackend` — always available.
//! * `DhtBackend` (`discovery-dht`) — mainline-DHT shard buckets with
//!   signed service ads.
//! * `MdnsBackend` (`discovery-mdns`) — local-network discovery via the
//!   external `iroh-mdns-address-lookup` crate (in iroh 1.0.0-rc.0 mDNS
//!   moved out of the core iroh crate).

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

#[cfg(feature = "discovery-dht")]
pub use dht::{DhtBackend, DhtPublisher, DhtPublisherConfig};
#[cfg(feature = "discovery-mdns")]
pub use mdns::MdnsBackend;
