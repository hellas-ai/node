//! Peer feeds: static lists and broadcast-channel-backed feeds.

use std::pin::Pin;

use ::iroh::EndpointId;
use futures::stream::{Stream, StreamExt};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

use super::discovery::DiscoveredPeer;

/// Result alias for fallible feed streams. Backends use this to surface
/// transient discovery errors without tearing the whole engine down.
pub type FeedResult<T> = std::result::Result<T, FeedError>;

/// Discovery-side error for backend-specific failures.
#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    /// Backend-specific error, stringified.
    #[error("{0}")]
    Backend(String),
}

/// Scope for feed applicability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Applies to all services.
    Any,
    /// Applies only to a specific service ALPN.
    Service(Vec<u8>),
}

/// Description of a peer feed (priority, trust, scope, and stream).
pub struct PeerFeedSpec {
    /// Human-readable name for logging.
    pub name: &'static str,
    /// Lower values are polled first.
    pub priority: u8,
    /// Source/producer trust level (0 = none, 255 = full).
    pub trust: u8,
    /// Which services this feed applies to.
    pub scope: Scope,
    /// Stream yielding discovered peers.
    pub stream: PeerFeed,
}

/// Type alias for feed streams.
#[cfg(not(target_arch = "wasm32"))]
pub type PeerFeed = Pin<Box<dyn Stream<Item = FeedResult<DiscoveredPeer>> + Send>>;

/// Type alias for feed streams (WASM variant, no `Send` bound).
#[cfg(target_arch = "wasm32")]
pub type PeerFeed = Pin<Box<dyn Stream<Item = FeedResult<DiscoveredPeer>>>>;

/// Build a finite feed from a static peer list.
#[must_use]
pub fn static_feed(peers: Vec<EndpointId>, priority: u8, trust: u8, scope: Scope) -> PeerFeedSpec {
    let peer_trust = trust;
    let stream = futures::stream::iter(peers.into_iter().map(move |id| {
        Ok(DiscoveredPeer {
            id,
            trust: peer_trust,
        })
    }))
    .boxed();
    PeerFeedSpec {
        name: "static",
        priority,
        trust,
        scope,
        stream,
    }
}

/// Build a feed backed by a `tokio::sync::broadcast` channel. Used by
/// the peer-exchange backend and any caller that wants to inject peers
/// from outside the discovery system.
#[must_use]
pub fn channel_feed(rx: broadcast::Receiver<EndpointId>, priority: u8, trust: u8) -> PeerFeedSpec {
    let peer_trust = trust;
    let stream = BroadcastStream::new(rx)
        .filter_map(|msg| async move { msg.ok() })
        .map(move |id| {
            Ok(DiscoveredPeer {
                id,
                trust: peer_trust,
            })
        })
        .boxed();
    PeerFeedSpec {
        name: "peer-exchange",
        priority,
        trust,
        scope: Scope::Any,
        stream,
    }
}

/// Check if a scope applies to an ALPN.
#[must_use]
pub fn scope_matches(scope: &Scope, alpn: &[u8]) -> bool {
    match scope {
        Scope::Any => true,
        Scope::Service(s) => s.as_slice() == alpn,
    }
}
