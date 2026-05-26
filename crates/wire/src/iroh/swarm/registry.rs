//! `ServiceRegistry`: owns pluggable discovery backends and per-service pools.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ::iroh::Endpoint;
use futures::stream::Stream;

use crate::iroh::pool::{Pool, PoolOptions};
use crate::transport::ServiceMarker;

use super::discovery::{Discovery, Peer};
use super::engine::SwarmEngine;
use super::peers::{FeedError, PeerFeedSpec};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    alpn: Vec<u8>,
    options: PoolOptions,
}

/// Unified registry for pluggable peer discovery backends, plus a
/// per-service connection-pool cache.
#[derive(Clone)]
pub struct ServiceRegistry {
    endpoint: Endpoint,
    backends: Vec<Arc<dyn Discovery>>,
    pool_options: PoolOptions,
    pools: Arc<Mutex<HashMap<PoolKey, Pool>>>,
}

impl ServiceRegistry {
    /// Create an empty registry with no backends.
    #[must_use]
    pub fn new(endpoint: &Endpoint) -> Self {
        Self {
            endpoint: endpoint.clone(),
            backends: Vec::new(),
            pool_options: PoolOptions::default(),
            pools: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Add a discovery backend. Returns `&mut Self` for chaining.
    pub fn add<D: Discovery>(&mut self, backend: D) -> &mut Self {
        self.backends.push(Arc::new(backend));
        self
    }

    /// Add a pre-wrapped `Arc<dyn Discovery>` backend.
    pub fn add_shared(&mut self, backend: Arc<dyn Discovery>) -> &mut Self {
        self.backends.push(backend);
        self
    }

    /// Set default pool options used for service-scoped connection reuse.
    ///
    /// Existing cached pools are retained; the new options apply to pools
    /// created after this call.
    pub fn with_pool_options(&mut self, options: PoolOptions) -> &mut Self {
        self.pool_options = options;
        self
    }

    /// Access the endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Discover peers for a service.
    ///
    /// Returns a merged, deduped, priority-ordered stream across all
    /// registered backends whose scope matches the service ALPN.
    pub fn discover<S: ServiceMarker>(&self) -> impl Stream<Item = Result<Peer, FeedError>> {
        let alpn = S::ALPN.as_bytes().to_vec();
        let feeds = self.build_feeds(&alpn);
        SwarmEngine::new(self.endpoint.id(), &alpn, feeds)
    }

    /// Get a shared pool for a service using the registry defaults.
    ///
    /// Pools are cached by `(ALPN, options)` so repeated calls return
    /// the same handle.
    #[must_use]
    pub fn pool<S: ServiceMarker>(&self) -> Pool {
        let alpn = S::ALPN.as_bytes().to_vec();
        self.pool_for_alpn(&alpn, self.pool_options.clone())
    }

    fn build_feeds(&self, alpn: &[u8]) -> Vec<PeerFeedSpec> {
        self.backends.iter().flat_map(|b| b.feeds(alpn)).collect()
    }

    fn pool_for_alpn(&self, alpn: &[u8], options: PoolOptions) -> Pool {
        let key = PoolKey {
            alpn: alpn.to_vec(),
            options: options.clone(),
        };
        let mut pools = self
            .pools
            .lock()
            .expect("service registry pool cache should not be poisoned");
        pools
            .entry(key)
            .or_insert_with(|| Pool::new(self.endpoint.clone(), alpn, options))
            .clone()
    }
}
