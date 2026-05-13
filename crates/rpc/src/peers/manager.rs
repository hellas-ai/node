#[cfg(feature = "iroh-client")]
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use thiserror::Error;

use super::MethodKey;
use super::{
    AcquireDenied, DiscoverySource, Outcome, PeerChange, PeerEntry, PeerEvent, PeerId,
    PeerRegistry, PeerRegistryConfig, Permit, RequestKind, ServiceKey, ServiceObservation,
    ServiceState, TransportSecurity,
};

/// Shared peer-state owner for application code.
///
/// `PeerRegistry` stays the deterministic sans-io state machine. `PeerManager`
/// is the small ergonomic wrapper used by clients, servers, and discovery
/// drivers that want shared state, monotonic timestamps, and Drop-based
/// request release.
///
/// Timestamps are milliseconds since the manager was constructed — not wall
/// clock. This means age and latency arithmetic is immune to NTP/manual clock
/// changes. Absolute calendar timestamps must be carried in caller-owned
/// fields, not derived from `PeerEntry::{first_seen_ms, last_seen_ms}`.
#[derive(Clone, Debug)]
pub struct PeerManager {
    registry: Arc<Mutex<PeerRegistry>>,
    base: Instant,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    pub fn new() -> Self {
        Self::with_config(PeerRegistryConfig::default())
    }

    pub fn with_config(config: PeerRegistryConfig) -> Self {
        Self {
            registry: Arc::new(Mutex::new(PeerRegistry::with_config(config))),
            base: Instant::now(),
        }
    }

    pub fn from_registry(registry: PeerRegistry) -> Self {
        Self {
            registry: Arc::new(Mutex::new(registry)),
            base: Instant::now(),
        }
    }

    /// Milliseconds since this manager was constructed.
    ///
    /// Monotonic: never goes backward, never jumps forward across NTP / DST /
    /// manual clock changes. All timestamps stored in `PeerEntry` and used
    /// for admission/EMA/eviction are produced by this method.
    pub fn now_ms(&self) -> u64 {
        u64::try_from(Instant::now().duration_since(self.base).as_millis())
            .unwrap_or(u64::MAX)
    }

    pub fn snapshot(&self) -> Result<PeerRegistry, PeerManagerError> {
        Ok(self.lock()?.clone())
    }

    pub fn with_registry<R>(
        &self,
        read: impl FnOnce(&PeerRegistry) -> R,
    ) -> Result<R, PeerManagerError> {
        let registry = self.lock()?;
        Ok(read(&registry))
    }

    pub fn peer(&self, peer: PeerId) -> PeerSession {
        PeerSession {
            manager: self.clone(),
            peer,
        }
    }

    pub fn service_session<S: ServiceKey>(&self, peer: PeerId) -> PeerServiceSession<S> {
        self.peer(peer).service::<S>()
    }

    fn apply(&self, peer: PeerId, event: PeerEvent) -> Result<PeerChange, PeerManagerError> {
        let now = self.now_ms();
        Ok(self.lock()?.apply(now, peer, event))
    }

    pub fn observe_discovered_peer(
        &self,
        peer: PeerId,
        source: DiscoverySource,
        transport_security: TransportSecurity,
    ) -> Result<PeerChange, PeerManagerError> {
        self.apply(
            peer,
            PeerEvent::Discovered {
                source,
                transport_security,
            },
        )
    }

    pub fn observe_discovered_service_name(
        &self,
        peer: PeerId,
        source: DiscoverySource,
        service: &'static str,
        transport_security: TransportSecurity,
    ) -> Result<ServiceObservation, PeerManagerError> {
        let now = self.now_ms();
        Ok(self
            .lock()?
            .observe_discovered_service(now, peer, source, service, transport_security))
    }

    pub fn observe_discovered_service<S: ServiceKey>(
        &self,
        peer: PeerId,
        source: DiscoverySource,
        transport_security: TransportSecurity,
    ) -> Result<ServiceObservation, PeerManagerError> {
        self.observe_discovered_service_name(peer, source, S::NAME, transport_security)
    }

    pub fn observe_inbound_request(
        &self,
        peer: PeerId,
        kind: RequestKind,
        rtt_ms: Option<f64>,
    ) -> Result<PeerChange, PeerManagerError> {
        let now = self.now_ms();
        Ok(self
            .lock()?
            .observe_inbound_request(now, peer, kind, rtt_ms)?)
    }

    pub fn observe_invalid_request(&self, peer: PeerId) -> Result<PeerChange, PeerManagerError> {
        let now = self.now_ms();
        Ok(self.lock()?.observe_invalid_request(now, peer))
    }

    pub fn observe_rate_limited(&self, peer: PeerId) -> Result<PeerChange, PeerManagerError> {
        self.apply(peer, PeerEvent::RateLimited)
    }

    pub fn forget_peer(&self, peer: PeerId) -> Result<PeerChange, PeerManagerError> {
        self.apply(peer, PeerEvent::Forgotten)
    }

    pub fn set_peer_label(
        &self,
        peer: PeerId,
        label: impl Into<String>,
    ) -> Result<PeerChange, PeerManagerError> {
        self.apply(
            peer,
            PeerEvent::LabelSet {
                label: label.into(),
            },
        )
    }

    pub fn set_peer_trusted(
        &self,
        peer: PeerId,
        trusted: bool,
    ) -> Result<PeerChange, PeerManagerError> {
        self.apply(peer, PeerEvent::TrustSet { trusted })
    }

    pub fn acquire_rpc(
        &self,
        peer: PeerId,
        kind: RequestKind,
        observation: RpcObservation,
    ) -> Result<RpcPermitGuard, PeerManagerError> {
        let now = self.now_ms();
        let mut registry = self.lock()?;
        registry.apply(
            now,
            peer,
            PeerEvent::Discovered {
                source: observation.source,
                transport_security: observation.initial_security,
            },
        );
        let permit = registry.try_acquire(now, peer, kind)?;
        drop(registry);

        Ok(RpcPermitGuard {
            manager: self.clone(),
            permit: Some(permit),
            started: Instant::now(),
            observation,
        })
    }

    pub fn acquire_method<M: MethodKey>(
        &self,
        peer: PeerId,
        observation: RpcObservation,
    ) -> Result<RpcPermitGuard, PeerManagerError> {
        self.acquire_rpc(peer, RequestKind::for_method::<M>(), observation)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, PeerRegistry>, PeerManagerError> {
        self.registry
            .lock()
            .map_err(|_| PeerManagerError::Unavailable)
    }
}

#[cfg(feature = "iroh")]
pub fn iroh_service_alpn<S: ServiceKey>() -> String {
    format!("/{}/1.0", S::NAME)
}

/// `PeerExtractor` for the iroh transport.
///
/// Reads `tonic_iroh_transport::IrohContext` from request extensions — the
/// transport injects it on every accepted bidi stream so the managed server
/// wrappers can match the request to a peer identity without seeing iroh
/// types themselves.
///
/// Gated on `iroh-client` or `iroh-server` because `IrohContext` is only
/// re-exported by `tonic-iroh-transport` when one of its `client`/`server`
/// sub-features is on. Bare `iroh` (just `From<EndpointId> for PeerId`) is
/// not enough.
#[cfg(any(feature = "iroh-client", feature = "iroh-server"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct IrohPeerExtractor;

#[cfg(any(feature = "iroh-client", feature = "iroh-server"))]
impl super::PeerExtractor for IrohPeerExtractor {
    fn extract<B>(&self, request: &http::Request<B>) -> Option<super::InboundPeerObservation> {
        use tonic_iroh_transport::iroh::endpoint::PathId;
        let context = request
            .extensions()
            .get::<tonic_iroh_transport::IrohContext>()?;
        Some(super::InboundPeerObservation {
            peer: PeerId::from(context.node_id),
            rtt_ms: context
                .connection
                .rtt(PathId::ZERO)
                .map(|d| d.as_secs_f64() * 1000.0),
        })
    }
}

#[cfg(feature = "iroh")]
impl PeerManager {
    pub fn iroh_peer(&self, peer: tonic_iroh_transport::iroh::EndpointId) -> PeerSession {
        self.peer(PeerId::from(peer))
    }

    pub fn iroh_service_session<S: ServiceKey>(
        &self,
        peer: tonic_iroh_transport::iroh::EndpointId,
    ) -> PeerServiceSession<S> {
        self.iroh_peer(peer).service::<S>()
    }

    pub fn observe_iroh_service<S: ServiceKey>(
        &self,
        peer: tonic_iroh_transport::iroh::EndpointId,
    ) -> Result<ServiceObservation, PeerManagerError> {
        self.iroh_service_session::<S>(peer).observe_discovered(
            DiscoverySource::Transport("discovery"),
            TransportSecurity::Untrusted,
        )
    }

    pub fn acquire_iroh_method<M: MethodKey>(
        &self,
        peer: tonic_iroh_transport::iroh::EndpointId,
    ) -> Result<RpcPermitGuard, PeerManagerError> {
        self.iroh_service_session::<<M as MethodKey>::Service>(peer)
            .acquire_method::<M>(RpcObservation::authenticated_transport("iroh"))
    }
}

/// Managed outbound iroh pool for one generated service.
///
/// This is the transport-side companion to [`PeerManager`]. It acquires a
/// typed request permit before opening the tonic channel and records connection
/// failures itself, so callers cannot accidentally leave the registry with a
/// leaked in-flight request when dialing fails. Successful calls still return
/// the [`RpcPermitGuard`] because the caller knows when the RPC body or stream
/// has actually finished.
#[cfg(feature = "iroh-client")]
pub struct IrohRpcPool<S: ServiceKey> {
    pool: tonic_iroh_transport::ConnectionPool,
    manager: PeerManager,
    _service: PhantomData<fn() -> S>,
}

#[cfg(feature = "iroh-client")]
impl<S: ServiceKey> Clone for IrohRpcPool<S> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            manager: self.manager.clone(),
            _service: PhantomData,
        }
    }
}

#[cfg(feature = "iroh-client")]
impl<S: ServiceKey> std::fmt::Debug for IrohRpcPool<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohRpcPool")
            .field("service", &S::NAME)
            .field("pool", &self.pool)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "iroh-client")]
impl<S: ServiceKey> IrohRpcPool<S> {
    #[must_use]
    pub fn new(
        endpoint: tonic_iroh_transport::iroh::Endpoint,
        manager: PeerManager,
        options: tonic_iroh_transport::PoolOptions,
    ) -> Self {
        let alpn = iroh_service_alpn::<S>();
        Self::from_pool(
            tonic_iroh_transport::ConnectionPool::new(endpoint, alpn.as_bytes(), options),
            manager,
        )
    }

    #[must_use]
    pub fn from_pool(pool: tonic_iroh_transport::ConnectionPool, manager: PeerManager) -> Self {
        Self {
            pool,
            manager,
            _service: PhantomData,
        }
    }

    #[must_use]
    pub const fn manager(&self) -> &PeerManager {
        &self.manager
    }

    #[must_use]
    pub const fn pool(&self) -> &tonic_iroh_transport::ConnectionPool {
        &self.pool
    }

    pub async fn channel<M: MethodKey<Service = S>>(
        &self,
        peer: tonic_iroh_transport::iroh::EndpointId,
    ) -> Result<(tonic_iroh_transport::IrohChannel, RpcPermitGuard), IrohRpcPoolError> {
        let mut permit = self.manager.acquire_iroh_method::<M>(peer)?;
        match self.pool.channel(peer).await {
            Ok(channel) => Ok((channel, permit)),
            Err(source) => {
                permit.finish_connect_err(source.to_string());
                Err(IrohRpcPoolError::Connect {
                    service: S::NAME,
                    source,
                })
            }
        }
    }
}

#[cfg(feature = "iroh-client")]
#[derive(Debug, Error)]
pub enum IrohRpcPoolError {
    #[error(transparent)]
    Peer(#[from] PeerManagerError),
    #[error("connect to {service}: {source}")]
    Connect {
        service: &'static str,
        source: tonic_iroh_transport::Error,
    },
}

/// Iroh-transport façade — the user-facing entry point for outbound RPCs.
///
/// One `IrohTransport` owns the endpoint, a shared `PeerManager`, and a lazy
/// cache of `ConnectionPool`s keyed by service ALPN. Each `peer(id)` call
/// returns a cheap `IrohPeerHandle` that callers chain typed RPC methods on
/// (via codegen-emitted extension traits like `CourtesyClient for
/// IrohPeerHandle`). The pool for a service is materialized on first use,
/// so binaries only pay for the protocols they actually call.
#[cfg(feature = "iroh-client")]
#[derive(Clone, Debug)]
pub struct IrohTransport {
    inner: Arc<IrohTransportInner>,
}

#[cfg(feature = "iroh-client")]
struct IrohTransportInner {
    endpoint: tonic_iroh_transport::iroh::Endpoint,
    manager: PeerManager,
    pools: Mutex<HashMap<&'static str, tonic_iroh_transport::ConnectionPool>>,
    pool_options: tonic_iroh_transport::PoolOptions,
}

#[cfg(feature = "iroh-client")]
impl std::fmt::Debug for IrohTransportInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pool_alpns: Vec<&str> = self
            .pools
            .lock()
            .map(|map| map.keys().copied().collect())
            .unwrap_or_default();
        f.debug_struct("IrohTransport")
            .field("endpoint", &self.endpoint.id())
            .field("pools", &pool_alpns)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "iroh-client")]
impl IrohTransport {
    pub fn new(endpoint: tonic_iroh_transport::iroh::Endpoint, manager: PeerManager) -> Self {
        Self::with_options(
            endpoint,
            manager,
            tonic_iroh_transport::PoolOptions::default(),
        )
    }

    pub fn with_options(
        endpoint: tonic_iroh_transport::iroh::Endpoint,
        manager: PeerManager,
        pool_options: tonic_iroh_transport::PoolOptions,
    ) -> Self {
        Self {
            inner: Arc::new(IrohTransportInner {
                endpoint,
                manager,
                pools: Mutex::new(HashMap::new()),
                pool_options,
            }),
        }
    }

    /// Typed handle for a remote peer reachable over this transport.
    pub fn peer(&self, peer_id: tonic_iroh_transport::iroh::EndpointId) -> IrohPeerHandle {
        IrohPeerHandle {
            transport: self.inner.clone(),
            peer_id,
        }
    }

    pub fn manager(&self) -> &PeerManager {
        &self.inner.manager
    }

    pub fn endpoint(&self) -> &tonic_iroh_transport::iroh::Endpoint {
        &self.inner.endpoint
    }

    /// Get-or-create the pool for service `S`. Pools are cached so repeated
    /// calls for the same service share a single tonic-iroh-transport pool
    /// (with its connection cache, dial timeouts, etc).
    pub fn pool<S: ServiceKey>(&self) -> IrohRpcPool<S> {
        self.inner.pool::<S>()
    }
}

#[cfg(feature = "iroh-client")]
impl IrohTransportInner {
    fn pool<S: ServiceKey>(&self) -> IrohRpcPool<S> {
        let alpn = iroh_service_alpn::<S>();
        let mut pools = self
            .pools
            .lock()
            .expect("IrohTransport::pools mutex poisoned");
        let pool = pools.entry(S::NAME).or_insert_with(|| {
            tonic_iroh_transport::ConnectionPool::new(
                self.endpoint.clone(),
                alpn.as_bytes(),
                self.pool_options.clone(),
            )
        });
        IrohRpcPool::from_pool(pool.clone(), self.manager.clone())
    }
}

/// Typed handle for one (transport, peer) pair.
///
/// Cheap to clone. The actual outbound RPC machinery (per-service pool dialing,
/// admission, finishing the permit) is reached through codegen-emitted
/// extension traits like `CourtesyClient for IrohPeerHandle`, which sit
/// alongside this type and pick up the right pool via `pool::<CourtesyService>()`.
#[cfg(feature = "iroh-client")]
#[derive(Clone)]
pub struct IrohPeerHandle {
    transport: Arc<IrohTransportInner>,
    peer_id: tonic_iroh_transport::iroh::EndpointId,
}

#[cfg(feature = "iroh-client")]
impl std::fmt::Debug for IrohPeerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohPeerHandle")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "iroh-client")]
impl IrohPeerHandle {
    pub const fn peer_id(&self) -> tonic_iroh_transport::iroh::EndpointId {
        self.peer_id
    }

    pub fn manager(&self) -> &PeerManager {
        &self.transport.manager
    }

    pub fn endpoint(&self) -> &tonic_iroh_transport::iroh::Endpoint {
        &self.transport.endpoint
    }

    /// Lazily-materialised connection pool for a specific generated service.
    /// Codegen-emitted extension traits use this to dial.
    pub fn pool<S: ServiceKey>(&self) -> IrohRpcPool<S> {
        self.transport.pool::<S>()
    }

    /// Service-typed permit-acquisition shortcut: equivalent to
    /// `self.manager().acquire_iroh_method::<M>(self.peer_id())` but reads
    /// better at typed call sites.
    pub fn acquire_method<M: MethodKey>(&self) -> Result<RpcPermitGuard, PeerManagerError> {
        self.manager().acquire_iroh_method::<M>(self.peer_id)
    }
}

/// Logical session view for one remote peer.
///
/// This is not a transport connection handle. It is a typed view over shared
/// peer facts. A transport may have zero, one, or many physical links for the
/// peer while all observations still converge here.
#[derive(Clone, Debug)]
pub struct PeerSession {
    manager: PeerManager,
    peer: PeerId,
}

impl PeerSession {
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }

    pub fn observe_discovered(
        &self,
        source: DiscoverySource,
        transport_security: TransportSecurity,
    ) -> Result<PeerChange, PeerManagerError> {
        self.manager
            .observe_discovered_peer(self.peer, source, transport_security)
    }

    pub fn forget(&self) -> Result<PeerChange, PeerManagerError> {
        self.manager.forget_peer(self.peer)
    }

    pub fn set_label(&self, label: impl Into<String>) -> Result<PeerChange, PeerManagerError> {
        self.manager.set_peer_label(self.peer, label)
    }

    pub fn set_trusted(&self, trusted: bool) -> Result<PeerChange, PeerManagerError> {
        self.manager.set_peer_trusted(self.peer, trusted)
    }

    pub fn service<S: ServiceKey>(&self) -> PeerServiceSession<S> {
        PeerServiceSession {
            manager: self.manager.clone(),
            peer: self.peer,
            _service: PhantomData,
        }
    }

    pub fn with_entry<R>(
        &self,
        read: impl FnOnce(Option<&PeerEntry>) -> R,
    ) -> Result<R, PeerManagerError> {
        self.manager
            .with_registry(|registry| read(registry.get(self.peer)))
    }

    pub fn entry_snapshot(&self) -> Result<Option<PeerEntry>, PeerManagerError> {
        self.with_entry(|entry| entry.cloned())
    }
}

/// Logical session view for one `(peer, service)` pair.
///
/// This is the API shape application and generated client code should prefer.
/// It keeps service capability explicit while preserving the global peer state
/// underneath.
#[derive(Clone, Debug)]
pub struct PeerServiceSession<S: ServiceKey> {
    manager: PeerManager,
    peer: PeerId,
    _service: PhantomData<fn() -> S>,
}

impl<S: ServiceKey> PeerServiceSession<S> {
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }

    pub const fn service_name(&self) -> &'static str {
        S::NAME
    }

    pub fn observe_discovered(
        &self,
        source: DiscoverySource,
        transport_security: TransportSecurity,
    ) -> Result<ServiceObservation, PeerManagerError> {
        self.manager
            .observe_discovered_service::<S>(self.peer, source, transport_security)
    }

    pub fn acquire_method<M: MethodKey<Service = S>>(
        &self,
        observation: RpcObservation,
    ) -> Result<RpcPermitGuard, PeerManagerError> {
        self.manager
            .acquire_rpc(self.peer, RequestKind::for_method::<M>(), observation)
    }

    pub fn state(&self) -> Result<Option<ServiceState>, PeerManagerError> {
        self.manager.with_registry(|registry| {
            registry
                .get(self.peer)
                .and_then(|entry| entry.service::<S>())
                .cloned()
        })
    }
}

/// How an outbound RPC should update peer facts around transport security.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcObservation {
    pub source: DiscoverySource,
    pub initial_security: TransportSecurity,
    pub completion_security: TransportSecurity,
}

impl RpcObservation {
    pub const fn new(
        source: DiscoverySource,
        initial_security: TransportSecurity,
        completion_security: TransportSecurity,
    ) -> Self {
        Self {
            source,
            initial_security,
            completion_security,
        }
    }

    /// A transport that proves peer identity only after the channel/RPC has
    /// completed far enough to bind bytes to the remote peer.
    pub const fn authenticated_transport(name: &'static str) -> Self {
        Self::new(
            DiscoverySource::Transport(name),
            TransportSecurity::Untrusted,
            TransportSecurity::Authenticated,
        )
    }

    pub const fn untrusted_transport(name: &'static str) -> Self {
        Self::new(
            DiscoverySource::Transport(name),
            TransportSecurity::Untrusted,
            TransportSecurity::Untrusted,
        )
    }
}

/// RAII request permit returned by [`PeerManager::acquire_rpc`].
///
/// Dropping the guard records a cancellation and releases the in-flight slot.
/// Call `finish_ok`, `finish_err`, or `finish_connect_err` exactly once when the
/// request reaches a terminal state.
#[derive(Debug)]
pub struct RpcPermitGuard {
    manager: PeerManager,
    permit: Option<Permit>,
    started: Instant,
    observation: RpcObservation,
}

impl RpcPermitGuard {
    pub fn finish_ok(&mut self) {
        self.observe_completed_service();
        self.release(Outcome::ok(duration_ms(self.started.elapsed())));
    }

    pub fn finish_err(&mut self, error: impl Into<String>) {
        self.observe_completed_service();
        self.release(Outcome::Err {
            rtt_ms: Some(duration_ms(self.started.elapsed())),
            error: error.into(),
        });
    }

    /// Record failure before the transport established a peer-authenticated RPC.
    pub fn finish_connect_err(&mut self, error: impl Into<String>) {
        self.release(Outcome::Err {
            rtt_ms: Some(duration_ms(self.started.elapsed())),
            error: error.into(),
        });
    }

    fn observe_completed_service(&self) {
        let Some(permit) = self.permit.as_ref() else {
            return;
        };
        let now = self.manager.now_ms();
        let Ok(mut registry) = self.manager.lock() else {
            return;
        };
        registry.apply(
            now,
            permit.peer(),
            PeerEvent::Discovered {
                source: self.observation.source,
                transport_security: self.observation.completion_security,
            },
        );
        registry.apply(
            now,
            permit.peer(),
            PeerEvent::ServiceObserved {
                service: permit.kind().service,
                transport_security: self.observation.completion_security,
            },
        );
    }

    fn release(&mut self, outcome: Outcome) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let now = self.manager.now_ms();
        if let Ok(mut registry) = self.manager.lock() {
            registry.release(now, permit, outcome);
        }
    }
}

impl Drop for RpcPermitGuard {
    fn drop(&mut self) {
        self.release(Outcome::Cancelled);
    }
}

#[derive(Debug, Error)]
pub enum PeerManagerError {
    #[error("peer registry is unavailable")]
    Unavailable,
    #[error(transparent)]
    Admission(#[from] AcquireDenied),
}

pub(super) fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(all(test, feature = "swarm"))]
mod tests {
    use super::*;
    use crate::service::NodeService;

    fn peer(byte: u8) -> PeerId {
        PeerId::from([byte; 32])
    }

    fn config() -> PeerRegistryConfig {
        PeerRegistryConfig {
            max_peers: 16,
            max_services_per_peer: 4,
            max_in_flight_per_peer: 2,
            max_in_flight_total: 4,
            bucket_capacity: 4.0,
            bucket_refill_per_sec: 1.0,
            ..PeerRegistryConfig::default()
        }
    }

    #[test]
    fn successful_rpc_records_authenticated_service_and_releases_slot() {
        let manager = PeerManager::with_config(config());
        let id = peer(1);

        let mut permit = manager
            .acquire_rpc(
                id,
                RequestKind::for_method::<crate::service::methods::GetNodeInfo>(),
                RpcObservation::authenticated_transport("iroh"),
            )
            .expect("request should be admitted");
        assert_eq!(
            manager
                .with_registry(PeerRegistry::total_in_flight)
                .expect("registry should be readable"),
            1
        );

        permit.finish_ok();

        let registry = manager.snapshot().expect("registry should be readable");
        let entry = registry.get(id).expect("peer should exist");
        assert_eq!(entry.transport_security, TransportSecurity::Authenticated);
        assert!(entry.has_service_key::<NodeService>());
        assert_eq!(entry.in_flight, 0);
        assert_eq!(registry.total_in_flight(), 0);
    }

    #[test]
    fn connect_error_does_not_authenticate_or_observe_service() {
        let manager = PeerManager::with_config(config());
        let id = peer(2);

        let mut permit = manager
            .acquire_rpc(
                id,
                RequestKind::for_method::<crate::service::methods::GetNodeInfo>(),
                RpcObservation::authenticated_transport("iroh"),
            )
            .expect("request should be admitted");
        permit.finish_connect_err("connect failed");

        let registry = manager.snapshot().expect("registry should be readable");
        let entry = registry.get(id).expect("peer should exist");
        assert_eq!(entry.transport_security, TransportSecurity::Untrusted);
        assert!(!entry.has_service_key::<NodeService>());
        assert_eq!(entry.in_flight, 0);
        assert_eq!(entry.error_count, 1);
    }

    #[test]
    fn dropped_guard_records_cancellation() {
        let manager = PeerManager::with_config(config());
        let id = peer(3);

        let permit = manager
            .acquire_rpc(
                id,
                RequestKind::for_method::<crate::service::methods::GetNodeInfo>(),
                RpcObservation::authenticated_transport("iroh"),
            )
            .expect("request should be admitted");
        drop(permit);

        let registry = manager.snapshot().expect("registry should be readable");
        let entry = registry.get(id).expect("peer should exist");
        assert_eq!(entry.cancelled_count, 1);
        assert_eq!(entry.in_flight, 0);
        assert_eq!(registry.total_in_flight(), 0);
    }

    #[test]
    fn service_session_ties_method_to_service() {
        let manager = PeerManager::with_config(config());
        let id = peer(4);
        let node = manager.peer(id).service::<NodeService>();

        let mut permit = node
            .acquire_method::<crate::service::methods::GetNodeInfo>(
                RpcObservation::authenticated_transport("iroh"),
            )
            .expect("request should be admitted");
        permit.finish_ok();

        let service = node
            .state()
            .expect("registry should be readable")
            .expect("node service should be recorded");
        assert_eq!(service.service, <NodeService as ServiceKey>::NAME);
        assert_eq!(service.success_count, 1);
    }

    #[test]
    fn peer_session_records_discovery_without_service() {
        let manager = PeerManager::with_config(config());
        let id = peer(5);

        let change = manager
            .peer(id)
            .observe_discovered(DiscoverySource::PeerExchange, TransportSecurity::Untrusted)
            .expect("peer should be recorded");
        assert!(change.inserted);

        let entry = manager
            .peer(id)
            .entry_snapshot()
            .expect("registry should be readable")
            .expect("peer should exist");
        assert!(entry.services.is_empty());
    }

    #[test]
    fn peer_session_records_label_trust_and_forget() {
        let manager = PeerManager::with_config(config());
        let id = peer(6);
        let peer = manager.peer(id);

        peer.observe_discovered(DiscoverySource::Manual, TransportSecurity::Untrusted)
            .expect("peer should be recorded");
        peer.set_label("local gpu")
            .expect("label should be recorded");
        peer.set_trusted(true).expect("trust should be recorded");

        let entry = peer
            .entry_snapshot()
            .expect("registry should be readable")
            .expect("peer should exist");
        assert_eq!(entry.label.as_deref(), Some("local gpu"));
        assert!(entry.trusted);

        peer.forget().expect("peer should be forgotten");
        assert!(
            peer.entry_snapshot()
                .expect("registry should be readable")
                .is_none()
        );
    }
}
