use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;

use super::MethodKey;
use super::{
    AcquireDenied, DiscoverySource, Outcome, PeerChange, PeerEvent, PeerId, PeerRegistry,
    PeerRegistryConfig, Permit, RequestKind, ServiceKey, ServiceObservation, TransportSecurity,
};

/// Shared peer-state owner for application code.
///
/// `PeerRegistry` stays the deterministic sans-io state machine. `PeerManager`
/// is the small ergonomic wrapper used by clients, servers, and discovery
/// drivers that want shared state, wall-clock timestamps, and Drop-based request
/// release.
#[derive(Clone, Debug)]
pub struct PeerManager {
    registry: Arc<Mutex<PeerRegistry>>,
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
        }
    }

    pub fn from_registry(registry: PeerRegistry) -> Self {
        Self {
            registry: Arc::new(Mutex::new(registry)),
        }
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

    pub fn apply(&self, peer: PeerId, event: PeerEvent) -> Result<PeerChange, PeerManagerError> {
        Ok(self.lock()?.apply(now_ms(), peer, event))
    }

    pub fn observe_discovered_service(
        &self,
        peer: PeerId,
        source: DiscoverySource,
        service: &'static str,
        transport_security: TransportSecurity,
    ) -> Result<ServiceObservation, PeerManagerError> {
        Ok(self.lock()?.observe_discovered_service(
            now_ms(),
            peer,
            source,
            service,
            transport_security,
        ))
    }

    pub fn observe_discovered_service_key<S: ServiceKey>(
        &self,
        peer: PeerId,
        source: DiscoverySource,
        transport_security: TransportSecurity,
    ) -> Result<ServiceObservation, PeerManagerError> {
        self.observe_discovered_service(peer, source, S::NAME, transport_security)
    }

    pub fn observe_inbound_request(
        &self,
        peer: PeerId,
        kind: RequestKind,
        cost: f32,
        rtt_ms: Option<f64>,
    ) -> Result<PeerChange, PeerManagerError> {
        Ok(self
            .lock()?
            .observe_inbound_request(now_ms(), peer, kind, cost, rtt_ms)?)
    }

    pub fn observe_invalid_request(&self, peer: PeerId) -> Result<PeerChange, PeerManagerError> {
        Ok(self.lock()?.observe_invalid_request(now_ms(), peer))
    }

    pub fn acquire_rpc(
        &self,
        peer: PeerId,
        kind: RequestKind,
        cost: f32,
        observation: RpcObservation,
    ) -> Result<RpcPermitGuard, PeerManagerError> {
        let now = now_ms();
        let mut registry = self.lock()?;
        registry.apply(
            now,
            peer,
            PeerEvent::Discovered {
                source: observation.source,
                transport_security: observation.initial_security,
            },
        );
        let permit = registry.try_acquire(now, peer, kind, cost)?;
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
        cost: f32,
        observation: RpcObservation,
    ) -> Result<RpcPermitGuard, PeerManagerError> {
        self.acquire_rpc(peer, RequestKind::for_method::<M>(), cost, observation)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, PeerRegistry>, PeerManagerError> {
        self.registry
            .lock()
            .map_err(|_| PeerManagerError::Unavailable)
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
        let Ok(mut registry) = self.manager.lock() else {
            return;
        };
        let now = now_ms();
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
        if let Ok(mut registry) = self.manager.lock() {
            registry.release(now_ms(), permit, outcome);
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

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

pub(super) fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(test)]
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
                1.0,
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
                1.0,
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
                1.0,
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
}
