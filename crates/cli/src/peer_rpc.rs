use anyhow::{Context, anyhow};
use hellas_rpc::peers::{
    DiscoverySource, Outcome, PeerEvent, PeerId, PeerRegistry, Permit, RequestKind,
    TransportSecurity,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tonic_iroh_transport::iroh::EndpointId;

pub(crate) type SharedPeerRegistry = Arc<Mutex<PeerRegistry>>;

pub(crate) struct PeerPermitGuard {
    registry: SharedPeerRegistry,
    permit: Option<Permit>,
    started: Instant,
}

impl PeerPermitGuard {
    pub(crate) fn finish_ok(&mut self) {
        self.observe_authenticated_service();
        self.release(Outcome::ok(duration_ms(self.started.elapsed())));
    }

    pub(crate) fn finish_err(&mut self, error: String) {
        self.observe_authenticated_service();
        self.release(Outcome::Err {
            rtt_ms: Some(duration_ms(self.started.elapsed())),
            error,
        });
    }

    pub(crate) fn finish_connect_err(&mut self, error: String) {
        self.release(Outcome::Err {
            rtt_ms: Some(duration_ms(self.started.elapsed())),
            error,
        });
    }

    fn observe_authenticated_service(&self) {
        let Some(permit) = self.permit.as_ref() else {
            return;
        };
        if let Ok(mut registry) = self.registry.lock() {
            let now = now_ms();
            registry.apply(
                now,
                permit.peer(),
                PeerEvent::Discovered {
                    source: DiscoverySource::Transport("iroh"),
                    transport_security: TransportSecurity::Authenticated,
                },
            );
            registry.apply(
                now,
                permit.peer(),
                PeerEvent::ServiceObserved {
                    service: permit.kind().service,
                    transport_security: TransportSecurity::Authenticated,
                },
            );
        }
    }

    fn release(&mut self, outcome: Outcome) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        if let Ok(mut registry) = self.registry.lock() {
            registry.release(now_ms(), permit, outcome);
        }
    }
}

impl Drop for PeerPermitGuard {
    fn drop(&mut self) {
        self.release(Outcome::Cancelled);
    }
}

pub(crate) fn acquire_rpc(
    registry: &SharedPeerRegistry,
    peer_id: EndpointId,
    service: &'static str,
    method: &'static str,
    cost: f32,
) -> anyhow::Result<PeerPermitGuard> {
    let now = now_ms();
    let registry_peer_id = peer_id_from_endpoint(peer_id);
    let mut registry_guard = registry
        .lock()
        .map_err(|_| anyhow!("peer registry is unavailable"))?;
    registry_guard.apply(
        now,
        registry_peer_id,
        PeerEvent::Discovered {
            source: DiscoverySource::Transport("iroh"),
            transport_security: TransportSecurity::Untrusted,
        },
    );
    let permit = registry_guard
        .try_acquire(
            now,
            registry_peer_id,
            RequestKind::new(service, method),
            cost,
        )
        .with_context(|| format!("RPC admission denied for {peer_id} {service}/{method}"))?;
    drop(registry_guard);

    Ok(PeerPermitGuard {
        registry: registry.clone(),
        permit: Some(permit),
        started: Instant::now(),
    })
}

pub(crate) fn observe_discovered_service(
    registry: &SharedPeerRegistry,
    peer_id: EndpointId,
    service: &'static str,
) {
    if let Ok(mut registry) = registry.lock() {
        registry.observe_discovered_service(
            now_ms(),
            peer_id_from_endpoint(peer_id),
            DiscoverySource::Transport("discovery"),
            service,
            TransportSecurity::Untrusted,
        );
    }
}

fn peer_id_from_endpoint(peer_id: EndpointId) -> PeerId {
    PeerId::from(*peer_id.as_bytes())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}
