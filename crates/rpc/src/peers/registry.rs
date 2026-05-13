use std::collections::HashMap;

use super::admission::{AcquireDenied, Outcome, Permit, RequestKind, TokenBucket};
use super::id::PeerId;
use super::security::{AuthLevel, TransportSecurity};

const DEFAULT_MAX_PEERS: usize = 2048;
const DEFAULT_MAX_SERVICES_PER_PEER: usize = 32;
const DEFAULT_MAX_IN_FLIGHT_PER_PEER: usize = 16;
const DEFAULT_MAX_IN_FLIGHT_TOTAL: usize = 256;
const DEFAULT_BUCKET_CAPACITY: f64 = 24.0;
const DEFAULT_BUCKET_REFILL_PER_SEC: f64 = 2.0;
const DEFAULT_RTT_EMA_ALPHA: f64 = 0.2;
const DEFAULT_MAX_LABEL_LEN: usize = 128;
const DEFAULT_MAX_ERROR_LEN: usize = 256;

/// Memory and admission bounds for a peer registry.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PeerRegistryConfig {
    pub max_peers: usize,
    pub max_services_per_peer: usize,
    pub max_in_flight_per_peer: usize,
    pub max_in_flight_total: usize,
    pub bucket_capacity: f64,
    pub bucket_refill_per_sec: f64,
    pub rtt_ema_alpha: f64,
    pub max_label_len: usize,
    pub max_error_len: usize,
}

impl Default for PeerRegistryConfig {
    fn default() -> Self {
        Self {
            max_peers: DEFAULT_MAX_PEERS,
            max_services_per_peer: DEFAULT_MAX_SERVICES_PER_PEER,
            max_in_flight_per_peer: DEFAULT_MAX_IN_FLIGHT_PER_PEER,
            max_in_flight_total: DEFAULT_MAX_IN_FLIGHT_TOTAL,
            bucket_capacity: DEFAULT_BUCKET_CAPACITY,
            bucket_refill_per_sec: DEFAULT_BUCKET_REFILL_PER_SEC,
            rtt_ema_alpha: DEFAULT_RTT_EMA_ALPHA,
            max_label_len: DEFAULT_MAX_LABEL_LEN,
            max_error_len: DEFAULT_MAX_ERROR_LEN,
        }
    }
}

impl PeerRegistryConfig {
    /// Conservative profile for low-memory devices.
    pub const fn small(max_peers: usize) -> Self {
        Self {
            max_peers,
            max_services_per_peer: 8,
            max_in_flight_per_peer: 2,
            max_in_flight_total: 8,
            bucket_capacity: 8.0,
            bucket_refill_per_sec: 1.0,
            rtt_ema_alpha: DEFAULT_RTT_EMA_ALPHA,
            max_label_len: 64,
            max_error_len: 128,
        }
    }

    fn normalized(mut self) -> Self {
        if !self.bucket_capacity.is_finite() || self.bucket_capacity < 0.0 {
            self.bucket_capacity = 0.0;
        }
        if !self.bucket_refill_per_sec.is_finite() || self.bucket_refill_per_sec < 0.0 {
            self.bucket_refill_per_sec = 0.0;
        }
        if !self.rtt_ema_alpha.is_finite() {
            self.rtt_ema_alpha = DEFAULT_RTT_EMA_ALPHA;
        }
        self.rtt_ema_alpha = self.rtt_ema_alpha.clamp(0.0, 1.0);
        self
    }
}

/// Where a peer observation came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoverySource {
    Manual,
    StaticConfig,
    PeerExchange,
    Mdns,
    Dht,
    Transport(&'static str),
}

/// Pure input event for peer state.
#[derive(Clone, Debug, PartialEq)]
pub enum PeerEvent {
    Discovered {
        source: DiscoverySource,
        transport_security: TransportSecurity,
    },
    ServiceObserved {
        service: &'static str,
        transport_security: TransportSecurity,
    },
    RttSample {
        rtt_ms: f64,
    },
    LabelSet {
        label: String,
    },
    TrustSet {
        trusted: bool,
    },
    Forgotten,
}

/// Coarse change summary returned from registry mutations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerChange {
    pub peer: PeerId,
    pub inserted: bool,
    pub updated: bool,
    pub removed: bool,
    pub evicted: Option<PeerId>,
    pub dropped: bool,
}

impl PeerChange {
    const fn updated(peer: PeerId) -> Self {
        Self {
            peer,
            inserted: false,
            updated: true,
            removed: false,
            evicted: None,
            dropped: false,
        }
    }

    const fn dropped(peer: PeerId) -> Self {
        Self {
            peer,
            inserted: false,
            updated: false,
            removed: false,
            evicted: None,
            dropped: true,
        }
    }
}

/// Last-known state for a service on a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
    Observed,
    Healthy,
    Failed,
}

/// Per-service facts tracked by the registry.
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceState {
    pub service: &'static str,
    pub status: ServiceStatus,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub transport_security: TransportSecurity,
    pub success_count: u64,
    pub error_count: u64,
    pub last_rtt_ms: Option<f64>,
    pub last_error: Option<String>,
}

impl ServiceState {
    fn observed(service: &'static str, now_ms: u64, transport_security: TransportSecurity) -> Self {
        Self {
            service,
            status: ServiceStatus::Observed,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            transport_security,
            success_count: 0,
            error_count: 0,
            last_rtt_ms: None,
            last_error: None,
        }
    }

    fn observe(&mut self, now_ms: u64, transport_security: TransportSecurity) {
        self.last_seen_ms = now_ms;
        self.transport_security = self.transport_security.strongest(transport_security);
    }

    fn record_success(&mut self, now_ms: u64, rtt_ms: f64) {
        self.status = ServiceStatus::Healthy;
        self.last_seen_ms = now_ms;
        self.success_count = self.success_count.saturating_add(1);
        self.last_rtt_ms = clean_rtt(rtt_ms);
        self.last_error = None;
    }

    fn record_error(&mut self, now_ms: u64, rtt_ms: Option<f64>, error: String) {
        self.status = ServiceStatus::Failed;
        self.last_seen_ms = now_ms;
        self.error_count = self.error_count.saturating_add(1);
        self.last_rtt_ms = rtt_ms.and_then(clean_rtt);
        self.last_error = Some(error);
    }
}

/// Per-peer facts and counters.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerEntry {
    pub id: PeerId,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub last_source: Option<DiscoverySource>,
    pub transport_security: TransportSecurity,
    pub auth_level: AuthLevel,
    pub trusted: bool,
    pub label: Option<String>,
    pub services: HashMap<&'static str, ServiceState>,
    pub rtt_ema_ms: Option<f64>,
    pub success_count: u64,
    pub error_count: u64,
    pub cancelled_count: u64,
    pub total_requests: u64,
    pub rate_limited_count: u64,
    pub in_flight: usize,
    pub last_error: Option<String>,
    bucket: TokenBucket,
}

impl PeerEntry {
    fn new(id: PeerId, now_ms: u64, bucket_capacity: f64) -> Self {
        Self {
            id,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            last_source: None,
            transport_security: TransportSecurity::Untrusted,
            auth_level: AuthLevel::Untrusted,
            trusted: false,
            label: None,
            services: HashMap::new(),
            rtt_ema_ms: None,
            success_count: 0,
            error_count: 0,
            cancelled_count: 0,
            total_requests: 0,
            rate_limited_count: 0,
            in_flight: 0,
            last_error: None,
            bucket: TokenBucket::new(now_ms, bucket_capacity),
        }
    }

    pub fn has_service(&self, service: &'static str) -> bool {
        self.services.contains_key(service)
    }

    pub fn service_state(&self, service: &'static str) -> Option<&ServiceState> {
        self.services.get(service)
    }

    pub const fn latency_ms(&self) -> Option<f64> {
        self.rtt_ema_ms
    }

    fn update_auth_level(&mut self) {
        self.auth_level =
            AuthLevel::from_transport_and_trust(self.transport_security, self.trusted);
    }

    fn observe_transport(&mut self, transport_security: TransportSecurity) {
        self.transport_security = self.transport_security.strongest(transport_security);
        self.update_auth_level();
    }

    fn observe_service(
        &mut self,
        service: &'static str,
        now_ms: u64,
        transport_security: TransportSecurity,
        max_services: usize,
    ) -> bool {
        if let Some(state) = self.services.get_mut(service) {
            state.observe(now_ms, transport_security);
            return true;
        }

        if self.services.len() >= max_services {
            return false;
        }

        self.services.insert(
            service,
            ServiceState::observed(service, now_ms, transport_security),
        );
        true
    }

    fn record_rtt(&mut self, rtt_ms: f64, alpha: f64) {
        let Some(rtt_ms) = clean_rtt(rtt_ms) else {
            return;
        };

        self.rtt_ema_ms = Some(match self.rtt_ema_ms {
            Some(current) => current.mul_add(1.0 - alpha, rtt_ms * alpha),
            None => rtt_ms,
        });
    }

    fn eviction_key(&self) -> (u8, u8, usize, u64, u64) {
        (
            u8::from(self.trusted),
            self.transport_security.strength(),
            self.services.len(),
            self.success_count,
            self.last_seen_ms,
        )
    }
}

/// Bounded, sans-io registry for peer facts and request admission.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerRegistry {
    config: PeerRegistryConfig,
    peers: HashMap<PeerId, PeerEntry>,
    total_in_flight: usize,
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::with_config(PeerRegistryConfig::default())
    }
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: PeerRegistryConfig) -> Self {
        let config = config.normalized();
        Self {
            config,
            peers: HashMap::with_capacity(config.max_peers.min(1024)),
            total_in_flight: 0,
        }
    }

    pub const fn config(&self) -> PeerRegistryConfig {
        self.config
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub const fn total_in_flight(&self) -> usize {
        self.total_in_flight
    }

    pub fn get(&self, peer: PeerId) -> Option<&PeerEntry> {
        self.peers.get(&peer)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PeerEntry> {
        self.peers.values()
    }

    pub fn with_service(&self, service: &'static str) -> impl Iterator<Item = &PeerEntry> {
        self.iter().filter(move |peer| peer.has_service(service))
    }

    pub fn latency(&self, peer: PeerId) -> Option<f64> {
        self.get(peer).and_then(PeerEntry::latency_ms)
    }

    pub fn apply(&mut self, now_ms: u64, peer: PeerId, event: PeerEvent) -> PeerChange {
        if matches!(event, PeerEvent::Forgotten) {
            let removed = self.peers.remove(&peer).is_some();
            return PeerChange {
                peer,
                inserted: false,
                updated: false,
                removed,
                evicted: None,
                dropped: false,
            };
        }

        let Ok((inserted, evicted)) = self.ensure_peer(now_ms, peer) else {
            return PeerChange::dropped(peer);
        };

        let max_services = self.config.max_services_per_peer;
        let max_label_len = self.config.max_label_len;
        let Some(entry) = self.peers.get_mut(&peer) else {
            return PeerChange::dropped(peer);
        };

        entry.last_seen_ms = now_ms;
        let mut dropped = false;

        match event {
            PeerEvent::Discovered {
                source,
                transport_security,
            } => {
                entry.last_source = Some(source);
                entry.observe_transport(transport_security);
            }
            PeerEvent::ServiceObserved {
                service,
                transport_security,
            } => {
                entry.observe_transport(transport_security);
                dropped = !entry.observe_service(service, now_ms, transport_security, max_services);
            }
            PeerEvent::RttSample { rtt_ms } => {
                entry.record_rtt(rtt_ms, self.config.rtt_ema_alpha);
            }
            PeerEvent::LabelSet { label } => {
                entry.label = Some(truncate_string(label, max_label_len));
            }
            PeerEvent::TrustSet { trusted } => {
                entry.trusted = trusted;
                entry.update_auth_level();
            }
            PeerEvent::Forgotten => unreachable!("forgotten events are handled before insert"),
        }

        PeerChange {
            peer,
            inserted,
            updated: !inserted,
            removed: false,
            evicted,
            dropped,
        }
    }

    pub fn try_acquire(
        &mut self,
        now_ms: u64,
        peer: PeerId,
        kind: RequestKind,
        cost: f32,
    ) -> Result<Permit, AcquireDenied> {
        if self.total_in_flight >= self.config.max_in_flight_total {
            return Err(AcquireDenied::InFlightTotal {
                limit: self.config.max_in_flight_total,
            });
        }

        self.ensure_peer(now_ms, peer)
            .map_err(|_| AcquireDenied::PeerLimit {
                peer,
                max_peers: self.config.max_peers,
            })?;

        let Some(entry) = self.peers.get_mut(&peer) else {
            return Err(AcquireDenied::PeerLimit {
                peer,
                max_peers: self.config.max_peers,
            });
        };

        if entry.in_flight >= self.config.max_in_flight_per_peer {
            return Err(AcquireDenied::InFlightPeer {
                peer,
                limit: self.config.max_in_flight_per_peer,
            });
        }

        if let Err(retry_after_ms) = entry.bucket.try_take(
            now_ms,
            self.config.bucket_capacity,
            self.config.bucket_refill_per_sec,
            cost,
        ) {
            entry.rate_limited_count = entry.rate_limited_count.saturating_add(1);
            return Err(AcquireDenied::RateLimited {
                peer,
                retry_after_ms,
            });
        }

        entry.in_flight += 1;
        entry.total_requests = entry.total_requests.saturating_add(1);
        entry.last_seen_ms = now_ms;
        self.total_in_flight += 1;

        Ok(Permit::new(peer, kind, now_ms, cost))
    }

    pub fn release(&mut self, now_ms: u64, permit: Permit, outcome: Outcome) -> PeerChange {
        self.total_in_flight = self.total_in_flight.saturating_sub(1);

        let peer = permit.peer();
        let max_services = self.config.max_services_per_peer;
        let alpha = self.config.rtt_ema_alpha;
        let max_error_len = self.config.max_error_len;

        let Some(entry) = self.peers.get_mut(&peer) else {
            return PeerChange::dropped(peer);
        };

        entry.in_flight = entry.in_flight.saturating_sub(1);
        entry.last_seen_ms = now_ms;

        match outcome {
            Outcome::Ok { rtt_ms } => {
                entry.success_count = entry.success_count.saturating_add(1);
                entry.record_rtt(rtt_ms, alpha);
                if entry.observe_service(
                    permit.kind().service,
                    now_ms,
                    entry.transport_security,
                    max_services,
                ) && let Some(service) = entry.services.get_mut(permit.kind().service)
                {
                    service.record_success(now_ms, rtt_ms);
                }
                entry.last_error = None;
            }
            Outcome::Err { rtt_ms, error } => {
                entry.error_count = entry.error_count.saturating_add(1);
                if let Some(rtt_ms) = rtt_ms {
                    entry.record_rtt(rtt_ms, alpha);
                }
                let error = truncate_string(error, max_error_len);
                if let Some(service) = entry.services.get_mut(permit.kind().service) {
                    service.record_error(now_ms, rtt_ms, error.clone());
                }
                entry.last_error = Some(error);
            }
            Outcome::Cancelled => {
                entry.cancelled_count = entry.cancelled_count.saturating_add(1);
            }
        }

        PeerChange::updated(peer)
    }

    fn ensure_peer(&mut self, now_ms: u64, peer: PeerId) -> Result<(bool, Option<PeerId>), ()> {
        if self.peers.contains_key(&peer) {
            return Ok((false, None));
        }

        if self.config.max_peers == 0 {
            return Err(());
        }

        let evicted = if self.peers.len() >= self.config.max_peers {
            let Some(evicted) = self.eviction_candidate() else {
                return Err(());
            };
            self.peers.remove(&evicted);
            Some(evicted)
        } else {
            None
        };

        self.peers.insert(
            peer,
            PeerEntry::new(peer, now_ms, self.config.bucket_capacity),
        );
        Ok((true, evicted))
    }

    fn eviction_candidate(&self) -> Option<PeerId> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.in_flight == 0)
            .min_by_key(|(_, peer)| peer.eviction_key())
            .map(|(id, _)| *id)
    }
}

fn clean_rtt(rtt_ms: f64) -> Option<f64> {
    if rtt_ms.is_finite() && rtt_ms >= 0.0 {
        Some(rtt_ms)
    } else {
        None
    }
}

fn truncate_string(mut value: String, max_len: usize) -> String {
    if value.len() <= max_len {
        return value;
    }

    value.truncate(max_len);
    while !value.is_char_boundary(value.len()) {
        value.pop();
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "hellas.swarm.v1.Node";
    const GET_NODE_INFO: RequestKind = RequestKind::new(NODE, "GetNodeInfo");

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
    fn tracks_service_observations_without_security_downgrade() {
        let mut registry = PeerRegistry::with_config(config());
        let id = peer(1);

        let change = registry.apply(
            10,
            id,
            PeerEvent::Discovered {
                source: DiscoverySource::Manual,
                transport_security: TransportSecurity::Authenticated,
            },
        );
        assert!(change.inserted);

        registry.apply(
            20,
            id,
            PeerEvent::ServiceObserved {
                service: NODE,
                transport_security: TransportSecurity::Untrusted,
            },
        );

        let entry = registry.get(id).expect("peer should exist");
        assert_eq!(entry.transport_security, TransportSecurity::Authenticated);
        assert_eq!(entry.auth_level, AuthLevel::Authenticated);
        assert!(entry.has_service(NODE));
    }

    #[test]
    fn enforces_per_peer_in_flight_limit() {
        let mut registry = PeerRegistry::with_config(PeerRegistryConfig {
            max_in_flight_per_peer: 1,
            bucket_capacity: 10.0,
            ..config()
        });
        let id = peer(2);

        let permit = registry
            .try_acquire(0, id, GET_NODE_INFO, 1.0)
            .expect("first request should be admitted");
        let denied = registry
            .try_acquire(1, id, GET_NODE_INFO, 1.0)
            .expect_err("second request should exceed peer in-flight limit");
        assert_eq!(denied, AcquireDenied::InFlightPeer { peer: id, limit: 1 });

        registry.release(2, permit, Outcome::ok(5.0));
        let permit = registry
            .try_acquire(3, id, GET_NODE_INFO, 1.0)
            .expect("slot should reopen after release");
        registry.release(4, permit, Outcome::ok(5.0));
    }

    #[test]
    fn enforces_token_bucket_rate_limit() {
        let mut registry = PeerRegistry::with_config(PeerRegistryConfig {
            bucket_capacity: 1.0,
            bucket_refill_per_sec: 0.0,
            ..config()
        });
        let id = peer(3);

        let permit = registry
            .try_acquire(0, id, GET_NODE_INFO, 1.0)
            .expect("first request should spend the only token");
        registry.release(1, permit, Outcome::ok(5.0));

        let denied = registry
            .try_acquire(2, id, GET_NODE_INFO, 1.0)
            .expect_err("second request should be rate limited");
        assert_eq!(
            denied,
            AcquireDenied::RateLimited {
                peer: id,
                retry_after_ms: None
            }
        );
    }

    #[test]
    fn records_latency_ema_and_success_counts() {
        let mut registry = PeerRegistry::with_config(config());
        let id = peer(4);

        let first = registry.try_acquire(0, id, GET_NODE_INFO, 1.0).unwrap();
        registry.release(10, first, Outcome::ok(100.0));
        let second = registry.try_acquire(20, id, GET_NODE_INFO, 1.0).unwrap();
        registry.release(30, second, Outcome::ok(200.0));

        let entry = registry.get(id).unwrap();
        assert_eq!(entry.success_count, 2);
        assert_eq!(entry.service_state(NODE).unwrap().success_count, 2);
        assert!((entry.latency_ms().unwrap() - 120.0).abs() < f64::EPSILON);
    }

    #[test]
    fn evicts_oldest_idle_peer_when_full() {
        let mut registry = PeerRegistry::with_config(PeerRegistryConfig {
            max_peers: 2,
            ..config()
        });
        let first = peer(5);
        let second = peer(6);
        let third = peer(7);

        registry.apply(
            10,
            first,
            PeerEvent::Discovered {
                source: DiscoverySource::Manual,
                transport_security: TransportSecurity::Untrusted,
            },
        );
        registry.apply(
            20,
            second,
            PeerEvent::Discovered {
                source: DiscoverySource::Manual,
                transport_security: TransportSecurity::Untrusted,
            },
        );
        let change = registry.apply(
            30,
            third,
            PeerEvent::Discovered {
                source: DiscoverySource::Manual,
                transport_security: TransportSecurity::Untrusted,
            },
        );

        assert_eq!(change.evicted, Some(first));
        assert!(registry.get(first).is_none());
        assert!(registry.get(second).is_some());
        assert!(registry.get(third).is_some());
    }

    #[test]
    fn normalizes_invalid_float_config() {
        let registry = PeerRegistry::with_config(PeerRegistryConfig {
            bucket_capacity: f64::NAN,
            bucket_refill_per_sec: -1.0,
            rtt_ema_alpha: 4.0,
            ..config()
        });

        assert_eq!(registry.config().bucket_capacity, 0.0);
        assert_eq!(registry.config().bucket_refill_per_sec, 0.0);
        assert_eq!(registry.config().rtt_ema_alpha, 1.0);
    }
}
