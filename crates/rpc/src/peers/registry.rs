use std::collections::HashMap;

use super::ServiceKey;
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
    InvalidRequest,
    RateLimited,
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

/// Result of recording that a discovered peer offers a service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceObservation {
    pub peer: PeerId,
    pub peer_inserted: bool,
    pub service_inserted: bool,
    pub evicted: Option<PeerId>,
    pub dropped: bool,
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
    pub invalid_request_count: u64,
    pub rate_limited_count: u64,
    pub in_flight: usize,
    pub last_error: Option<String>,
    /// Set by `PeerEvent::Forgotten` when the peer still has outstanding
    /// permits. The entry is excluded from public queries (`get`, `iter`,
    /// `with_service`) but stays in the underlying map so the `release`
    /// path for the in-flight permits keeps decrementing counts correctly.
    /// The entry is removed for real once `in_flight` reaches zero.
    tombstoned: bool,
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
            invalid_request_count: 0,
            rate_limited_count: 0,
            in_flight: 0,
            last_error: None,
            tombstoned: false,
            bucket: TokenBucket::new(now_ms, bucket_capacity),
        }
    }

    pub fn has_service(&self, service: &'static str) -> bool {
        self.services.contains_key(service)
    }

    pub fn has_service_name(&self, service: &str) -> bool {
        self.services.contains_key(service)
    }

    pub fn has_service_key<S: ServiceKey>(&self) -> bool {
        self.has_service(S::NAME)
    }

    pub fn service_state(&self, service: &'static str) -> Option<&ServiceState> {
        self.services.get(service)
    }

    pub fn service<S: ServiceKey>(&self) -> Option<&ServiceState> {
        self.service_state(S::NAME)
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

    /// Record a service observation. When the per-peer service cap is hit,
    /// evict the lowest-value service (fewest successes, oldest last_seen,
    /// then alphabetical name) to make room — silent drop-on-cap would
    /// silently lose per-service accounting for the *new* service every
    /// time, which is the wrong tradeoff. Returns `Some(evicted_name)` if
    /// an eviction occurred, `None` otherwise.
    fn observe_service(
        &mut self,
        service: &'static str,
        now_ms: u64,
        transport_security: TransportSecurity,
        max_services: usize,
    ) -> Option<&'static str> {
        if let Some(state) = self.services.get_mut(service) {
            state.observe(now_ms, transport_security);
            return None;
        }

        let max = max_services.max(1);
        let evicted = if self.services.len() >= max {
            let evict = self
                .services
                .values()
                .min_by_key(|s| (s.success_count, s.last_seen_ms, s.service))
                .map(|s| s.service);
            if let Some(name) = evict {
                self.services.remove(name);
                Some(name)
            } else {
                None
            }
        } else {
            None
        };

        self.services.insert(
            service,
            ServiceState::observed(service, now_ms, transport_security),
        );
        evicted
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

    /// Order: trust < transport security < #services < successes < last_seen
    /// < PeerId. The trailing `PeerId` is a stable tie-breaker so eviction
    /// stays deterministic even when every other key matches — HashMap
    /// iteration order is randomized and would otherwise leak into output.
    fn eviction_key(&self) -> (u8, u8, usize, u64, u64, PeerId) {
        (
            u8::from(self.trusted),
            self.transport_security.strength(),
            self.services.len(),
            self.success_count,
            self.last_seen_ms,
            self.id,
        )
    }
}

/// How `apply_inner` should treat a tombstoned peer when handling a
/// non-`Forgotten` event.
#[derive(Clone, Copy, Debug)]
enum TombstoneAction {
    /// Clear `tombstoned` — the event is fresh observed activity overriding
    /// the operator's earlier `forget`.
    Revive,
    /// Leave `tombstoned` alone — the event is a completion notification
    /// from an RPC that started before the forget; should record stats but
    /// not un-forget.
    Preserve,
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
        self.peers.get(&peer).filter(|e| !e.tombstoned)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PeerEntry> {
        self.peers.values().filter(|e| !e.tombstoned)
    }

    pub fn with_service(&self, service: &'static str) -> impl Iterator<Item = &PeerEntry> {
        self.iter().filter(move |peer| peer.has_service(service))
    }

    pub fn with_service_key<S: ServiceKey>(&self) -> impl Iterator<Item = &PeerEntry> {
        self.with_service(S::NAME)
    }

    pub fn latency(&self, peer: PeerId) -> Option<f64> {
        self.get(peer).and_then(PeerEntry::latency_ms)
    }

    /// Record an inbound request from a peer without inferring that the peer
    /// provides the requested service.
    ///
    /// This is for server-side accounting and admission. Outbound RPC clients
    /// should use [`Self::try_acquire`] and [`Self::release`] instead, because a
    /// successful outbound call proves the remote peer provides that service.
    pub fn observe_inbound_request(
        &mut self,
        now_ms: u64,
        peer: PeerId,
        _kind: RequestKind,
        rtt_ms: Option<f64>,
    ) -> Result<PeerChange, AcquireDenied> {
        let (inserted, evicted) =
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

        entry.last_seen_ms = now_ms;
        entry.total_requests = entry.total_requests.saturating_add(1);
        if let Some(rtt_ms) = rtt_ms {
            entry.record_rtt(rtt_ms, self.config.rtt_ema_alpha);
        }

        if let Err(retry_after_ms) = entry.bucket.try_take(
            now_ms,
            self.config.bucket_capacity,
            self.config.bucket_refill_per_sec,
        ) {
            entry.rate_limited_count = entry.rate_limited_count.saturating_add(1);
            return Err(AcquireDenied::RateLimited {
                peer,
                retry_after_ms,
            });
        }

        Ok(PeerChange {
            peer,
            inserted,
            updated: !inserted,
            removed: false,
            evicted,
            dropped: false,
        })
    }

    pub fn observe_invalid_request(&mut self, now_ms: u64, peer: PeerId) -> PeerChange {
        self.apply(now_ms, peer, PeerEvent::InvalidRequest)
    }

    pub fn observe_discovered_service(
        &mut self,
        now_ms: u64,
        peer: PeerId,
        source: DiscoverySource,
        service: &'static str,
        transport_security: TransportSecurity,
    ) -> ServiceObservation {
        let service_was_known = self
            .get(peer)
            .is_some_and(|entry| entry.has_service(service));

        let discovery_change = self.apply(
            now_ms,
            peer,
            PeerEvent::Discovered {
                source,
                transport_security,
            },
        );
        if discovery_change.dropped {
            return ServiceObservation {
                peer,
                peer_inserted: false,
                service_inserted: false,
                evicted: discovery_change.evicted,
                dropped: true,
            };
        }

        let service_change = self.apply(
            now_ms,
            peer,
            PeerEvent::ServiceObserved {
                service,
                transport_security,
            },
        );

        ServiceObservation {
            peer,
            peer_inserted: discovery_change.inserted,
            service_inserted: !service_was_known && !service_change.dropped,
            evicted: discovery_change.evicted.or(service_change.evicted),
            dropped: service_change.dropped,
        }
    }

    pub fn apply(&mut self, now_ms: u64, peer: PeerId, event: PeerEvent) -> PeerChange {
        self.apply_inner(now_ms, peer, event, TombstoneAction::Revive)
    }

    /// Apply a completion-side observation (a successful or failed RPC) to
    /// the registry *without* reviving a tombstoned peer. The
    /// `RpcPermitGuard` finishers call this so that an in-flight RPC
    /// completing after `forget_peer` still credits stats correctly but
    /// doesn't undo the operator's forget — otherwise the subsequent
    /// `release` would no longer purge the entry.
    pub fn apply_completion(
        &mut self,
        now_ms: u64,
        peer: PeerId,
        event: PeerEvent,
    ) -> PeerChange {
        self.apply_inner(now_ms, peer, event, TombstoneAction::Preserve)
    }

    fn apply_inner(
        &mut self,
        now_ms: u64,
        peer: PeerId,
        event: PeerEvent,
        tombstone: TombstoneAction,
    ) -> PeerChange {
        if matches!(event, PeerEvent::Forgotten) {
            // Defer removal while permits are still in flight so the release
            // path doesn't try to decrement counts on a missing entry. The
            // peer is excluded from `get`/`iter`/`with_service` immediately
            // (tombstoned), and the final `release` that drops in_flight to
            // zero purges the entry for real.
            let removed = match self.peers.get_mut(&peer) {
                Some(entry) if entry.in_flight == 0 => {
                    self.peers.remove(&peer);
                    true
                }
                Some(entry) => {
                    entry.tombstoned = true;
                    true
                }
                None => false,
            };
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

        // Apply-side events revive a tombstoned peer (fresh observation
        // overrides operator's forget); completion-side events preserve the
        // tombstone so the subsequent release still purges the entry.
        if matches!(tombstone, TombstoneAction::Revive) {
            entry.tombstoned = false;
        }
        entry.last_seen_ms = now_ms;

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
                let _ = entry.observe_service(service, now_ms, transport_security, max_services);
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
            PeerEvent::InvalidRequest => {
                entry.invalid_request_count = entry.invalid_request_count.saturating_add(1);
            }
            PeerEvent::RateLimited => {
                entry.rate_limited_count = entry.rate_limited_count.saturating_add(1);
            }
            PeerEvent::Forgotten => unreachable!("forgotten events are handled before insert"),
        }

        PeerChange {
            peer,
            inserted,
            updated: !inserted,
            removed: false,
            evicted,
            dropped: false,
        }
    }

    pub fn try_acquire(
        &mut self,
        now_ms: u64,
        peer: PeerId,
        kind: RequestKind,
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

        Ok(Permit::new(peer, kind, now_ms))
    }

    pub fn release(&mut self, now_ms: u64, mut permit: Permit, outcome: Outcome) -> PeerChange {
        permit.disarm();
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
                let _ = entry.observe_service(
                    permit.kind().service,
                    now_ms,
                    entry.transport_security,
                    max_services,
                );
                if let Some(service) = entry.services.get_mut(permit.kind().service) {
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

        // Final-release purge for tombstoned peers: once the last in-flight
        // permit clears, the entry is gone.
        if entry.tombstoned && entry.in_flight == 0 {
            self.peers.remove(&peer);
            return PeerChange {
                peer,
                inserted: false,
                updated: false,
                removed: true,
                evicted: None,
                dropped: false,
            };
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

#[cfg(all(test, feature = "swarm"))]
mod tests {
    use super::*;
    use crate::service::NodeService;

    const NODE: &str = "hellas.swarm.v1.Node";
    const GET_NODE_INFO: RequestKind =
        RequestKind::for_method::<crate::service::methods::GetNodeInfo>();

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
        assert!(entry.has_service_key::<NodeService>());
        assert!(entry.service::<NodeService>().is_some());
    }

    #[test]
    fn observe_discovered_service_reports_new_service_once() {
        let mut registry = PeerRegistry::with_config(config());
        let id = peer(8);

        let first = registry.observe_discovered_service(
            10,
            id,
            DiscoverySource::Mdns,
            NODE,
            TransportSecurity::Untrusted,
        );
        assert!(first.peer_inserted);
        assert!(first.service_inserted);
        assert!(!first.dropped);

        let second = registry.observe_discovered_service(
            20,
            id,
            DiscoverySource::Mdns,
            NODE,
            TransportSecurity::Untrusted,
        );
        assert!(!second.peer_inserted);
        assert!(!second.service_inserted);

        let entry = registry.get(id).expect("peer should exist");
        assert!(entry.has_service(NODE));
        assert_eq!(registry.with_service_key::<NodeService>().count(), 1);
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
            .try_acquire(0, id, GET_NODE_INFO)
            .expect("first request should be admitted");
        let denied = registry
            .try_acquire(1, id, GET_NODE_INFO)
            .expect_err("second request should exceed peer in-flight limit");
        assert_eq!(denied, AcquireDenied::InFlightPeer { peer: id, limit: 1 });

        registry.release(2, permit, Outcome::ok(5.0));
        let permit = registry
            .try_acquire(3, id, GET_NODE_INFO)
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
            .try_acquire(0, id, GET_NODE_INFO)
            .expect("first request should spend the only token");
        registry.release(1, permit, Outcome::ok(5.0));

        let denied = registry
            .try_acquire(2, id, GET_NODE_INFO)
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

        let first = registry.try_acquire(0, id, GET_NODE_INFO).unwrap();
        registry.release(10, first, Outcome::ok(100.0));
        let second = registry.try_acquire(20, id, GET_NODE_INFO).unwrap();
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

    #[test]
    fn inbound_requests_do_not_imply_service_capability() {
        let mut registry = PeerRegistry::with_config(config());
        let id = peer(9);

        registry
            .observe_inbound_request(10, id, GET_NODE_INFO, Some(25.0))
            .expect("inbound request should be recorded");

        let entry = registry.get(id).expect("peer should exist");
        assert_eq!(entry.total_requests, 1);
        assert_eq!(entry.success_count, 0);
        assert_eq!(entry.latency_ms(), Some(25.0));
        assert!(!entry.has_service(NODE));
    }

    #[test]
    fn tracks_invalid_requests() {
        let mut registry = PeerRegistry::with_config(config());
        let id = peer(10);

        registry.observe_invalid_request(10, id);
        registry.observe_invalid_request(20, id);

        let entry = registry.get(id).expect("peer should exist");
        assert_eq!(entry.invalid_request_count, 2);
    }

    #[test]
    fn auth_level_ordering_matches_authority() {
        // Variant declaration order in security.rs is load-bearing — these
        // assertions catch any future reordering that flips the meaning of
        // policy filters like `entry.auth_level >= AuthLevel::Authenticated`.
        assert!(AuthLevel::Authenticated > AuthLevel::Local);
        assert!(AuthLevel::Local > AuthLevel::Trusted);
        assert!(AuthLevel::Trusted > AuthLevel::Untrusted);
    }

    #[test]
    fn forgotten_with_in_flight_defers_until_release() {
        let mut registry = PeerRegistry::with_config(config());
        let id = peer(11);

        let permit = registry.try_acquire(0, id, GET_NODE_INFO).unwrap();
        // Peer is in queries while in flight.
        assert!(registry.get(id).is_some());
        assert_eq!(registry.total_in_flight(), 1);

        // Forget while in flight: hidden from queries, but still alive
        // internally so the release path doesn't double-count.
        let change = registry.apply(5, id, PeerEvent::Forgotten);
        assert!(change.removed, "Forgotten reports removed even when deferred");
        assert!(registry.get(id).is_none(), "tombstoned peer hidden from get");
        assert_eq!(registry.iter().count(), 0, "tombstoned peer hidden from iter");
        assert_eq!(registry.total_in_flight(), 1);

        // Release the permit: now the entry is actually gone.
        let change = registry.release(10, permit, Outcome::ok(5.0));
        assert!(change.removed);
        assert_eq!(registry.total_in_flight(), 0);
    }

    #[test]
    fn forgotten_immediate_when_idle() {
        let mut registry = PeerRegistry::with_config(config());
        let id = peer(12);

        registry.apply(
            0,
            id,
            PeerEvent::Discovered {
                source: DiscoverySource::Manual,
                transport_security: TransportSecurity::Untrusted,
            },
        );

        let change = registry.apply(5, id, PeerEvent::Forgotten);
        assert!(change.removed);
        assert!(registry.get(id).is_none());
    }

    #[test]
    fn rediscovery_revives_tombstoned_peer() {
        let mut registry = PeerRegistry::with_config(config());
        let id = peer(13);

        let permit = registry.try_acquire(0, id, GET_NODE_INFO).unwrap();
        registry.apply(5, id, PeerEvent::Forgotten);
        assert!(registry.get(id).is_none());

        registry.apply(
            10,
            id,
            PeerEvent::Discovered {
                source: DiscoverySource::Mdns,
                transport_security: TransportSecurity::Authenticated,
            },
        );
        // Re-discovery un-tombstones; release doesn't purge a live entry.
        registry.release(15, permit, Outcome::ok(5.0));
        let entry = registry.get(id).expect("peer should be live again");
        assert_eq!(entry.transport_security, TransportSecurity::Authenticated);
    }

    #[test]
    fn service_cap_evicts_lowest_value() {
        let mut registry = PeerRegistry::with_config(PeerRegistryConfig {
            max_services_per_peer: 2,
            ..config()
        });
        let id = peer(14);

        // Three services; the cap is two. The first observed should be
        // evicted (zero successes, oldest last_seen).
        for (i, name) in ["svc.A", "svc.B", "svc.C"].iter().enumerate() {
            registry.apply(
                (i as u64) * 10,
                id,
                PeerEvent::ServiceObserved {
                    service: name,
                    transport_security: TransportSecurity::Untrusted,
                },
            );
        }
        let entry = registry.get(id).expect("peer should exist");
        assert_eq!(entry.services.len(), 2);
        assert!(!entry.has_service("svc.A"), "lowest-value service evicted");
        assert!(entry.has_service("svc.B"));
        assert!(entry.has_service("svc.C"));
    }

    #[test]
    fn eviction_tie_break_uses_peer_id_so_choice_is_deterministic() {
        // With max_peers=2, inserting a third peer must evict one of the
        // existing two. When every other eviction key is identical (same
        // discovery moment, same trust, same security, same services,
        // same success count), the only differentiator is PeerId. The
        // trailing PeerId in eviction_key turns randomized HashMap
        // iteration into a stable, lowest-id-evicts-first rule — repeated
        // runs against the same inputs must always evict the same peer.
        let lower = peer(1);
        let upper = peer(2);

        // Run a small number of trials with fresh registries; without the
        // PeerId tiebreaker, HashMap's iteration order would surface here
        // as a random pick.
        for _ in 0..16 {
            let mut registry = PeerRegistry::with_config(PeerRegistryConfig {
                max_peers: 2,
                ..config()
            });

            registry.apply(
                0,
                lower,
                PeerEvent::Discovered {
                    source: DiscoverySource::Manual,
                    transport_security: TransportSecurity::Untrusted,
                },
            );
            registry.apply(
                0,
                upper,
                PeerEvent::Discovered {
                    source: DiscoverySource::Manual,
                    transport_security: TransportSecurity::Untrusted,
                },
            );

            let third = peer(3);
            let change = registry.apply(
                0,
                third,
                PeerEvent::Discovered {
                    source: DiscoverySource::Manual,
                    transport_security: TransportSecurity::Untrusted,
                },
            );
            assert_eq!(
                change.evicted,
                Some(lower),
                "lowest PeerId should win the eviction tie-break every run"
            );
        }
    }

    #[test]
    fn peer_id_display_alternate_emits_full_hex() {
        let id = peer(0xab);
        let short = format!("{id}");
        let full = format!("{id:#}");
        assert!(short.contains('…'), "default Display truncates");
        assert_eq!(full.len(), 64, "alternate emits 64 hex chars");
        assert!(full.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
