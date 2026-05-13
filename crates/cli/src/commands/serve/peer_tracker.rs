use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hellas_rpc::peers::{
    DiscoverySource, PeerEntry, PeerEvent, PeerId, PeerRegistry, PeerRegistryConfig,
    RequestKind as RegistryRequestKind, ServiceKey, TransportSecurity,
};
use hellas_rpc::service::{
    CourtesyService, ExecuteService, NodeService as NodeRpcService, OpaqueService, SymbolicService,
};
use tonic_iroh_transport::iroh::EndpointId;

pub(super) const NODE_SERVICE_ALPN: &str = "/hellas.swarm.v1.Node/1.0";
pub(super) const EXECUTE_SERVICE_ALPN: &str = "/hellas.v1.Execute/1.0";
pub(super) const MAX_SERVICE_ALPN_LEN: usize = 128;

const LEGACY_NODE_SERVICE_ALPN: &str = "/hellas.Node/1.0";
const LEGACY_EXECUTE_SERVICE_ALPN: &str = "/hellas.Execute/1.0";
const SYMBOLIC_SERVICE_ALPN: &str = "/hellas.symbolic.v1.Symbolic/1.0";
const OPAQUE_SERVICE_ALPN: &str = "/hellas.opaque.v1.Opaque/1.0";
const COURTESY_SERVICE_ALPN: &str = "/hellas.courtesy.v1.Courtesy/1.0";

const NODE_SERVICE_NAME: &str = <NodeRpcService as ServiceKey>::NAME;
const EXECUTE_SERVICE_NAME: &str = <ExecuteService as ServiceKey>::NAME;
const SYMBOLIC_SERVICE_NAME: &str = <SymbolicService as ServiceKey>::NAME;
const OPAQUE_SERVICE_NAME: &str = <OpaqueService as ServiceKey>::NAME;
const COURTESY_SERVICE_NAME: &str = <CourtesyService as ServiceKey>::NAME;

const MAX_TRACKED_PEERS: usize = 2048;
const MAX_KNOWN_PEERS_RESPONSE: usize = 64;
const STALE_PEER_AFTER: Duration = Duration::from_secs(15 * 60);
const DEFAULT_LATENCY_SCORE: i64 = 450;

/// Request classes with different admission costs.
#[derive(Clone, Copy, Debug)]
pub(super) enum RequestKind {
    GetNodeInfo,
    GetKnownPeers,
    ExecuteRpc,
}

impl RequestKind {
    const fn registry_kind(self) -> RegistryRequestKind {
        match self {
            Self::GetNodeInfo => RegistryRequestKind::new(NODE_SERVICE_NAME, "GetNodeInfo"),
            Self::GetKnownPeers => RegistryRequestKind::new(NODE_SERVICE_NAME, "GetKnownPeers"),
            Self::ExecuteRpc => RegistryRequestKind::new(EXECUTE_SERVICE_NAME, "ExecuteRpc"),
        }
    }

    const fn admission_policy(self) -> (f32, bool) {
        match self {
            Self::GetNodeInfo => (0.5, false),
            Self::ExecuteRpc => (1.0, false),
            Self::GetKnownPeers => (4.0, true),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RequestAdmission {
    pub allow: bool,
    pub disclosure_limit: usize,
}

/// Server-side wrapper around the shared peer registry.
///
/// Inbound requests are accounting signals, not service-capability proof. A
/// browser can call `GetKnownPeers`, but that does not mean the browser is a
/// node service provider. Service facts only enter through `mark_service`.
pub(super) struct PeerTracker {
    local_id: EndpointId,
    registry: PeerRegistry,
    known_peers_global_bucket: TokenBucket,
}

impl PeerTracker {
    pub(super) fn new(local_id: EndpointId) -> Self {
        Self {
            local_id,
            registry: PeerRegistry::with_config(PeerRegistryConfig {
                max_peers: MAX_TRACKED_PEERS,
                bucket_capacity: 24.0,
                bucket_refill_per_sec: 2.0,
                ..PeerRegistryConfig::default()
            }),
            // Bound global CPU/alloc pressure from many concurrent GetKnownPeers calls.
            known_peers_global_bucket: TokenBucket::new(16.0, 4.0),
        }
    }

    pub(super) fn observe_request(
        &mut self,
        peer_id: EndpointId,
        observed_rtt: Option<Duration>,
        kind: RequestKind,
    ) -> RequestAdmission {
        let now = now_ms();
        let bucket_now = Instant::now();
        let registry_peer_id = peer_id_from_endpoint(peer_id);
        let (cost, throttleable) = kind.admission_policy();
        let rtt_ms = observed_rtt.map(duration_ms);

        let per_peer_ok = self
            .registry
            .observe_inbound_request(now, registry_peer_id, kind.registry_kind(), cost, rtt_ms)
            .is_ok();

        let disclosure_limit = self
            .registry
            .get(registry_peer_id)
            .map_or(8, |peer| disclosure_limit(peer, now));

        let global_ok = if matches!(kind, RequestKind::GetKnownPeers) {
            self.known_peers_global_bucket.take(1.0, bucket_now)
        } else {
            true
        };
        if throttleable && !global_ok {
            self.registry
                .apply(now, registry_peer_id, PeerEvent::RateLimited);
        }

        let allow = if throttleable {
            per_peer_ok && global_ok
        } else {
            true
        };

        RequestAdmission {
            allow,
            disclosure_limit,
        }
    }

    /// Mark a peer as a provider for a specific service discovered by transport.
    pub(super) fn mark_service(&mut self, peer_id: EndpointId, service: &'static str) {
        self.registry.observe_discovered_service(
            now_ms(),
            peer_id_from_endpoint(peer_id),
            DiscoverySource::Transport("discovery"),
            service,
            TransportSecurity::Untrusted,
        );
    }

    pub(super) fn mark_invalid_request(&mut self, peer_id: EndpointId) {
        self.registry
            .observe_invalid_request(now_ms(), peer_id_from_endpoint(peer_id));
    }

    pub(super) fn ranked_known_peers(
        &self,
        requester: EndpointId,
        requested_service_alpn: &str,
        disclosure_limit: usize,
    ) -> Vec<EndpointId> {
        let now = now_ms();
        let response_limit = disclosure_limit.min(MAX_KNOWN_PEERS_RESPONSE);
        let mut candidates: Vec<(EndpointId, i64)> = self
            .registry
            .iter()
            .filter_map(|peer| {
                let peer_id = endpoint_from_peer_id(peer.id)?;
                if peer_id == self.local_id || peer_id == requester {
                    return None;
                }
                let age_ms = now.saturating_sub(peer.last_seen_ms);
                if age_ms > duration_ms_u64(STALE_PEER_AFTER) {
                    return None;
                }
                if !matches_service_filter(peer, requested_service_alpn) {
                    return None;
                }
                let score = recommendation_score(peer, now);
                if score <= 0 {
                    return None;
                }
                Some((peer_id, score))
            })
            .collect();

        candidates.sort_by(|(_, left_score), (_, right_score)| right_score.cmp(left_score));
        candidates
            .into_iter()
            .take(response_limit)
            .map(|(peer_id, _)| peer_id)
            .collect()
    }
}

fn matches_service_filter(peer: &PeerEntry, requested_service_alpn: &str) -> bool {
    if requested_service_alpn.is_empty() {
        return !peer.services.is_empty();
    }
    service_for_filter(requested_service_alpn).map_or_else(
        || peer.has_service_name(requested_service_alpn),
        |service| peer.has_service(service),
    )
}

fn service_for_filter(requested_service_alpn: &str) -> Option<&'static str> {
    match requested_service_alpn {
        NODE_SERVICE_ALPN | LEGACY_NODE_SERVICE_ALPN | NODE_SERVICE_NAME => Some(NODE_SERVICE_NAME),
        EXECUTE_SERVICE_ALPN | LEGACY_EXECUTE_SERVICE_ALPN | EXECUTE_SERVICE_NAME => {
            Some(EXECUTE_SERVICE_NAME)
        }
        SYMBOLIC_SERVICE_ALPN | SYMBOLIC_SERVICE_NAME => Some(SYMBOLIC_SERVICE_NAME),
        OPAQUE_SERVICE_ALPN | OPAQUE_SERVICE_NAME => Some(OPAQUE_SERVICE_NAME),
        COURTESY_SERVICE_ALPN | COURTESY_SERVICE_NAME => Some(COURTESY_SERVICE_NAME),
        _ => None,
    }
}

fn disclosure_limit(peer: &PeerEntry, now_ms: u64) -> usize {
    let score = recommendation_score(peer, now_ms);
    if score < 600 {
        8
    } else if score < 1600 {
        24
    } else {
        MAX_KNOWN_PEERS_RESPONSE
    }
}

fn recommendation_score(peer: &PeerEntry, now_ms: u64) -> i64 {
    let age_ms = now_ms.saturating_sub(peer.last_seen_ms);
    let age_secs = age_ms as f64 / 1000.0;
    let recency_score =
        ((1.0 - (age_secs / STALE_PEER_AFTER.as_secs_f64())).clamp(0.0, 1.0) * 1000.0) as i64;

    let latency_score = peer
        .rtt_ema_ms
        .map(latency_score)
        .unwrap_or(DEFAULT_LATENCY_SCORE);

    let lifespan_secs = now_ms.saturating_sub(peer.first_seen_ms) as f64 / 1000.0;
    let stability_score = ((lifespan_secs / 60.0).clamp(0.0, 20.0) * 50.0) as i64;

    let request_score = (peer.total_requests.min(60) as i64) * 8;
    let behavior_penalty = bounded_penalty(peer.invalid_request_count, 350)
        + bounded_penalty(peer.rate_limited_count, 110);

    (latency_score * 4) + (recency_score * 3) + (stability_score * 2) + request_score
        - behavior_penalty
}

fn latency_score(rtt_ms: f64) -> i64 {
    if rtt_ms <= 5.0 {
        return 1000;
    }
    if rtt_ms >= 2_500.0 {
        return 0;
    }
    (((2_500.0 - rtt_ms) / 2_495.0) * 1000.0) as i64
}

fn bounded_penalty(count: u64, weight: i64) -> i64 {
    count.saturating_mul(weight as u64).min(i64::MAX as u64) as i64
}

fn peer_id_from_endpoint(peer_id: EndpointId) -> PeerId {
    PeerId::from(*peer_id.as_bytes())
}

fn endpoint_from_peer_id(peer_id: PeerId) -> Option<EndpointId> {
    EndpointId::from_bytes(peer_id.as_bytes()).ok()
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

fn duration_ms_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec,
            last_refill: Instant::now(),
        }
    }

    fn take(&mut self, cost: f64, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last_refill = now;
        }
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic_iroh_transport::iroh::SecretKey;

    fn endpoint_id(byte: u8) -> EndpointId {
        SecretKey::from([byte; 32]).public()
    }

    /// Two real servers publish via DHT. Three browser sessions open the
    /// explorer, each health-checking the node and asking for peers. Only the
    /// two real servers should ever appear in responses — browsers and CLI
    /// clients must not leak.
    #[test]
    fn mixed_servers_browsers_and_cli_clients() {
        let node = endpoint_id(0);
        let server_a = endpoint_id(1);
        let server_b = endpoint_id(2);
        let mut tracker = PeerTracker::new(node);

        tracker.mark_service(server_a, NODE_SERVICE_NAME);
        let _ = tracker.observe_request(
            server_a,
            Some(Duration::from_millis(20)),
            RequestKind::GetKnownPeers,
        );
        tracker.mark_service(server_b, NODE_SERVICE_NAME);
        let _ = tracker.observe_request(
            server_b,
            Some(Duration::from_millis(80)),
            RequestKind::GetKnownPeers,
        );

        let browsers: Vec<_> = (10..13).map(endpoint_id).collect();
        for &browser in &browsers {
            let _ = tracker.observe_request(browser, None, RequestKind::GetNodeInfo);
            let admission = tracker.observe_request(browser, None, RequestKind::GetKnownPeers);
            assert!(admission.allow);

            let peers = tracker.ranked_known_peers(browser, NODE_SERVICE_ALPN, 64);
            assert_eq!(peers.len(), 2, "browser should see exactly the 2 servers");
            assert!(peers.contains(&server_a));
            assert!(peers.contains(&server_b));
        }

        let cli = endpoint_id(20);
        let _ = tracker.observe_request(
            cli,
            Some(Duration::from_millis(5)),
            RequestKind::GetNodeInfo,
        );
        let _ = tracker.observe_request(
            cli,
            Some(Duration::from_millis(5)),
            RequestKind::GetKnownPeers,
        );

        let peers = tracker.ranked_known_peers(cli, NODE_SERVICE_ALPN, 64);
        assert_eq!(peers.len(), 2, "CLI should also only see the 2 servers");
        assert_eq!(peers[0], server_a);
    }

    /// A server starts with no known peers. Browsers connect and ask for peers
    /// repeatedly, getting rate-limited. Then a real server appears via DHT.
    /// Subsequent browser queries should find it despite the earlier rate
    /// limiting.
    #[test]
    fn late_server_discovery_after_browser_spam() {
        let node = endpoint_id(0);
        let mut tracker = PeerTracker::new(node);

        let browser = endpoint_id(10);
        let mut denied = 0;
        for _ in 0..20 {
            let _ = tracker.observe_request(browser, None, RequestKind::GetNodeInfo);
            let admission = tracker.observe_request(browser, None, RequestKind::GetKnownPeers);
            if !admission.allow {
                denied += 1;
            }
            let peers = tracker.ranked_known_peers(browser, NODE_SERVICE_ALPN, 64);
            assert!(peers.is_empty(), "no servers registered yet");
        }
        assert!(denied > 0, "browser should hit rate limit");

        let server = endpoint_id(1);
        tracker.mark_service(server, NODE_SERVICE_NAME);
        let _ = tracker.observe_request(
            server,
            Some(Duration::from_millis(30)),
            RequestKind::GetNodeInfo,
        );

        let browser2 = endpoint_id(11);
        let _ = tracker.observe_request(browser2, None, RequestKind::GetNodeInfo);
        let admission = tracker.observe_request(browser2, None, RequestKind::GetKnownPeers);
        if admission.allow {
            let peers = tracker.ranked_known_peers(browser2, NODE_SERVICE_ALPN, 64);
            assert_eq!(peers, vec![server]);
        }
        let peers = tracker.ranked_known_peers(browser2, NODE_SERVICE_ALPN, 64);
        assert_eq!(
            peers,
            vec![server],
            "server should be visible once admitted"
        );
    }

    /// Simulates a small network: node X knows about servers A, B, C. Server A
    /// sends many invalid requests and gets penalised. Server C has very high
    /// latency. A new peer asks for known peers and should get B first.
    #[test]
    fn ranking_with_penalties_and_latency() {
        let node = endpoint_id(0);
        let a = endpoint_id(1);
        let b = endpoint_id(2);
        let c = endpoint_id(3);
        let mut tracker = PeerTracker::new(node);

        for &s in &[a, b, c] {
            tracker.mark_service(s, NODE_SERVICE_NAME);
        }
        let _ =
            tracker.observe_request(a, Some(Duration::from_millis(40)), RequestKind::GetNodeInfo);
        let _ =
            tracker.observe_request(b, Some(Duration::from_millis(10)), RequestKind::GetNodeInfo);
        let _ = tracker.observe_request(
            c,
            Some(Duration::from_millis(2000)),
            RequestKind::GetNodeInfo,
        );

        for _ in 0..15 {
            tracker.mark_invalid_request(a);
        }

        let requester = endpoint_id(10);
        let _ = tracker.observe_request(requester, None, RequestKind::GetKnownPeers);

        let peers = tracker.ranked_known_peers(requester, NODE_SERVICE_ALPN, 64);
        assert!(!peers.is_empty());
        assert_eq!(
            peers[0], b,
            "well-behaved low-latency server should rank first"
        );
        assert!(!peers.contains(&a) || peers.last() == Some(&a));
    }

    /// Disclosure limit is based on recommendation score. A peer that has been
    /// penalised gets a smaller window than a well-behaved peer.
    #[test]
    fn penalised_peer_gets_smaller_disclosure_limit() {
        let node = endpoint_id(0);
        let mut tracker = PeerTracker::new(node);

        for i in 1..=30u8 {
            let s = endpoint_id(i);
            tracker.mark_service(s, NODE_SERVICE_NAME);
            let _ = tracker.observe_request(
                s,
                Some(Duration::from_millis(50)),
                RequestKind::GetNodeInfo,
            );
        }

        let good_peer = endpoint_id(100);
        let good_admission = tracker.observe_request(
            good_peer,
            Some(Duration::from_millis(20)),
            RequestKind::GetKnownPeers,
        );
        assert!(good_admission.allow);

        let bad_peer = endpoint_id(101);
        let _ = tracker.observe_request(
            bad_peer,
            Some(Duration::from_millis(20)),
            RequestKind::GetNodeInfo,
        );
        for _ in 0..20 {
            tracker.mark_invalid_request(bad_peer);
        }
        let bad_admission = tracker.observe_request(
            bad_peer,
            Some(Duration::from_millis(20)),
            RequestKind::GetKnownPeers,
        );

        assert!(
            bad_admission.disclosure_limit < good_admission.disclosure_limit,
            "penalised peer (limit={}) should get fewer peers than well-behaved (limit={})",
            bad_admission.disclosure_limit,
            good_admission.disclosure_limit,
        );
    }

    /// Two servers know about each other. Server A calls get_known_peers on the
    /// node repeatedly over time. The node should consistently return server B
    /// without duplication or degradation.
    #[test]
    fn server_to_server_peer_exchange_over_time() {
        let node = endpoint_id(0);
        let server_a = endpoint_id(1);
        let server_b = endpoint_id(2);
        let mut tracker = PeerTracker::new(node);

        tracker.mark_service(server_a, NODE_SERVICE_NAME);
        tracker.mark_service(server_b, NODE_SERVICE_NAME);
        let _ = tracker.observe_request(
            server_a,
            Some(Duration::from_millis(25)),
            RequestKind::GetNodeInfo,
        );
        let _ = tracker.observe_request(
            server_b,
            Some(Duration::from_millis(30)),
            RequestKind::GetNodeInfo,
        );

        for round in 0..10 {
            let admission = tracker.observe_request(
                server_a,
                Some(Duration::from_millis(25)),
                RequestKind::GetKnownPeers,
            );
            if admission.allow {
                let peers = tracker.ranked_known_peers(
                    server_a,
                    NODE_SERVICE_ALPN,
                    admission.disclosure_limit,
                );
                assert_eq!(
                    peers,
                    vec![server_b],
                    "round {round}: server A should consistently see server B"
                );
            }
        }
    }

    #[test]
    fn service_filters_use_specific_service_facts() {
        let node = endpoint_id(0);
        let node_only = endpoint_id(1);
        let executor = endpoint_id(2);
        let custom = endpoint_id(3);
        let mut tracker = PeerTracker::new(node);

        tracker.mark_service(node_only, NODE_SERVICE_NAME);
        tracker.mark_service(executor, NODE_SERVICE_NAME);
        tracker.mark_service(executor, EXECUTE_SERVICE_NAME);
        tracker.mark_service(custom, "example.Custom");

        let requester = endpoint_id(10);
        let all_service_peers = tracker.ranked_known_peers(requester, "", 64);
        assert!(all_service_peers.contains(&node_only));
        assert!(all_service_peers.contains(&executor));
        assert!(all_service_peers.contains(&custom));

        let node_peers = tracker.ranked_known_peers(requester, NODE_SERVICE_ALPN, 64);
        assert!(node_peers.contains(&node_only));
        assert!(node_peers.contains(&executor));

        let execute_peers = tracker.ranked_known_peers(requester, EXECUTE_SERVICE_ALPN, 64);
        assert_eq!(execute_peers, vec![executor]);

        let custom_peers = tracker.ranked_known_peers(requester, "example.Custom", 64);
        assert_eq!(custom_peers, vec![custom]);
    }
}
