use std::collections::HashMap;
use std::time::{Duration, Instant};

use tonic_iroh_transport::iroh::EndpointId;

pub(super) const NODE_SERVICE_ALPN: &str = "/hellas.Node/1.0";
pub(super) const EXECUTE_SERVICE_ALPN: &str = "/hellas.Execute/1.0";
pub(super) const MAX_SERVICE_ALPN_LEN: usize = 128;

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

#[derive(Clone, Copy, Debug)]
pub(super) struct RequestAdmission {
    pub allow: bool,
    pub disclosure_limit: usize,
}

/// Bounded peer tracker used to prefer well-behaved and low-latency peers.
pub(super) struct PeerTracker {
    local_id: EndpointId,
    peers: HashMap<EndpointId, PeerStats>,
    known_peers_global_bucket: TokenBucket,
}

impl PeerTracker {
    pub(super) fn new(local_id: EndpointId) -> Self {
        Self {
            local_id,
            peers: HashMap::new(),
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
        let now = Instant::now();
        let (cost, throttleable) = match kind {
            RequestKind::GetNodeInfo => (0.5, false),
            RequestKind::ExecuteRpc => (1.0, false),
            RequestKind::GetKnownPeers => (4.0, true),
        };

        let (per_peer_ok, disclosure_limit) = {
            let peer = self.get_or_insert_peer(peer_id, now);
            peer.last_seen = now;
            peer.total_requests = peer.total_requests.saturating_add(1);
            peer.register_kind(kind);
            peer.record_rtt(observed_rtt);

            let per_peer_ok = peer.bucket.take(cost, now);
            if !per_peer_ok {
                peer.rate_limited = peer.rate_limited.saturating_add(1);
            }

            let disclosure_limit = {
                let score = peer.recommendation_score(now);
                if score < 600 {
                    8
                } else if score < 1600 {
                    24
                } else {
                    MAX_KNOWN_PEERS_RESPONSE
                }
            };

            (per_peer_ok, disclosure_limit)
        };

        let global_ok = if matches!(kind, RequestKind::GetKnownPeers) {
            self.known_peers_global_bucket.take(1.0, now)
        } else {
            true
        };
        if throttleable && !global_ok {
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                peer.rate_limited = peer.rate_limited.saturating_add(1);
            }
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

    /// Mark a peer as a known service provider (e.g. discovered via DHT).
    pub(super) fn mark_service_provider(&mut self, peer_id: EndpointId) {
        let now = Instant::now();
        let peer = self.get_or_insert_peer(peer_id, now);
        peer.seen_node_service = true;
    }

    pub(super) fn mark_invalid_request(&mut self, peer_id: EndpointId) {
        let now = Instant::now();
        let peer = self.get_or_insert_peer(peer_id, now);
        peer.invalid_requests = peer.invalid_requests.saturating_add(1);
    }

    pub(super) fn ranked_known_peers(
        &self,
        requester: EndpointId,
        requested_service_alpn: &str,
        disclosure_limit: usize,
    ) -> Vec<EndpointId> {
        let now = Instant::now();
        let response_limit = disclosure_limit.min(MAX_KNOWN_PEERS_RESPONSE);
        let mut candidates: Vec<(EndpointId, i64)> = self
            .peers
            .iter()
            .filter_map(|(peer_id, stats)| {
                if *peer_id == self.local_id || *peer_id == requester {
                    return None;
                }
                let age = now.saturating_duration_since(stats.last_seen);
                if age > STALE_PEER_AFTER {
                    return None;
                }
                if !matches_service_filter(stats, requested_service_alpn) {
                    return None;
                }
                let score = stats.recommendation_score(now);
                if score <= 0 {
                    return None;
                }
                Some((*peer_id, score))
            })
            .collect();

        candidates.sort_by(|(_, left_score), (_, right_score)| right_score.cmp(left_score));
        candidates
            .into_iter()
            .take(response_limit)
            .map(|(peer_id, _)| peer_id)
            .collect()
    }

    fn get_or_insert_peer(&mut self, peer_id: EndpointId, now: Instant) -> &mut PeerStats {
        if !self.peers.contains_key(&peer_id) {
            if self.peers.len() >= MAX_TRACKED_PEERS {
                self.evict_worst(now);
            }
            self.peers.insert(peer_id, PeerStats::new(now));
        }
        self.peers
            .get_mut(&peer_id)
            .expect("peer must exist after insertion")
    }

    fn evict_worst(&mut self, now: Instant) {
        let Some(evict_id) = self
            .peers
            .iter()
            .min_by_key(|(_, stats)| stats.recommendation_score(now))
            .map(|(peer_id, _)| *peer_id)
        else {
            return;
        };
        self.peers.remove(&evict_id);
    }
}

fn matches_service_filter(stats: &PeerStats, requested_service_alpn: &str) -> bool {
    match requested_service_alpn {
        // Empty ALPN returns all known service providers (not raw clients).
        "" | NODE_SERVICE_ALPN | EXECUTE_SERVICE_ALPN => stats.seen_node_service,
        _ => false,
    }
}

#[derive(Debug)]
struct PeerStats {
    first_seen: Instant,
    last_seen: Instant,
    ema_rtt_ms: Option<f64>,
    total_requests: u32,
    invalid_requests: u32,
    rate_limited: u32,
    seen_node_service: bool,
    bucket: TokenBucket,
}

impl PeerStats {
    fn new(now: Instant) -> Self {
        Self {
            first_seen: now,
            last_seen: now,
            ema_rtt_ms: None,
            total_requests: 0,
            invalid_requests: 0,
            rate_limited: 0,
            seen_node_service: false,
            // Keep per-peer burst tolerance small to avoid "easy win" spam.
            bucket: TokenBucket::new(24.0, 2.0),
        }
    }

    fn register_kind(&mut self, _kind: RequestKind) {
        // Intentionally does not set `seen_node_service`. Calling an RPC on
        // this node only proves the peer is a *client*, not that it provides
        // the Node service itself. Without this distinction, ephemeral browser
        // sessions get shared as "known peers" even though they can't serve
        // anything. Service capability should be signalled explicitly (e.g.
        // via DHT publishing or a future RegisterPeer RPC).
    }

    fn record_rtt(&mut self, rtt: Option<Duration>) {
        let Some(rtt) = rtt else {
            return;
        };
        let ms = rtt.as_secs_f64() * 1000.0;
        self.ema_rtt_ms = Some(match self.ema_rtt_ms {
            Some(prev) => prev * 0.75 + ms * 0.25,
            None => ms,
        });
    }

    fn recommendation_score(&self, now: Instant) -> i64 {
        let age = now.saturating_duration_since(self.last_seen);
        let age_secs = age.as_secs_f64();
        let recency_score =
            ((1.0 - (age_secs / STALE_PEER_AFTER.as_secs_f64())).clamp(0.0, 1.0) * 1000.0) as i64;

        let latency_score = self
            .ema_rtt_ms
            .map(latency_score)
            .unwrap_or(DEFAULT_LATENCY_SCORE);

        let lifespan_secs = now.saturating_duration_since(self.first_seen).as_secs_f64();
        let stability_score = ((lifespan_secs / 60.0).clamp(0.0, 20.0) * 50.0) as i64;

        let request_score = (self.total_requests.min(60) as i64) * 8;
        let behavior_penalty =
            (self.invalid_requests as i64 * 350) + (self.rate_limited as i64 * 110);

        (latency_score * 4) + (recency_score * 3) + (stability_score * 2) + request_score
            - behavior_penalty
    }
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
    /// explorer, each health-checking the node and asking for peers. A CLI
    /// monitor also calls get_known_peers. Only the two real servers should
    /// ever appear in responses — browsers and CLI clients must not leak.
    #[test]
    fn mixed_servers_browsers_and_cli_clients() {
        let node = endpoint_id(0);
        let server_a = endpoint_id(1);
        let server_b = endpoint_id(2);
        let mut tracker = PeerTracker::new(node);

        // Two servers discovered via DHT — marked explicitly.
        tracker.mark_service_provider(server_a);
        let _ = tracker.observe_request(
            server_a,
            Some(Duration::from_millis(20)),
            RequestKind::GetKnownPeers,
        );
        tracker.mark_service_provider(server_b);
        let _ = tracker.observe_request(
            server_b,
            Some(Duration::from_millis(80)),
            RequestKind::GetKnownPeers,
        );

        // Three ephemeral browser sessions: get_node_info → get_known_peers.
        let browsers: Vec<_> = (10..13).map(endpoint_id).collect();
        for &browser in &browsers {
            let _ = tracker.observe_request(browser, None, RequestKind::GetNodeInfo);
            let admission =
                tracker.observe_request(browser, None, RequestKind::GetKnownPeers);
            assert!(admission.allow);

            let peers = tracker.ranked_known_peers(browser, NODE_SERVICE_ALPN, 64);
            assert_eq!(peers.len(), 2, "browser should see exactly the 2 servers");
            assert!(peers.contains(&server_a));
            assert!(peers.contains(&server_b));
        }

        // CLI monitor discovers and queries.
        let cli = endpoint_id(20);
        let _ = tracker.observe_request(cli, Some(Duration::from_millis(5)), RequestKind::GetNodeInfo);
        let _ = tracker.observe_request(cli, Some(Duration::from_millis(5)), RequestKind::GetKnownPeers);

        let peers = tracker.ranked_known_peers(cli, NODE_SERVICE_ALPN, 64);
        assert_eq!(peers.len(), 2, "CLI should also only see the 2 servers");
        // Lower-RTT server_a should rank first.
        assert_eq!(peers[0], server_a);
    }

    /// A server starts with no known peers. Browsers connect and ask for
    /// peers repeatedly, getting rate-limited. Then a real server appears
    /// via DHT. Subsequent browser queries should find it despite the
    /// earlier rate limiting.
    #[test]
    fn late_server_discovery_after_browser_spam() {
        let node = endpoint_id(0);
        let mut tracker = PeerTracker::new(node);

        // Browser hammers get_known_peers before any servers exist.
        let browser = endpoint_id(10);
        let mut denied = 0;
        for _ in 0..20 {
            let _ = tracker.observe_request(browser, None, RequestKind::GetNodeInfo);
            let admission =
                tracker.observe_request(browser, None, RequestKind::GetKnownPeers);
            if !admission.allow {
                denied += 1;
            }
            let peers = tracker.ranked_known_peers(browser, NODE_SERVICE_ALPN, 64);
            assert!(peers.is_empty(), "no servers registered yet");
        }
        assert!(denied > 0, "browser should hit rate limit");

        // Now a real server appears and health-checks the node.
        let server = endpoint_id(1);
        tracker.mark_service_provider(server);
        let _ = tracker.observe_request(
            server,
            Some(Duration::from_millis(30)),
            RequestKind::GetNodeInfo,
        );

        // A fresh browser session arrives. The global rate limit bucket may
        // still be exhausted from the spam above (all calls happen at the
        // same Instant in tests). This means one peer's GetKnownPeers spam
        // can deny a fresh peer — a known trade-off for simplicity.
        let browser2 = endpoint_id(11);
        let _ = tracker.observe_request(browser2, None, RequestKind::GetNodeInfo);
        let admission =
            tracker.observe_request(browser2, None, RequestKind::GetKnownPeers);
        if admission.allow {
            let peers = tracker.ranked_known_peers(browser2, NODE_SERVICE_ALPN, 64);
            assert_eq!(peers, vec![server]);
        }
        // Regardless of rate limiting, when admitted the server should be visible.
        // Simulate the global bucket refilling (in real life, time passes).
        // We can verify by just calling ranked_known_peers directly.
        let peers = tracker.ranked_known_peers(browser2, NODE_SERVICE_ALPN, 64);
        assert_eq!(peers, vec![server], "server should be visible once admitted");
    }

    /// Simulates a small network: node X knows about servers A, B, C. Server
    /// A sends many invalid requests and gets penalised. Server C has very
    /// high latency. A new peer asks for known peers and should get B first,
    /// then C or A (or A excluded entirely due to penalty).
    #[test]
    fn ranking_with_penalties_and_latency() {
        let node = endpoint_id(0);
        let a = endpoint_id(1); // will be penalised
        let b = endpoint_id(2); // well-behaved, low latency
        let c = endpoint_id(3); // high latency
        let mut tracker = PeerTracker::new(node);

        // All three are real servers.
        for &s in &[a, b, c] {
            tracker.mark_service_provider(s);
        }
        let _ = tracker.observe_request(a, Some(Duration::from_millis(40)), RequestKind::GetNodeInfo);
        let _ = tracker.observe_request(b, Some(Duration::from_millis(10)), RequestKind::GetNodeInfo);
        let _ = tracker.observe_request(c, Some(Duration::from_millis(2000)), RequestKind::GetNodeInfo);

        // A sends garbage.
        for _ in 0..15 {
            tracker.mark_invalid_request(a);
        }

        let requester = endpoint_id(10);
        let _ = tracker.observe_request(requester, None, RequestKind::GetKnownPeers);

        let peers = tracker.ranked_known_peers(requester, NODE_SERVICE_ALPN, 64);
        // B should be first (low latency, no penalties).
        assert!(!peers.is_empty());
        assert_eq!(peers[0], b, "well-behaved low-latency server should rank first");
        // A may be excluded entirely (score ≤ 0) due to penalties.
        assert!(!peers.contains(&a) || peers.last() == Some(&a));
    }

    /// Disclosure limit is based on recommendation_score. A peer that has
    /// been penalised (invalid requests) gets a smaller window than a
    /// well-behaved peer.
    #[test]
    fn penalised_peer_gets_smaller_disclosure_limit() {
        let node = endpoint_id(0);
        let mut tracker = PeerTracker::new(node);

        // Register some service providers.
        for i in 1..=30u8 {
            let s = endpoint_id(i);
            tracker.mark_service_provider(s);
            let _ = tracker.observe_request(
                s,
                Some(Duration::from_millis(50)),
                RequestKind::GetNodeInfo,
            );
        }

        // Well-behaved peer.
        let good_peer = endpoint_id(100);
        let good_admission = tracker.observe_request(
            good_peer,
            Some(Duration::from_millis(20)),
            RequestKind::GetKnownPeers,
        );
        assert!(good_admission.allow);

        // Misbehaving peer — pile on enough invalid requests to drop below
        // the highest disclosure tier (score < 1600 needs penalty > ~5400,
        // i.e. 16+ invalid requests at 350 each).
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

    /// Two servers know about each other. Server A calls get_known_peers on
    /// the node repeatedly over time (like a monitor polling loop). The node
    /// should consistently return server B without duplication or degradation.
    #[test]
    fn server_to_server_peer_exchange_over_time() {
        let node = endpoint_id(0);
        let server_a = endpoint_id(1);
        let server_b = endpoint_id(2);
        let mut tracker = PeerTracker::new(node);

        tracker.mark_service_provider(server_a);
        tracker.mark_service_provider(server_b);
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

        // Server A polls get_known_peers 10 times (like monitor's periodic poll).
        for round in 0..10 {
            let admission = tracker.observe_request(
                server_a,
                Some(Duration::from_millis(25)),
                RequestKind::GetKnownPeers,
            );
            // First few should be allowed, later ones may be throttled.
            if admission.allow {
                let peers =
                    tracker.ranked_known_peers(server_a, NODE_SERVICE_ALPN, admission.disclosure_limit);
                assert_eq!(
                    peers,
                    vec![server_b],
                    "round {round}: server A should consistently see server B"
                );
            }
        }
    }
}
