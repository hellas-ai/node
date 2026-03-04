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
    HealthCheck,
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
            known_peers_global_bucket: TokenBucket::new(200.0, 40.0),
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
            RequestKind::HealthCheck => (0.5, false),
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
    if requested_service_alpn.is_empty() {
        return true;
    }
    match requested_service_alpn {
        NODE_SERVICE_ALPN => stats.seen_node_service,
        // In this binary, Node+Execute are published together by the same server process.
        EXECUTE_SERVICE_ALPN => stats.seen_node_service,
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

    fn register_kind(&mut self, kind: RequestKind) {
        match kind {
            RequestKind::HealthCheck | RequestKind::GetKnownPeers => {
                self.seen_node_service = true;
            }
            RequestKind::ExecuteRpc => {}
        }
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

    #[test]
    fn prefers_lower_rtt_peers() {
        let local = endpoint_id(1);
        let a = endpoint_id(2);
        let b = endpoint_id(3);
        let requester = endpoint_id(4);
        let mut tracker = PeerTracker::new(local);

        let _ = tracker.observe_request(
            a,
            Some(Duration::from_millis(20)),
            RequestKind::GetKnownPeers,
        );
        let _ = tracker.observe_request(
            b,
            Some(Duration::from_millis(300)),
            RequestKind::GetKnownPeers,
        );
        let _ = tracker.observe_request(
            requester,
            Some(Duration::from_millis(40)),
            RequestKind::GetKnownPeers,
        );

        let peers = tracker.ranked_known_peers(requester, "", 64);
        assert_eq!(peers.first().copied(), Some(a));
    }

    #[test]
    fn rate_limits_get_known_peers_bursts() {
        let local = endpoint_id(1);
        let peer = endpoint_id(2);
        let mut tracker = PeerTracker::new(local);

        let mut denied = 0usize;
        for _ in 0..40 {
            let admission = tracker.observe_request(
                peer,
                Some(Duration::from_millis(30)),
                RequestKind::GetKnownPeers,
            );
            if !admission.allow {
                denied += 1;
            }
        }

        assert!(denied > 0, "burst traffic should be throttled");
    }

    #[test]
    fn service_filter_only_returns_matching_activity() {
        let local = endpoint_id(1);
        let execute_peer = endpoint_id(2);
        let node_only_peer = endpoint_id(3);
        let requester = endpoint_id(4);
        let mut tracker = PeerTracker::new(local);

        let _ = tracker.observe_request(execute_peer, None, RequestKind::ExecuteRpc);
        let _ = tracker.observe_request(node_only_peer, None, RequestKind::HealthCheck);
        let _ = tracker.observe_request(requester, None, RequestKind::GetKnownPeers);

        let execute_only = tracker.ranked_known_peers(requester, EXECUTE_SERVICE_ALPN, 64);
        assert_eq!(execute_only, vec![node_only_peer]);
    }

    #[test]
    fn execute_rpc_alone_does_not_mark_service_capability() {
        let local = endpoint_id(1);
        let execute_caller = endpoint_id(2);
        let requester = endpoint_id(3);
        let mut tracker = PeerTracker::new(local);

        let _ = tracker.observe_request(execute_caller, None, RequestKind::ExecuteRpc);
        let _ = tracker.observe_request(requester, None, RequestKind::GetKnownPeers);

        let execute_candidates = tracker.ranked_known_peers(requester, EXECUTE_SERVICE_ALPN, 64);
        assert!(
            execute_candidates.is_empty(),
            "execute callers are not assumed to provide execute service"
        );
    }
}
