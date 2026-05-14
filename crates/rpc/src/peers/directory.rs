use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::admission::{RequestKind, TokenBucket};
use super::{
    AuthLevel, DiscoverySource, PeerEntry, PeerId, PeerManager, PeerManagerError,
    PeerRegistryConfig, RpcMethod, RpcService, ServiceObservation, TransportSecurity,
};

const DEFAULT_MAX_TRACKED_PEERS: usize = 2048;
const DEFAULT_MAX_KNOWN_PEERS_RESPONSE: usize = 64;
const DEFAULT_STALE_PEER_AFTER_MS: u64 = 15 * 60 * 1000;
const DEFAULT_LATENCY_SCORE: i64 = 450;
const DEFAULT_MAX_SERVICE_FILTER_LEN: usize = 128;
const DEFAULT_GLOBAL_BUCKET_CAPACITY: f64 = 16.0;
const DEFAULT_GLOBAL_BUCKET_REFILL_PER_SEC: f64 = 4.0;

/// Alias accepted by peer-disclosure service filters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceAlias {
    pub query: &'static str,
    pub service: &'static str,
}

impl ServiceAlias {
    pub const fn new(query: &'static str, service: &'static str) -> Self {
        Self { query, service }
    }
}

fn default_service_aliases() -> Vec<ServiceAlias> {
    // Derive the alias table from the generated `KNOWN_SERVICES` list so the
    // directory's view of "what services exist" stays in sync with codegen.
    // Each service contributes two aliases: one keyed by ALPN and one keyed
    // by FQN, both pointing at the FQN as the canonical service name.
    let mut aliases = Vec::with_capacity(crate::services::KNOWN_SERVICES.len() * 2);
    for entry in crate::services::KNOWN_SERVICES {
        aliases.push(ServiceAlias::new(entry.alpn, entry.name));
        aliases.push(ServiceAlias::new(entry.name, entry.name));
    }
    aliases
}

/// Policy and bounds for serving peer-disclosure APIs.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerDirectoryConfig {
    pub registry: PeerRegistryConfig,
    pub max_known_peers_response: usize,
    pub stale_peer_after_ms: u64,
    pub default_latency_score: i64,
    pub max_service_filter_len: usize,
    pub global_known_peers_bucket_capacity: f64,
    pub global_known_peers_bucket_refill_per_sec: f64,
    pub service_aliases: Vec<ServiceAlias>,
    /// Minimum `AuthLevel` a peer must hold to appear in
    /// [`PeerDirectory::ranked_known_peers`]. Default is `Untrusted` (no
    /// filtering); set higher to gate disclosure on transport-authenticated
    /// or operator-trusted peers only.
    pub min_disclosed_auth_level: AuthLevel,
}

impl Default for PeerDirectoryConfig {
    fn default() -> Self {
        Self {
            registry: PeerRegistryConfig {
                max_peers: DEFAULT_MAX_TRACKED_PEERS,
                bucket_capacity: 24.0,
                bucket_refill_per_sec: 2.0,
                ..PeerRegistryConfig::default()
            },
            max_known_peers_response: DEFAULT_MAX_KNOWN_PEERS_RESPONSE,
            stale_peer_after_ms: DEFAULT_STALE_PEER_AFTER_MS,
            default_latency_score: DEFAULT_LATENCY_SCORE,
            max_service_filter_len: DEFAULT_MAX_SERVICE_FILTER_LEN,
            global_known_peers_bucket_capacity: DEFAULT_GLOBAL_BUCKET_CAPACITY,
            global_known_peers_bucket_refill_per_sec: DEFAULT_GLOBAL_BUCKET_REFILL_PER_SEC,
            service_aliases: default_service_aliases(),
            min_disclosed_auth_level: AuthLevel::Untrusted,
        }
    }
}

impl PeerDirectoryConfig {
    fn normalized(mut self) -> Self {
        if !self.global_known_peers_bucket_capacity.is_finite()
            || self.global_known_peers_bucket_capacity < 0.0
        {
            self.global_known_peers_bucket_capacity = 0.0;
        }
        if !self.global_known_peers_bucket_refill_per_sec.is_finite()
            || self.global_known_peers_bucket_refill_per_sec < 0.0
        {
            self.global_known_peers_bucket_refill_per_sec = 0.0;
        }
        self.registry = self.registry.normalized();
        self
    }

    /// Combinations that would make the directory behave nonsensically.
    /// Bubbles up the per-peer registry's reasons plus the directory's
    /// own global-disclosure-bucket check, so a config check at startup
    /// reports every violation at once.
    pub fn validate(&self) -> Vec<String> {
        let mut reasons = self.registry.validate();
        if self.global_known_peers_bucket_capacity > 0.0
            && self.global_known_peers_bucket_capacity < 1.0
        {
            reasons.push(format!(
                "global_known_peers_bucket_capacity {:.3} is in (0, 1): the \
                 shared disclosure bucket can never hold a full token, so \
                 every rate-limited disclosure-style request would be \
                 rejected. Set it >= 1.0 or 0.0.",
                self.global_known_peers_bucket_capacity
            ));
        }
        reasons
    }
}

/// Server-side request accounting policy.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct InboundRequestPolicy {
    pub kind: RequestKind,
    pub reject_when_limited: bool,
}

impl InboundRequestPolicy {
    pub const fn account_only(kind: RequestKind) -> Self {
        Self {
            kind,
            reject_when_limited: false,
        }
    }

    pub const fn rate_limited(kind: RequestKind) -> Self {
        Self {
            kind,
            reject_when_limited: true,
        }
    }

    pub const fn account_method<M: RpcMethod>() -> Self {
        Self::account_only(RequestKind::for_method::<M>())
    }

    pub const fn rate_limited_method<M: RpcMethod>() -> Self {
        Self::rate_limited(RequestKind::for_method::<M>())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboundAdmission {
    pub allow: bool,
    pub disclosure_limit: usize,
}

/// Shared peer directory for server-side peer exchange and recommendation.
///
/// This is the reusable replacement for ad-hoc server peer trackers. It builds
/// on `PeerManager` for all state changes, adds one global disclosure limiter,
/// and keeps ranking/filtering policy in the shared RPC crate.
#[derive(Clone, Debug)]
pub struct PeerDirectory {
    local_peer: PeerId,
    manager: PeerManager,
    config: Arc<PeerDirectoryConfig>,
    known_peers_global_bucket: Arc<Mutex<TokenBucket>>,
}

impl PeerDirectory {
    pub fn new(local_peer: PeerId) -> Self {
        Self::with_config(local_peer, PeerDirectoryConfig::default())
    }

    pub fn with_config(local_peer: PeerId, config: PeerDirectoryConfig) -> Self {
        let config = config.normalized();
        let reasons = config.validate();
        assert!(
            reasons.is_empty(),
            "PeerDirectoryConfig is invalid:\n  - {}",
            reasons.join("\n  - "),
        );
        let manager = PeerManager::with_config(config.registry);
        let bucket = TokenBucket::new(manager.now_ms(), config.global_known_peers_bucket_capacity);
        Self {
            local_peer,
            manager,
            known_peers_global_bucket: Arc::new(Mutex::new(bucket)),
            config: Arc::new(config),
        }
    }

    pub const fn local_peer(&self) -> PeerId {
        self.local_peer
    }

    pub fn manager(&self) -> PeerManager {
        self.manager.clone()
    }

    pub fn max_service_filter_len(&self) -> usize {
        self.config.max_service_filter_len
    }

    pub fn observe_inbound_request(
        &self,
        peer: PeerId,
        observed_rtt_ms: Option<f64>,
        policy: InboundRequestPolicy,
    ) -> Result<InboundAdmission, PeerManagerError> {
        // Stats first — every inbound request bumps total_requests and the
        // RTT EMA, regardless of whether the policy will reject.
        self.manager.observe_inbound_request(peer, observed_rtt_ms)?;

        let now = self.manager.now_ms();
        let disclosure_limit = self.manager.with_registry(|registry| {
            registry
                .get(peer)
                .map_or(8, |entry| disclosure_limit(entry, now, self.config.as_ref()))
        })?;

        if !policy.reject_when_limited {
            // Account-only methods don't touch the per-peer bucket: that
            // bucket exists to gate disclosure-style methods, and letting
            // ordinary calls drain it would lock those out for free.
            return Ok(InboundAdmission {
                allow: true,
                disclosure_limit,
            });
        }

        // Rate-limited path: spend a per-peer token first. If that fails,
        // the global bucket is irrelevant — refuse.
        let per_peer_ok = self.manager.try_admit_inbound(peer).is_ok();
        if !per_peer_ok {
            let _ = self.manager.observe_rate_limited(peer);
            return Ok(InboundAdmission {
                allow: false,
                disclosure_limit,
            });
        }

        // Per-peer admitted — now check the shared disclosure bucket. We
        // only spend a global token if the per-peer check passed so an
        // abusive peer past its own limit can't collateral-damage other
        // peers by draining the shared bucket.
        let global_ok = self
            .known_peers_global_bucket
            .lock()
            .map_err(|_| PeerManagerError::Unavailable)?
            .try_take(
                now,
                self.config.global_known_peers_bucket_capacity,
                self.config.global_known_peers_bucket_refill_per_sec,
            )
            .is_ok();
        if !global_ok {
            let _ = self.manager.observe_rate_limited(peer);
        }

        Ok(InboundAdmission {
            allow: global_ok,
            disclosure_limit,
        })
    }

    pub fn observe_invalid_request(&self, peer: PeerId) -> Result<(), PeerManagerError> {
        self.manager.observe_invalid_request(peer).map(|_| ())
    }

    pub fn observe_discovered_service_name(
        &self,
        peer: PeerId,
        source: DiscoverySource,
        service: &'static str,
        transport_security: TransportSecurity,
    ) -> Result<ServiceObservation, PeerManagerError> {
        self.manager
            .observe_discovered_service_name(peer, source, service, transport_security)
    }

    pub fn observe_discovered_service<S: RpcService>(
        &self,
        peer: PeerId,
        source: DiscoverySource,
        transport_security: TransportSecurity,
    ) -> Result<ServiceObservation, PeerManagerError> {
        self.manager
            .observe_discovered_service::<S>(peer, source, transport_security)
    }

    pub fn ranked_known_peers(
        &self,
        requester: PeerId,
        requested_service_filter: &str,
        disclosure_limit: usize,
    ) -> Result<Vec<PeerId>, PeerManagerError> {
        let now = self.manager.now_ms();
        let response_limit = disclosure_limit.min(self.config.max_known_peers_response);
        let config = self.config.as_ref();
        self.manager.with_registry(|registry| {
            let mut candidates: Vec<(PeerId, i64)> = registry
                .iter()
                .filter_map(|peer| {
                    if peer.id == self.local_peer || peer.id == requester {
                        return None;
                    }
                    if !peer.auth_level.allows_at_least(config.min_disclosed_auth_level) {
                        return None;
                    }
                    let age_ms = now.saturating_sub(peer.last_seen_ms);
                    if age_ms > config.stale_peer_after_ms {
                        return None;
                    }
                    if !matches_service_filter(peer, requested_service_filter, config) {
                        return None;
                    }
                    let score = recommendation_score(peer, now, config);
                    if score <= 0 {
                        return None;
                    }
                    Some((peer.id, score))
                })
                .collect();

            // Higher score first; PeerId ascending tie-breaks. The PeerId
            // disambiguator is load-bearing — without it, equal-score peers
            // came back in HashMap iteration order, leaking randomness into
            // a public response that callers (and tests) rely on being
            // deterministic.
            candidates.sort_by(|(left_id, left_score), (right_id, right_score)| {
                right_score
                    .cmp(left_score)
                    .then_with(|| left_id.cmp(right_id))
            });
            candidates
                .into_iter()
                .take(response_limit)
                .map(|(peer_id, _)| peer_id)
                .collect()
        })
    }
}

fn matches_service_filter(
    peer: &PeerEntry,
    requested_service_filter: &str,
    config: &PeerDirectoryConfig,
) -> bool {
    if requested_service_filter.is_empty() {
        return !peer.services.is_empty();
    }
    service_for_filter(requested_service_filter, config).map_or_else(
        || peer.has_service_name(requested_service_filter),
        |service| peer.has_service(service),
    )
}

fn service_for_filter(
    requested_service_filter: &str,
    config: &PeerDirectoryConfig,
) -> Option<&'static str> {
    config
        .service_aliases
        .iter()
        .find(|alias| alias.query == requested_service_filter)
        .map(|alias| alias.service)
}

fn disclosure_limit(peer: &PeerEntry, now_ms: u64, config: &PeerDirectoryConfig) -> usize {
    let score = recommendation_score(peer, now_ms, config);
    if score < 600 {
        8
    } else if score < 1600 {
        24
    } else {
        config.max_known_peers_response
    }
}

fn recommendation_score(peer: &PeerEntry, now_ms: u64, config: &PeerDirectoryConfig) -> i64 {
    let age_ms = now_ms.saturating_sub(peer.last_seen_ms);
    let age_secs = age_ms as f64 / 1000.0;
    let stale_after_secs = Duration::from_millis(config.stale_peer_after_ms).as_secs_f64();
    let recency_score = ((1.0 - (age_secs / stale_after_secs)).clamp(0.0, 1.0) * 1000.0) as i64;

    let latency_score = peer
        .rtt_ema_ms
        .map(latency_score)
        .unwrap_or(config.default_latency_score);

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

// Directory behaviour is meaningful only when there are concrete services to
// observe, so the tests assume both swarm (for Node/get_known_peers) and
// execute (for cross-service filtering). With either off, the tests compile
// out — the impl above still works at any feature subset.
#[cfg(all(test, feature = "swarm", feature = "execute"))]
mod tests {
    use super::*;
    use crate::services::execute::Execute as ExecuteService;
    use crate::services::node::Node as NodeService;
    use hellas_wire::ServiceMarker;

    const GET_NODE_INFO: RequestKind =
        RequestKind::for_method::<crate::services::node::GetNodeInfo>();
    const GET_KNOWN_PEERS: RequestKind =
        RequestKind::for_method::<crate::services::node::GetKnownPeers>();

    // Test-local aliases for the well-known ALPNs.
    const NODE_SERVICE_ALPN: &str = <NodeService as ServiceMarker>::ALPN;
    const EXECUTE_SERVICE_ALPN: &str = <ExecuteService as ServiceMarker>::ALPN;

    fn peer(byte: u8) -> PeerId {
        PeerId::from([byte; 32])
    }

    fn duration_ms(duration: Duration) -> f64 {
        duration.as_secs_f64() * 1000.0
    }

    fn directory(local_peer: PeerId) -> PeerDirectory {
        PeerDirectory::with_config(
            local_peer,
            PeerDirectoryConfig {
                registry: PeerRegistryConfig {
                    max_peers: 256,
                    bucket_capacity: 24.0,
                    bucket_refill_per_sec: 2.0,
                    ..PeerRegistryConfig::default()
                },
                ..PeerDirectoryConfig::default()
            },
        )
    }

    fn mark_node(directory: &PeerDirectory, peer: PeerId) {
        directory
            .observe_discovered_service::<NodeService>(
                peer,
                DiscoverySource::Transport("discovery"),
                TransportSecurity::Untrusted,
            )
            .expect("service should be recorded");
    }

    #[test]
    fn mixed_servers_browsers_and_cli_clients() {
        let node = peer(0);
        let server_a = peer(1);
        let server_b = peer(2);
        let directory = directory(node);

        mark_node(&directory, server_a);
        let _ = directory.observe_inbound_request(
            server_a,
            Some(duration_ms(Duration::from_millis(20))),
            InboundRequestPolicy::rate_limited(GET_KNOWN_PEERS),
        );
        mark_node(&directory, server_b);
        let _ = directory.observe_inbound_request(
            server_b,
            Some(duration_ms(Duration::from_millis(80))),
            InboundRequestPolicy::rate_limited(GET_KNOWN_PEERS),
        );

        let browsers: Vec<_> = (10..13).map(peer).collect();
        for &browser in &browsers {
            let _ = directory.observe_inbound_request(
                browser,
                None,
                InboundRequestPolicy::account_only(GET_NODE_INFO),
            );
            let admission = directory
                .observe_inbound_request(
                    browser,
                    None,
                    InboundRequestPolicy::rate_limited(GET_KNOWN_PEERS),
                )
                .expect("request should be accounted");
            assert!(admission.allow);

            let peers = directory
                .ranked_known_peers(browser, NODE_SERVICE_ALPN, 64)
                .expect("known peers should be ranked");
            assert_eq!(peers.len(), 2, "browser should see exactly the 2 servers");
            assert!(peers.contains(&server_a));
            assert!(peers.contains(&server_b));
        }

        let cli = peer(20);
        let _ = directory.observe_inbound_request(
            cli,
            Some(duration_ms(Duration::from_millis(5))),
            InboundRequestPolicy::account_only(GET_NODE_INFO),
        );
        let _ = directory.observe_inbound_request(
            cli,
            Some(duration_ms(Duration::from_millis(5))),
            InboundRequestPolicy::rate_limited(GET_KNOWN_PEERS),
        );

        let peers = directory
            .ranked_known_peers(cli, NODE_SERVICE_ALPN, 64)
            .expect("known peers should be ranked");
        assert_eq!(peers.len(), 2, "CLI should also only see the 2 servers");
        assert_eq!(peers[0], server_a);
    }

    #[test]
    fn late_server_discovery_after_browser_spam() {
        let node = peer(0);
        let directory = directory(node);

        let browser = peer(10);
        let mut denied = 0;
        for _ in 0..20 {
            let _ = directory.observe_inbound_request(
                browser,
                None,
                InboundRequestPolicy::account_only(GET_NODE_INFO),
            );
            let admission = directory
                .observe_inbound_request(
                    browser,
                    None,
                    InboundRequestPolicy::rate_limited(GET_KNOWN_PEERS),
                )
                .expect("request should be accounted");
            if !admission.allow {
                denied += 1;
            }
            let peers = directory
                .ranked_known_peers(browser, NODE_SERVICE_ALPN, 64)
                .expect("known peers should be ranked");
            assert!(peers.is_empty(), "no servers registered yet");
        }
        assert!(denied > 0, "browser should hit rate limit");

        let server = peer(1);
        mark_node(&directory, server);
        let _ = directory.observe_inbound_request(
            server,
            Some(duration_ms(Duration::from_millis(30))),
            InboundRequestPolicy::account_only(GET_NODE_INFO),
        );

        let browser2 = peer(11);
        let _ = directory.observe_inbound_request(
            browser2,
            None,
            InboundRequestPolicy::account_only(GET_NODE_INFO),
        );
        let admission = directory
            .observe_inbound_request(
                browser2,
                None,
                InboundRequestPolicy::rate_limited(GET_KNOWN_PEERS),
            )
            .expect("request should be accounted");
        if admission.allow {
            let peers = directory
                .ranked_known_peers(browser2, NODE_SERVICE_ALPN, 64)
                .expect("known peers should be ranked");
            assert_eq!(peers, vec![server]);
        }
        let peers = directory
            .ranked_known_peers(browser2, NODE_SERVICE_ALPN, 64)
            .expect("known peers should be ranked");
        assert_eq!(
            peers,
            vec![server],
            "server should be visible once admitted"
        );
    }

    #[test]
    fn ranking_with_penalties_and_latency() {
        let node = peer(0);
        let a = peer(1);
        let b = peer(2);
        let c = peer(3);
        let directory = directory(node);

        for &server in &[a, b, c] {
            mark_node(&directory, server);
        }
        let _ = directory.observe_inbound_request(
            a,
            Some(duration_ms(Duration::from_millis(40))),
            InboundRequestPolicy::account_only(GET_NODE_INFO),
        );
        let _ = directory.observe_inbound_request(
            b,
            Some(duration_ms(Duration::from_millis(10))),
            InboundRequestPolicy::account_only(GET_NODE_INFO),
        );
        let _ = directory.observe_inbound_request(
            c,
            Some(duration_ms(Duration::from_millis(2000))),
            InboundRequestPolicy::account_only(GET_NODE_INFO),
        );

        for _ in 0..15 {
            directory
                .observe_invalid_request(a)
                .expect("invalid request should be recorded");
        }

        let requester = peer(10);
        let _ = directory.observe_inbound_request(
            requester,
            None,
            InboundRequestPolicy::rate_limited(GET_KNOWN_PEERS),
        );

        let peers = directory
            .ranked_known_peers(requester, NODE_SERVICE_ALPN, 64)
            .expect("known peers should be ranked");
        assert!(!peers.is_empty());
        assert_eq!(
            peers[0], b,
            "well-behaved low-latency server should rank first"
        );
        assert!(!peers.contains(&a) || peers.last() == Some(&a));
    }

    #[test]
    fn penalised_peer_gets_smaller_disclosure_limit() {
        let node = peer(0);
        let directory = directory(node);

        for i in 1..=30u8 {
            let server = peer(i);
            mark_node(&directory, server);
            let _ = directory.observe_inbound_request(
                server,
                Some(duration_ms(Duration::from_millis(50))),
                InboundRequestPolicy::account_only(GET_NODE_INFO),
            );
        }

        let good_peer = peer(100);
        let good_admission = directory
            .observe_inbound_request(
                good_peer,
                Some(duration_ms(Duration::from_millis(20))),
                InboundRequestPolicy::rate_limited(GET_KNOWN_PEERS),
            )
            .expect("request should be accounted");
        assert!(good_admission.allow);

        let bad_peer = peer(101);
        let _ = directory.observe_inbound_request(
            bad_peer,
            Some(duration_ms(Duration::from_millis(20))),
            InboundRequestPolicy::account_only(GET_NODE_INFO),
        );
        for _ in 0..20 {
            directory
                .observe_invalid_request(bad_peer)
                .expect("invalid request should be recorded");
        }
        let bad_admission = directory
            .observe_inbound_request(
                bad_peer,
                Some(duration_ms(Duration::from_millis(20))),
                InboundRequestPolicy::rate_limited(GET_KNOWN_PEERS),
            )
            .expect("request should be accounted");

        assert!(
            bad_admission.disclosure_limit < good_admission.disclosure_limit,
            "penalised peer (limit={}) should get fewer peers than well-behaved (limit={})",
            bad_admission.disclosure_limit,
            good_admission.disclosure_limit,
        );
    }

    #[test]
    fn server_to_server_peer_exchange_over_time() {
        let node = peer(0);
        let server_a = peer(1);
        let server_b = peer(2);
        let directory = directory(node);

        mark_node(&directory, server_a);
        mark_node(&directory, server_b);
        let _ = directory.observe_inbound_request(
            server_a,
            Some(duration_ms(Duration::from_millis(25))),
            InboundRequestPolicy::account_only(GET_NODE_INFO),
        );
        let _ = directory.observe_inbound_request(
            server_b,
            Some(duration_ms(Duration::from_millis(30))),
            InboundRequestPolicy::account_only(GET_NODE_INFO),
        );

        for round in 0..10 {
            let admission = directory
                .observe_inbound_request(
                    server_a,
                    Some(duration_ms(Duration::from_millis(25))),
                    InboundRequestPolicy::rate_limited(GET_KNOWN_PEERS),
                )
                .expect("request should be accounted");
            if admission.allow {
                let peers = directory
                    .ranked_known_peers(server_a, NODE_SERVICE_ALPN, admission.disclosure_limit)
                    .expect("known peers should be ranked");
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
        let node = peer(0);
        let node_only = peer(1);
        let executor = peer(2);
        let custom = peer(3);
        let directory = directory(node);

        mark_node(&directory, node_only);
        mark_node(&directory, executor);
        directory
            .observe_discovered_service::<ExecuteService>(
                executor,
                DiscoverySource::Transport("discovery"),
                TransportSecurity::Untrusted,
            )
            .expect("service should be recorded");
        directory
            .observe_discovered_service_name(
                custom,
                DiscoverySource::Transport("discovery"),
                "example.Custom",
                TransportSecurity::Untrusted,
            )
            .expect("service should be recorded");

        let requester = peer(10);
        let all_service_peers = directory
            .ranked_known_peers(requester, "", 64)
            .expect("known peers should be ranked");
        assert!(all_service_peers.contains(&node_only));
        assert!(all_service_peers.contains(&executor));
        assert!(all_service_peers.contains(&custom));

        let node_peers = directory
            .ranked_known_peers(requester, NODE_SERVICE_ALPN, 64)
            .expect("known peers should be ranked");
        assert!(node_peers.contains(&node_only));
        assert!(node_peers.contains(&executor));

        let execute_peers = directory
            .ranked_known_peers(requester, EXECUTE_SERVICE_ALPN, 64)
            .expect("known peers should be ranked");
        assert_eq!(execute_peers, vec![executor]);

        let custom_peers = directory
            .ranked_known_peers(requester, "example.Custom", 64)
            .expect("known peers should be ranked");
        assert_eq!(custom_peers, vec![custom]);
    }

    #[test]
    fn ranked_known_peers_tie_breaks_on_peer_id_for_determinism() {
        // Equal recommendation scores must not surface in random
        // HashMap-iteration order. The sort uses PeerId ascending as a
        // tiebreaker so the public response is deterministic — repeated
        // calls against the same state return the same vector, even when
        // the registry contains many peers with identical scores.
        let local = peer(0);
        let requester = peer(99);

        // Build identical peers (same service, same security, no traffic),
        // so recommendation_score collapses to a tie across them.
        let mut ids = vec![peer(5), peer(2), peer(7), peer(1), peer(3)];

        // Run the sequence repeatedly with the peers inserted in different
        // orders; the response order must remain identical.
        let mut expected: Option<Vec<PeerId>> = None;
        let id_count = ids.len();
        for trial in 0..8 {
            let directory = directory(local);
            // Rotate insertion order each trial so any HashMap bias would
            // show up as different observed output.
            ids.rotate_left(trial % id_count);

            for id in &ids {
                mark_node(&directory, *id);
            }

            let peers = directory
                .ranked_known_peers(requester, NODE_SERVICE_ALPN, 64)
                .expect("known peers should be ranked");

            match &expected {
                None => expected = Some(peers),
                Some(prev) => assert_eq!(
                    &peers, prev,
                    "ranked_known_peers must be deterministic across insertion orders"
                ),
            }
        }

        let result = expected.expect("at least one trial ran");
        // PeerId ascending: peer(1) < peer(2) < peer(3) < peer(5) < peer(7).
        assert_eq!(result, vec![peer(1), peer(2), peer(3), peer(5), peer(7)]);
    }

    #[test]
    #[should_panic(expected = "PeerDirectoryConfig is invalid")]
    fn with_config_panics_on_unsatisfiable_global_bucket() {
        // Sub-unit global disclosure bucket with positive refill — the
        // shared rate-limited bucket can never hold a full token, so
        // every disclosure-style request would be rejected.
        let _ = PeerDirectory::with_config(
            peer(0),
            PeerDirectoryConfig {
                global_known_peers_bucket_capacity: 0.5,
                global_known_peers_bucket_refill_per_sec: 1.0,
                ..PeerDirectoryConfig::default()
            },
        );
    }

    #[test]
    fn account_only_methods_do_not_drain_rate_limit_bucket() {
        // `account_only` requests bypass the per-peer rate-limit bucket
        // entirely. Only `rate_limited` policies spend a token, so a flood
        // of `GetNodeInfo` (account-only) can't starve admission for
        // `GetKnownPeers` (rate-limited).
        let directory = PeerDirectory::with_config(
            peer(0),
            PeerDirectoryConfig {
                registry: PeerRegistryConfig {
                    max_peers: 8,
                    // Capacity 1 makes the regression unmistakable: a single
                    // account_only call under the old behaviour would drain
                    // the bucket and the next rate_limited call would be
                    // rejected.
                    bucket_capacity: 1.0,
                    bucket_refill_per_sec: 0.0,
                    ..PeerRegistryConfig::default()
                },
                ..PeerDirectoryConfig::default()
            },
        );

        let caller = peer(1);

        // Hammer with account_only requests — these should NOT touch the
        // bucket.
        for _ in 0..32 {
            let admission = directory
                .observe_inbound_request(
                    caller,
                    None,
                    InboundRequestPolicy::account_only(GET_NODE_INFO),
                )
                .expect("account_only never errors");
            assert!(admission.allow);
        }

        // The first rate_limited call must still be admitted — the bucket
        // is intact because nothing has spent it yet.
        let admission = directory
            .observe_inbound_request(
                caller,
                None,
                InboundRequestPolicy::rate_limited(GET_KNOWN_PEERS),
            )
            .expect("rate_limited returns Ok with allow=false on overflow");
        assert!(admission.allow, "rate_limited call must succeed after only account_only traffic");

        // A second rate_limited call should be rejected — the bucket only
        // held one token and we just spent it.
        let admission = directory
            .observe_inbound_request(
                caller,
                None,
                InboundRequestPolicy::rate_limited(GET_KNOWN_PEERS),
            )
            .expect("rate_limited returns Ok with allow=false on overflow");
        assert!(!admission.allow, "drained bucket must reject the next rate_limited call");
    }
}
