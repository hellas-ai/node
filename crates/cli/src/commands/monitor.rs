use crate::commands::CliResult;

use anyhow::Context;
use futures::StreamExt;
use hellas_pb::swarm::node_client::NodeClient;
use hellas_pb::swarm::{GetKnownPeersRequest, GetNodeInfoRequest, GetNodeInfoResponse};
use hellas_rpc::GRPC_MESSAGE_LIMIT;
use hellas_rpc::discovery::DiscoveryEndpoint;
use hellas_rpc::peers::{
    DiscoverySource, Outcome, PeerEvent, PeerId, PeerRegistry, Permit,
    RequestKind as PeerRequestKind, TransportSecurity,
};
use hellas_rpc::service::{ExecuteService, NodeService};
use std::collections::HashSet;
use std::future;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};
use tonic_iroh_transport::iroh::{EndpointId, SecretKey};
use tonic_iroh_transport::swarm::{
    DhtBackend, MdnsBackend, Peer, PeerExchangeBackend, ServiceRegistry,
};
use tonic_iroh_transport::{ConnectionPool, PoolOptions};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const RPC_TIMEOUT: Duration = Duration::from_secs(3);
const NODE_SERVICE_NAME: &str = "hellas.swarm.v1.Node";
const EXECUTE_SERVICE_NAME: &str = "hellas.v1.Execute";

struct PeerInterrogationOutcome {
    node_info: GetNodeInfoResponse,
    known_peers: Vec<EndpointId>,
    invalid_known_peers: usize,
    known_peers_error: Option<String>,
}

struct DiscoveryEventContext<'a> {
    node_pool: &'a ConnectionPool,
    peer_registry: &'a Arc<Mutex<PeerRegistry>>,
    interrogate: bool,
    interrogated: &'a mut HashSet<EndpointId>,
    interrogations: &'a mut JoinSet<(EndpointId, anyhow::Result<PeerInterrogationOutcome>)>,
}

pub async fn run(
    timeout_secs: Option<u64>,
    interrogate: bool,
    secret_key: SecretKey,
) -> CliResult<()> {
    let bound = DiscoveryEndpoint::bind(Some(secret_key)).await?;
    let endpoint = bound.endpoint;
    let mdns = bound.bindings.mdns;
    let shared_dht = bound.bindings.dht;

    let peer_exchange = PeerExchangeBackend::new();
    let mut registry = ServiceRegistry::new(&endpoint);
    registry.with_pool_options(PoolOptions {
        connect_timeout: CONNECT_TIMEOUT,
        ..PoolOptions::default()
    });
    registry.add(MdnsBackend::new(mdns));
    registry.add(DhtBackend::with_dht(&endpoint, shared_dht));
    registry.add(peer_exchange.clone());
    let node_pool = registry.pool::<NodeService>();

    let mut node_discovery = Box::pin(registry.discover::<NodeService>());
    let mut execute_discovery = Box::pin(registry.discover::<ExecuteService>());

    let peer_registry = Arc::new(Mutex::new(PeerRegistry::default()));
    let mut interrogations = JoinSet::new();
    let mut interrogated = HashSet::new();

    let mut interrogation_ok = 0usize;
    let mut interrogation_failed = 0usize;
    let mut hinted_peers = 0usize;
    let mut node_done = false;
    let mut execute_done = false;

    println!(
        "event=monitor-start local_peer={} interrogate={} timeout_secs={}",
        endpoint.id(),
        interrogate,
        timeout_secs
            .map(|secs| secs.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!("event=monitor-ready message=\"press Ctrl+C to stop\"");

    let monitor_timeout = async {
        if let Some(secs) = timeout_secs {
            tokio::time::sleep(Duration::from_secs(secs)).await;
        } else {
            future::pending::<()>().await;
        }
    };
    tokio::pin!(monitor_timeout);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("event=monitor-stop reason=signal");
                break;
            }
            _ = &mut monitor_timeout => {
                println!("event=monitor-stop reason=timeout");
                break;
            }
            peer = node_discovery.next(), if !node_done => {
                match peer {
                    Some(Ok(peer)) => {
                        handle_discovery_event(
                            "node",
                            NODE_SERVICE_NAME,
                            &peer,
                            DiscoveryEventContext {
                                node_pool: &node_pool,
                                peer_registry: &peer_registry,
                                interrogate,
                                interrogated: &mut interrogated,
                                interrogations: &mut interrogations,
                            },
                        );
                    }
                    Some(Err(err)) => {
                        println!("event=discovery-error service=node error=\"{err}\"");
                    }
                    None => {
                        node_done = true;
                        println!("event=discovery-complete service=node");
                    }
                }
            }
            peer = execute_discovery.next(), if !execute_done => {
                match peer {
                    Some(Ok(peer)) => {
                        handle_discovery_event(
                            "execute",
                            EXECUTE_SERVICE_NAME,
                            &peer,
                            DiscoveryEventContext {
                                node_pool: &node_pool,
                                peer_registry: &peer_registry,
                                interrogate,
                                interrogated: &mut interrogated,
                                interrogations: &mut interrogations,
                            },
                        );
                    }
                    Some(Err(err)) => {
                        println!("event=discovery-error service=execute error=\"{err}\"");
                    }
                    None => {
                        execute_done = true;
                        println!("event=discovery-complete service=execute");
                    }
                }
            }
            joined = interrogations.join_next(), if !interrogations.is_empty() => {
                match joined {
                    Some(Ok((peer_id, Ok(outcome)))) => {
                        interrogation_ok += 1;
                        let info = &outcome.node_info;
                        println!(
                            "event=node-info peer={} reported_node_id={} version={} build={} os={} uptime_seconds={} graffiti={}",
                            peer_id,
                            info.node_id,
                            info.version,
                            info.build,
                            info.os,
                            info.uptime_seconds,
                            String::from_utf8_lossy(&info.graffiti),
                        );

                        if let Some(err) = outcome.known_peers_error.as_deref() {
                            println!("event=known-peers-error peer={} error=\"{}\"", peer_id, err);
                        }

                        if outcome.invalid_known_peers > 0 {
                            println!(
                                "event=known-peers-invalid peer={} invalid_count={}",
                                peer_id,
                                outcome.invalid_known_peers
                            );
                        }

                        println!(
                            "event=known-peers peer={} count={}",
                            peer_id,
                            outcome.known_peers.len()
                        );

                        if !outcome.known_peers.is_empty() {
                            hinted_peers += outcome.known_peers.len();
                            if let Ok(mut registry) = peer_registry.lock() {
                                let now = now_ms();
                                for hinted in &outcome.known_peers {
                                    registry.apply(
                                        now,
                                        peer_id_from_endpoint(*hinted),
                                        PeerEvent::Discovered {
                                            source: DiscoverySource::PeerExchange,
                                            transport_security: TransportSecurity::Untrusted,
                                        },
                                    );
                                }
                            }
                            for hinted in &outcome.known_peers {
                                println!("event=peer-hint from={} peer={}", peer_id, hinted);
                            }
                            peer_exchange.ingest_peers(outcome.known_peers.iter().copied());
                        }
                    }
                    Some(Ok((peer_id, Err(err)))) => {
                        interrogation_failed += 1;
                        println!("event=interrogate-error peer={} error=\"{err:#}\"", peer_id);
                    }
                    Some(Err(err)) => {
                        interrogation_failed += 1;
                        println!("event=interrogate-error error=\"task join failed: {err}\"");
                    }
                    None => {}
                }
            }
        }

        if node_done && execute_done && interrogations.is_empty() {
            println!("event=monitor-stop reason=discovery-exhausted");
            break;
        }
    }

    let (unique_peers, node_service_peers, execute_service_peers) =
        peer_registry.lock().map_or((0, 0, 0), |registry| {
            (
                registry.len(),
                registry.with_service(NODE_SERVICE_NAME).count(),
                registry.with_service(EXECUTE_SERVICE_NAME).count(),
            )
        });

    println!(
        "event=monitor-summary unique_peers={} node_service_peers={} execute_service_peers={} interrogated={} interrogation_ok={} interrogation_failed={} hinted_peers={}",
        unique_peers,
        node_service_peers,
        execute_service_peers,
        interrogated.len(),
        interrogation_ok,
        interrogation_failed,
        hinted_peers
    );

    Ok(())
}

fn handle_discovery_event(
    service: &str,
    service_name: &'static str,
    peer: &Peer,
    context: DiscoveryEventContext<'_>,
) {
    let peer_id = peer.id();
    let registry_peer_id = peer_id_from_endpoint(peer_id);
    let first_service_observation = context.peer_registry.lock().map_or(true, |mut registry| {
        let already_seen = registry
            .get(registry_peer_id)
            .is_some_and(|entry| entry.has_service(service_name));
        if already_seen {
            return false;
        }

        let now = now_ms();
        registry.apply(
            now,
            registry_peer_id,
            PeerEvent::Discovered {
                source: DiscoverySource::Transport("discovery"),
                transport_security: TransportSecurity::Untrusted,
            },
        );
        registry.apply(
            now,
            registry_peer_id,
            PeerEvent::ServiceObserved {
                service: service_name,
                transport_security: TransportSecurity::Untrusted,
            },
        );
        true
    });

    if !first_service_observation {
        return;
    }

    println!(
        "event=discovered service={} peer={} source={} trust={} remote_trust={} source_trust={}",
        service,
        peer_id,
        peer.source(),
        peer.trust(),
        peer.remote_trust(),
        peer.source_trust()
    );

    if context.interrogate && context.interrogated.insert(peer_id) {
        println!("event=interrogate-start peer={}", peer_id);
        let node_pool = context.node_pool.clone();
        let peer_registry = context.peer_registry.clone();
        context.interrogations.spawn(async move {
            let result = interrogate_peer(node_pool, peer_registry, peer_id).await;
            (peer_id, result)
        });
    }
}

async fn interrogate_peer(
    node_pool: ConnectionPool,
    peer_registry: Arc<Mutex<PeerRegistry>>,
    peer_id: EndpointId,
) -> anyhow::Result<PeerInterrogationOutcome> {
    let channel = node_pool
        .channel(peer_id)
        .await
        .with_context(|| format!("failed to connect to node service on {peer_id}"))?;

    let mut client = NodeClient::new(channel)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);

    let node_info_permit = acquire_rpc(
        &peer_registry,
        peer_id,
        PeerRequestKind::new(NODE_SERVICE_NAME, "GetNodeInfo"),
        1.0,
    )?;
    let node_info_started = std::time::Instant::now();
    let node_info = match timeout(RPC_TIMEOUT, client.get_node_info(GetNodeInfoRequest {})).await {
        Ok(Ok(resp)) => {
            observe_authenticated_service(&peer_registry, peer_id, NODE_SERVICE_NAME);
            release_rpc(
                &peer_registry,
                node_info_permit,
                Outcome::ok(duration_ms(node_info_started.elapsed())),
            );
            resp.into_inner()
        }
        Ok(Err(status)) => {
            let error = format!("get_node_info RPC failed: {status}");
            release_rpc(
                &peer_registry,
                node_info_permit,
                Outcome::Err {
                    rtt_ms: Some(duration_ms(node_info_started.elapsed())),
                    error: error.clone(),
                },
            );
            return Err(anyhow::anyhow!(error));
        }
        Err(_) => {
            let error = format!("get_node_info timed out after {RPC_TIMEOUT:?}");
            release_rpc(
                &peer_registry,
                node_info_permit,
                Outcome::Err {
                    rtt_ms: Some(duration_ms(node_info_started.elapsed())),
                    error: error.clone(),
                },
            );
            return Err(anyhow::anyhow!(error));
        }
    };

    let mut known_peers = Vec::new();
    let mut invalid_known_peers = 0usize;
    let mut known_peers_error = None;

    match acquire_rpc(
        &peer_registry,
        peer_id,
        PeerRequestKind::new(NODE_SERVICE_NAME, "GetKnownPeers"),
        0.25,
    ) {
        Ok(known_peers_permit) => {
            let known_peers_started = std::time::Instant::now();
            match timeout(
                RPC_TIMEOUT,
                client.get_known_peers(GetKnownPeersRequest {
                    service_alpn: String::new(),
                }),
            )
            .await
            {
                Ok(Ok(resp)) => {
                    release_rpc(
                        &peer_registry,
                        known_peers_permit,
                        Outcome::ok(duration_ms(known_peers_started.elapsed())),
                    );
                    let mut dedupe = HashSet::new();
                    for raw_id in resp.into_inner().peer_ids {
                        match decode_endpoint_id(&raw_id) {
                            Ok(id) if id != peer_id => {
                                if dedupe.insert(id) {
                                    known_peers.push(id);
                                }
                            }
                            Ok(_) => {}
                            Err(_) => invalid_known_peers += 1,
                        }
                    }
                }
                Ok(Err(status)) => {
                    let error = format!("get_known_peers RPC failed: {status}");
                    release_rpc(
                        &peer_registry,
                        known_peers_permit,
                        Outcome::Err {
                            rtt_ms: Some(duration_ms(known_peers_started.elapsed())),
                            error: error.clone(),
                        },
                    );
                    known_peers_error = Some(error);
                }
                Err(_) => {
                    let error = format!("get_known_peers timed out after {RPC_TIMEOUT:?}");
                    release_rpc(
                        &peer_registry,
                        known_peers_permit,
                        Outcome::Err {
                            rtt_ms: Some(duration_ms(known_peers_started.elapsed())),
                            error: error.clone(),
                        },
                    );
                    known_peers_error = Some(error);
                }
            }
        }
        Err(err) => {
            known_peers_error = Some(err.to_string());
        }
    }

    Ok(PeerInterrogationOutcome {
        node_info,
        known_peers,
        invalid_known_peers,
        known_peers_error,
    })
}

fn acquire_rpc(
    registry: &Arc<Mutex<PeerRegistry>>,
    peer_id: EndpointId,
    kind: PeerRequestKind,
    cost: f32,
) -> anyhow::Result<Permit> {
    registry
        .lock()
        .map_err(|_| anyhow::anyhow!("peer registry is unavailable"))?
        .try_acquire(now_ms(), peer_id_from_endpoint(peer_id), kind, cost)
        .map_err(Into::into)
}

fn release_rpc(registry: &Arc<Mutex<PeerRegistry>>, permit: Permit, outcome: Outcome) {
    if let Ok(mut registry) = registry.lock() {
        registry.release(now_ms(), permit, outcome);
    }
}

fn observe_authenticated_service(
    registry: &Arc<Mutex<PeerRegistry>>,
    peer_id: EndpointId,
    service: &'static str,
) {
    if let Ok(mut registry) = registry.lock() {
        let now = now_ms();
        let peer_id = peer_id_from_endpoint(peer_id);
        registry.apply(
            now,
            peer_id,
            PeerEvent::Discovered {
                source: DiscoverySource::Transport("iroh"),
                transport_security: TransportSecurity::Authenticated,
            },
        );
        registry.apply(
            now,
            peer_id,
            PeerEvent::ServiceObserved {
                service,
                transport_security: TransportSecurity::Authenticated,
            },
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

fn decode_endpoint_id(raw_id: &[u8]) -> anyhow::Result<EndpointId> {
    let bytes: [u8; 32] = raw_id
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid endpoint id length: {}", raw_id.len()))?;
    EndpointId::from_bytes(&bytes).context("invalid endpoint id bytes")
}
