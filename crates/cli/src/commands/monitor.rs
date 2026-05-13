use crate::commands::CliResult;
use crate::peer_rpc::{PeerManager, acquire_iroh_method, observe_iroh_service};

use anyhow::Context;
use futures::StreamExt;
use hellas_pb::swarm::node_client::NodeClient;
use hellas_pb::swarm::{GetKnownPeersRequest, GetNodeInfoRequest, GetNodeInfoResponse};
use hellas_rpc::GRPC_MESSAGE_LIMIT;
use hellas_rpc::discovery::DiscoveryEndpoint;
use hellas_rpc::peers::{DiscoverySource, PeerId, ServiceKey, TransportSecurity};
use hellas_rpc::service::{ExecuteService, NodeService, methods};
use std::collections::HashSet;
use std::future;
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};
use tonic_iroh_transport::iroh::{EndpointId, SecretKey};
use tonic_iroh_transport::swarm::{
    DhtBackend, MdnsBackend, Peer, PeerExchangeBackend, ServiceRegistry,
};
use tonic_iroh_transport::{ConnectionPool, PoolOptions};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const RPC_TIMEOUT: Duration = Duration::from_secs(3);
struct PeerInterrogationOutcome {
    node_info: GetNodeInfoResponse,
    known_peers: Vec<EndpointId>,
    invalid_known_peers: usize,
    known_peers_error: Option<String>,
}

struct DiscoveryEventContext<'a> {
    node_pool: &'a ConnectionPool,
    peer_registry: &'a PeerManager,
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

    let peer_registry = PeerManager::default();
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
                        handle_discovery_event::<NodeService>(
                            "node",
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
                        handle_discovery_event::<ExecuteService>(
                            "execute",
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
                            for hinted in &outcome.known_peers {
                                let _ = peer_registry
                                    .peer(peer_id_from_endpoint(*hinted))
                                    .observe_discovered(
                                        DiscoverySource::PeerExchange,
                                        TransportSecurity::Untrusted,
                                    );
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

    let (unique_peers, node_service_peers, execute_service_peers) = peer_registry
        .with_registry(|registry| {
            (
                registry.len(),
                registry.with_service_key::<NodeService>().count(),
                registry.with_service_key::<ExecuteService>().count(),
            )
        })
        .unwrap_or((0, 0, 0));

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

fn handle_discovery_event<S: ServiceKey>(
    service: &str,
    peer: &Peer,
    context: DiscoveryEventContext<'_>,
) {
    let peer_id = peer.id();
    if !observe_iroh_service::<S>(context.peer_registry, peer_id) {
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
    peer_registry: PeerManager,
    peer_id: EndpointId,
) -> anyhow::Result<PeerInterrogationOutcome> {
    let channel = node_pool
        .channel(peer_id)
        .await
        .with_context(|| format!("failed to connect to node service on {peer_id}"))?;

    let mut client = NodeClient::new(channel)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);

    let mut node_info_permit =
        acquire_iroh_method::<methods::GetNodeInfo>(&peer_registry, peer_id, 1.0)?;
    let node_info = match timeout(RPC_TIMEOUT, client.get_node_info(GetNodeInfoRequest {})).await {
        Ok(Ok(resp)) => {
            node_info_permit.finish_ok();
            resp.into_inner()
        }
        Ok(Err(status)) => {
            let error = format!("get_node_info RPC failed: {status}");
            node_info_permit.finish_err(error.clone());
            return Err(anyhow::anyhow!(error));
        }
        Err(_) => {
            let error = format!("get_node_info timed out after {RPC_TIMEOUT:?}");
            node_info_permit.finish_err(error.clone());
            return Err(anyhow::anyhow!(error));
        }
    };

    let mut known_peers = Vec::new();
    let mut invalid_known_peers = 0usize;
    let mut known_peers_error = None;

    match acquire_iroh_method::<methods::GetKnownPeers>(&peer_registry, peer_id, 0.25) {
        Ok(mut known_peers_permit) => {
            match timeout(
                RPC_TIMEOUT,
                client.get_known_peers(GetKnownPeersRequest {
                    service_alpn: String::new(),
                }),
            )
            .await
            {
                Ok(Ok(resp)) => {
                    known_peers_permit.finish_ok();
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
                    known_peers_permit.finish_err(error.clone());
                    known_peers_error = Some(error);
                }
                Err(_) => {
                    let error = format!("get_known_peers timed out after {RPC_TIMEOUT:?}");
                    known_peers_permit.finish_err(error.clone());
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

fn peer_id_from_endpoint(peer_id: EndpointId) -> PeerId {
    PeerId::from(*peer_id.as_bytes())
}

fn decode_endpoint_id(raw_id: &[u8]) -> anyhow::Result<EndpointId> {
    let bytes: [u8; 32] = raw_id
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid endpoint id length: {}", raw_id.len()))?;
    EndpointId::from_bytes(&bytes).context("invalid endpoint id bytes")
}
