use crate::commands::CliResult;

use anyhow::Context;
use futures::StreamExt;
use hellas_pb::swarm::{GetKnownPeersRequest, GetNodeInfoRequest, GetNodeInfoResponse};
use hellas_rpc::client::NodeClient;
use hellas_rpc::discovery::DiscoveryEndpoint;
use hellas_rpc::peers::{
    DiscoverySource, IrohTransport, PeerId, PeerManager, ServiceKey, TransportSecurity,
};
use hellas_rpc::service::{ExecuteService, NodeService};
use std::collections::HashSet;
use std::future;
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};
use tonic_iroh_transport::PoolOptions;
use tonic_iroh_transport::iroh::{EndpointId, SecretKey};
use tonic_iroh_transport::swarm::{
    DhtBackend, MdnsBackend, Peer, PeerExchangeBackend, ServiceRegistry,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const RPC_TIMEOUT: Duration = Duration::from_secs(3);
struct PeerInterrogationOutcome {
    node_info: GetNodeInfoResponse,
    known_peers: Vec<EndpointId>,
    invalid_known_peers: usize,
    known_peers_error: Option<String>,
}

struct DiscoveryEventContext<'a> {
    transport: &'a IrohTransport,
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

    let peer_registry = PeerManager::default();
    let transport = IrohTransport::with_options(
        endpoint.clone(),
        peer_registry.clone(),
        PoolOptions {
            connect_timeout: CONNECT_TIMEOUT,
            ..PoolOptions::default()
        },
    );

    let mut node_discovery = Box::pin(registry.discover::<NodeService>());
    let mut execute_discovery = Box::pin(registry.discover::<ExecuteService>());

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
                                transport: &transport,
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
                                transport: &transport,
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
                                    .peer(PeerId::from(*hinted))
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
    let service_inserted = context
        .peer_registry
        .observe_iroh_service::<S>(peer_id)
        .map_or(true, |observation| observation.service_inserted);
    if !service_inserted {
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
        let transport = context.transport.clone();
        context.interrogations.spawn(async move {
            let result = interrogate_peer(transport, peer_id).await;
            (peer_id, result)
        });
    }
}

async fn interrogate_peer(
    transport: IrohTransport,
    peer_id: EndpointId,
) -> anyhow::Result<PeerInterrogationOutcome> {
    let peer = transport.peer(peer_id);

    // Permits, admission, and finish-on-error are handled inside the typed
    // call builders — the call site is just the request + timeout.
    let node_info = match timeout(RPC_TIMEOUT, peer.get_node_info(GetNodeInfoRequest {})).await {
        Ok(Ok(resp)) => resp.into_inner(),
        Ok(Err(err)) => return Err(anyhow::anyhow!("get_node_info RPC failed: {err}")),
        Err(_) => {
            return Err(anyhow::anyhow!(
                "get_node_info timed out after {RPC_TIMEOUT:?}"
            ));
        }
    };

    let mut known_peers = Vec::new();
    let mut invalid_known_peers = 0usize;
    let mut known_peers_error = None;

    match timeout(
        RPC_TIMEOUT,
        peer.get_known_peers(GetKnownPeersRequest {
            service_alpn: String::new(),
        }),
    )
    .await
    {
        Ok(Ok(resp)) => {
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
        Ok(Err(err)) => {
            known_peers_error = Some(format!("get_known_peers RPC failed: {err}"));
        }
        Err(_) => {
            known_peers_error = Some(format!("get_known_peers timed out after {RPC_TIMEOUT:?}"));
        }
    }

    Ok(PeerInterrogationOutcome {
        node_info,
        known_peers,
        invalid_known_peers,
        known_peers_error,
    })
}

fn decode_endpoint_id(raw_id: &[u8]) -> anyhow::Result<EndpointId> {
    let bytes: [u8; 32] = raw_id
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid endpoint id length: {}", raw_id.len()))?;
    EndpointId::from_bytes(&bytes).context("invalid endpoint id bytes")
}
