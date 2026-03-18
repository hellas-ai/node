use crate::commands::CliResult;

use anyhow::Context;
use futures::StreamExt;
use hellas_rpc::discovery::bind_resolver_endpoint;
use hellas_rpc::pb::hellas::node_client::NodeClient;
use hellas_rpc::pb::hellas::{GetKnownPeersRequest, HealthCheckRequest, HealthCheckResponse};
use hellas_rpc::service::{ExecuteService, NodeService};
use hellas_rpc::GRPC_MESSAGE_LIMIT;
use std::collections::HashSet;
use std::future;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::swarm::{
    DhtBackend, MdnsBackend, Peer, PeerExchangeBackend, ServiceRegistry,
};
use tonic_iroh_transport::IrohConnect;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const RPC_TIMEOUT: Duration = Duration::from_secs(3);

struct PeerInterrogationOutcome {
    health: HealthCheckResponse,
    known_peers: Vec<EndpointId>,
    invalid_known_peers: usize,
    known_peers_error: Option<String>,
}

struct DiscoveryEventContext<'a> {
    endpoint: &'a Endpoint,
    interrogate: bool,
    service_seen: &'a mut HashSet<EndpointId>,
    unique_peers: &'a mut HashSet<EndpointId>,
    interrogated: &'a mut HashSet<EndpointId>,
    interrogations: &'a mut JoinSet<(EndpointId, anyhow::Result<PeerInterrogationOutcome>)>,
}

pub async fn run(timeout_secs: Option<u64>, interrogate: bool) -> CliResult<()> {
    let bound = bind_resolver_endpoint().await?;
    let endpoint = bound.endpoint;
    let mdns = bound.bindings.mdns;
    let shared_dht = bound.bindings.dht;

    let peer_exchange = PeerExchangeBackend::new();
    let mut registry = ServiceRegistry::new(&endpoint);
    registry.add(MdnsBackend::new(mdns));
    registry.add(DhtBackend::with_dht(&endpoint, shared_dht));
    registry.add(peer_exchange.clone());

    let mut node_discovery = Box::pin(registry.discover::<NodeService>());
    let mut execute_discovery = Box::pin(registry.discover::<ExecuteService>());

    let mut interrogations = JoinSet::new();
    let mut node_seen = HashSet::new();
    let mut execute_seen = HashSet::new();
    let mut unique_peers = HashSet::new();
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
                            &peer,
                            DiscoveryEventContext {
                                endpoint: &endpoint,
                                interrogate,
                                service_seen: &mut node_seen,
                                unique_peers: &mut unique_peers,
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
                            &peer,
                            DiscoveryEventContext {
                                endpoint: &endpoint,
                                interrogate,
                                service_seen: &mut execute_seen,
                                unique_peers: &mut unique_peers,
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
                        println!(
                            "event=health peer={} version={} uptime_seconds={} reported_node_id={}",
                            peer_id,
                            outcome.health.version,
                            outcome.health.uptime_seconds,
                            outcome.health.node_id
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

    println!(
        "event=monitor-summary unique_peers={} node_service_peers={} execute_service_peers={} interrogated={} interrogation_ok={} interrogation_failed={} hinted_peers={}",
        unique_peers.len(),
        node_seen.len(),
        execute_seen.len(),
        interrogated.len(),
        interrogation_ok,
        interrogation_failed,
        hinted_peers
    );

    Ok(())
}

fn handle_discovery_event(service: &str, peer: &Peer, context: DiscoveryEventContext<'_>) {
    let peer_id = peer.id();
    if !context.service_seen.insert(peer_id) {
        return;
    }

    context.unique_peers.insert(peer_id);
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
        let endpoint = context.endpoint.clone();
        context.interrogations.spawn(async move {
            let result = interrogate_peer(endpoint, peer_id).await;
            (peer_id, result)
        });
    }
}

async fn interrogate_peer(
    endpoint: Endpoint,
    peer_id: EndpointId,
) -> anyhow::Result<PeerInterrogationOutcome> {
    let channel = NodeService::connect(&endpoint, peer_id.into())
        .connect_timeout(CONNECT_TIMEOUT)
        .await
        .with_context(|| format!("failed to connect to node service on {peer_id}"))?;

    let mut client = NodeClient::new(channel)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);

    let health = timeout(RPC_TIMEOUT, client.health_check(HealthCheckRequest {}))
        .await
        .map_err(|_| anyhow::anyhow!("health_check timed out after {RPC_TIMEOUT:?}"))?
        .context("health_check RPC failed")?
        .into_inner();

    let mut known_peers = Vec::new();
    let mut invalid_known_peers = 0usize;
    let mut known_peers_error = None;

    match timeout(
        RPC_TIMEOUT,
        client.get_known_peers(GetKnownPeersRequest {
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
        Ok(Err(status)) => {
            known_peers_error = Some(format!("get_known_peers RPC failed: {status}"));
        }
        Err(_) => {
            known_peers_error = Some(format!("get_known_peers timed out after {RPC_TIMEOUT:?}"));
        }
    }

    Ok(PeerInterrogationOutcome {
        health,
        known_peers,
        invalid_known_peers,
        known_peers_error,
    })
}

fn decode_endpoint_id(raw_id: &[u8]) -> anyhow::Result<EndpointId> {
    let bytes: [u8; 32] = raw_id
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid endpoint id length: {}", raw_id.len()))?;
    EndpointId::from_bytes(&bytes)
        .map_err(|err| anyhow::anyhow!("invalid endpoint id bytes: {err}"))
}
