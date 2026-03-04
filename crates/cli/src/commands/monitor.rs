use crate::commands::CliResult;

#[cfg(feature = "discovery")]
use crate::commands::common::{shared_pkarr_client, GRPC_MESSAGE_LIMIT};
#[cfg(feature = "discovery")]
use anyhow::Context;
#[cfg(feature = "discovery")]
use futures::StreamExt;
#[cfg(feature = "discovery")]
use hellas_rpc::pb::hellas::node_client::NodeClient;
#[cfg(feature = "discovery")]
use hellas_rpc::pb::hellas::{GetKnownPeersRequest, HealthCheckRequest, HealthCheckResponse};
#[cfg(feature = "discovery")]
use hellas_rpc::service::{ExecuteService, NodeService};
#[cfg(feature = "discovery")]
use std::collections::HashSet;
#[cfg(feature = "discovery")]
use std::future;
#[cfg(feature = "discovery")]
use std::sync::Arc;
#[cfg(feature = "discovery")]
use tokio::task::JoinSet;
#[cfg(feature = "discovery")]
use tokio::time::{timeout, Duration};
#[cfg(feature = "discovery")]
use tonic_iroh_transport::iroh::address_lookup::mdns::MdnsAddressLookup;
#[cfg(feature = "discovery")]
use tonic_iroh_transport::iroh::address_lookup::pkarr::dht::DhtAddressLookup;
#[cfg(feature = "discovery")]
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
#[cfg(feature = "discovery")]
use tonic_iroh_transport::swarm::{
    DhtBackend, MdnsBackend, Peer, PeerExchangeBackend, ServiceRegistry,
};
#[cfg(feature = "discovery")]
use tonic_iroh_transport::IrohConnect;

#[cfg(feature = "discovery")]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(feature = "discovery")]
const RPC_TIMEOUT: Duration = Duration::from_secs(3);

#[cfg(feature = "discovery")]
struct PeerInterrogationOutcome {
    health: HealthCheckResponse,
    known_peers: Vec<EndpointId>,
    invalid_known_peers: usize,
    known_peers_error: Option<String>,
}

#[cfg(feature = "discovery")]
pub async fn run(timeout_secs: Option<u64>, interrogate: bool) -> CliResult<()> {
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    // Local-network discovery only (do not advertise as a service).
    let mdns = MdnsAddressLookup::builder()
        .advertise(false)
        .service_name("hellas")
        .build(endpoint.id())
        .context("failed to start mDNS discovery")?;
    endpoint.address_lookup().add(mdns.clone());

    let shared_pkarr = shared_pkarr_client().context("failed to initialize shared pkarr client")?;
    let shared_dht = Arc::new(
        shared_pkarr
            .dht()
            .ok_or_else(|| anyhow::anyhow!("shared pkarr client has no DHT handle"))?,
    );

    // Internet discovery via pkarr + DHT (resolver-only; no publish).
    let pkarr = DhtAddressLookup::builder()
        .client(shared_pkarr)
        .n0_dns_pkarr_relay()
        .no_publish()
        .build()
        .context("failed to initialize pkarr+DHT discovery")?;
    endpoint.address_lookup().add(pkarr);

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
                            &endpoint,
                            &peer,
                            interrogate,
                            &mut node_seen,
                            &mut unique_peers,
                            &mut interrogated,
                            &mut interrogations,
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
                            &endpoint,
                            &peer,
                            interrogate,
                            &mut execute_seen,
                            &mut unique_peers,
                            &mut interrogated,
                            &mut interrogations,
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

#[cfg(feature = "discovery")]
fn handle_discovery_event(
    service: &str,
    endpoint: &Endpoint,
    peer: &Peer,
    interrogate: bool,
    service_seen: &mut HashSet<EndpointId>,
    unique_peers: &mut HashSet<EndpointId>,
    interrogated: &mut HashSet<EndpointId>,
    interrogations: &mut JoinSet<(EndpointId, anyhow::Result<PeerInterrogationOutcome>)>,
) {
    let peer_id = peer.id();
    if !service_seen.insert(peer_id) {
        return;
    }

    unique_peers.insert(peer_id);
    println!(
        "event=discovered service={} peer={} source={} trust={} peer_trust={} source_trust={}",
        service,
        peer_id,
        peer.source(),
        peer.trust(),
        peer.peer_trust(),
        peer.source_trust()
    );

    if interrogate && interrogated.insert(peer_id) {
        println!("event=interrogate-start peer={}", peer_id);
        let endpoint = endpoint.clone();
        interrogations.spawn(async move {
            let result = interrogate_peer(endpoint, peer_id).await;
            (peer_id, result)
        });
    }
}

#[cfg(feature = "discovery")]
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

#[cfg(feature = "discovery")]
fn decode_endpoint_id(raw_id: &[u8]) -> anyhow::Result<EndpointId> {
    let bytes: [u8; 32] = raw_id
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid endpoint id length: {}", raw_id.len()))?;
    EndpointId::from_bytes(&bytes)
        .map_err(|err| anyhow::anyhow!("invalid endpoint id bytes: {err}"))
}

#[cfg(not(feature = "discovery"))]
pub async fn run(_timeout_secs: Option<u64>, _interrogate: bool) -> CliResult<()> {
    anyhow::bail!("monitor requires the `discovery` feature")
}
