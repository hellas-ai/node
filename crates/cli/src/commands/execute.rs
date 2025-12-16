use crate::commands::CliResult;
use crate::bootstrap_peers::bootstrap_peer_ids;
use anyhow::Context;
use hellas_rpc::pb::hellas::execute_client::ExecuteClient;
use hellas_rpc::pb::hellas::execute_server::ExecuteServer;
use hellas_rpc::pb::hellas::{
    get_quote_request, ExecuteRequest, ExecuteStatusRequest, GetQuoteRequest, LlmQuoteRequest,
    Presence,
};
use std::io::{self, Write};
use tokio::time::{timeout, Duration, Instant};
use tokio_stream::StreamExt;
use tonic_iroh_transport::gossip::join;
use tonic_iroh_transport::iroh::discovery::mdns::{DiscoveryEvent, MdnsDiscovery};
use tonic_iroh_transport::iroh::discovery::pkarr::dht::DhtDiscovery;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId, Watcher};
use tonic_iroh_transport::{IrohConnect, TransportBuilder, TransportGuard};

const GRPC_MESSAGE_LIMIT: usize = 32 * 1024 * 1024;
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const BOOTSTRAP_JOIN_TIMEOUT: Duration = Duration::from_secs(3);

pub async fn run(
    node_id: Option<EndpointId>,
    model: String,
    prompt: String,
    max_seq: u32,
) -> CliResult<()> {
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    // Needed for local-network bootstrap discovery when the user doesn't provide a node id.
    let mdns = MdnsDiscovery::builder()
        .advertise(false)
        .service_name("hellas")
        .build(endpoint.id())
        .context("failed to start mDNS discovery")?;
    endpoint.discovery().add(mdns.clone());

    // Add internet discovery via pkarr+DHT as a resolver (no publish).
    // `Endpoint::builder()` already includes pkarr publisher + DNS resolver via the N0 preset.
    let dht = DhtDiscovery::builder()
        .n0_dns_pkarr_relay()
        .no_publish()
        .build()
        .context("failed to initialize pkarr+DHT discovery")?;
    endpoint.discovery().add(dht);

    let (node_id, _transport) = match node_id {
        Some(id) => (id, None),
        None => {
            let (id, transport) = discover_executor(&endpoint, &mdns, &model).await?;
            (id, Some(transport))
        }
    };

    let channel = ExecuteServer::<()>::connect(&endpoint, node_id.into())
        .await
        .with_context(|| format!("failed to connect to node {node_id}"))?;

    let mut client = ExecuteClient::new(channel)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);

    // 1. Get quote
    let req = GetQuoteRequest {
        payload: Some(get_quote_request::Payload::LlmPrompt(LlmQuoteRequest {
            huggingface_model_id: model.clone(),
            prompt: prompt.clone(),
            max_seq,
        })),
    };
    info!("Getting quote... {req:?}");
    let quote = client
        .get_quote(req)
        .await
        .context("GetQuote RPC failed")?
        .into_inner();

    info!("Got quote: {quote:?}");

    // 2. Execute
    let req = ExecuteRequest {
        quote_id: quote.quote_id.as_bytes().to_vec(),
    };
    info!("Req: {req:?}");
    let exec = client
        .execute(req)
        .await
        .context("Execute RPC failed")?
        .into_inner();
    info!("Executing: {exec:?}");

    // 3. Stream status until completed
    let req = ExecuteStatusRequest {
        execution_id: exec.execution_id.clone(),
    };
    info!("Streaming status: {req:?}");
    let mut stream = client
        .execute_stream(req)
        .await
        .context("ExecuteStream RPC failed")?
        .into_inner();

    while let Some(progress) = stream.next().await {
        let progress = progress.context("ExecuteStream RPC progress failed")?;
        if let Some(decoded) = progress.decoded.as_deref() {
            debug!(
                "Status: {} | Progress: {} | Decoded chunk: {}",
                progress.status, progress.progress, decoded
            );
            print!("{}", decoded);
            io::stdout().flush()?;
        } else if progress.chunk.is_empty() {
            debug!(
                "Status: {} | Progress: {}",
                progress.status, progress.progress
            );
        } else {
            debug!(
                "Status: {} | Progress: {} | Chunk bytes: {}",
                progress.status,
                progress.progress,
                progress.chunk.len()
            );
        }
        if progress.status == "completed" || progress.status == "failed" {
            break;
        }
    }

    Ok(())
}

async fn discover_executor(
    endpoint: &Endpoint,
    mdns: &MdnsDiscovery,
    model: &str,
) -> CliResult<(EndpointId, TransportGuard)> {
    info!("No node ID provided, discovering executor via gossip...");

    // Wait for endpoint to have addresses before starting gossip
    let mut addr_stream = endpoint.watch_addr().stream();
    let _ = timeout(DISCOVERY_TIMEOUT, async {
        while let Some(addr) = addr_stream.next().await {
            let addrs: Vec<_> = addr.ip_addrs().collect();
            if !addrs.is_empty() {
                info!("endpoint ready with {} addresses", addrs.len());
                return;
            }
        }
    })
    .await;

    // Gossip won't send anything unless we have at least one connected neighbor.
    // Use mDNS to discover local peers for the bootstrap dial.
    let mut bootstrap: Vec<EndpointId> = Vec::new();
    let mut mdns_events = mdns.subscribe().await;
    let mdns_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < mdns_deadline {
        let remaining = mdns_deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, mdns_events.next()).await {
            Ok(Some(DiscoveryEvent::Discovered { endpoint_info, .. })) => {
                if endpoint_info.endpoint_id == endpoint.id() {
                    continue;
                }
                if !bootstrap.contains(&endpoint_info.endpoint_id) {
                    bootstrap.push(endpoint_info.endpoint_id);
                }
            }
            Ok(Some(DiscoveryEvent::Expired { .. })) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }

    if bootstrap.is_empty() {
        info!("No peers discovered via mDNS, falling back to compiled-in bootstrap peers");
    } else {
        info!(peers = bootstrap.len(), "Discovered local peers via mDNS");
    }

    for peer in bootstrap_peer_ids() {
        if peer == endpoint.id() {
            continue;
        }
        if !bootstrap.contains(&peer) {
            bootstrap.push(peer);
        }
    }

    if bootstrap.is_empty() {
        return Err(anyhow::anyhow!(
            "No bootstrap peers available (mDNS found none and BOOTSTRAP_PEERS is empty); pass a `node_id`."
        ));
    }

    let transport = TransportBuilder::new(endpoint.clone())
        .with_gossip_config(Default::default())
        .spawn()
        .await
        .context("failed to start gossip transport")?;

    let gossip = transport
        .gossip()
        .cloned()
        .context("gossip handle missing from transport")?;

    let mut topic = match timeout(
        BOOTSTRAP_JOIN_TIMEOUT,
        join::<Presence>(&gossip, bootstrap.clone()),
    )
    .await
    {
        Ok(Ok(topic)) => topic,
        Ok(Err(err)) => {
            warn!(
                peers = bootstrap.len(),
                "failed to join presence topic with full bootstrap set: {err}"
            );
            let mut last_err: Option<anyhow::Error> = None;
            let mut topic: Option<_> = None;
            for peer in bootstrap {
                match timeout(BOOTSTRAP_JOIN_TIMEOUT, join::<Presence>(&gossip, vec![peer])).await {
                    Ok(Ok(t)) => {
                        topic = Some(t);
                        break;
                    }
                    Ok(Err(e)) => {
                        last_err = Some(anyhow::anyhow!(e));
                    }
                    Err(e) => {
                        last_err = Some(anyhow::anyhow!("bootstrap join timeout: {e}"));
                    }
                }
            }
            topic.ok_or_else(|| {
                last_err.unwrap_or_else(|| anyhow::anyhow!("failed to join presence topic"))
            })?
        }
        Err(e) => {
            return Err(anyhow::anyhow!("bootstrap join timeout: {e}"));
        }
    };

    // optional but gives us feedback on connectivity before we broadcast
    if let Err(e) = timeout(DISCOVERY_TIMEOUT, topic.joined()).await {
        debug!("gossip join wait timed out: {e:?}");
    }

    let req_id = format!(
        "{}-{}",
        endpoint.id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );

    let presence = Presence {
        hf_id: model.to_string(),
        req_id: req_id.clone(),
        peer_id: endpoint.id().to_string(),
        ttl_ms: DISCOVERY_TIMEOUT.as_millis() as u64,
        is_executor: false,
    };

    topic
        .broadcast(&presence)
        .await
        .context("failed to broadcast presence request")?;

    let selected = timeout(DISCOVERY_TIMEOUT, async {
        while let Some(event) = topic.recv().await {
            let (_ctx, msg) = event.context("gossip receive error")?;
            if msg.req_id != req_id || msg.hf_id != model {
                continue;
            }
            if !msg.is_executor {
                continue;
            }
            let node_id: EndpointId = msg
                .peer_id
                .parse()
                .context("failed to parse executor peer id")?;
            info!("Discovered executor {}", node_id);
            return Ok::<EndpointId, anyhow::Error>(node_id);
        }
        Err(anyhow::anyhow!(
            "gossip stream closed before discovery completed"
        ))
    })
    .await
    .context("discovery timed out waiting for executor")??;

    Ok((selected, transport))
}
