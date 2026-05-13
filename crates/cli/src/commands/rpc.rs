use crate::commands::CliResult;
use anyhow::Context;
use hellas_pb::swarm::GetNodeInfoRequest;
use hellas_pb::swarm::node_client::NodeClient;
use hellas_rpc::discovery::DiscoveryEndpoint;
use hellas_rpc::iroh_client::{IrohNodeClient, finish_unary, tracked_iroh_channel};
use hellas_rpc::peers::PeerManager;
use hellas_rpc::service::{NodeService, methods};
use std::net::SocketAddr;
use tonic_iroh_transport::iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};
use tonic_iroh_transport::{IrohConnect, PoolOptions};

pub async fn run(
    node_id: EndpointId,
    node_addrs: Vec<SocketAddr>,
    secret_key: SecretKey,
) -> CliResult<()> {
    let peer_registry = PeerManager::default();
    let endpoint = DiscoveryEndpoint::bind(Some(secret_key)).await?.endpoint;
    let response = if node_addrs.is_empty() {
        IrohNodeClient::new(
            endpoint.clone(),
            peer_registry.clone(),
            PoolOptions::default(),
        )
        .get_node_info(node_id, GetNodeInfoRequest {})
        .await
        .with_context(|| format!("get_node_info RPC failed for node {node_id}"))?
        .into_inner()
    } else {
        let endpoint_addr =
            EndpointAddr::from_parts(node_id, node_addrs.into_iter().map(TransportAddr::Ip));
        let (channel, permit) = tracked_iroh_channel::<methods::GetNodeInfo, _, _>(
            &peer_registry,
            node_id,
            1.0,
            async {
                NodeService::connect(&endpoint, endpoint_addr)
                    .await
                    .with_context(|| format!("failed to connect to node {node_id}"))
            },
        )
        .await?;
        let mut client = NodeClient::new(channel);
        finish_unary::<methods::GetNodeInfo, _>(
            permit,
            client.get_node_info(GetNodeInfoRequest {}).await,
        )
        .context("get_node_info RPC failed")?
        .into_inner()
    };

    println!("Node ID:  {}", response.node_id);
    println!("Version:  {}", response.version);
    println!("Build:    {}", response.build);
    println!("OS:       {}", response.os);
    println!("Uptime:   {}s", response.uptime_seconds);
    println!("Graffiti: {}", String::from_utf8_lossy(&response.graffiti));

    Ok(())
}
