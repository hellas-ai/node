use crate::commands::CliResult;
use anyhow::Context;
use hellas_pb::swarm::GetNodeInfoRequest;
use hellas_pb::swarm::node_client::NodeClient as TonicNodeClient;
use hellas_rpc::client::NodeClient;
use hellas_rpc::discovery::DiscoveryEndpoint;
use hellas_rpc::iroh_client::{finish_unary, tracked_iroh_channel};
use hellas_rpc::peers::{IrohTransport, PeerManager};
use hellas_rpc::service::{NodeService, methods};
use std::net::SocketAddr;
use tonic_iroh_transport::IrohConnect;
use tonic_iroh_transport::iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};

pub async fn run(
    node_id: EndpointId,
    node_addrs: Vec<SocketAddr>,
    secret_key: SecretKey,
) -> CliResult<()> {
    let peer_registry = PeerManager::default();
    let endpoint = DiscoveryEndpoint::bind(Some(secret_key)).await?.endpoint;
    let response = if node_addrs.is_empty() {
        let transport = IrohTransport::new(endpoint.clone(), peer_registry.clone());
        transport
            .peer(node_id)
            .get_node_info(GetNodeInfoRequest {})
            .await
            .with_context(|| format!("get_node_info RPC failed for node {node_id}"))?
            .into_inner()
    } else {
        let endpoint_addr =
            EndpointAddr::from_parts(node_id, node_addrs.into_iter().map(TransportAddr::Ip));
        let (channel, permit) = tracked_iroh_channel::<methods::GetNodeInfo, _, _>(
            &peer_registry,
            node_id,
            async {
                NodeService::connect(&endpoint, endpoint_addr)
                    .await
                    .with_context(|| format!("failed to connect to node {node_id}"))
            },
        )
        .await?;
        let mut client = TonicNodeClient::new(channel);
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
