use crate::commands::CliResult;
use anyhow::Context;
use hellas_rpc::pb::swarm::GetNodeInfoRequest;
use hellas_rpc::client::NodeClient;
use hellas_rpc::discovery::DiscoveryEndpoint;
use hellas_rpc::peers::{IrohTransport, PeerManager};
use std::net::SocketAddr;
use iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};

pub async fn run(
    node_id: EndpointId,
    node_addrs: Vec<SocketAddr>,
    secret_key: SecretKey,
) -> CliResult<()> {
    let peer_registry = PeerManager::default();
    let endpoint = DiscoveryEndpoint::bind(Some(secret_key)).await?.endpoint;
    let transport = IrohTransport::new(endpoint.clone(), peer_registry.clone());

    let handle = if node_addrs.is_empty() {
        transport.peer(node_id)
    } else {
        let endpoint_addr =
            EndpointAddr::from_parts(node_id, node_addrs.into_iter().map(TransportAddr::Ip));
        transport.peer_at(node_id, endpoint_addr)
    };

    let response = handle
        .get_node_info(GetNodeInfoRequest {})
        .await
        .with_context(|| format!("get_node_info RPC failed for node {node_id}"))?
        .into_inner();

    println!("Node ID:  {}", response.node_id);
    println!("Version:  {}", response.version);
    println!("Build:    {}", response.build);
    println!("OS:       {}", response.os);
    println!("Uptime:   {}s", response.uptime_seconds);
    println!("Graffiti: {}", String::from_utf8_lossy(&response.graffiti));

    Ok(())
}
