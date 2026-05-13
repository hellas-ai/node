use crate::commands::CliResult;
use anyhow::Context;
use hellas_pb::swarm::GetNodeInfoRequest;
use hellas_pb::swarm::node_client::NodeClient;
use hellas_rpc::discovery::DiscoveryEndpoint;
use hellas_rpc::service::{NodeService, methods};
use std::net::SocketAddr;
use tonic_iroh_transport::iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};
use tonic_iroh_transport::{ConnectionPool, IrohConnect, PoolOptions};

use hellas_rpc::peers::PeerManager;

pub async fn run(
    node_id: EndpointId,
    node_addrs: Vec<SocketAddr>,
    secret_key: SecretKey,
) -> CliResult<()> {
    let peer_registry = PeerManager::default();
    let endpoint = DiscoveryEndpoint::bind(Some(secret_key)).await?.endpoint;
    let mut permit = peer_registry.acquire_iroh_method::<methods::GetNodeInfo>(node_id, 1.0)?;
    let channel_result = if node_addrs.is_empty() {
        let pool =
            ConnectionPool::for_service::<NodeService>(endpoint.clone(), PoolOptions::default());
        pool.channel(node_id)
            .await
            .with_context(|| format!("failed to connect to node {node_id}"))
    } else {
        NodeService::connect(
            &endpoint,
            EndpointAddr::from_parts(node_id, node_addrs.into_iter().map(TransportAddr::Ip)),
        )
        .await
        .with_context(|| format!("failed to connect to node {node_id}"))
    };
    let channel = match channel_result {
        Ok(channel) => channel,
        Err(err) => {
            permit.finish_connect_err(err.to_string());
            return Err(err);
        }
    };

    let mut client = NodeClient::new(channel);
    let response = match client.get_node_info(GetNodeInfoRequest {}).await {
        Ok(response) => {
            permit.finish_ok();
            response.into_inner()
        }
        Err(err) => {
            permit.finish_err(err.to_string());
            return Err(err).context("get_node_info RPC failed");
        }
    };

    println!("Node ID:  {}", response.node_id);
    println!("Version:  {}", response.version);
    println!("Build:    {}", response.build);
    println!("OS:       {}", response.os);
    println!("Uptime:   {}s", response.uptime_seconds);
    println!("Graffiti: {}", String::from_utf8_lossy(&response.graffiti));

    Ok(())
}
