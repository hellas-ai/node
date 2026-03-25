use crate::commands::CliResult;
use anyhow::Context;
use hellas_rpc::discovery::DiscoveryEndpoint;
use hellas_rpc::pb::hellas::GetNodeInfoRequest;
use hellas_rpc::pb::hellas::node_client::NodeClient;
use hellas_rpc::service::NodeService;
use std::net::SocketAddr;
use tonic_iroh_transport::iroh::{EndpointAddr, EndpointId, TransportAddr};
use tonic_iroh_transport::{ConnectionPool, IrohConnect, PoolOptions};

pub async fn run(node_id: EndpointId, node_addrs: Vec<SocketAddr>) -> CliResult<()> {
    let endpoint = DiscoveryEndpoint::bind().await?.endpoint;
    let channel = if node_addrs.is_empty() {
        let pool =
            ConnectionPool::for_service::<NodeService>(endpoint.clone(), PoolOptions::default());
        pool.channel(node_id)
            .await
            .with_context(|| format!("failed to connect to node {node_id}"))?
    } else {
        NodeService::connect(
            &endpoint,
            EndpointAddr::from_parts(node_id, node_addrs.into_iter().map(TransportAddr::Ip)),
        )
        .await
        .with_context(|| format!("failed to connect to node {node_id}"))?
    };

    let mut client = NodeClient::new(channel);
    let response = client
        .get_node_info(GetNodeInfoRequest {})
        .await
        .context("get_node_info RPC failed")?
        .into_inner();

    println!("Node ID:  {}", response.node_id);
    println!("Version:  {}", response.version);
    println!("Build:    {}", response.build);
    println!("OS:       {}", response.os);
    println!("Uptime:   {}s", response.uptime_seconds);
    println!(
        "Graffiti: {}",
        String::from_utf8_lossy(&response.graffiti)
    );

    Ok(())
}
