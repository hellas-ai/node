use crate::commands::CliResult;
use anyhow::Context;
use hellas_rpc::discovery::DiscoveryEndpoint;
use hellas_rpc::pb::hellas::HealthCheckRequest;
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
        .health_check(HealthCheckRequest {})
        .await
        .context("health check RPC failed")?
        .into_inner();

    println!("Version: {}", response.version);
    println!("Uptime: {}s", response.uptime_seconds);
    println!("Node ID: {}", response.node_id);

    Ok(())
}
