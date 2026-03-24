use crate::commands::CliResult;
use anyhow::Context;
use hellas_rpc::discovery::DiscoveryEndpoint;
use hellas_rpc::pb::hellas::HealthCheckRequest;
use hellas_rpc::pb::hellas::node_client::NodeClient;
use hellas_rpc::service::NodeService;
use tonic_iroh_transport::{ConnectionPool, PoolOptions};
use tonic_iroh_transport::iroh::EndpointId;

pub async fn run(node_id: EndpointId) -> CliResult<()> {
    let endpoint = DiscoveryEndpoint::bind().await?.endpoint;
    let pool = ConnectionPool::for_service::<NodeService>(endpoint, PoolOptions::default());
    let channel = pool
        .channel(node_id)
        .await
        .with_context(|| format!("failed to connect to node {node_id}"))?;

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
