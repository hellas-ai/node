use crate::commands::CliResult;
use anyhow::Context;
use hellas_rpc::pb::hellas::node_client::NodeClient;
use hellas_rpc::pb::hellas::HealthCheckRequest;
use hellas_rpc::service::NodeService;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::IrohConnect;

pub async fn run(node_id: EndpointId) -> CliResult<()> {
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    let channel = NodeService::connect(&endpoint, node_id.into())
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
