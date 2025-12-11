use hellas_rpc::pb::hellas::node_client::NodeClient;
use hellas_rpc::pb::hellas::node_server::NodeServer;
use hellas_rpc::pb::hellas::HealthCheckRequest;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::IrohConnect;

pub async fn run(node_id: EndpointId) {
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .expect("Failed to create iroh endpoint");

    let channel = NodeServer::<()>::connect(&endpoint, node_id.into())
        .await
        .expect("Failed to connect");

    let mut client = NodeClient::new(channel);
    let response = client
        .health_check(HealthCheckRequest {})
        .await
        .expect("Health check failed")
        .into_inner();

    println!("Version: {}", response.version);
    println!("Uptime: {}s", response.uptime_seconds);
    println!("Node ID: {}", response.node_id);
}
