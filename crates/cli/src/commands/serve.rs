use hellas_executor::{ExecuteServer, Executor};
use hellas_rpc::pb::hellas::node_server::{Node, NodeServer};
use hellas_rpc::pb::hellas::{HealthCheckRequest, HealthCheckResponse};
use tonic::{Request, Response, Status};
use tonic_iroh_transport::iroh::Endpoint;
use tonic_iroh_transport::RpcServer;

use std::time::Instant;

struct NodeService {
    start_time: Instant,
    node_id: String,
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            node_id: self.node_id.clone(),
        }))
    }
}

pub async fn run() {
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .expect("Failed to create iroh endpoint");

    let node_id = endpoint.id().to_string();
    println!("Node Address: {node_id}");

    let node_service = NodeService {
        start_time: Instant::now(),
        node_id,
    };

    let executor = Executor::spawn();

    let rpc_guard = RpcServer::new(endpoint)
        .add_service(NodeServer::new(node_service))
        .add_service(ExecuteServer::new(executor))
        .serve()
        .await
        .expect("Failed to start RPC server");

    println!("RPC server running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for shutdown signal");

    rpc_guard.shutdown().await.expect("Shutdown failed");
}
