use crate::commands::CliResult;
use anyhow::Context;
use hellas_executor::{ExecuteServer, Executor};
use hellas_rpc::pb::hellas::node_server::{Node, NodeServer};
use hellas_rpc::pb::hellas::{HealthCheckRequest, HealthCheckResponse};
use tonic::{Request, Response, Status};
use tonic_iroh_transport::iroh::Endpoint;
use tonic_iroh_transport::RpcServer;

use std::time::Instant;
use tokio::time::{timeout, Duration};
use tracing::warn;

const GRPC_MESSAGE_LIMIT: usize = 32 * 1024 * 1024;

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

pub async fn run() -> CliResult<()> {
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    let node_id = endpoint.id().to_string();
    println!("Node Address: {node_id}");

    let node_service = NodeService {
        start_time: Instant::now(),
        node_id,
    };

    let executor = Executor::spawn();

    let execute_service = ExecuteServer::new(executor)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);

    let rpc_guard = RpcServer::new(endpoint)
        .add_service(NodeServer::new(node_service))
        .add_service(execute_service)
        .serve()
        .await
        .context("failed to start RPC server")?;

    println!("RPC server running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for shutdown signal")?;

    println!("Shutting down RPC server...");
    match timeout(Duration::from_secs(5), rpc_guard.shutdown()).await {
        Ok(result) => result.context("failed to shut down RPC server")?,
        Err(_) => {
            warn!("graceful shutdown timed out; forcing shutdown");
            // At this point, drop will signal shutdown; exit to avoid hanging
            std::process::exit(0);
        }
    }

    Ok(())
}
