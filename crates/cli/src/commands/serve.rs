use hellas_rpc::pb::hellas::node_server::{Node, NodeServer};
use hellas_rpc::pb::hellas::{PingRequest, PingResponse};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tonic_iroh_transport::iroh::protocol::Router;
use tonic_iroh_transport::GrpcProtocolHandler;

struct NodeService;

#[tonic::async_trait]
impl Node for NodeService {
    async fn ping(&self, _request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        Ok(Response::new(PingResponse {}))
    }
}

pub async fn run() {
    let endpoint = tonic_iroh_transport::iroh::Endpoint::builder()
        .bind()
        .await
        .expect("Failed to create iroh endpoint");

    println!("Node Address: {}", endpoint.id());

    let (handler, incoming, alpn) = GrpcProtocolHandler::for_service::<NodeServer<NodeService>>();

    let _router = Router::builder(endpoint).accept(alpn, handler).spawn();

    Server::builder()
        .add_service(NodeServer::new(NodeService))
        .serve_with_incoming(incoming)
        .await
        .expect("Server failed");
}
