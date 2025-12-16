use anyhow::Context;
use hellas_executor::{ExecuteServer, Executor};
use hellas_rpc::pb::hellas::node_server::{Node, NodeServer};
use hellas_rpc::pb::hellas::{HealthCheckRequest, HealthCheckResponse, Presence};
use std::time::Instant;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tonic_iroh_transport::gossip::{topic_for, GossipHandler, GossipRequest};
use tonic_iroh_transport::iroh::discovery::mdns::MdnsDiscovery;
use tonic_iroh_transport::iroh::discovery::EndpointData;
use tonic_iroh_transport::iroh::discovery::pkarr::dht::DhtDiscovery;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId, TransportAddr};
use tonic_iroh_transport::TransportBuilder;
use tonic_iroh_transport::iroh::discovery::Discovery;
use tonic_iroh_transport::iroh::Watcher;
use std::net::Ipv6Addr;
use std::net::SocketAddrV6;

const GRPC_MESSAGE_LIMIT: usize = 32 * 1024 * 1024;
const DEFAULT_PORT: u16 = 31145;

#[derive(Clone)]
struct PresenceResponder {
    endpoint_id: EndpointId,
}

#[tonic::async_trait]
impl GossipHandler<Presence> for PresenceResponder {
    async fn handle(&self, request: GossipRequest<Presence>) -> Result<(), Status> {
        let msg = request.get_ref();
        if msg.is_executor {
            return Ok(());
        }

        info!(
            hf_id = %msg.hf_id,
            req_id = %msg.req_id,
            from = %request.context().delivered_from.fmt_short(),
            "responding to presence request"
        );

        let reply = Presence {
            hf_id: msg.hf_id.clone(),
            req_id: msg.req_id.clone(),
            peer_id: self.endpoint_id.to_string(),
            ttl_ms: msg.ttl_ms,
            is_executor: true,
        };

        request
            .sender()
            .broadcast(&reply)
            .await
            .map_err(|e| Status::internal(format!("failed to broadcast presence reply: {e}")))?;

        Ok(())
    }
}

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

pub(super) struct NodeHandle {
    endpoint: Endpoint,
    guard: tonic_iroh_transport::TransportGuard,
    addr_task: tokio::task::JoinHandle<()>,
}

impl NodeHandle {
    pub(super) fn node_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub(super) async fn shutdown(self) -> anyhow::Result<()> {
        self.addr_task.abort();
        let _ = self.addr_task.await;
        self.guard
            .shutdown()
            .await
            .context("failed to shut down transport")?;
        Ok(())
    }
}

pub(super) async fn spawn_node(enable_discovery: bool) -> anyhow::Result<NodeHandle> {
    let mut builder = Endpoint::builder()
        .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DEFAULT_PORT))
        .bind_addr_v6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEFAULT_PORT, 0, 0));

    if enable_discovery {
        builder = builder
            .discovery(MdnsDiscovery::builder().service_name("hellas"))
            // Adds internet discovery (DHT + optional pkarr relay); `Endpoint::builder()`
            // already includes pkarr publisher + DNS resolver via the N0 preset.
            .discovery(DhtDiscovery::builder().n0_dns_pkarr_relay());
    } else {
        builder = builder.clear_discovery();
    }

    let endpoint = builder
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    // Seed discovery with current addresses and keep publishing updates.
    let discovery = endpoint.discovery().clone();
    let mut addr_stream = endpoint.watch_addr().stream();
    let addr_task = tokio::spawn(async move {
        while let Some(addr) = addr_stream.next().await {
            let addrs: Vec<_> = addr.ip_addrs().map(|a| TransportAddr::Ip(*a)).collect();
            if addrs.is_empty() {
                continue;
            }
            info!("discovery: {addrs:?}");
            let data = EndpointData::new(addrs);
            discovery.publish(&data);
        }
    });

    let node_service = NodeService {
        start_time: Instant::now(),
        node_id: endpoint.id().to_string(),
    };

    let executor = Executor::spawn();
    let execute_service = ExecuteServer::new(executor)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);

    let presence_responder = PresenceResponder {
        endpoint_id: endpoint.id(),
    };

    let guard = TransportBuilder::new(endpoint.clone())
        .add_gossip::<Presence, _>(presence_responder)
        .add_rpc(NodeServer::new(node_service))
        .add_rpc(execute_service)
        .spawn()
        .await
        .context("failed to start transport")?;

    info!(
        topic = ?topic_for::<Presence>(),
        "listening for gossip presence requests"
    );

    Ok(NodeHandle { endpoint, guard, addr_task })
}
