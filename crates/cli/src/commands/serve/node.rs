use super::peer_tracker::{PeerTracker, RequestKind, MAX_SERVICE_ALPN_LEN};
use crate::commands::common::{shared_pkarr_client, GRPC_MESSAGE_LIMIT};
use anyhow::Context;
use hellas_executor::{DownloadPolicy, ExecutePolicy, ExecuteServer, Executor};
use hellas_rpc::pb::hellas::node_server::{Node, NodeServer};
use hellas_rpc::pb::hellas::{
    GetKnownPeersRequest, GetKnownPeersResponse, HealthCheckRequest, HealthCheckResponse,
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tonic::{Request, Response, Status};
use tonic_iroh_transport::iroh::address_lookup::mdns::MdnsAddressLookup;
use tonic_iroh_transport::iroh::address_lookup::pkarr::dht::DhtAddressLookup;
use tonic_iroh_transport::iroh::endpoint::PathId;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::swarm::DhtBackend;
use tonic_iroh_transport::{IrohContext, TransportBuilder};

const DEFAULT_PORT: u16 = 31145;
const MAX_PORT_RETRIES: u16 = 100;

struct NodeService {
    start_time: Instant,
    node_id: String,
    peer_tracker: Arc<Mutex<PeerTracker>>,
}

#[derive(Clone)]
struct ExecutePeerInterceptor {
    peer_tracker: Arc<Mutex<PeerTracker>>,
}

impl tonic::service::Interceptor for ExecutePeerInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        if let Some((peer_id, observed_rtt)) = peer_observation(&request) {
            if let Ok(mut tracker) = self.peer_tracker.lock() {
                let _ = tracker.observe_request(peer_id, observed_rtt, RequestKind::ExecuteRpc);
            }
        }
        Ok(request)
    }
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn health_check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        if let Some((peer_id, observed_rtt)) = peer_observation(&request) {
            if let Ok(mut tracker) = self.peer_tracker.lock() {
                let _ = tracker.observe_request(peer_id, observed_rtt, RequestKind::HealthCheck);
            }
        }

        Ok(Response::new(HealthCheckResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            node_id: self.node_id.clone(),
        }))
    }

    async fn get_known_peers(
        &self,
        request: Request<GetKnownPeersRequest>,
    ) -> Result<Response<GetKnownPeersResponse>, Status> {
        let Some((requester_id, observed_rtt)) = peer_observation(&request) else {
            return Err(Status::unauthenticated("missing peer context"));
        };

        let req = request.into_inner();
        if req.service_alpn.len() > MAX_SERVICE_ALPN_LEN {
            if let Ok(mut tracker) = self.peer_tracker.lock() {
                tracker.mark_invalid_request(requester_id);
            }
            return Err(Status::invalid_argument(format!(
                "service_alpn too long (max {MAX_SERVICE_ALPN_LEN} bytes)"
            )));
        }

        let mut tracker = self
            .peer_tracker
            .lock()
            .map_err(|_| Status::internal("peer tracker is unavailable"))?;

        let admission =
            tracker.observe_request(requester_id, observed_rtt, RequestKind::GetKnownPeers);
        if !admission.allow {
            warn!(
                peer = %requester_id,
                "rate-limited get_known_peers request"
            );
            return Err(Status::resource_exhausted(
                "rate-limited get_known_peers request",
            ));
        }

        let peers = tracker.ranked_known_peers(
            requester_id,
            req.service_alpn.as_str(),
            admission.disclosure_limit,
        );
        let peer_ids = peers
            .into_iter()
            .map(|peer_id| peer_id.as_bytes().to_vec())
            .collect();

        Ok(Response::new(GetKnownPeersResponse { peer_ids }))
    }
}

fn peer_observation<T>(request: &Request<T>) -> Option<(EndpointId, Option<std::time::Duration>)> {
    let context = request.extensions().get::<IrohContext>()?;
    Some((context.node_id, context.connection.rtt(PathId::ZERO)))
}

pub(super) struct NodeHandle {
    endpoint: Endpoint,
    guard: tonic_iroh_transport::TransportGuard,
}

impl NodeHandle {
    pub(super) fn node_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub(super) async fn shutdown(self) -> anyhow::Result<()> {
        self.guard
            .shutdown()
            .await
            .context("failed to shut down transport")?;
        Ok(())
    }
}

pub(super) async fn spawn_node(
    port: Option<u16>,
    download_policy: DownloadPolicy,
    execute_policy: ExecutePolicy,
) -> anyhow::Result<NodeHandle> {
    let shared_pkarr = shared_pkarr_client().context("failed to initialize shared pkarr client")?;
    let shared_dht = Arc::new(
        shared_pkarr
            .dht()
            .ok_or_else(|| anyhow::anyhow!("shared pkarr client has no DHT handle"))?,
    );

    let endpoint = if let Some(port) = port {
        // Explicit port: fail if it can't bind.
        Endpoint::builder()
            .bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?
            .bind_addr(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))?
            .address_lookup(MdnsAddressLookup::builder().service_name("hellas"))
            .address_lookup(
                DhtAddressLookup::builder()
                    .client(shared_pkarr.clone())
                    .n0_dns_pkarr_relay(),
            )
            .bind()
            .await
            .with_context(|| format!("failed to bind on port {port}"))?
    } else {
        // Auto port: try DEFAULT_PORT, then increment until one works.
        let mut endpoint = None;
        for offset in 0..MAX_PORT_RETRIES {
            let p = DEFAULT_PORT.wrapping_add(offset);
            match Endpoint::builder()
                .bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, p))
                .and_then(|b| b.bind_addr(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, p, 0, 0)))
            {
                Ok(builder) => {
                    let builder = builder
                        .address_lookup(MdnsAddressLookup::builder().service_name("hellas"))
                        .address_lookup(
                            DhtAddressLookup::builder()
                                .client(shared_pkarr.clone())
                                .n0_dns_pkarr_relay(),
                        );
                    match builder.bind().await {
                        Ok(ep) => {
                            if offset > 0 {
                                info!("port {DEFAULT_PORT} in use, bound to port {p}");
                            }
                            endpoint = Some(ep);
                            break;
                        }
                        Err(e) => {
                            debug!("port {p} unavailable: {e:#}");
                        }
                    }
                }
                Err(e) => {
                    debug!("port {p} unavailable: {e:#}");
                }
            }
        }
        endpoint.ok_or_else(|| {
            anyhow::anyhow!(
                "failed to bind on any port in range {DEFAULT_PORT}..{}",
                DEFAULT_PORT + MAX_PORT_RETRIES
            )
        })?
    };

    let node_service = NodeService {
        start_time: Instant::now(),
        node_id: endpoint.id().to_string(),
        peer_tracker: Arc::new(Mutex::new(PeerTracker::new(endpoint.id()))),
    };

    let execute_interceptor = ExecutePeerInterceptor {
        peer_tracker: node_service.peer_tracker.clone(),
    };

    let executor = Executor::spawn(download_policy, execute_policy);
    let execute_service = ExecuteServer::new(executor)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
    let execute_service =
        tonic::service::interceptor::InterceptedService::new(execute_service, execute_interceptor);

    let mut transport = TransportBuilder::new(endpoint.clone())
        .add_rpc(NodeServer::new(node_service))
        .add_rpc(execute_service);

    let dht = DhtBackend::with_dht(&endpoint, shared_dht);
    let publisher = dht.create_publisher(Default::default());
    transport = transport.with_publisher(publisher);

    let guard = transport
        .spawn()
        .await
        .context("failed to start transport")?;

    Ok(NodeHandle { endpoint, guard })
}
