use super::peer_tracker::{MAX_SERVICE_ALPN_LEN, PeerTracker, RequestKind};
use anyhow::Context;
use catgrad::prelude::Dtype;
use futures::StreamExt;
use futures::future::try_join_all;
use hellas_core::ProducerSigningKey;
use hellas_executor::{
    ArtifactStoreConfig, CourtesyServer, ExecuteServer, Executor, ExecutorMetrics, OpaqueServer,
    SymbolicServer,
};
use hellas_pb::swarm::node_server::{Node, NodeServer};
use hellas_pb::swarm::{
    GetKnownPeersRequest, GetKnownPeersResponse, GetNodeInfoRequest, GetNodeInfoResponse,
};
use hellas_rpc::GRPC_MESSAGE_LIMIT;
use hellas_rpc::discovery::DiscoveryBindings;
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tonic::codec::CompressionEncoding;
use tonic::service::interceptor::InterceptedService;
use tonic::{Request, Response, Status};
use tonic_iroh_transport::iroh::address_lookup::{DnsAddressLookup, PkarrPublisher};
use tonic_iroh_transport::iroh::endpoint::{PathId, presets};
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::otel::TraceContextLayer;
use tonic_iroh_transport::swarm::{DhtBackend, MdnsBackend, ServiceRegistry};
use tonic_iroh_transport::{IrohContext, PoolOptions, TransportBuilder};

const DEFAULT_PORT: u16 = 31145;
const MAX_PORT_RETRIES: u16 = 100;

struct NodeService {
    start_time: Instant,
    node_id: String,
    build: String,
    graffiti: Vec<u8>,
    peer_tracker: Arc<Mutex<PeerTracker>>,
}

#[derive(Clone)]
struct ExecutePeerInterceptor {
    peer_tracker: Arc<Mutex<PeerTracker>>,
}

impl tonic::service::Interceptor for ExecutePeerInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        if let Some((peer_id, observed_rtt)) = peer_observation(&request)
            && let Ok(mut tracker) = self.peer_tracker.lock()
        {
            let _ = tracker.observe_request(peer_id, observed_rtt, RequestKind::ExecuteRpc);
        }
        Ok(request)
    }
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn get_node_info(
        &self,
        request: Request<GetNodeInfoRequest>,
    ) -> Result<Response<GetNodeInfoResponse>, Status> {
        if let Some((peer_id, observed_rtt)) = peer_observation(&request)
            && let Ok(mut tracker) = self.peer_tracker.lock()
        {
            let _ = tracker.observe_request(peer_id, observed_rtt, RequestKind::GetNodeInfo);
        }

        Ok(Response::new(GetNodeInfoResponse {
            node_id: self.node_id.clone(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            build: self.build.clone(),
            os: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            graffiti: self.graffiti.clone(),
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

async fn bind_endpoint(
    secret_key: tonic_iroh_transport::iroh::SecretKey,
    port: u16,
) -> anyhow::Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .clear_address_lookup()
        .address_lookup(PkarrPublisher::n0_dns())
        .address_lookup(DnsAddressLookup::n0_dns())
        .bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?
        .bind_addr(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))?
        .bind()
        .await
        .map_err(Into::into)
}

pub(super) struct NodeHandle {
    node_id: EndpointId,
    guard: tonic_iroh_transport::TransportGuard,
}

impl NodeHandle {
    pub(super) fn node_id(&self) -> EndpointId {
        self.node_id
    }

    pub(super) async fn shutdown(self) -> anyhow::Result<()> {
        let Self { guard, .. } = self;
        guard.endpoint().close().await;
        drop(guard);
        Ok(())
    }
}

pub(super) async fn spawn_node(
    port: Option<u16>,
    download_policy: DownloadPolicy,
    execute_policy: ExecutePolicy,
    queue_size: usize,
    preload_weights: Vec<String>,
    build: String,
    graffiti: Vec<u8>,
    supported_dtypes: Vec<Dtype>,
    artifact_store_path: PathBuf,
    secret_key: tonic_iroh_transport::iroh::SecretKey,
    producer_key: ProducerSigningKey,
    metrics: Arc<ExecutorMetrics>,
) -> anyhow::Result<NodeHandle> {
    let endpoint = if let Some(port) = port {
        // Explicit port: fail if it can't bind.
        bind_endpoint(secret_key.clone(), port)
            .await
            .with_context(|| format!("failed to bind on port {port}"))?
    } else {
        // Auto port: try DEFAULT_PORT, then increment until one works.
        let mut endpoint = None;
        for offset in 0..MAX_PORT_RETRIES {
            let p = DEFAULT_PORT.wrapping_add(offset);
            match bind_endpoint(secret_key.clone(), p).await {
                Ok(ep) => {
                    if offset > 0 {
                        info!("port {DEFAULT_PORT} in use, bound to port {p}");
                    }
                    endpoint = Some(ep);
                    break;
                }
                Err(e) => debug!("port {p} unavailable: {e:#}"),
            }
        }
        endpoint.ok_or_else(|| {
            anyhow::anyhow!(
                "failed to bind on any port in range {DEFAULT_PORT}..{}",
                DEFAULT_PORT + MAX_PORT_RETRIES
            )
        })?
    };
    let shared_dht = DiscoveryBindings::attach(&endpoint, true, true)
        .context("failed to attach node discovery lookups")?
        .dht;

    let node_service = NodeService {
        start_time: Instant::now(),
        node_id: endpoint.id().to_string(),
        build,
        graffiti,
        peer_tracker: Arc::new(Mutex::new(PeerTracker::new(endpoint.id()))),
    };

    let peer_tracker = node_service.peer_tracker.clone();

    let execute_interceptor = ExecutePeerInterceptor {
        peer_tracker: peer_tracker.clone(),
    };

    info!(
        path = %artifact_store_path.display(),
        "using persistent artifact blob store"
    );
    let executor = Executor::spawn_with_metrics_and_producer_key_and_artifact_store(
        download_policy,
        execute_policy,
        queue_size,
        supported_dtypes,
        metrics,
        Arc::new(producer_key),
        ArtifactStoreConfig::fs(artifact_store_path.clone()),
    )
    .await
    .context("failed to initialize executor backend")?;

    let execute_service = ExecuteServer::new(executor.clone())
        .accept_compressed(CompressionEncoding::Zstd)
        .send_compressed(CompressionEncoding::Zstd)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
    let symbolic_service = SymbolicServer::new(executor.clone())
        .accept_compressed(CompressionEncoding::Zstd)
        .send_compressed(CompressionEncoding::Zstd)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
    let opaque_service = OpaqueServer::new(executor.clone())
        .accept_compressed(CompressionEncoding::Zstd)
        .send_compressed(CompressionEncoding::Zstd)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
    let courtesy_service = CourtesyServer::new(executor.clone())
        .accept_compressed(CompressionEncoding::Zstd)
        .send_compressed(CompressionEncoding::Zstd)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);

    let trace_layer = TraceContextLayer;

    let mut transport = TransportBuilder::new(endpoint.clone())
        .add_rpc(trace_layer.layer(NodeServer::new(node_service)))
        .add_rpc(InterceptedService::new(
            trace_layer.layer(execute_service),
            execute_interceptor.clone(),
        ))
        .add_rpc(InterceptedService::new(
            trace_layer.layer(symbolic_service),
            execute_interceptor.clone(),
        ))
        .add_rpc(InterceptedService::new(
            trace_layer.layer(opaque_service),
            execute_interceptor,
        ))
        .add_rpc(trace_layer.layer(courtesy_service));

    let dht = DhtBackend::with_dht(&endpoint, Arc::clone(&shared_dht));
    let publisher = dht.create_publisher(Default::default());
    transport = transport.with_publisher(publisher);

    let guard = transport
        .spawn()
        .await
        .context("failed to start transport")?;

    // Background peer discovery: watch DHT + mDNS for other executors and
    // feed them into the PeerTracker so GetKnownPeers returns useful results.
    {
        let peer_tracker = peer_tracker.clone();
        let disc_endpoint = endpoint.clone();
        let disc_dht = DhtBackend::with_dht(&disc_endpoint, Arc::clone(&shared_dht));
        tokio::spawn(async move {
            use hellas_rpc::service::{
                CourtesyService as CourtesySvc, ExecuteService as ExecSvc, NodeService as NodeSvc,
                OpaqueService as OpaqueSvc, SymbolicService as SymbolicSvc,
            };
            let Ok(bindings) = DiscoveryBindings::client(disc_endpoint.id()) else {
                warn!("failed to create discovery bindings for peer tracker");
                return;
            };
            let mut registry = ServiceRegistry::new(&disc_endpoint);
            registry.with_pool_options(PoolOptions::default());
            registry.add(MdnsBackend::new(bindings.mdns));
            registry.add(disc_dht);
            let mut node_peers = Box::pin(registry.discover::<NodeSvc>());
            let mut exec_peers = Box::pin(registry.discover::<ExecSvc>());
            let mut symbolic_peers = Box::pin(registry.discover::<SymbolicSvc>());
            let mut opaque_peers = Box::pin(registry.discover::<OpaqueSvc>());
            let mut courtesy_peers = Box::pin(registry.discover::<CourtesySvc>());
            loop {
                let peer_id = tokio::select! {
                    Some(Ok(peer)) = node_peers.next() => peer.id(),
                    Some(Ok(peer)) = exec_peers.next() => peer.id(),
                    Some(Ok(peer)) = symbolic_peers.next() => peer.id(),
                    Some(Ok(peer)) = opaque_peers.next() => peer.id(),
                    Some(Ok(peer)) = courtesy_peers.next() => peer.id(),
                    else => break,
                };
                if let Ok(mut tracker) = peer_tracker.lock() {
                    tracker.mark_service_provider(peer_id);
                }
            }
        });
    }

    // Preload weights in the background so the node is reachable immediately.
    if !preload_weights.is_empty() {
        let count = preload_weights.len();
        info!(count, "preloading startup weights in background");
        let preload_executor = executor.clone();
        tokio::spawn(async move {
            let results = try_join_all(preload_weights.into_iter().map(|model| {
                let executor = preload_executor.clone();
                async move {
                    executor
                        .preload_weights(model.clone())
                        .await
                        .with_context(|| format!("failed to preload weights for {model}"))
                }
            }))
            .await;
            match results {
                Ok(_) => info!(count, "startup weight preload complete"),
                Err(e) => warn!("startup weight preload failed: {e:#}"),
            }
        });
    }

    Ok(NodeHandle {
        node_id: endpoint.id(),
        guard,
    })
}
