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
use hellas_rpc::peers::{
    DiscoverySource, InboundAdmission, IrohPeerExtractor, PeerDirectory, PeerId, ServiceKey,
    TransportSecurity,
};
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use hellas_rpc::server::ManagedServer;
use hellas_rpc::service::{
    CourtesyService as CourtesyRpcService, ExecuteService as ExecuteRpcService,
    NodeService as NodeRpcService, OpaqueService as OpaqueRpcService,
    SymbolicService as SymbolicRpcService,
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tonic::codec::CompressionEncoding;
use tonic::{Request, Response, Status};
use tonic_iroh_transport::iroh::address_lookup::{DnsAddressLookup, PkarrPublisher};
use tonic_iroh_transport::iroh::endpoint::presets;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::swarm::{DhtBackend, MdnsBackend, ServiceRegistry};
use tonic_iroh_transport::{PoolOptions, TransportBuilder};

// `traced_service` wraps a tonic service with W3C trace context extraction when
// the `otel` feature is on; with the feature off it returns the service
// unchanged so the trace layer compiles to nothing.
#[cfg(feature = "otel")]
fn traced_service<S>(svc: S) -> tonic_iroh_transport::otel::TraceContextService<S> {
    tower::Layer::layer(&tonic_iroh_transport::otel::TraceContextLayer, svc)
}
#[cfg(not(feature = "otel"))]
fn traced_service<S>(svc: S) -> S {
    svc
}

const DEFAULT_PORT: u16 = 31145;
const MAX_PORT_RETRIES: u16 = 100;

struct NodeService {
    start_time: Instant,
    node_id: String,
    build: String,
    graffiti: Vec<u8>,
    peer_directory: PeerDirectory,
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn get_node_info(
        &self,
        _request: Request<GetNodeInfoRequest>,
    ) -> Result<Response<GetNodeInfoResponse>, Status> {
        // Admission is handled by the `ManagedServer<NodeService, …>` wrapper
        // around this tonic server — no per-method observe call needed here.
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
        // Admission ran in the wrapper and stashed the result. If it didn't
        // (no wrapper installed, e.g. a future direct-mount path) we fall
        // back to the most conservative defaults.
        let admission = request
            .extensions()
            .get::<InboundAdmission>()
            .copied()
            .unwrap_or(InboundAdmission {
                allow: true,
                disclosure_limit: 8,
            });
        let requester_id = request
            .extensions()
            .get::<tonic_iroh_transport::IrohContext>()
            .map(|ctx| ctx.node_id)
            .ok_or_else(|| Status::unauthenticated("missing peer context"))?;
        let requester = PeerId::from(requester_id);

        let req = request.into_inner();
        let max_service_filter_len = self.peer_directory.max_service_filter_len();
        if req.service_alpn.len() > max_service_filter_len {
            let _ = self.peer_directory.observe_invalid_request(requester);
            return Err(Status::invalid_argument(format!(
                "service_alpn too long (max {max_service_filter_len} bytes)"
            )));
        }

        let peers = self
            .peer_directory
            .ranked_known_peers(
                requester,
                req.service_alpn.as_str(),
                admission.disclosure_limit,
            )
            .map_err(|_| Status::internal("peer directory is unavailable"))?;
        let peer_ids = peers
            .into_iter()
            .map(|peer_id| peer_id.as_bytes().to_vec())
            .collect();

        Ok(Response::new(GetKnownPeersResponse { peer_ids }))
    }
}

fn observe_discovered_peer_service<S: ServiceKey>(
    peer_directory: &PeerDirectory,
    peer_id: EndpointId,
) {
    let _ = peer_directory.observe_discovered_service::<S>(
        PeerId::from(peer_id),
        DiscoverySource::Transport("discovery"),
        TransportSecurity::Untrusted,
    );
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

    /// Snapshot of iroh's internal metrics. The returned `EndpointMetrics`
    /// contains `Arc`s into the live metric storage, so values continue to
    /// update as iroh records them.
    #[cfg(feature = "otel")]
    pub(super) fn iroh_metrics(&self) -> tonic_iroh_transport::iroh::metrics::EndpointMetrics {
        self.guard.endpoint().metrics().clone()
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
        peer_directory: PeerDirectory::new(PeerId::from(endpoint.id())),
    };

    let peer_directory = node_service.peer_directory.clone();

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

    // Every inbound RPC is gated through the typed admission wrapper; the
    // service impls themselves are free of per-method observe_inbound_request
    // calls and method-name strings.
    let mut transport = TransportBuilder::new(endpoint.clone())
        .add_rpc(traced_service(ManagedServer::<NodeRpcService, _, _>::new(
            NodeServer::new(node_service),
            peer_directory.clone(),
            IrohPeerExtractor,
        )))
        .add_rpc(traced_service(
            ManagedServer::<ExecuteRpcService, _, _>::new(
                execute_service,
                peer_directory.clone(),
                IrohPeerExtractor,
            ),
        ))
        .add_rpc(traced_service(
            ManagedServer::<SymbolicRpcService, _, _>::new(
                symbolic_service,
                peer_directory.clone(),
                IrohPeerExtractor,
            ),
        ))
        .add_rpc(traced_service(
            ManagedServer::<OpaqueRpcService, _, _>::new(
                opaque_service,
                peer_directory.clone(),
                IrohPeerExtractor,
            ),
        ))
        .add_rpc(traced_service(
            ManagedServer::<CourtesyRpcService, _, _>::new(
                courtesy_service,
                peer_directory.clone(),
                IrohPeerExtractor,
            ),
        ));

    let dht = DhtBackend::with_dht(&endpoint, Arc::clone(&shared_dht));
    let publisher = dht.create_publisher(Default::default());
    transport = transport.with_publisher(publisher);

    let guard = transport
        .spawn()
        .await
        .context("failed to start transport")?;

    // Background peer discovery: watch DHT + mDNS for other executors and
    // feed them into the peer directory so GetKnownPeers returns useful results.
    {
        let peer_directory = peer_directory.clone();
        let disc_endpoint = endpoint.clone();
        let disc_dht = DhtBackend::with_dht(&disc_endpoint, Arc::clone(&shared_dht));
        tokio::spawn(async move {
            let Ok(bindings) = DiscoveryBindings::client(disc_endpoint.id()) else {
                warn!("failed to create discovery bindings for peer directory");
                return;
            };
            let mut registry = ServiceRegistry::new(&disc_endpoint);
            registry.with_pool_options(PoolOptions::default());
            registry.add(MdnsBackend::new(bindings.mdns));
            registry.add(disc_dht);
            let mut node_peers = Box::pin(registry.discover::<NodeRpcService>());
            let mut exec_peers = Box::pin(registry.discover::<ExecuteRpcService>());
            let mut symbolic_peers = Box::pin(registry.discover::<SymbolicRpcService>());
            let mut opaque_peers = Box::pin(registry.discover::<OpaqueRpcService>());
            let mut courtesy_peers = Box::pin(registry.discover::<CourtesyRpcService>());
            loop {
                tokio::select! {
                    Some(Ok(peer)) = node_peers.next() => {
                        observe_discovered_peer_service::<NodeRpcService>(&peer_directory, peer.id());
                    }
                    Some(Ok(peer)) = exec_peers.next() => {
                        observe_discovered_peer_service::<ExecuteRpcService>(&peer_directory, peer.id());
                    }
                    Some(Ok(peer)) = symbolic_peers.next() => {
                        observe_discovered_peer_service::<SymbolicRpcService>(&peer_directory, peer.id());
                    }
                    Some(Ok(peer)) = opaque_peers.next() => {
                        observe_discovered_peer_service::<OpaqueRpcService>(&peer_directory, peer.id());
                    }
                    Some(Ok(peer)) = courtesy_peers.next() => {
                        observe_discovered_peer_service::<CourtesyRpcService>(&peer_directory, peer.id());
                    }
                    else => break,
                };
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
