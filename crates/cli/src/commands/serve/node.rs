use anyhow::Context;
use hellas_executor::{ExecuteServer, Executor};
use hellas_rpc::pb::hellas::node_server::{Node, NodeServer};
use hellas_rpc::pb::hellas::{
    GetKnownPeersRequest, GetKnownPeersResponse, HealthCheckRequest, HealthCheckResponse,
};
use pkarr::Client as PkarrClient;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Instant;
use tonic::{Request, Response, Status};
use tonic_iroh_transport::iroh::address_lookup::mdns::MdnsAddressLookup;
use tonic_iroh_transport::iroh::address_lookup::pkarr::dht::DhtAddressLookup;
use tonic_iroh_transport::iroh::address_lookup::pkarr::{
    N0_DNS_PKARR_RELAY_PROD, N0_DNS_PKARR_RELAY_STAGING,
};
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::swarm::DhtBackend;
use tonic_iroh_transport::TransportBuilder;

const GRPC_MESSAGE_LIMIT: usize = 32 * 1024 * 1024;
const DEFAULT_PORT: u16 = 31145;

fn n0_pkarr_relay() -> &'static str {
    if std::env::var_os("IROH_FORCE_STAGING_RELAYS").is_some() {
        N0_DNS_PKARR_RELAY_STAGING
    } else {
        N0_DNS_PKARR_RELAY_PROD
    }
}

fn shared_pkarr_client() -> anyhow::Result<PkarrClient> {
    let mut builder = PkarrClient::builder();
    builder.no_default_network();
    builder.dht(|dht| dht);
    builder
        .relays(&[n0_pkarr_relay()])
        .map_err(|err| anyhow::anyhow!("failed to configure pkarr relay: {err}"))?;
    let client = builder
        .build()
        .map_err(|err| anyhow::anyhow!("failed to build pkarr client: {err}"))?;
    Ok(client)
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

    async fn get_known_peers(
        &self,
        _request: Request<GetKnownPeersRequest>,
    ) -> Result<Response<GetKnownPeersResponse>, Status> {
        // TODO: track connected peers and return them for transitive discovery
        Ok(Response::new(GetKnownPeersResponse { peer_ids: vec![] }))
    }
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

pub(super) async fn spawn_node() -> anyhow::Result<NodeHandle> {
    let shared_pkarr = shared_pkarr_client().context("failed to initialize shared pkarr client")?;
    let shared_dht = Arc::new(
        shared_pkarr
            .dht()
            .ok_or_else(|| anyhow::anyhow!("shared pkarr client has no DHT handle"))?,
    );

    let builder = Endpoint::builder()
        .bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DEFAULT_PORT))?
        .bind_addr(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEFAULT_PORT, 0, 0))?
        .address_lookup(MdnsAddressLookup::builder().service_name("hellas"))
        .address_lookup(
            DhtAddressLookup::builder()
                .client(shared_pkarr)
                .n0_dns_pkarr_relay(),
        );

    let endpoint = builder
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    let node_service = NodeService {
        start_time: Instant::now(),
        node_id: endpoint.id().to_string(),
    };

    let executor = Executor::spawn();
    let execute_service = ExecuteServer::new(executor)
        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);

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
