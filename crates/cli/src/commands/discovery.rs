use anyhow::Context;
#[cfg(feature = "hellas-executor")]
use hellas_rpc::services::courtesy::Courtesy;
#[cfg(feature = "hellas-executor")]
use hellas_rpc::services::evaluate::Evaluate;
#[cfg(feature = "hellas-executor")]
use hellas_rpc::services::execute::Execute;
#[cfg(feature = "hellas-executor")]
use hellas_rpc::services::fetch::Fetch;
#[cfg(feature = "hellas-executor")]
use hellas_rpc::services::node::Node;
#[cfg(feature = "hellas-executor")]
use hellas_wire::ServiceMarker;
#[cfg(feature = "hellas-executor")]
use hellas_wire::iroh::swarm::DhtPublisherConfig;
use hellas_wire::iroh::swarm::{DhtBackend, MdnsBackend, PeerExchangeBackend, ServiceRegistry};
use iroh::Endpoint;
#[cfg(feature = "hellas-executor")]
use iroh::endpoint_info::UserData;
use iroh_mdns_address_lookup::MdnsAddressLookup;
#[cfg(feature = "hellas-executor")]
use tokio::sync::broadcast;
#[cfg(feature = "hellas-executor")]
use tokio::task::JoinHandle;

pub(crate) struct DiscoveryRegistry {
    pub(crate) registry: ServiceRegistry,
    pub(crate) peer_exchange: PeerExchangeBackend,
}

#[cfg(feature = "hellas-executor")]
pub(crate) struct DiscoveryAdvertiser {
    mdns: MdnsAddressLookup,
    shutdown: broadcast::Sender<()>,
    task: JoinHandle<()>,
}

#[cfg(feature = "hellas-executor")]
impl DiscoveryAdvertiser {
    pub(crate) async fn shutdown(self) {
        let Self {
            mdns,
            shutdown,
            task,
        } = self;
        let _ = shutdown.send(());
        let _ = task.await;
        drop(mdns);
    }
}

#[cfg(feature = "hellas-executor")]
pub(crate) fn served_alpns() -> Vec<Vec<u8>> {
    vec![
        Execute::ALPN.as_bytes().to_vec(),
        Evaluate::ALPN.as_bytes().to_vec(),
        Fetch::ALPN.as_bytes().to_vec(),
        Courtesy::ALPN.as_bytes().to_vec(),
        Node::ALPN.as_bytes().to_vec(),
    ]
}

pub(crate) fn build_client_registry(endpoint: &Endpoint) -> anyhow::Result<DiscoveryRegistry> {
    let mdns = MdnsAddressLookup::builder()
        .advertise(false)
        .build(endpoint.id())
        .context("failed to start mDNS discovery")?;
    endpoint
        .address_lookup()
        .context("iroh endpoint has no address lookup registry")?
        .add(mdns.clone());

    let dht = DhtBackend::new(endpoint).context("failed to start DHT discovery")?;
    let peer_exchange = PeerExchangeBackend::new();

    let mut registry = ServiceRegistry::new(endpoint);
    registry.add(MdnsBackend::new(mdns));
    registry.add(dht);
    registry.add(peer_exchange.clone());

    Ok(DiscoveryRegistry {
        registry,
        peer_exchange,
    })
}

#[cfg(feature = "hellas-executor")]
pub(crate) fn start_server_advertising(
    endpoint: &Endpoint,
    alpns: &[Vec<u8>],
) -> anyhow::Result<DiscoveryAdvertiser> {
    let encoded = hellas_wire::iroh::swarm::mdns::encode_alpns(alpns)
        .context("service ALPN metadata is too large for mDNS")?;
    let user_data: UserData = encoded
        .parse()
        .context("failed to encode service metadata")?;
    endpoint.set_user_data_for_address_lookup(Some(user_data));

    let mdns = MdnsAddressLookup::builder()
        .build(endpoint.id())
        .context("failed to start mDNS advertising")?;
    endpoint
        .address_lookup()
        .context("iroh endpoint has no address lookup registry")?
        .add(mdns.clone());

    let dht = DhtBackend::new(endpoint).context("failed to start DHT publisher")?;
    let mut publisher = dht.create_publisher(DhtPublisherConfig::default());
    for alpn in alpns {
        publisher.add_service(alpn.clone());
    }
    let (shutdown, shutdown_rx) = broadcast::channel(1);
    let task = tokio::spawn(publisher.run(shutdown_rx));

    Ok(DiscoveryAdvertiser {
        mdns,
        shutdown,
        task,
    })
}
