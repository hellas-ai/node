use anyhow::Context;
#[cfg(feature = "evaluate")]
use hellas_rpc::services::courtesy::Courtesy;
use hellas_rpc::services::fetch::Fetch;
use hellas_rpc::services::node::Node;
use hellas_rpc::services::work::Work;
use hellas_rpc::services::work_setup::WorkSetup;
use hellas_wire::ServiceMarker;
use hellas_wire::iroh::swarm::{DhtBackend, DhtPublisherConfig};
use iroh::Endpoint;
use iroh::endpoint_info::UserData;
use iroh_mdns_address_lookup::MdnsAddressLookup;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

pub(crate) struct DiscoveryAdvertiser {
    mdns: MdnsAddressLookup,
    shutdown: broadcast::Sender<()>,
    task: JoinHandle<()>,
}

impl DiscoveryAdvertiser {
    pub(crate) async fn shutdown(self) {
        let Self {
            mdns,
            shutdown,
            task,
        } = self;
        let _ = shutdown.send(());
        // DHT publication is disposable discovery state, and an in-flight
        // network write may not observe the signal promptly. Do not hold node
        // shutdown behind it.
        task.abort();
        let _ = task.await;
        drop(mdns);
    }
}

pub(crate) fn served_alpns(work_configured: bool) -> Vec<Vec<u8>> {
    let mut alpns = vec![
        Node::ALPN.as_bytes().to_vec(),
        Fetch::ALPN.as_bytes().to_vec(),
    ];
    #[cfg(feature = "evaluate")]
    alpns.push(Courtesy::ALPN.as_bytes().to_vec());
    if work_configured {
        alpns.extend([
            WorkSetup::ALPN.as_bytes().to_vec(),
            Work::ALPN.as_bytes().to_vec(),
        ]);
    }
    alpns
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_capabilities_match_the_compiled_node() {
        #[cfg(feature = "evaluate")]
        assert_eq!(
            served_alpns(false),
            [
                Node::ALPN.as_bytes(),
                Fetch::ALPN.as_bytes(),
                Courtesy::ALPN.as_bytes(),
            ]
        );
        #[cfg(not(feature = "evaluate"))]
        assert_eq!(
            served_alpns(false),
            [Node::ALPN.as_bytes(), Fetch::ALPN.as_bytes()]
        );
    }

    #[test]
    fn work_config_advertises_exactly_both_work_alpns_with_node() {
        #[cfg(feature = "evaluate")]
        assert_eq!(
            served_alpns(true),
            [
                Node::ALPN.as_bytes(),
                Fetch::ALPN.as_bytes(),
                Courtesy::ALPN.as_bytes(),
                WorkSetup::ALPN.as_bytes(),
                Work::ALPN.as_bytes(),
            ]
        );
        #[cfg(not(feature = "evaluate"))]
        assert_eq!(
            served_alpns(true),
            [
                Node::ALPN.as_bytes(),
                Fetch::ALPN.as_bytes(),
                WorkSetup::ALPN.as_bytes(),
                Work::ALPN.as_bytes(),
            ]
        );
    }
}
