use std::sync::Arc;

use pkarr::Client as PkarrClient;
use pkarr::mainline::Dht;
use thiserror::Error;
use tonic_iroh_transport::iroh::Endpoint;
use tonic_iroh_transport::iroh::EndpointId;
use tonic_iroh_transport::iroh::address_lookup::IntoAddressLookupError;
use tonic_iroh_transport::iroh::address_lookup::mdns::MdnsAddressLookup;
use tonic_iroh_transport::iroh::address_lookup::pkarr::dht::DhtAddressLookup;
use tonic_iroh_transport::iroh::address_lookup::pkarr::{
    N0_DNS_PKARR_RELAY_PROD, N0_DNS_PKARR_RELAY_STAGING,
};
use tonic_iroh_transport::iroh::endpoint::BindError;

pub struct DiscoveryBindings {
    pub mdns: MdnsAddressLookup,
    pub dht: Arc<Dht>,
}

pub struct DiscoveryEndpoint {
    pub endpoint: Endpoint,
    pub bindings: DiscoveryBindings,
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("failed to create iroh endpoint")]
    BindEndpoint {
        #[source]
        source: BindError,
    },
    #[error("failed to start mDNS discovery")]
    BuildMdnsLookup {
        #[source]
        source: IntoAddressLookupError,
    },
    #[error("failed to initialize DHT client")]
    BuildDhtClient {
        #[source]
        source: std::io::Error,
    },
    #[error("failed to initialize pkarr client")]
    BuildPkarrClient {
        #[source]
        source: pkarr::errors::BuildError,
    },
    #[error("invalid pkarr relay URL: {relay}")]
    InvalidPkarrRelay { relay: &'static str },
    #[error("shared pkarr client has no DHT handle")]
    MissingDhtHandle,
    #[error("failed to initialize pkarr+DHT discovery")]
    BuildPkarrLookup {
        #[source]
        source: IntoAddressLookupError,
    },
}

fn n0_pkarr_relay() -> &'static str {
    if std::env::var_os("IROH_FORCE_STAGING_RELAYS").is_some() {
        N0_DNS_PKARR_RELAY_STAGING
    } else {
        N0_DNS_PKARR_RELAY_PROD
    }
}

impl DiscoveryBindings {
    pub fn client(endpoint_id: EndpointId) -> Result<Self, DiscoveryError> {
        let mdns = MdnsAddressLookup::builder()
            .advertise(false)
            .service_name("hellas")
            .build(endpoint_id)
            .map_err(|source| DiscoveryError::BuildMdnsLookup { source })?;
        let dht = Arc::new(Dht::client().map_err(|source| DiscoveryError::BuildDhtClient {
            source,
        })?);
        Ok(Self { mdns, dht })
    }

    pub fn attach(
        endpoint: &Endpoint,
        advertise_mdns: bool,
        publish_pkarr: bool,
    ) -> Result<Self, DiscoveryError> {
        let mdns = MdnsAddressLookup::builder()
            .advertise(advertise_mdns)
            .service_name("hellas")
            .build(endpoint.id())
            .map_err(|source| DiscoveryError::BuildMdnsLookup { source })?;
        endpoint.address_lookup().add(mdns.clone());

        let shared_pkarr = build_shared_pkarr_client()?;
        let dht = Arc::new(shared_pkarr.dht().ok_or(DiscoveryError::MissingDhtHandle)?);

        let mut pkarr = DhtAddressLookup::builder()
            .client(shared_pkarr)
            .n0_dns_pkarr_relay();
        if !publish_pkarr {
            pkarr = pkarr.no_publish();
        }
        let pkarr = pkarr
            .build()
            .map_err(|source| DiscoveryError::BuildPkarrLookup { source })?;
        endpoint.address_lookup().add(pkarr);

        Ok(Self { mdns, dht })
    }
}

impl DiscoveryEndpoint {
    pub async fn bind() -> Result<Self, DiscoveryError> {
        let endpoint = Endpoint::builder()
            .bind()
            .await
            .map_err(|source| DiscoveryError::BindEndpoint { source })?;
        let bindings = DiscoveryBindings::attach(&endpoint, false, false)?;
        Ok(Self { endpoint, bindings })
    }
}

fn build_shared_pkarr_client() -> Result<PkarrClient, DiscoveryError> {
    let mut builder = PkarrClient::builder();
    builder.no_default_network();
    builder.dht(|dht| dht);
    let relay = n0_pkarr_relay();
    builder
        .relays(&[relay])
        .map_err(|_| DiscoveryError::InvalidPkarrRelay { relay })?;
    builder
        .build()
        .map_err(|source| DiscoveryError::BuildPkarrClient { source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_bindings_builds_unattached_resources() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let endpoint_id = EndpointId::from_bytes(&bytes).expect("valid endpoint id");
        let bindings = DiscoveryBindings::client(endpoint_id).expect("client bindings");
        let _ = bindings.mdns;
        let _ = bindings.dht;
    }
}
