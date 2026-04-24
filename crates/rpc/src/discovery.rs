use std::sync::Arc;

use mainline::Dht;
use thiserror::Error;
use tonic_iroh_transport::iroh::Endpoint;
use tonic_iroh_transport::iroh::EndpointId;
use tonic_iroh_transport::iroh::SecretKey;
use tonic_iroh_transport::iroh::address_lookup::AddressLookupBuilderError;
use tonic_iroh_transport::iroh::address_lookup::mdns::MdnsAddressLookup;
use tonic_iroh_transport::iroh::address_lookup::pkarr::dht::DhtAddressLookup;
use tonic_iroh_transport::iroh::endpoint::{BindError, EndpointError, presets};

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
        source: AddressLookupBuilderError,
    },
    #[error("failed to initialize DHT client")]
    BuildDhtClient {
        #[source]
        source: std::io::Error,
    },
    #[error("failed to initialize DHT address lookup")]
    BuildPkarrLookup {
        #[source]
        source: AddressLookupBuilderError,
    },
    #[error("failed to access endpoint address lookup services")]
    AddressLookupUnavailable {
        #[source]
        source: EndpointError,
    },
}

impl DiscoveryBindings {
    pub fn client(endpoint_id: EndpointId) -> Result<Self, DiscoveryError> {
        let mdns = MdnsAddressLookup::builder()
            .advertise(false)
            .service_name("hellas")
            .build(endpoint_id)
            .map_err(|source| DiscoveryError::BuildMdnsLookup { source })?;
        let dht =
            Arc::new(Dht::client().map_err(|source| DiscoveryError::BuildDhtClient { source })?);
        Ok(Self { mdns, dht })
    }

    pub fn attach(
        endpoint: &Endpoint,
        advertise_mdns: bool,
        publish_pkarr: bool,
    ) -> Result<Self, DiscoveryError> {
        let address_lookup = endpoint
            .address_lookup()
            .map_err(|source| DiscoveryError::AddressLookupUnavailable { source })?;
        let mdns = MdnsAddressLookup::builder()
            .advertise(advertise_mdns)
            .service_name("hellas")
            .build(endpoint.id())
            .map_err(|source| DiscoveryError::BuildMdnsLookup { source })?;
        address_lookup.add(mdns.clone());

        // Standalone DHT handle for the sharded-service DhtBackend; iroh's
        // DhtAddressLookup builds its own Dht internally (0.98 changed the
        // constructor to take a DhtBuilder rather than a shared pkarr client).
        let dht = Arc::new(Dht::client().map_err(|source| DiscoveryError::BuildDhtClient { source })?);

        let mut dht_lookup = DhtAddressLookup::builder();
        if !publish_pkarr {
            dht_lookup = dht_lookup.no_publish();
        }
        let dht_lookup = dht_lookup
            .build()
            .map_err(|source| DiscoveryError::BuildPkarrLookup { source })?;
        address_lookup.add(dht_lookup);

        Ok(Self { mdns, dht })
    }
}

impl DiscoveryEndpoint {
    pub async fn bind(secret_key: Option<SecretKey>) -> Result<Self, DiscoveryError> {
        let mut builder = Endpoint::builder(presets::N0);
        if let Some(key) = secret_key {
            builder = builder.secret_key(key);
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|source| DiscoveryError::BindEndpoint { source })?;
        let bindings = DiscoveryBindings::attach(&endpoint, false, false)?;
        Ok(Self { endpoint, bindings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `DiscoveryBindings::client` internally calls `MdnsAddressLookup::builder().build()`,
    // which spawns a background task and so needs a running Tokio runtime.
    #[tokio::test]
    async fn client_bindings_builds_unattached_resources() {
        // EndpointId is an Ed25519 public key — not every 32-byte sequence
        // decompresses to a valid Edwards point. Any 32-byte secret does
        // yield a valid public key though, so derive one deterministically.
        let endpoint_id = SecretKey::from_bytes(&[1u8; 32]).public();
        let bindings = DiscoveryBindings::client(endpoint_id).expect("client bindings");
        let _ = bindings.mdns;
        let _ = bindings.dht;
    }
}
