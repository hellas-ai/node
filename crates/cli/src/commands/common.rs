pub const GRPC_MESSAGE_LIMIT: usize = 32 * 1024 * 1024;

#[cfg(feature = "discovery")]
use pkarr::Client as PkarrClient;
#[cfg(feature = "discovery")]
use tonic_iroh_transport::iroh::address_lookup::pkarr::{
    N0_DNS_PKARR_RELAY_PROD, N0_DNS_PKARR_RELAY_STAGING,
};

#[cfg(feature = "discovery")]
fn n0_pkarr_relay() -> &'static str {
    if std::env::var_os("IROH_FORCE_STAGING_RELAYS").is_some() {
        N0_DNS_PKARR_RELAY_STAGING
    } else {
        N0_DNS_PKARR_RELAY_PROD
    }
}

#[cfg(feature = "discovery")]
pub fn shared_pkarr_client() -> anyhow::Result<PkarrClient> {
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
