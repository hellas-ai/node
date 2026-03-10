pub type CliResult<T = ()> = anyhow::Result<T>;

pub(crate) async fn bind_client_endpoint() -> CliResult<tonic_iroh_transport::iroh::Endpoint> {
    use anyhow::Context;
    use hellas_rpc::discovery::shared_pkarr_client;
    use tonic_iroh_transport::iroh::address_lookup::mdns::MdnsAddressLookup;
    use tonic_iroh_transport::iroh::address_lookup::pkarr::dht::DhtAddressLookup;
    use tonic_iroh_transport::iroh::Endpoint;

    let endpoint = Endpoint::builder()
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    let mdns = MdnsAddressLookup::builder()
        .advertise(false)
        .service_name("hellas")
        .build(endpoint.id())
        .context("failed to start mDNS discovery")?;
    endpoint.address_lookup().add(mdns);

    let shared_pkarr = shared_pkarr_client().context("failed to initialize shared pkarr client")?;
    let pkarr = DhtAddressLookup::builder()
        .client(shared_pkarr)
        .n0_dns_pkarr_relay()
        .no_publish()
        .build()
        .context("failed to initialize pkarr+DHT discovery")?;
    endpoint.address_lookup().add(pkarr);

    Ok(endpoint)
}

pub mod execute;
pub mod gateway;
pub mod health;
pub(crate) mod local_model;
pub mod monitor;
#[cfg(feature = "serve")]
pub mod serve;
