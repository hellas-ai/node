use crate::commands::CliResult;
use anyhow::Context;
use hellas_rpc::pb::hellas::execute_client::ExecuteClient;
use hellas_rpc::pb::hellas::{
    get_quote_request, ExecuteRequest, ExecuteStatusRequest, GetQuoteRequest, LlmQuoteRequest,
};
use hellas_rpc::service::ExecuteService;
#[cfg(feature = "discovery")]
use pkarr::Client as PkarrClient;
use std::io::{self, Write};
#[cfg(feature = "discovery")]
use std::sync::Arc;
#[cfg(feature = "discovery")]
use tokio::time::Duration;
#[cfg(feature = "discovery")]
use tonic::Code;
#[cfg(feature = "discovery")]
use tonic_iroh_transport::iroh::address_lookup::mdns::MdnsAddressLookup;
#[cfg(feature = "discovery")]
use tonic_iroh_transport::iroh::address_lookup::pkarr::dht::DhtAddressLookup;
#[cfg(feature = "discovery")]
use tonic_iroh_transport::iroh::address_lookup::pkarr::{
    N0_DNS_PKARR_RELAY_PROD, N0_DNS_PKARR_RELAY_STAGING,
};
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
#[cfg(feature = "discovery")]
use tonic_iroh_transport::swarm::{DhtBackend, MdnsBackend, ServiceRegistry};
use tonic_iroh_transport::IrohConnect;

const GRPC_MESSAGE_LIMIT: usize = 32 * 1024 * 1024;
#[cfg(feature = "discovery")]
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(feature = "discovery")]
fn n0_pkarr_relay() -> &'static str {
    if std::env::var_os("IROH_FORCE_STAGING_RELAYS").is_some() {
        N0_DNS_PKARR_RELAY_STAGING
    } else {
        N0_DNS_PKARR_RELAY_PROD
    }
}

#[cfg(feature = "discovery")]
fn shared_pkarr_client() -> CliResult<PkarrClient> {
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

pub async fn run(
    node_id: Option<EndpointId>,
    model: String,
    prompt: String,
    max_seq: u32,
) -> CliResult<()> {
    let endpoint = Endpoint::builder()
        .bind()
        .await
        .context("failed to create iroh endpoint")?;

    let quote_req = GetQuoteRequest {
        payload: Some(get_quote_request::Payload::LlmPrompt(LlmQuoteRequest {
            huggingface_model_id: model.clone(),
            prompt: prompt.clone(),
            max_seq,
        })),
    };
    info!("Getting quote... {quote_req:?}");

    let (mut client, quote) = match node_id {
        Some(id) => {
            let channel = ExecuteService::connect(&endpoint, id.into())
                .await
                .with_context(|| format!("failed to connect to node {id}"))?;
            let mut client = ExecuteClient::new(channel)
                .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
                .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
            let quote = client
                .get_quote(quote_req.clone())
                .await
                .context("GetQuote RPC failed")?
                .into_inner();
            (client, quote)
        }
        None => {
            #[cfg(feature = "discovery")]
            {
                // Set up mDNS for local-network discovery (client-only, no advertise).
                let mdns = MdnsAddressLookup::builder()
                    .advertise(false)
                    .service_name("hellas")
                    .build(endpoint.id())
                    .context("failed to start mDNS discovery")?;
                endpoint.address_lookup().add(mdns.clone());

                let shared_pkarr =
                    shared_pkarr_client().context("failed to initialize shared pkarr client")?;
                let shared_dht = Arc::new(
                    shared_pkarr
                        .dht()
                        .ok_or_else(|| anyhow::anyhow!("shared pkarr client has no DHT handle"))?,
                );

                // Add internet discovery via pkarr+DHT as a resolver (no publish).
                let pkarr = DhtAddressLookup::builder()
                    .client(shared_pkarr)
                    .n0_dns_pkarr_relay()
                    .no_publish()
                    .build()
                    .context("failed to initialize pkarr+DHT discovery")?;
                endpoint.address_lookup().add(pkarr);

                info!("No node ID provided, discovering executor");
                let mut registry = ServiceRegistry::new(&endpoint);
                registry.add(MdnsBackend::new(mdns));
                registry.add(DhtBackend::with_dht(&endpoint, shared_dht));

                let mut locator = registry
                    .find::<ExecuteService>()
                    .timeout(DISCOVERY_TIMEOUT)
                    .start();

                let mut ready_client_quote = None;
                let mut not_ready_count = 0usize;
                let mut discovery_errors = 0usize;
                let mut quote_errors = 0usize;

                while let Some(next_channel) = tokio_stream::StreamExt::next(&mut locator).await {
                    let channel = match next_channel {
                        Ok(channel) => channel,
                        Err(err) => {
                            discovery_errors += 1;
                            debug!("discovered candidate failed to connect: {err:#}");
                            continue;
                        }
                    };

                    let mut candidate = ExecuteClient::new(channel)
                        .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
                        .max_encoding_message_size(GRPC_MESSAGE_LIMIT);

                    match candidate.get_quote(quote_req.clone()).await {
                        Ok(resp) => {
                            ready_client_quote = Some((candidate, resp.into_inner()));
                            break;
                        }
                        Err(status) => {
                            let is_weights_not_ready = status.code() == Code::FailedPrecondition;
                            if is_weights_not_ready {
                                not_ready_count += 1;
                                info!(
                                    model = %model,
                                    "discovered executor missing requested weights, trying next provider"
                                );
                                continue;
                            }

                            quote_errors += 1;
                            debug!("discovered executor rejected quote: {status}");
                        }
                    }
                }

                match ready_client_quote {
                    Some((client, quote)) => (client, quote),
                    None => {
                        if not_ready_count > 0 {
                            anyhow::bail!(
                                "no discovered executor had weights ready for model {model} (not_ready={not_ready_count}, discovery_errors={discovery_errors}, quote_errors={quote_errors})"
                            );
                        }
                        anyhow::bail!(
                            "failed to discover an executor that can serve the request (discovery_errors={discovery_errors}, quote_errors={quote_errors})"
                        );
                    }
                }
            }
            #[cfg(not(feature = "discovery"))]
            {
                anyhow::bail!(
                    "node_id is required when CLI is built without the `discovery` feature"
                );
            }
        }
    };

    info!("Got quote: {quote:?}");

    // 2. Execute
    let req = ExecuteRequest {
        quote_id: quote.quote_id.clone(),
    };
    info!("Req: {req:?}");
    let exec = client
        .execute(req)
        .await
        .context("Execute RPC failed")?
        .into_inner();
    info!("Executing: {exec:?}");

    // 3. Stream status until completed
    let req = ExecuteStatusRequest {
        execution_id: exec.execution_id.clone(),
    };
    info!("Streaming status: {req:?}");
    let mut stream = client
        .execute_stream(req)
        .await
        .context("ExecuteStream RPC failed")?
        .into_inner();

    while let Some(progress) = tokio_stream::StreamExt::next(&mut stream).await {
        let progress = progress.context("ExecuteStream RPC progress failed")?;
        if let Some(decoded) = progress.decoded.as_deref() {
            debug!(
                "Status: {} | Progress: {} | Decoded chunk: {}",
                progress.status, progress.progress, decoded
            );
            print!("{}", decoded);
            io::stdout().flush()?;
        } else if progress.chunk.is_empty() {
            debug!(
                "Status: {} | Progress: {}",
                progress.status, progress.progress
            );
        } else {
            debug!(
                "Status: {} | Progress: {} | Chunk bytes: {}",
                progress.status,
                progress.progress,
                progress.chunk.len()
            );
        }
        if progress.status == "completed" || progress.status == "failed" {
            break;
        }
    }

    Ok(())
}
