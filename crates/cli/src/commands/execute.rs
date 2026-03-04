#[cfg(feature = "discovery")]
use crate::commands::common::shared_pkarr_client;
use crate::commands::common::GRPC_MESSAGE_LIMIT;
use crate::commands::CliResult;
use anyhow::Context;
use hellas_rpc::pb::hellas::execute_client::ExecuteClient;
use hellas_rpc::pb::hellas::{
    get_quote_request, ExecuteRequest, ExecuteStatusRequest, ExecutionStatus, GetQuoteRequest,
    GetQuoteResponse, LlmQuoteRequest,
};
use hellas_rpc::service::ExecuteService;
use std::io::{self, Write};
#[cfg(feature = "discovery")]
use std::sync::Arc;
#[cfg(feature = "discovery")]
use tokio::time::Duration;
use tonic::transport::Channel;
#[cfg(feature = "discovery")]
use tonic_iroh_transport::iroh::address_lookup::mdns::MdnsAddressLookup;
#[cfg(feature = "discovery")]
use tonic_iroh_transport::iroh::address_lookup::pkarr::dht::DhtAddressLookup;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
#[cfg(feature = "discovery")]
use tonic_iroh_transport::swarm::{DhtBackend, MdnsBackend, ServiceRegistry};
use tonic_iroh_transport::IrohConnect;

#[cfg(feature = "discovery")]
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn run(
    node_id: Option<EndpointId>,
    model: String,
    prompt: String,
    max_seq: u32,
    retries: usize,
    backup_quotes: usize,
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

    match node_id {
        // ── Direct node path: no retry, no discovery ──
        Some(id) => {
            let channel = ExecuteService::connect(&endpoint, id.into())
                .await
                .with_context(|| format!("failed to connect to node {id}"))?;
            let mut client = ExecuteClient::new(channel)
                .max_decoding_message_size(GRPC_MESSAGE_LIMIT)
                .max_encoding_message_size(GRPC_MESSAGE_LIMIT);
            let quote = client
                .get_quote(quote_req)
                .await
                .with_context(|| format!("node {id} declined quote"))?
                .into_inner();
            execute_and_stream(&mut client, &quote).await
        }

        // ── Discovery path: parallel quoting + execution failover ──
        None => {
            #[cfg(feature = "discovery")]
            {
                use crate::commands::quote_stream::{QuoteError, QuoteStreamBuilder};
                use futures::StreamExt;

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

                let locator = registry
                    .find::<ExecuteService>()
                    .timeout(DISCOVERY_TIMEOUT)
                    .start();

                let mut quotes = QuoteStreamBuilder::new(quote_req)
                    .backup_quotes(backup_quotes)
                    .start(locator);

                let mut attempts = 0;
                while let Some(result) = quotes.next().await {
                    match result {
                        Ok((mut client, quote)) => {
                            attempts += 1;
                            if attempts > retries + 1 {
                                anyhow::bail!("max retries ({retries}) exceeded");
                            }
                            match execute_and_stream(&mut client, &quote).await {
                                Ok(()) => return Ok(()),
                                Err(err) => {
                                    warn!(
                                        attempt = attempts,
                                        "execution failed, trying next provider: {err:#}"
                                    );
                                }
                            }
                        }
                        Err(QuoteError::Declined(status)) => {
                            info!("provider declined quote: {status}");
                        }
                        Err(QuoteError::ConnectFailed(e)) => {
                            debug!("candidate connect error: {e:#}");
                        }
                    }
                }
                anyhow::bail!("no provider could serve the request");
            }
            #[cfg(not(feature = "discovery"))]
            {
                let _ = (retries, backup_quotes);
                anyhow::bail!(
                    "node_id is required when CLI is built without the `discovery` feature"
                );
            }
        }
    }
}

async fn execute_and_stream(
    client: &mut ExecuteClient<Channel>,
    quote: &GetQuoteResponse,
) -> anyhow::Result<()> {
    info!("Got quote: {quote:?}");

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
        let status =
            ExecutionStatus::try_from(progress.status).unwrap_or(ExecutionStatus::Unspecified);
        let status_label = status.as_str_name();
        if let Some(decoded) = progress.decoded.as_deref() {
            debug!(
                "Status: {} | Progress: {} | Decoded chunk: {}",
                status_label, progress.progress, decoded
            );
            print!("{}", decoded);
            io::stdout().flush()?;
        } else if progress.chunk.is_empty() {
            debug!("Status: {} | Progress: {}", status_label, progress.progress);
        } else {
            debug!(
                "Status: {} | Progress: {} | Chunk bytes: {}",
                status_label,
                progress.progress,
                progress.chunk.len()
            );
        }
        if matches!(status, ExecutionStatus::Completed | ExecutionStatus::Failed) {
            break;
        }
    }

    Ok(())
}
