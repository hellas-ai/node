use crate::commands::local_model::LocalModelAssets;
use crate::commands::{bind_client_endpoint, CliResult};
use anyhow::{anyhow, Context};
use catgrad_llm::IncrementalDetokenizer;
use futures::StreamExt;
use hellas_rpc::discovery::{
    shared_pkarr_client, AcceptedQuote, QuoteError, QuoteStream, QuoteStreamBuilder,
};
use hellas_rpc::pb::hellas::execute_client::ExecuteClient;
use hellas_rpc::pb::hellas::{
    ExecuteRequest, ExecuteStatusRequest, ExecutionStatus, GetQuoteResponse,
};
use hellas_rpc::service::ExecuteService;
use hellas_rpc::{decode_token_ids, GRPC_MESSAGE_LIMIT};
use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::Arc;
use tokio::time::Duration;
use tonic::transport::Channel;
use tonic_iroh_transport::iroh::address_lookup::mdns::MdnsAddressLookup;
use tonic_iroh_transport::iroh::address_lookup::pkarr::dht::DhtAddressLookup;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::swarm::{DhtBackend, Locator, MdnsBackend, ServiceRegistry};
use tonic_iroh_transport::IrohConnect;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn run(
    node_id: Option<EndpointId>,
    model: String,
    prompt: String,
    max_seq: u32,
    retries: usize,
    backup_quotes: usize,
) -> CliResult<()> {
    let assets = Arc::new(LocalModelAssets::load(&model)?);
    let prepared = assets.prepare_plain_prompt(&prompt)?;
    let quote_req = assets.build_quote_request(&prepared, max_seq)?;
    let stop_token_ids = prepared.stop_token_ids.clone();
    info!("Getting quote... {quote_req:?}");

    match node_id {
        Some(id) => {
            let endpoint = bind_client_endpoint().await?;
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
            execute_and_stream(&mut client, &quote, assets, stop_token_ids).await
        }
        None => {
            let endpoint = Endpoint::builder()
                .bind()
                .await
                .context("failed to create iroh endpoint")?;

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
                    .ok_or_else(|| anyhow!("shared pkarr client has no DHT handle"))?,
            );

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

            let mut quotes = QuoteStreamBuilder::new(quote_req).start(locator);
            let mut buffered_quotes = VecDeque::new();
            let max_attempts = retries.saturating_add(1);

            for attempt in 1..=max_attempts {
                let (client, quote) =
                    next_accepted_quote(&mut quotes, &mut buffered_quotes).await?;

                match execute_with_prefetch(
                    client,
                    quote,
                    assets.clone(),
                    stop_token_ids.clone(),
                    &mut quotes,
                    &mut buffered_quotes,
                    backup_quotes,
                )
                .await
                {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        if attempt == max_attempts {
                            return Err(err.context(format!("max retries ({retries}) exceeded")));
                        }
                        warn!(attempt, "execution failed, trying next provider: {err:#}");
                    }
                }
            }

            anyhow::bail!("max retries ({retries}) exceeded");
        }
    }
}

async fn execute_and_stream(
    client: &mut ExecuteClient<Channel>,
    quote: &GetQuoteResponse,
    assets: Arc<LocalModelAssets>,
    stop_token_ids: Vec<i32>,
) -> anyhow::Result<()> {
    info!("Got quote: {quote:?}");

    let exec = client
        .execute(ExecuteRequest {
            quote_id: quote.quote_id.clone(),
            stream_batch_size: Some(1),
        })
        .await
        .context("Execute RPC failed")?
        .into_inner();
    info!("Executing: {exec:?}");

    let mut stream = client
        .execute_stream(ExecuteStatusRequest {
            execution_id: exec.execution_id.clone(),
        })
        .await
        .context("ExecuteStream RPC failed")?
        .into_inner();

    let mut decoder = IncrementalDetokenizer::new(
        {
            let assets = Arc::clone(&assets);
            move |tokens| assets.decode_tokens(tokens)
        },
        &stop_token_ids,
    );

    while let Some(progress) = tokio_stream::StreamExt::next(&mut stream).await {
        let progress = progress.context("ExecuteStream RPC progress failed")?;
        let status =
            ExecutionStatus::try_from(progress.status).unwrap_or(ExecutionStatus::Unspecified);
        let status_label = status.as_str_name();

        if !progress.chunk.is_empty() {
            let token_ids = decode_token_ids(&progress.chunk)
                .map_err(|err| anyhow!("failed to decode streamed token batch: {err}"))?;
            let token_ids: Vec<i32> = token_ids
                .into_iter()
                .map(|token| {
                    i32::try_from(token)
                        .map_err(|_| anyhow!("streamed token id {token} exceeds i32 range"))
                })
                .collect::<Result<_, _>>()?;
            let delta = decoder
                .push_tokens(&token_ids)
                .context("failed to detokenize streamed token batch")?;
            debug!(
                "Status: {} | Progress: {} | Token batch: {}",
                status_label,
                progress.progress,
                token_ids.len()
            );
            if !delta.is_empty() {
                print!("{delta}");
                io::stdout().flush()?;
            }
        } else {
            debug!("Status: {} | Progress: {}", status_label, progress.progress);
        }

        if status == ExecutionStatus::Failed {
            anyhow::bail!("remote execution failed");
        }
        if status == ExecutionStatus::Completed {
            break;
        }
    }

    Ok(())
}

async fn next_accepted_quote(
    quotes: &mut QuoteStream<Locator>,
    buffered_quotes: &mut VecDeque<AcceptedQuote>,
) -> anyhow::Result<AcceptedQuote> {
    if let Some(accepted) = buffered_quotes.pop_front() {
        return Ok(accepted);
    }

    while let Some(result) = quotes.next().await {
        match result {
            Ok(accepted) => return Ok(accepted),
            Err(QuoteError::Declined(status)) => info!("provider declined quote: {status}"),
            Err(QuoteError::ConnectFailed(err)) => debug!("candidate connect error: {err:#}"),
        }
    }

    anyhow::bail!("no provider could serve the request");
}

async fn execute_with_prefetch(
    client: ExecuteClient<Channel>,
    quote: GetQuoteResponse,
    assets: Arc<LocalModelAssets>,
    stop_token_ids: Vec<i32>,
    quotes: &mut QuoteStream<Locator>,
    buffered_quotes: &mut VecDeque<AcceptedQuote>,
    backup_quotes: usize,
) -> anyhow::Result<()> {
    let mut execute_fut = Box::pin(async move {
        let mut client = client;
        execute_and_stream(&mut client, &quote, assets, stop_token_ids).await
    });
    let mut discovery_done = false;

    loop {
        tokio::select! {
            result = &mut execute_fut => return result,
            result = quotes.next(), if !discovery_done && buffered_quotes.len() < backup_quotes => {
                match result {
                    Some(Ok(accepted)) => buffered_quotes.push_back(accepted),
                    Some(Err(QuoteError::Declined(status))) => info!("provider declined quote: {status}"),
                    Some(Err(QuoteError::ConnectFailed(err))) => debug!("candidate connect error: {err:#}"),
                    None => discovery_done = true,
                }
            }
        }
    }
}
