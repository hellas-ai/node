use crate::commands::CliResult;
use crate::execution::CliRuntime;
use futures::StreamExt;
use hellas_client::iroh::fetch_execution_stream;
use hellas_client::{ExecutionRoute, FetchExecutionEvent, FetchOutcome, ProducerTrust};
use hellas_rpc::fetch::build_input_events;
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::stream::input_event_to_pb;
use hellas_rpc::{ContentId, ProducerSigningKey};
use iroh::{EndpointId, SecretKey};
use std::io::{self, Write};
use std::net::SocketAddr;
use tracing::trace;

pub struct ExecuteOptions {
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    pub service: String,
    pub method: String,
    pub execution_environment: ContentId,
    pub payload: Vec<u8>,
    pub retries: usize,
    pub producer_key: ProducerSigningKey,
    pub trusted_producer_public_keys: Vec<hellas_rpc::PublicKey>,
}

pub async fn run(options: ExecuteOptions, secret_key: SecretKey) -> CliResult<()> {
    serde_json::from_slice::<serde_json::Value>(&options.payload)
        .map_err(|err| anyhow::anyhow!("--payload must be UTF-8 JSON: {err}"))?;

    let caller_key = options.producer_key;

    // Mirrors the producer-side default for trusted callers: with no keys
    // configured, only output signed by our own producer key verifies.
    let trust = if options.trusted_producer_public_keys.is_empty() {
        ProducerTrust::keys([caller_key.public_key()])
    } else {
        ProducerTrust::keys(options.trusted_producer_public_keys.iter().copied())
    };
    let caller_key = std::sync::Arc::new(caller_key);

    let route =
        ExecutionRoute::remote(options.node_id, options.node_addrs.clone(), options.retries);
    let runtime = CliRuntime::remote(secret_key).await?;

    let request = FetchRequest {
        input: signed_input_events(
            &options.service,
            &options.method,
            &options.payload,
            options.execution_environment,
            &caller_key,
        )?,
    };
    let stream = fetch_execution_stream(runtime, request, route, trust, caller_key);
    tokio::pin!(stream);

    let mut completed = false;
    while let Some(event) = stream.next().await {
        match event? {
            FetchExecutionEvent::Chunk {
                position, event, ..
            } => {
                trace!(position, "fetch output event");
                serde_json::to_writer(&mut io::stdout(), &event)?;
                io::stdout().write_all(b"\n")?;
                io::stdout().flush()?;
            }
            FetchExecutionEvent::Done(FetchOutcome::Completed { terminal, .. }) => {
                serde_json::to_writer(&mut io::stdout(), &terminal.to_output_event())?;
                io::stdout().write_all(b"\n")?;
                io::stdout().flush()?;
                completed = true;
                break;
            }
            FetchExecutionEvent::Done(FetchOutcome::Failed { position, error }) => {
                anyhow::bail!("fetch execution failed at position {position}: {error}");
            }
        }
    }
    if !completed {
        anyhow::bail!("fetch execution stream ended without terminal outcome");
    }

    crate::tracing_config::suppress_execute_tail_logs();
    Ok(())
}

pub(crate) fn signed_input_events(
    service: &str,
    method: &str,
    payload: &[u8],
    execution_environment: ContentId,
    key: &ProducerSigningKey,
) -> anyhow::Result<Vec<hellas_rpc::pb::execute::InputEventEnvelope>> {
    let events = build_input_events(service, method, payload, execution_environment, key)?;
    Ok(events.iter().map(input_event_to_pb).collect())
}
