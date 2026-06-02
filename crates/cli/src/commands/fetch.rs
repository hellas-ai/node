use crate::commands::CliResult;
use crate::execution::{
    ExecutionRoute, ExecutionRuntime, FetchExecutionEvent, FetchExecutionRequest, FetchOutcome,
};
#[cfg(feature = "hellas-executor")]
use catgrad::prelude::Dtype;
use futures::StreamExt;
use hellas_core::ProducerSigningKey;
use hellas_rpc::fetch::build_input_events;
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::stream::input_event_to_pb;
use iroh::{EndpointId, SecretKey};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::trace;

pub struct ExecuteOptions {
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    pub service: String,
    pub method: String,
    pub payload: Vec<u8>,
    pub retries: usize,
    #[cfg(feature = "hellas-executor")]
    pub local: bool,
    pub producer_key_path: Option<PathBuf>,
}

pub async fn run(options: ExecuteOptions, secret_key: SecretKey) -> CliResult<()> {
    serde_json::from_slice::<serde_json::Value>(&options.payload)
        .map_err(|err| anyhow::anyhow!("--payload must be UTF-8 JSON: {err}"))?;

    let caller_key =
        crate::identity::load_or_create_producer_key(options.producer_key_path.as_deref())?;

    #[cfg(feature = "hellas-executor")]
    let route = if options.local {
        ExecutionRoute::Local
    } else {
        ExecutionRoute::remote(options.node_id, options.node_addrs.clone(), options.retries)
    };
    #[cfg(not(feature = "hellas-executor"))]
    let route =
        ExecutionRoute::remote(options.node_id, options.node_addrs.clone(), options.retries);

    #[cfg(feature = "hellas-executor")]
    let runtime = if options.local {
        ExecutionRuntime::spawn_default_local_with_producer_key(
            hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY,
            vec![Dtype::F32],
            ProducerSigningKey::from_secret_bytes(caller_key.to_secret_bytes())?,
        )?
        .with_remote(secret_key)
        .await?
    } else {
        ExecutionRuntime::remote(secret_key).await?
    };
    #[cfg(not(feature = "hellas-executor"))]
    let runtime = ExecutionRuntime::remote(secret_key).await?;

    let request = FetchRequest {
        input: signed_input_events(
            &options.service,
            &options.method,
            &options.payload,
            &caller_key,
        )?,
        service: options.service,
        method: options.method,
    };
    let execution = FetchExecutionRequest::new(runtime, request, route);
    let uses_remote = execution.uses_remote_transport();
    let stream = execution.stream();
    tokio::pin!(stream);

    let mut wrote_chunks = false;
    let mut completed = false;
    while let Some(event) = stream.next().await {
        match event? {
            FetchExecutionEvent::Chunk { position, bytes } => {
                trace!(position, bytes = bytes.len(), "fetch output chunk");
                wrote_chunks = true;
                io::stdout().write_all(&bytes)?;
                io::stdout().flush()?;
            }
            FetchExecutionEvent::Done(FetchOutcome::Completed { output, .. }) => {
                if !wrote_chunks {
                    io::stdout().write_all(&output)?;
                    io::stdout().flush()?;
                }
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

    if uses_remote {
        crate::tracing_config::suppress_execute_tail_logs();
    }
    Ok(())
}

fn signed_input_events(
    service: &str,
    method: &str,
    payload: &[u8],
    key: &ProducerSigningKey,
) -> anyhow::Result<Vec<hellas_rpc::pb::execute::InputEventEnvelope>> {
    let events = build_input_events(service, method, payload, key)?;
    Ok(events.iter().map(input_event_to_pb).collect())
}
