use crate::commands::CliResult;
use crate::execution::{
    ExecutionRoute, ExecutionRuntime, OpaqueExecutionEvent, OpaqueExecutionRequest, OpaqueOutcome,
};
#[cfg(feature = "hellas-executor")]
use catgrad::prelude::Dtype;
use futures::StreamExt;
use hellas_pb::opaque::OpaqueRequest;
use std::io::{self, Write};
use std::net::SocketAddr;
#[cfg(feature = "hellas-executor")]
use std::path::PathBuf;
use tonic_iroh_transport::iroh::{EndpointId, SecretKey};

pub struct ExecuteOptions {
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    pub service: String,
    pub method: String,
    pub payload: Vec<u8>,
    pub retries: usize,
    #[cfg(feature = "hellas-executor")]
    pub local: bool,
    #[cfg(feature = "hellas-executor")]
    pub producer_key_path: Option<PathBuf>,
}

pub async fn run(options: ExecuteOptions, secret_key: SecretKey) -> CliResult<()> {
    serde_json::from_slice::<serde_json::Value>(&options.payload)
        .map_err(|err| anyhow::anyhow!("--payload must be UTF-8 JSON: {err}"))?;

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
        let producer_key =
            crate::identity::load_or_create_producer_key(options.producer_key_path.as_deref())?;
        ExecutionRuntime::spawn_default_local_with_producer_key(
            hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY,
            vec![Dtype::F32],
            producer_key,
        )?
        .with_secret_key(secret_key)
    } else {
        ExecutionRuntime::default().with_secret_key(secret_key)
    };
    #[cfg(not(feature = "hellas-executor"))]
    let runtime = ExecutionRuntime::default().with_secret_key(secret_key);

    let request = OpaqueRequest {
        service: options.service,
        method: options.method,
        payload: options.payload,
    };
    let execution = OpaqueExecutionRequest::new(runtime, request, route);
    let uses_remote = execution.uses_remote_transport();
    let stream = execution.stream();
    tokio::pin!(stream);

    let mut completed = false;
    while let Some(event) = stream.next().await {
        match event? {
            OpaqueExecutionEvent::Chunk { .. } => {}
            OpaqueExecutionEvent::Done(OpaqueOutcome::Completed { output, .. }) => {
                io::stdout().write_all(&output)?;
                io::stdout().flush()?;
                completed = true;
                break;
            }
            OpaqueExecutionEvent::Done(OpaqueOutcome::Failed { error, .. }) => {
                anyhow::bail!("opaque execution failed: {error}");
            }
        }
    }

    if uses_remote {
        crate::tracing_config::suppress_execute_tail_logs();
    }
    if !completed {
        anyhow::bail!("opaque execution stream ended without terminal outcome");
    }
    Ok(())
}
