use anyhow::{anyhow, Context};
use catgrad_llm::PreparedPrompt;
use futures::StreamExt;
use hellas_executor::{DownloadPolicy, ExecutePolicy, Executor, ExecutorHandle, ModelAssets};
use hellas_rpc::decode_token_ids;
use hellas_rpc::discovery::{DiscoveryEndpoint, QuoteError, QuoteStream};
use hellas_rpc::driver::{ExecuteDriver, RemoteExecuteDriver};
use hellas_rpc::pb::hellas::{
    execute_stream_event, ExecuteRequest, ExecuteStreamEvent, ExecutionStatus, GetQuoteRequest,
};
use hellas_rpc::service::ExecuteService;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::time::Duration;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::swarm::{DhtBackend, Locator, MdnsBackend, ServiceRegistry};
use tonic_iroh_transport::IrohConnect;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

type OutputSink<'a> = dyn FnMut(&[u8]) -> anyhow::Result<()> + Send + 'a;

#[derive(Clone)]
pub enum ExecutionRoute {
    Local,
    RemoteDirect(EndpointId),
    RemoteDiscovery {
        retries: usize,
        backup_quotes: usize,
    },
}

impl ExecutionRoute {
    pub fn remote(node_id: Option<EndpointId>, retries: usize, backup_quotes: usize) -> Self {
        match node_id {
            Some(node_id) => Self::RemoteDirect(node_id),
            None => Self::RemoteDiscovery {
                retries,
                backup_quotes,
            },
        }
    }
}

#[derive(Clone)]
pub enum ExecutionStrategy {
    Run(ExecutionRoute),
    Verify {
        primary: ExecutionRoute,
        shadow: ExecutionRoute,
    },
}

#[derive(Clone, Default)]
pub struct ExecutionRuntime {
    local_executor: Option<ExecutorHandle>,
}

pub struct ExecutionRequest {
    runtime: ExecutionRuntime,
    quote_req: GetQuoteRequest,
    strategy: ExecutionStrategy,
}

struct DiscoverySession {
    endpoint: Arc<Endpoint>,
    quotes: QuoteStream<Locator>,
}

struct QuotedDriver {
    _endpoint: Option<Arc<Endpoint>>,
    quote_id: String,
    driver: Box<dyn ExecuteDriver>,
}

impl QuotedDriver {
    fn new<D>(endpoint: Option<Arc<Endpoint>>, quote_id: String, driver: D) -> Self
    where
        D: ExecuteDriver + 'static,
    {
        Self {
            _endpoint: endpoint,
            quote_id,
            driver: Box::new(driver),
        }
    }
}

pub struct ExecutionOutput {
    pub output: Vec<u8>,
    pub completion_tokens: u32,
}

impl ExecutionRuntime {
    pub fn with_local_executor(local_executor: ExecutorHandle) -> Self {
        Self {
            local_executor: Some(local_executor),
        }
    }

    pub fn spawn_default_local(queue_capacity: usize) -> anyhow::Result<Self> {
        let local_executor =
            Executor::spawn(DownloadPolicy::Eager, ExecutePolicy::Eager, queue_capacity)
                .context("failed to initialize local execution backend")?;
        Ok(Self::with_local_executor(local_executor))
    }

    fn require_local_executor(&self) -> anyhow::Result<ExecutorHandle> {
        self.local_executor
            .clone()
            .ok_or_else(|| anyhow!("local execution requested but no local executor is configured"))
    }
}

impl ExecutionRequest {
    pub fn new(
        runtime: ExecutionRuntime,
        assets: Arc<ModelAssets>,
        prepared_prompt: PreparedPrompt,
        max_seq: u32,
        strategy: ExecutionStrategy,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            runtime,
            quote_req: assets.build_quote_request(&prepared_prompt, max_seq)?,
            strategy,
        })
    }

    pub async fn run(&self, sink: &mut OutputSink<'_>) -> anyhow::Result<ExecutionOutput> {
        match &self.strategy {
            ExecutionStrategy::Run(route) => self.run_route(route, sink).await,
            ExecutionStrategy::Verify { primary, shadow } => {
                let primary_output = self.run_route(primary, sink).await?;
                let shadow_output = self.run_route(shadow, &mut |_: &[u8]| Ok(())).await?;
                self.verify_matching_output(&primary_output, &shadow_output)?;
                Ok(primary_output)
            }
        }
    }

    async fn run_route(
        &self,
        route: &ExecutionRoute,
        sink: &mut OutputSink<'_>,
    ) -> anyhow::Result<ExecutionOutput> {
        match route {
            ExecutionRoute::RemoteDiscovery {
                retries,
                backup_quotes,
            } => {
                self.execute_discovered(*retries, *backup_quotes, sink)
                    .await
            }
            ExecutionRoute::Local => {
                let executor = self.runtime.require_local_executor()?;
                let quoted = self
                    .quote_driver(None, executor, || "local quote failed".to_string())
                    .await?;
                self.execute_quoted(quoted, sink).await
            }
            ExecutionRoute::RemoteDirect(node_id) => {
                let endpoint = Arc::new(DiscoveryEndpoint::bind().await?.endpoint);
                let channel = ExecuteService::connect(&endpoint, (*node_id).into())
                    .await
                    .with_context(|| format!("failed to connect to node {node_id}"))?;
                let quoted = self
                    .quote_driver(Some(endpoint), RemoteExecuteDriver::new(channel), || {
                        format!("node {node_id} declined quote")
                    })
                    .await?;
                self.execute_quoted(quoted, sink).await
            }
        }
    }

    async fn quote_driver<D>(
        &self,
        endpoint: Option<Arc<Endpoint>>,
        mut driver: D,
        context: impl FnOnce() -> String,
    ) -> anyhow::Result<QuotedDriver>
    where
        D: ExecuteDriver + 'static,
    {
        let quote = driver
            .get_quote(self.quote_req.clone())
            .await
            .with_context(context)?;
        Ok(QuotedDriver::new(endpoint, quote.quote_id, driver))
    }

    async fn start_discovery_session(&self) -> anyhow::Result<DiscoverySession> {
        let bound = DiscoveryEndpoint::bind().await?;
        let endpoint = Arc::new(bound.endpoint);
        let mdns = bound.bindings.mdns;
        let shared_dht = bound.bindings.dht;

        let mut registry = ServiceRegistry::new(&endpoint);
        registry.add(MdnsBackend::new(mdns));
        registry.add(DhtBackend::with_dht(&endpoint, shared_dht));

        let locator = registry
            .find::<ExecuteService>()
            .timeout(DISCOVERY_TIMEOUT)
            .start();

        Ok(DiscoverySession {
            endpoint,
            quotes: QuoteStream::from_request(locator, self.quote_req.clone()),
        })
    }

    async fn next_accepted_execution(
        &self,
        discovery: &mut DiscoverySession,
    ) -> anyhow::Result<QuotedDriver> {
        let mut last_decline = None;
        let mut last_connect_error = None;

        while let Some(result) = discovery.quotes.next().await {
            match result {
                Ok((client, quote)) => {
                    return Ok(QuotedDriver::new(
                        Some(discovery.endpoint.clone()),
                        quote.quote_id,
                        client,
                    ));
                }
                Err(QuoteError::Declined(status)) => {
                    info!("provider declined quote: {status}");
                    last_decline = Some(status);
                }
                Err(QuoteError::ConnectFailed(err)) => {
                    debug!("candidate connect error: {err:#}");
                    last_connect_error = Some(err);
                }
            }
        }

        if let Some(status) = last_decline {
            anyhow::bail!("all discovered providers declined the quote: {status}");
        }
        if let Some(err) = last_connect_error {
            return Err(err).context("failed to connect to discovered providers");
        }

        anyhow::bail!("no provider could serve the request");
    }

    async fn execute_discovered(
        &self,
        retries: usize,
        backup_quotes: usize,
        sink: &mut OutputSink<'_>,
    ) -> anyhow::Result<ExecutionOutput> {
        let mut discovery = self.start_discovery_session().await?;
        let mut buffered = VecDeque::new();
        let max_attempts = retries.saturating_add(1);

        info!("No node ID provided, discovering executor");

        for attempt in 1..=max_attempts {
            let prepared = match buffered.pop_front() {
                Some(prepared) => prepared,
                None => self.next_accepted_execution(&mut discovery).await?,
            };

            match self
                .execute_with_prefetch(prepared, &mut discovery, &mut buffered, backup_quotes, sink)
                .await
            {
                Ok(output) => return Ok(output),
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

    async fn execute_with_prefetch(
        &self,
        quoted: QuotedDriver,
        discovery: &mut DiscoverySession,
        buffered: &mut VecDeque<QuotedDriver>,
        backup_quotes: usize,
        sink: &mut OutputSink<'_>,
    ) -> anyhow::Result<ExecutionOutput> {
        let mut execute_fut = Box::pin(async move { self.execute_quoted(quoted, sink).await });
        let mut discovery_done = false;

        loop {
            tokio::select! {
                result = &mut execute_fut => return result,
                result = self.next_accepted_execution(discovery), if !discovery_done && buffered.len() < backup_quotes => {
                    match result {
                        Ok(prepared) => buffered.push_back(prepared),
                        Err(err) => {
                            debug!("no more backup providers available: {err:#}");
                            discovery_done = true;
                        }
                    }
                }
            }
        }
    }

    async fn execute_quoted(
        &self,
        mut quoted: QuotedDriver,
        sink: &mut OutputSink<'_>,
    ) -> anyhow::Result<ExecutionOutput> {
        let mut stream = quoted
            .driver
            .execute_streaming(ExecuteRequest {
                quote_id: quoted.quote_id.clone(),
                stream_batch_size: Some(1),
            })
            .await
            .context("failed to start execution stream")?;
        let mut output = Vec::new();
        let mut completion_tokens = 0u32;

        while let Some(event) = stream.next().await {
            if let Some(status) = self.consume_stream_event(
                event.context("execution stream failed")?,
                &mut output,
                &mut completion_tokens,
                sink,
            )? {
                if status == ExecutionStatus::Failed {
                    anyhow::bail!("execution failed");
                }
                if status == ExecutionStatus::Completed {
                    break;
                }
            }
        }

        Ok(ExecutionOutput {
            output,
            completion_tokens,
        })
    }

    fn verify_matching_output(
        &self,
        primary: &ExecutionOutput,
        shadow: &ExecutionOutput,
    ) -> anyhow::Result<()> {
        if primary.output == shadow.output {
            return Ok(());
        }

        if let (Ok(primary_tokens), Ok(shadow_tokens)) = (
            decode_token_ids(&primary.output),
            decode_token_ids(&shadow.output),
        ) {
            let mismatch_index = primary_tokens
                .iter()
                .zip(&shadow_tokens)
                .position(|(primary, shadow)| primary != shadow)
                .unwrap_or_else(|| primary_tokens.len().min(shadow_tokens.len()));
            let primary_token = primary_tokens.get(mismatch_index).copied();
            let shadow_token = shadow_tokens.get(mismatch_index).copied();
            anyhow::bail!(
                "primary/shadow outputs diverged at token {} (primary={:?}, shadow={:?}); primary_tokens={} shadow_tokens={}",
                mismatch_index,
                primary_token,
                shadow_token,
                primary_tokens.len(),
                shadow_tokens.len(),
            );
        }

        let mismatch_index = primary
            .output
            .iter()
            .zip(&shadow.output)
            .position(|(primary, shadow)| primary != shadow)
            .unwrap_or_else(|| primary.output.len().min(shadow.output.len()));
        let primary_byte = primary.output.get(mismatch_index).copied();
        let shadow_byte = shadow.output.get(mismatch_index).copied();

        anyhow::bail!(
            "primary/shadow outputs diverged at byte {} (primary={:?}, shadow={:?}); primary_bytes={} shadow_bytes={}",
            mismatch_index,
            primary_byte,
            shadow_byte,
            primary.output.len(),
            shadow.output.len(),
        );
    }

    fn consume_stream_event(
        &self,
        event: ExecuteStreamEvent,
        output: &mut Vec<u8>,
        completion_tokens: &mut u32,
        sink: &mut OutputSink<'_>,
    ) -> anyhow::Result<Option<ExecutionStatus>> {
        let (status, progress) = match event.event {
            Some(execute_stream_event::Event::Snapshot(snapshot)) => {
                if let Some(output_chunk) = snapshot.output.get(output.len()..) {
                    if !output_chunk.is_empty() {
                        output.extend_from_slice(output_chunk);
                        sink(output_chunk)?;
                    }
                }
                (
                    ExecutionStatus::try_from(snapshot.status)
                        .unwrap_or(ExecutionStatus::Unspecified),
                    snapshot.progress,
                )
            }
            Some(execute_stream_event::Event::Progress(progress)) => {
                if !progress.output_chunk.is_empty() {
                    output.extend_from_slice(&progress.output_chunk);
                    sink(&progress.output_chunk)?;
                }
                (
                    ExecutionStatus::try_from(progress.status)
                        .unwrap_or(ExecutionStatus::Unspecified),
                    progress.progress,
                )
            }
            None => return Ok(None),
        };

        *completion_tokens = u32::try_from(progress).unwrap_or(u32::MAX);
        Ok(Some(status))
    }
}
