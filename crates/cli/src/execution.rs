use anyhow::{anyhow, Context};
use catgrad_llm::PreparedPrompt;
use futures::StreamExt;
use hellas_executor::{DownloadPolicy, ExecutePolicy, Executor, ExecutorHandle, ModelAssets};
use hellas_rpc::decode_token_ids;
use hellas_rpc::discovery::{bind_resolver_endpoint, QuoteError, QuoteStream, QuoteStreamBuilder};
use hellas_rpc::driver::{ExecuteDriver, RemoteExecuteDriver};
use hellas_rpc::pb::hellas::{ExecuteRequest, ExecutionStatus, GetQuoteRequest, GetQuoteResponse};
use hellas_rpc::service::ExecuteService;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::time::Duration;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId};
use tonic_iroh_transport::swarm::{DhtBackend, Locator, MdnsBackend, ServiceRegistry};
use tonic_iroh_transport::IrohConnect;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_PREVIEW_CHARS: usize = 96;
const OUTPUT_PREVIEW_TOKENS: usize = 24;

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
    pub fn remote(
        node_id: Option<EndpointId>,
        retries: usize,
        backup_quotes: usize,
    ) -> Self {
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

pub struct ExecutionInvocation {
    assets: Arc<ModelAssets>,
    quote_req: GetQuoteRequest,
    stop_token_ids: Vec<i32>,
}

pub struct ExecutionRequest {
    runtime: ExecutionRuntime,
    invocation: ExecutionInvocation,
    strategy: ExecutionStrategy,
}

struct DiscoverySession {
    endpoint: Arc<Endpoint>,
    quotes: QuoteStream<Locator>,
}

struct PreparedExecution {
    _endpoint_guard: Option<Arc<Endpoint>>,
    quote: GetQuoteResponse,
    driver: Box<dyn ExecuteDriver>,
}

pub struct ExecutionOutput {
    pub token_bytes: Vec<u8>,
    pub text: String,
    pub completion_tokens: u32,
}

impl ExecutionInvocation {
    pub fn from_prepared_prompt(
        assets: Arc<ModelAssets>,
        prepared_prompt: PreparedPrompt,
        max_seq: u32,
    ) -> anyhow::Result<Self> {
        let stop_token_ids = prepared_prompt.stop_token_ids.clone();
        let quote_req = assets.build_quote_request(&prepared_prompt, max_seq)?;

        Ok(Self {
            assets,
            quote_req,
            stop_token_ids,
        })
    }
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

    fn local_executor(&self) -> anyhow::Result<ExecutorHandle> {
        self.local_executor
            .clone()
            .ok_or_else(|| anyhow!("local execution requested but no local executor is configured"))
    }
}

impl ExecutionRequest {
    pub fn new(
        runtime: ExecutionRuntime,
        invocation: ExecutionInvocation,
        strategy: ExecutionStrategy,
    ) -> Self {
        Self {
            runtime,
            invocation,
            strategy,
        }
    }

    pub async fn run<S>(&self, sink: &mut S) -> anyhow::Result<ExecutionOutput>
    where
        S: FnMut(&str) -> anyhow::Result<()>,
    {
        self.run_strategy(&self.strategy, sink).await
    }

    async fn run_strategy<S>(
        &self,
        strategy: &ExecutionStrategy,
        sink: &mut S,
    ) -> anyhow::Result<ExecutionOutput>
    where
        S: FnMut(&str) -> anyhow::Result<()>,
    {
        match strategy {
            ExecutionStrategy::Run(route) => self.run_route(route, sink).await,
            ExecutionStrategy::Verify { primary, shadow } => {
                let primary_output = self.run_route(primary, sink).await?;
                let shadow_output = self.run_route(shadow, &mut |_: &str| Ok(())).await?;
                self.verify_matching_output(&primary_output, &shadow_output)?;
                Ok(primary_output)
            }
        }
    }

    async fn run_route<S>(
        &self,
        route: &ExecutionRoute,
        sink: &mut S,
    ) -> anyhow::Result<ExecutionOutput>
    where
        S: FnMut(&str) -> anyhow::Result<()>,
    {
        match route {
            ExecutionRoute::RemoteDiscovery {
                retries,
                backup_quotes,
            } => {
                self.execute_discovered(*retries, *backup_quotes, sink)
                    .await
            }
            route => {
                let mut prepared = self.prepare_execution(route).await?;
                self.execute_prepared(&mut prepared, sink).await
            }
        }
    }

    async fn prepare_execution(&self, route: &ExecutionRoute) -> anyhow::Result<PreparedExecution> {
        match route {
            ExecutionRoute::Local => self.prepare_local_execution().await,
            ExecutionRoute::RemoteDirect(node_id) => self.prepare_direct_execution(*node_id).await,
            ExecutionRoute::RemoteDiscovery { .. } => self.prepare_discovery_execution().await,
        }
    }

    async fn prepare_local_execution(&self) -> anyhow::Result<PreparedExecution> {
        let mut executor = self.runtime.local_executor()?;
        let quote = executor
            .get_quote(self.invocation.quote_req.clone())
            .await
            .context("local quote failed")?;
        Ok(PreparedExecution::from_local(executor, quote))
    }

    async fn prepare_direct_execution(
        &self,
        node_id: EndpointId,
    ) -> anyhow::Result<PreparedExecution> {
        let endpoint = Arc::new(bind_resolver_endpoint().await?.endpoint);
        let channel = ExecuteService::connect(&endpoint, node_id.into())
            .await
            .with_context(|| format!("failed to connect to node {node_id}"))?;
        let mut driver = RemoteExecuteDriver::new(channel);
        let quote = driver
            .get_quote(self.invocation.quote_req.clone())
            .await
            .with_context(|| format!("node {node_id} declined quote"))?;

        Ok(PreparedExecution::from_remote(endpoint, driver, quote))
    }

    async fn prepare_discovery_execution(&self) -> anyhow::Result<PreparedExecution> {
        let mut discovery = self.start_discovery_session().await?;
        self.next_accepted_execution(&mut discovery).await
    }

    async fn start_discovery_session(&self) -> anyhow::Result<DiscoverySession> {
        let bound = bind_resolver_endpoint().await?;
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
            quotes: QuoteStreamBuilder::new(self.invocation.quote_req.clone()).start(locator),
        })
    }

    async fn next_accepted_execution(
        &self,
        discovery: &mut DiscoverySession,
    ) -> anyhow::Result<PreparedExecution> {
        let mut last_decline = None;
        let mut last_connect_error = None;

        while let Some(result) = discovery.quotes.next().await {
            match result {
                Ok((client, quote)) => {
                    return Ok(PreparedExecution::from_remote(
                        discovery.endpoint.clone(),
                        client,
                        quote,
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

    async fn execute_discovered<S>(
        &self,
        retries: usize,
        backup_quotes: usize,
        sink: &mut S,
    ) -> anyhow::Result<ExecutionOutput>
    where
        S: FnMut(&str) -> anyhow::Result<()>,
    {
        let mut discovery = self.start_discovery_session().await?;
        let mut buffered = VecDeque::new();
        let max_attempts = retries.saturating_add(1);

        info!("No node ID provided, discovering executor");

        for attempt in 1..=max_attempts {
            let prepared = self
                .next_prepared_execution(&mut discovery, &mut buffered)
                .await?;

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

    async fn next_prepared_execution(
        &self,
        discovery: &mut DiscoverySession,
        buffered: &mut VecDeque<PreparedExecution>,
    ) -> anyhow::Result<PreparedExecution> {
        if let Some(prepared) = buffered.pop_front() {
            return Ok(prepared);
        }

        self.next_accepted_execution(discovery).await
    }

    async fn execute_with_prefetch<S>(
        &self,
        prepared: PreparedExecution,
        discovery: &mut DiscoverySession,
        buffered: &mut VecDeque<PreparedExecution>,
        backup_quotes: usize,
        sink: &mut S,
    ) -> anyhow::Result<ExecutionOutput>
    where
        S: FnMut(&str) -> anyhow::Result<()>,
    {
        let mut execute_fut = Box::pin(async move {
            let mut prepared = prepared;
            self.execute_prepared(&mut prepared, sink).await
        });
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

    async fn execute_prepared<S>(
        &self,
        prepared: &mut PreparedExecution,
        sink: &mut S,
    ) -> anyhow::Result<ExecutionOutput>
    where
        S: FnMut(&str) -> anyhow::Result<()>,
    {
        let mut stream = prepared.start_progress_stream().await?;
        let mut decoder = self
            .invocation
            .assets
            .create_detokenizer(&self.invocation.stop_token_ids);
        let mut token_bytes = Vec::new();
        let mut completion_tokens = 0u32;

        while let Some(progress) = stream.next().await {
            let progress = progress.context("execution stream failed")?;
            let status =
                ExecutionStatus::try_from(progress.status).unwrap_or(ExecutionStatus::Unspecified);
            completion_tokens = u32::try_from(progress.progress).unwrap_or(u32::MAX);

            if !progress.chunk.is_empty() {
                token_bytes.extend_from_slice(&progress.chunk);

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
                if !delta.is_empty() {
                    sink(&delta)?;
                }
            }

            if status == ExecutionStatus::Failed {
                anyhow::bail!("execution failed");
            }
            if status == ExecutionStatus::Completed {
                break;
            }
        }

        Ok(ExecutionOutput {
            token_bytes,
            text: decoder.finish(),
            completion_tokens,
        })
    }

    fn verify_matching_output(
        &self,
        primary: &ExecutionOutput,
        shadow: &ExecutionOutput,
    ) -> anyhow::Result<()> {
        if primary.token_bytes == shadow.token_bytes {
            return Ok(());
        }

        let primary_tokens = decode_token_ids(&primary.token_bytes)
            .map_err(|err| anyhow!("failed to decode primary output tokens: {err}"))?;
        let shadow_tokens = decode_token_ids(&shadow.token_bytes)
            .map_err(|err| anyhow!("failed to decode shadow output tokens: {err}"))?;

        let mismatch_index = primary_tokens
            .iter()
            .zip(&shadow_tokens)
            .position(|(primary, shadow)| primary != shadow)
            .unwrap_or_else(|| primary_tokens.len().min(shadow_tokens.len()));

        let primary_token = primary_tokens.get(mismatch_index).copied();
        let shadow_token = shadow_tokens.get(mismatch_index).copied();
        let primary_preview = self.decode_preview(&primary_tokens);
        let shadow_preview = self.decode_preview(&shadow_tokens);

        anyhow::bail!(
            "primary/shadow outputs diverged at token {} (primary={:?}, shadow={:?}); primary_tokens={} shadow_tokens={}; primary_preview={:?}; shadow_preview={:?}",
            mismatch_index,
            primary_token,
            shadow_token,
            primary_tokens.len(),
            shadow_tokens.len(),
            primary_preview,
            shadow_preview,
        );
    }

    fn decode_preview(&self, token_ids: &[u32]) -> String {
        let end = token_ids.len().min(OUTPUT_PREVIEW_TOKENS);
        let mut preview = self
            .invocation
            .assets
            .decode_tokens(&token_ids[..end])
            .unwrap_or_else(|_| format!("{:?}", &token_ids[..end]));
        if preview.chars().count() > OUTPUT_PREVIEW_CHARS {
            preview = preview.chars().take(OUTPUT_PREVIEW_CHARS).collect();
            preview.push_str("...");
        } else if end < token_ids.len() {
            preview.push_str("...");
        }
        preview
    }
}

impl PreparedExecution {
    fn from_remote(
        endpoint: Arc<Endpoint>,
        driver: RemoteExecuteDriver,
        quote: GetQuoteResponse,
    ) -> Self {
        Self {
            _endpoint_guard: Some(endpoint),
            quote,
            driver: Box::new(driver),
        }
    }

    fn from_local(driver: impl ExecuteDriver + 'static, quote: GetQuoteResponse) -> Self {
        Self {
            _endpoint_guard: None,
            quote,
            driver: Box::new(driver),
        }
    }

    async fn start_progress_stream(
        &mut self,
    ) -> anyhow::Result<hellas_rpc::driver::ExecuteProgressStream> {
        self.driver
            .execute_streaming(ExecuteRequest {
                quote_id: self.quote.quote_id.clone(),
                stream_batch_size: Some(1),
            })
            .await
            .context("failed to start execution stream")
    }
}
