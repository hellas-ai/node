use anyhow::{Context, anyhow};
use catgrad_llm::PreparedPrompt;
use futures::StreamExt;
use hellas_executor::{DownloadPolicy, ExecutePolicy, Executor, ExecutorHandle, ModelAssets};
use hellas_rpc::decode_token_ids;
use hellas_rpc::discovery::DiscoveryBindings;
use hellas_rpc::driver::{ExecuteDriver, RemoteExecuteDriver};
use hellas_rpc::pb::hellas::{
    ExecuteRequest, ExecuteStreamEvent, ExecutionStatus, GetQuoteRequest, execute_stream_event,
};
use hellas_rpc::service::ExecuteService;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{Duration, timeout};
use tonic_iroh_transport::IrohConnect;
use tonic_iroh_transport::iroh::{Endpoint, EndpointId, endpoint::presets};
use tonic_iroh_transport::swarm::{DhtBackend, MdnsBackend, ServiceRegistry};

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);
const REMOTE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

type OutputSink<'a> = dyn FnMut(&[u8]) -> anyhow::Result<()> + Send + 'a;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionRoute {
    Local,
    RemoteDirect(EndpointId),
    RemoteDiscovery { retries: usize },
}

impl ExecutionRoute {
    pub fn remote(node_id: Option<EndpointId>, retries: usize) -> Self {
        match node_id {
            Some(node_id) => Self::RemoteDirect(node_id),
            None => Self::RemoteDiscovery { retries },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

pub struct ExecutionOutput {
    pub output: Vec<u8>,
    pub completion_tokens: u32,
}

struct QuotedRemoteDriver {
    peer_id: EndpointId,
    quote: hellas_rpc::pb::hellas::GetQuoteResponse,
    driver: RemoteExecuteDriver,
}

#[derive(Debug)]
enum QuoteCandidateError {
    Declined(tonic::Status),
    Connect(anyhow::Error),
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
            ExecutionRoute::RemoteDiscovery { retries } => self.execute_discovered(*retries, sink).await,
            ExecutionRoute::Local => {
                let mut executor = self.runtime.require_local_executor()?;
                let quote = self
                    .quote_with_driver(&mut executor, || "local quote failed".to_string())
                    .await?;
                self.execute_with_driver(&mut executor, quote.quote_id, sink).await
            }
            ExecutionRoute::RemoteDirect(node_id) => {
                let endpoint = Self::bind_remote_endpoint().await?;
                let mut quote = self.quote_remote_peer(&endpoint, *node_id).await?;
                let result = self
                    .execute_with_driver(&mut quote.driver, quote.quote.quote_id, sink)
                    .await;
                endpoint.close().await;
                result
            }
        }
    }

    async fn quote_with_driver<D>(
        &self,
        driver: &mut D,
        context: impl FnOnce() -> String,
    ) -> anyhow::Result<hellas_rpc::pb::hellas::GetQuoteResponse>
    where
        D: ExecuteDriver,
    {
        let start = Instant::now();
        let quote = driver
            .get_quote(self.quote_req.clone())
            .await
            .with_context(context)?;
        debug!(
            quote_id = %quote.quote_id,
            ttl_ms = quote.ttl_ms,
            quote_rpc_ms = start.elapsed().as_millis(),
            "quote rpc completed"
        );
        Ok(quote)
    }

    async fn bind_remote_endpoint() -> anyhow::Result<Arc<Endpoint>> {
        Ok(Arc::new(
            Endpoint::bind(presets::N0)
                .await
                .context("failed to create client transport endpoint")?,
        ))
    }

    async fn quote_remote_endpoint(
        quote_req: &GetQuoteRequest,
        endpoint: &Endpoint,
        peer_id: EndpointId,
    ) -> Result<QuotedRemoteDriver, QuoteCandidateError> {
        let start = Instant::now();
        let channel = ExecuteService::connect(endpoint, peer_id.into())
            .connect_timeout(REMOTE_CONNECT_TIMEOUT)
            .await
            .with_context(|| format!("failed to connect to node {peer_id}"))
            .map_err(QuoteCandidateError::Connect)?;
        let mut driver = RemoteExecuteDriver::new(channel);
        let quote = match driver.get_quote(quote_req.clone()).await {
            Ok(quote) => quote,
            Err(status) => return Err(QuoteCandidateError::Declined(status)),
        };
        debug!(
            quote_id = %quote.quote_id,
            ttl_ms = quote.ttl_ms,
            %peer_id,
            quote_rpc_ms = start.elapsed().as_millis(),
            "quote rpc completed"
        );
        Ok(QuotedRemoteDriver {
            peer_id,
            quote,
            driver,
        })
    }

    async fn quote_remote_peer(
        &self,
        endpoint: &Endpoint,
        peer_id: EndpointId,
    ) -> anyhow::Result<QuotedRemoteDriver> {
        Self::quote_remote_endpoint(&self.quote_req, endpoint, peer_id)
            .await
            .map_err(|err| match err {
                QuoteCandidateError::Declined(status) => {
                    anyhow::Error::from(status).context(format!("node {peer_id} declined quote"))
                }
                QuoteCandidateError::Connect(err) => err,
            })
    }

    async fn discover_remote_quote(
        &self,
        endpoint: &Endpoint,
    ) -> anyhow::Result<QuotedRemoteDriver> {
        let bindings = DiscoveryBindings::client(endpoint.id())?;

        let mut registry = ServiceRegistry::new(&endpoint);
        registry.add(MdnsBackend::new(bindings.mdns));
        registry.add(DhtBackend::with_dht(&endpoint, bindings.dht));

        let peers = Box::pin(registry.discover::<ExecuteService>());
        timeout(DISCOVERY_TIMEOUT, async {
            let mut last_decline = None;
            let mut last_connect_error = None;
            futures::pin_mut!(peers);

            while let Some(result) = peers.next().await {
                match result {
                    Ok(peer) => {
                        let peer_id = peer.id();
                        match Self::quote_remote_endpoint(&self.quote_req, endpoint, peer_id).await {
                            Ok(accepted) => return Ok(accepted),
                            Err(QuoteCandidateError::Declined(status)) => {
                                info!("provider declined quote: {status}");
                                last_decline = Some(status);
                            }
                            Err(QuoteCandidateError::Connect(err)) => {
                                debug!("candidate connect error: {err:#}");
                                last_connect_error = Some(err);
                            }
                        }
                    }
                    Err(err) => last_connect_error = Some(err.into()),
                }
            }

            if let Some(status) = last_decline {
                anyhow::bail!("all discovered providers declined the quote: {status}");
            }
            if let Some(err) = last_connect_error {
                return Err(err).context("failed to connect to discovered providers");
            }

            anyhow::bail!("no provider could serve the request");
        })
        .await
        .context("discovery timed out")?
    }

    async fn execute_discovered(
        &self,
        retries: usize,
        sink: &mut OutputSink<'_>,
    ) -> anyhow::Result<ExecutionOutput> {
        let max_attempts = retries.saturating_add(1);

        info!("No node ID provided, discovering executor");

        for attempt in 1..=max_attempts {
            let endpoint = Self::bind_remote_endpoint().await?;
            let mut quote = self.discover_remote_quote(&endpoint).await?;
            let peer_id = quote.peer_id;
            let mut committed = false;
            let mut tracked_sink = |output: &[u8]| -> anyhow::Result<()> {
                if !output.is_empty() {
                    committed = true;
                }
                sink(output)
            };

            let result = self
                .execute_with_driver(&mut quote.driver, quote.quote.quote_id, &mut tracked_sink)
                .await;
            endpoint.close().await;

            match result {
                Ok(output) => return Ok(output),
                Err(err) => {
                    if committed {
                        return Err(err.context(format!(
                            "execution failed on {peer_id} after output was emitted"
                        )));
                    }
                    if attempt == max_attempts {
                        return Err(err.context(format!("max retries ({retries}) exceeded")));
                    }
                    warn!(
                        attempt,
                        %peer_id,
                        "execution failed before output, rediscovering: {err:#}"
                    );
                }
            }
        }

        anyhow::bail!("max retries ({retries}) exceeded");
    }

    async fn execute_with_driver<D>(
        &self,
        driver: &mut D,
        quote_id: String,
        sink: &mut OutputSink<'_>,
    ) -> anyhow::Result<ExecutionOutput>
    where
        D: ExecuteDriver,
    {
        let start = Instant::now();
        let stream_start = Instant::now();
        let mut stream = driver
            .execute_streaming(ExecuteRequest {
                quote_id: quote_id.clone(),
                stream_batch_size: Some(1),
            })
            .await
            .context("failed to start execution stream")?;
        let stream_open_ms = stream_start.elapsed().as_millis();
        let mut output = Vec::new();
        let mut completion_tokens = 0u32;
        let mut first_event_logged = false;
        let mut first_output_logged = false;

        while let Some(event) = stream.next().await {
            let event = event.context("execution stream failed")?;
            if !first_event_logged {
                debug!(
                    quote_id = %quote_id,
                    stream_open_ms,
                    first_event_ms = start.elapsed().as_millis(),
                    "execute stream first event"
                );
                first_event_logged = true;
            }

            let had_output = output.len();
            if let Some(status) =
                self.consume_stream_event(event, &mut output, &mut completion_tokens, sink)?
            {
                if status == ExecutionStatus::Failed {
                    anyhow::bail!("execution failed");
                }
                if status == ExecutionStatus::Completed {
                    break;
                }
            }
            if !first_output_logged && output.len() > had_output {
                debug!(
                    quote_id = %quote_id,
                    stream_open_ms,
                    first_output_ms = start.elapsed().as_millis(),
                    "execute stream first output"
                );
                first_output_logged = true;
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

#[cfg(all(test, feature = "client"))]
mod timing_tests {
    use super::*;
    use hellas_executor::{ExecutorError, ModelAssets};
    use std::env;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::time::{Duration, sleep};

    fn required_env(name: &str) -> String {
        env::var(name).unwrap_or_else(|_| panic!("set {name} to run this timing test"))
    }

    fn optional_env_u32(name: &str, default: u32) -> u32 {
        env::var(name)
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(default)
    }

    #[test_log::test(tokio::test)]
    #[ignore = "manual local timing harness"]
    async fn local_two_job_timing() {
        let model = required_env("HELLAS_TIMING_MODEL");
        let prompt = env::var("HELLAS_TIMING_PROMPT")
            .unwrap_or_else(|_| "tell me a story about a boy named billy".to_string());
        let max_seq = optional_env_u32("HELLAS_TIMING_MAX_SEQ", 128);

        let assets = Arc::new(ModelAssets::load(&model).expect("failed to load model assets"));
        let runtime = ExecutionRuntime::spawn_default_local(
            hellas_executor::DEFAULT_EXECUTION_QUEUE_CAPACITY,
        )
        .expect("failed to start local executor");
        let prepared = assets
            .prepare_plain_prompt(&prompt)
            .expect("failed to prepare prompt");
        let quote_req = assets
            .build_quote_request(&prepared, max_seq)
            .expect("failed to build quote request");
        let executor = runtime
            .require_local_executor()
            .expect("missing local executor");

        for attempt in 1..=120 {
            match executor.quote(quote_req.clone()).await {
                Ok(_) => {
                    eprintln!("weights ready after {attempt} quote attempt(s)");
                    break;
                }
                Err(ExecutorError::WeightsNotReady(_)) if attempt < 120 => {
                    sleep(Duration::from_millis(250)).await;
                }
                Err(err) => panic!("failed to ready local weights: {err}"),
            }
        }

        for run_idx in 1..=2 {
            let prepared = assets
                .prepare_plain_prompt(&prompt)
                .expect("failed to prepare prompt");
            let request = ExecutionRequest::new(
                runtime.clone(),
                assets.clone(),
                prepared,
                max_seq,
                ExecutionStrategy::Run(ExecutionRoute::Local),
            )
            .expect("failed to build execution request");

            let start = Instant::now();
            let mut first_output_ms = None;
            let mut sink = |output: &[u8]| -> anyhow::Result<()> {
                if first_output_ms.is_none() && !output.is_empty() {
                    first_output_ms = Some(start.elapsed().as_millis());
                }
                Ok(())
            };

            let result = request.run(&mut sink).await.expect("execution failed");
            eprintln!(
                "run={run_idx} first_output_ms={} total_ms={} completion_tokens={}",
                first_output_ms.unwrap_or(0),
                start.elapsed().as_millis(),
                result.completion_tokens,
            );
        }
    }
}
