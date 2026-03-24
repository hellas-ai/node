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
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use tonic_iroh_transport::iroh::address_lookup::DnsAddressLookup;
use tonic_iroh_transport::iroh::{
    Endpoint, EndpointAddr, EndpointId, TransportAddr,
    endpoint::{PortmapperConfig, default_relay_mode},
};
use tonic_iroh_transport::swarm::{DhtBackend, MdnsBackend, ServiceRegistry};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic_iroh_transport::otel::TraceContextInjector;
use tonic_iroh_transport::{ConnectionPool, IrohConnect, PoolOptions};
use tracing::instrument;

type TracedChannel = InterceptedService<Channel, TraceContextInjector>;
type TracedDriver = RemoteExecuteDriver<TracedChannel>;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);
const REMOTE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

type OutputSink<'a> = dyn FnMut(&[u8]) -> anyhow::Result<()> + Send + 'a;

// ---------------------------------------------------------------------------
// Public configuration types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionRoute {
    Local,
    RemoteDirect(RemoteNodeTarget),
    RemoteDiscovery { retries: usize },
}

impl ExecutionRoute {
    pub fn remote(
        node_id: Option<EndpointId>,
        node_addrs: Vec<SocketAddr>,
        retries: usize,
    ) -> Self {
        match node_id {
            Some(node_id) => Self::RemoteDirect(RemoteNodeTarget {
                node_id,
                node_addrs,
            }),
            None => Self::RemoteDiscovery { retries },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteNodeTarget {
    pub node_id: EndpointId,
    pub node_addrs: Vec<SocketAddr>,
}

impl RemoteNodeTarget {
    fn endpoint_addr(&self) -> EndpointAddr {
        EndpointAddr::from_parts(
            self.node_id,
            self.node_addrs.iter().copied().map(TransportAddr::Ip),
        )
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

pub struct ExecutionOutput {
    pub output: Vec<u8>,
    pub completion_tokens: u32,
}

// ---------------------------------------------------------------------------
// ExecutionRuntime
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ExecutionRequest — thin construction + run wrapper
// ---------------------------------------------------------------------------

pub struct ExecutionRequest {
    runtime: ExecutionRuntime,
    quote_req: GetQuoteRequest,
    strategy: ExecutionStrategy,
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
        let mut prepared = self.prepare().await?;
        prepared.run(sink).await
    }

    pub(crate) async fn prepare(&self) -> anyhow::Result<PreparedExecution> {
        match &self.strategy {
            ExecutionStrategy::Run(route) => {
                let primary = PreparedRoute::prepare(&self.runtime, &self.quote_req, route).await?;
                Ok(PreparedExecution {
                    primary,
                    shadow: None,
                })
            }
            ExecutionStrategy::Verify { primary, shadow } => {
                let primary =
                    PreparedRoute::prepare(&self.runtime, &self.quote_req, primary).await?;
                let shadow = PreparedRoute::prepare(&self.runtime, &self.quote_req, shadow).await?;
                Ok(PreparedExecution {
                    primary,
                    shadow: Some(shadow),
                })
            }
        }
    }

    pub fn uses_remote_transport(&self) -> bool {
        let is_remote = |r: &ExecutionRoute| !matches!(r, ExecutionRoute::Local);
        match &self.strategy {
            ExecutionStrategy::Run(route) => is_remote(route),
            ExecutionStrategy::Verify { primary, shadow } => {
                is_remote(primary) || is_remote(shadow)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PreparedExecution — owns prepared routes, orchestrates verify
// ---------------------------------------------------------------------------

pub(crate) struct PreparedExecution {
    primary: PreparedRoute,
    shadow: Option<PreparedRoute>,
}

impl PreparedExecution {
    pub(crate) async fn run(
        &mut self,
        sink: &mut OutputSink<'_>,
    ) -> anyhow::Result<ExecutionOutput> {
        let primary_output = self.primary.run(sink).await?;
        if let Some(shadow) = &mut self.shadow {
            let shadow_output = shadow.run(&mut |_: &[u8]| Ok(())).await?;
            verify_matching_output(&primary_output, &shadow_output)?;
        }
        Ok(primary_output)
    }
}

// ---------------------------------------------------------------------------
// PreparedRoute — carries real state: quoted drivers, endpoint lifetimes,
// discovery retry tracking
// ---------------------------------------------------------------------------

enum PreparedRoute {
    Local {
        executor: ExecutorHandle,
        quote_id: String,
    },
    RemoteDirect(RemoteExecution),
    RemoteDiscovery {
        quote_req: GetQuoteRequest,
        retries: usize,
        active: Option<RemoteExecution>,
    },
}

struct RemoteExecution {
    endpoint: Arc<Endpoint>,
    peer_id: EndpointId,
    quote_id: String,
    driver: TracedDriver,
}

struct QuotedRemoteDriver {
    peer_id: EndpointId,
    quote: hellas_rpc::pb::hellas::GetQuoteResponse,
    driver: TracedDriver,
}

#[derive(Debug)]
enum QuoteCandidateError {
    Declined(tonic::Status),
    Connect(anyhow::Error),
}

impl PreparedRoute {
    #[instrument(skip_all, fields(?route))]
    async fn prepare(
        runtime: &ExecutionRuntime,
        quote_req: &GetQuoteRequest,
        route: &ExecutionRoute,
    ) -> anyhow::Result<Self> {
        match route {
            ExecutionRoute::Local => {
                let mut executor = runtime.require_local_executor()?;
                executor
                    .preload_weights(local_model_spec(quote_req))
                    .await
                    .context("failed to preload local weights")?;
                let quote = quote_with_driver(quote_req, &mut executor, || {
                    "local quote failed".to_string()
                })
                .await?;
                Ok(Self::Local {
                    executor,
                    quote_id: quote.quote_id,
                })
            }
            ExecutionRoute::RemoteDirect(target) => {
                let endpoint = bind_remote_endpoint().await?;
                let quote = quote_remote_target(quote_req, &endpoint, target).await?;
                Ok(Self::RemoteDirect(RemoteExecution::from_quoted(
                    endpoint, quote,
                )))
            }
            ExecutionRoute::RemoteDiscovery { retries } => Ok(Self::RemoteDiscovery {
                quote_req: quote_req.clone(),
                retries: *retries,
                active: None,
            }),
        }
    }

    #[instrument(skip_all)]
    async fn run(&mut self, sink: &mut OutputSink<'_>) -> anyhow::Result<ExecutionOutput> {
        match self {
            PreparedRoute::Local { executor, quote_id } => {
                execute_with_driver(executor, quote_id.clone(), sink).await
            }
            PreparedRoute::RemoteDirect(remote) => remote.run(sink).await,
            PreparedRoute::RemoteDiscovery {
                quote_req,
                retries,
                active,
            } => {
                let max_attempts = retries.saturating_add(1);
                info!("No node ID provided, discovering executor");

                for attempt in 1..=max_attempts {
                    if active.is_none() {
                        *active = Some(prepare_discovered_remote(quote_req).await?);
                    }

                    let remote = active.as_mut().expect("active remote execution");
                    let peer_id = remote.peer_id;
                    let mut committed = false;
                    let mut tracked_sink = |output: &[u8]| -> anyhow::Result<()> {
                        if !output.is_empty() {
                            committed = true;
                        }
                        sink(output)
                    };

                    let result = remote.run(&mut tracked_sink).await;

                    match result {
                        Ok(output) => return Ok(output),
                        Err(err) => {
                            if committed {
                                return Err(err.context(format!(
                                    "execution failed on {peer_id} after output was emitted"
                                )));
                            }
                            *active = None;
                            if attempt == max_attempts {
                                return Err(
                                    err.context(format!("max retries ({retries}) exceeded"))
                                );
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
        }
    }
}

impl RemoteExecution {
    fn from_quoted(endpoint: Arc<Endpoint>, quoted: QuotedRemoteDriver) -> Self {
        Self {
            endpoint,
            peer_id: quoted.peer_id,
            quote_id: quoted.quote.quote_id,
            driver: quoted.driver,
        }
    }

    #[instrument(skip_all, fields(peer_id = %self.peer_id, quote_id = %self.quote_id))]
    async fn run(&mut self, sink: &mut OutputSink<'_>) -> anyhow::Result<ExecutionOutput> {
        let _endpoint = &self.endpoint;
        execute_with_driver(&mut self.driver, self.quote_id.clone(), sink).await
    }
}

// ---------------------------------------------------------------------------
// Free functions — quoting, transport setup, execution, verification
// ---------------------------------------------------------------------------

#[instrument(skip_all, fields(model = %quote_req.huggingface_model_id))]
async fn quote_with_driver<D>(
    quote_req: &GetQuoteRequest,
    driver: &mut D,
    context: impl FnOnce() -> String,
) -> anyhow::Result<hellas_rpc::pb::hellas::GetQuoteResponse>
where
    D: ExecuteDriver,
{
    let quote = driver
        .get_quote(quote_req.clone())
        .await
        .with_context(context)?;
    tracing::Span::current().record("quote_id", &tracing::field::display(&quote.quote_id));
    Ok(quote)
}

async fn bind_remote_endpoint() -> anyhow::Result<Arc<Endpoint>> {
    Ok(Arc::new(
        Endpoint::empty_builder()
            .address_lookup(DnsAddressLookup::n0_dns())
            .relay_mode(default_relay_mode())
            .portmapper_config(PortmapperConfig::Disabled)
            .bind()
            .await
            .context("failed to create client transport endpoint")?,
    ))
}

fn bind_remote_pool(endpoint: &Endpoint) -> ConnectionPool {
    ConnectionPool::for_service::<ExecuteService>(
        endpoint.clone(),
        PoolOptions {
            connect_timeout: REMOTE_CONNECT_TIMEOUT,
            ..PoolOptions::default()
        },
    )
}

#[instrument(skip_all, fields(%peer_id, model = %quote_req.huggingface_model_id))]
async fn quote_remote_endpoint(
    quote_req: &GetQuoteRequest,
    pool: &ConnectionPool,
    peer_id: EndpointId,
) -> Result<QuotedRemoteDriver, QuoteCandidateError> {
    let channel = pool
        .channel(peer_id)
        .await
        .with_context(|| format!("failed to connect to node {peer_id}"))
        .map_err(QuoteCandidateError::Connect)?;
    let mut driver =
        RemoteExecuteDriver::with_service(InterceptedService::new(channel, TraceContextInjector));
    let quote = match driver.get_quote(quote_req.clone()).await {
        Ok(quote) => quote,
        Err(status) => return Err(QuoteCandidateError::Declined(status)),
    };
    Ok(QuotedRemoteDriver {
        peer_id,
        quote,
        driver,
    })
}

async fn quote_remote_peer(
    quote_req: &GetQuoteRequest,
    endpoint: &Endpoint,
    peer_id: EndpointId,
) -> anyhow::Result<QuotedRemoteDriver> {
    let pool = bind_remote_pool(endpoint);
    quote_remote_endpoint(quote_req, &pool, peer_id)
        .await
        .map_err(|err| match err {
            QuoteCandidateError::Declined(status) => {
                anyhow::Error::from(status).context(format!("node {peer_id} declined quote"))
            }
            QuoteCandidateError::Connect(err) => err,
        })
}

async fn quote_remote_target(
    quote_req: &GetQuoteRequest,
    endpoint: &Endpoint,
    target: &RemoteNodeTarget,
) -> anyhow::Result<QuotedRemoteDriver> {
    if target.node_addrs.is_empty() {
        return quote_remote_peer(quote_req, endpoint, target.node_id).await;
    }

    let channel = ExecuteService::connect(endpoint, target.endpoint_addr())
        .connect_timeout(REMOTE_CONNECT_TIMEOUT)
        .await
        .with_context(|| format!("failed to connect to node {}", target.node_id))?;
    let mut driver =
        RemoteExecuteDriver::with_service(InterceptedService::new(channel, TraceContextInjector));
    let quote = quote_with_driver(quote_req, &mut driver, || {
        format!("node {} declined quote", target.node_id)
    })
    .await?;

    Ok(QuotedRemoteDriver {
        peer_id: target.node_id,
        quote,
        driver,
    })
}

#[instrument(skip_all, fields(model = %quote_req.huggingface_model_id))]
async fn discover_remote_quote(
    quote_req: &GetQuoteRequest,
    endpoint: &Endpoint,
) -> anyhow::Result<QuotedRemoteDriver> {
    let bindings = DiscoveryBindings::client(endpoint.id())?;

    let mut registry = ServiceRegistry::new(&endpoint);
    registry.with_pool_options(PoolOptions {
        connect_timeout: REMOTE_CONNECT_TIMEOUT,
        ..PoolOptions::default()
    });
    registry.add(MdnsBackend::new(bindings.mdns));
    registry.add(DhtBackend::with_dht(&endpoint, bindings.dht));
    let pool = registry.pool::<ExecuteService>();

    let peers = Box::pin(registry.discover::<ExecuteService>());
    timeout(DISCOVERY_TIMEOUT, async {
        let mut last_decline = None;
        let mut last_connect_error = None;
        futures::pin_mut!(peers);

        while let Some(result) = peers.next().await {
            match result {
                Ok(peer) => {
                    let peer_id = peer.id();
                    match quote_remote_endpoint(quote_req, &pool, peer_id).await {
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

async fn prepare_discovered_remote(quote_req: &GetQuoteRequest) -> anyhow::Result<RemoteExecution> {
    let endpoint = bind_remote_endpoint().await?;
    let quote = discover_remote_quote(quote_req, &endpoint).await?;
    Ok(RemoteExecution::from_quoted(endpoint, quote))
}

#[instrument(skip_all, fields(%quote_id))]
async fn execute_with_driver<D>(
    driver: &mut D,
    quote_id: String,
    sink: &mut OutputSink<'_>,
) -> anyhow::Result<ExecutionOutput>
where
    D: ExecuteDriver,
{
    let mut stream = driver
        .execute_streaming(ExecuteRequest {
            quote_id: quote_id.clone(),
            stream_batch_size: Some(1),
        })
        .await
        .context("failed to start execution stream")?;
    let mut output = Vec::new();
    let mut completion_tokens = 0u32;

    while let Some(event) = stream.next().await {
        let event = event.context("execution stream failed")?;
        if let Some(status) =
            consume_stream_event(event, &mut output, &mut completion_tokens, sink)?
        {
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
                ExecutionStatus::try_from(snapshot.status).unwrap_or(ExecutionStatus::Unspecified),
                snapshot.progress,
            )
        }
        Some(execute_stream_event::Event::Progress(progress)) => {
            if !progress.output_chunk.is_empty() {
                output.extend_from_slice(&progress.output_chunk);
                sink(&progress.output_chunk)?;
            }
            (
                ExecutionStatus::try_from(progress.status).unwrap_or(ExecutionStatus::Unspecified),
                progress.progress,
            )
        }
        None => return Ok(None),
    };

    *completion_tokens = u32::try_from(progress).unwrap_or(u32::MAX);
    Ok(Some(status))
}

fn local_model_spec(quote_req: &GetQuoteRequest) -> String {
    let revision = quote_req.huggingface_revision.trim();
    if revision.is_empty() {
        quote_req.huggingface_model_id.clone()
    } else {
        format!("{}@{revision}", quote_req.huggingface_model_id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_matching_output_accepts_identical() {
        let a = ExecutionOutput {
            output: vec![1, 2, 3],
            completion_tokens: 3,
        };
        let b = ExecutionOutput {
            output: vec![1, 2, 3],
            completion_tokens: 3,
        };
        verify_matching_output(&a, &b).unwrap();
    }

    #[test]
    fn verify_matching_output_rejects_divergent() {
        let a = ExecutionOutput {
            output: vec![1, 2, 3],
            completion_tokens: 3,
        };
        let b = ExecutionOutput {
            output: vec![1, 2, 4],
            completion_tokens: 3,
        };
        let err = verify_matching_output(&a, &b).unwrap_err();
        assert!(format!("{err}").contains("diverged at byte 2"));
    }

    #[test]
    fn verify_matching_output_rejects_different_lengths() {
        let a = ExecutionOutput {
            output: vec![1, 2],
            completion_tokens: 2,
        };
        let b = ExecutionOutput {
            output: vec![1, 2, 3],
            completion_tokens: 3,
        };
        let err = verify_matching_output(&a, &b).unwrap_err();
        assert!(format!("{err}").contains("diverged"));
    }

    #[test]
    fn prepared_execution_without_shadow_skips_verify() {
        // PreparedExecution { shadow: None } should just run primary.
        // We can't easily test the async run() without a driver, but we can
        // verify the struct shape is correct.
        let exec = PreparedExecution {
            primary: PreparedRoute::RemoteDiscovery {
                quote_req: GetQuoteRequest::default(),
                retries: 0,
                active: None,
            },
            shadow: None,
        };
        assert!(exec.shadow.is_none());
    }
}

#[cfg(all(test, feature = "client"))]
mod timing_tests {
    use super::*;
    use catgrad_llm::PromptRequest;
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
            .prepare_request(&PromptRequest::plain(&prompt))
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
                .prepare_request(&PromptRequest::plain(&prompt))
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
