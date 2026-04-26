//! Stream-shaped CLI execution layer.
//!
//! The fundamental shape: every layer returns
//! `impl Stream<Item = anyhow::Result<ExecutionEvent>>`. Drop-cancellation
//! propagates naturally — when a consumer drops the stream, the generator
//! is dropped, which drops every in-flight future, which drops every
//! resource, which (for local executions) drops the per-execution
//! `mpsc::Receiver` the worker pushes chunks into. The worker observes
//! the closed channel on its next chunk send and converts it into a
//! cancel that the runner sees between decode steps.
//!
//! ```text
//! ExecutionRequest::stream  →  PreparedExecution::stream
//!                                ├─ primary: PreparedRoute::stream
//!                                │   ├─ Local:           execute_stream(executor)
//!                                │   ├─ RemoteDirect:    execute_stream(remote)
//!                                │   └─ RemoteDiscovery: retry loop wrapping execute_stream
//!                                └─ shadow (verify):    same shape, run after primary
//! ```
//!
//! Stream items separate two failure modes:
//!   - `Err(_)` — transport error: we don't know the executor's verdict.
//!   - `Ok(Done(Outcome::Failed))` — executor's explicit failure verdict.
//!
//! Discovery retry policy:
//!   - Transport error before any chunk → try the next peer.
//!   - Transport error after a chunk → propagate (committed work can't be retried).
//!   - `Done(Failed)` (executor verdict) → propagate, never retry.

#[cfg(feature = "hellas-executor")]
use anyhow::Error as AnyhowError;
use anyhow::{Context, anyhow, bail};
use async_stream::try_stream;
use catgrad::cid::Cid;
#[cfg(feature = "hellas-executor")]
use catgrad::prelude::Dtype;
use catgrad_llm::PreparedPrompt;
use catgrad_llm::runtime::TextReceipt;
use futures::StreamExt;
use futures::stream::{BoxStream, FuturesUnordered, Stream};
#[cfg(feature = "hellas-executor")]
use hellas_executor::{Executor, ExecutorHandle};
use hellas_rpc::discovery::DiscoveryBindings;
use hellas_rpc::driver::{ExecuteDriver, QuotedResponse, RemoteExecuteDriver};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::model::ModelAssets;
use hellas_rpc::pb::hellas::{
    self as pb, ExecuteRequest, ExecuteStreamEvent, GetQuoteRequest, execute_stream_event,
};
#[cfg(feature = "hellas-executor")]
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use hellas_rpc::service::ExecuteService;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Duration;
use tonic::service::interceptor::InterceptedService;
use tonic_iroh_transport::iroh::address_lookup::DnsAddressLookup;
use tonic_iroh_transport::iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr, endpoint::PortmapperConfig,
};
use tonic_iroh_transport::otel::TraceContextInjector;
use tonic_iroh_transport::swarm::{DhtBackend, MdnsBackend, ServiceRegistry};
use tonic_iroh_transport::{ConnectionPool, IrohChannel, IrohConnect, PoolOptions};
use tracing::instrument;

type TracedChannel = InterceptedService<IrohChannel, TraceContextInjector>;
type TracedDriver = RemoteExecuteDriver<TracedChannel>;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);
const REMOTE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Max quote RPCs in flight at once while draining the discovery stream.
/// Keep this high enough that we never stall the mDNS subscriber (the
/// consumer must drain at least as fast as iroh emits, i.e. ~1/sec per
/// peer), but low enough to avoid thundering-herd on the network.
const MAX_CONCURRENT_QUOTES: usize = 8;

// ---------------------------------------------------------------------------
// Public configuration types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionRoute {
    #[cfg(feature = "hellas-executor")]
    Local,
    RemoteDirect(RemoteNodeTarget),
    RemoteDiscovery {
        retries: usize,
    },
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
    #[cfg(feature = "hellas-executor")]
    local_executor: Option<ExecutorHandle>,
    secret_key: Option<SecretKey>,
}

// ---------------------------------------------------------------------------
// Stream item types
// ---------------------------------------------------------------------------

/// One observation from a streaming execution. Stream protocol: zero or
/// more `Chunk` events, terminated by exactly one `Done`.
#[derive(Debug, Clone)]
pub enum ExecutionEvent {
    Chunk {
        /// Cumulative tokens emitted *after* this chunk.
        position: u64,
        /// Little-endian u32 token IDs.
        tokens: Vec<u8>,
    },
    Done(Outcome),
}

/// Terminal verdict of an execution.
#[derive(Debug, Clone)]
pub enum Outcome {
    Completed {
        total_tokens: u64,
        stop_reason: StopReason,
        receipt_cid: Cid<TextReceipt>,
    },
    Failed {
        /// Tokens emitted before the failure (for honest usage reporting).
        position: u64,
        error: String,
    },
}

impl Outcome {
    /// Cumulative token count at the moment the run terminated.
    /// Authoritative for usage frames on both Completed and Failed.
    pub fn position(&self) -> u64 {
        match self {
            Self::Completed { total_tokens, .. } => *total_tokens,
            Self::Failed { position, .. } => *position,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    EndOfSequence,
    MaxNewTokens,
    Cancelled,
}

// ---------------------------------------------------------------------------
// ExecutionRuntime
// ---------------------------------------------------------------------------

impl ExecutionRuntime {
    #[cfg(feature = "hellas-executor")]
    pub fn with_local_executor(local_executor: ExecutorHandle) -> Self {
        Self {
            local_executor: Some(local_executor),
            secret_key: None,
        }
    }

    pub fn with_secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    #[cfg(feature = "hellas-executor")]
    pub fn spawn_default_local(
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
    ) -> anyhow::Result<Self> {
        let local_executor = Executor::spawn(
            DownloadPolicy::Eager,
            ExecutePolicy::Eager,
            queue_capacity,
            supported_dtypes,
        )
        .context("failed to initialize local execution backend")?;
        Ok(Self::with_local_executor(local_executor))
    }

    #[cfg(feature = "hellas-executor")]
    fn require_local_executor(&self) -> Result<ExecutorHandle, AnyhowError> {
        self.local_executor
            .clone()
            .ok_or_else(|| anyhow!("local execution requested but no local executor is configured"))
    }
}

// ---------------------------------------------------------------------------
// ExecutionRequest — public entry point
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

    /// True if any leg of this strategy talks to a remote executor.
    pub fn uses_remote_transport(&self) -> bool {
        #[cfg(feature = "hellas-executor")]
        let is_remote = |r: &ExecutionRoute| !matches!(r, ExecutionRoute::Local);
        #[cfg(not(feature = "hellas-executor"))]
        let is_remote = |_r: &ExecutionRoute| true;
        match &self.strategy {
            ExecutionStrategy::Run(route) => is_remote(route),
            ExecutionStrategy::Verify { primary, shadow } => {
                is_remote(primary) || is_remote(shadow)
            }
        }
    }

    /// Run the quote step (talking to the chosen executor) and return the
    /// `PreparedExecution`. Splitting prepare from `stream` lets callers
    /// (notably the gateway) read pre-flight provenance off
    /// `PreparedExecution::provenance()` *before* the response stream
    /// flushes its headers.
    pub async fn prepare(self) -> anyhow::Result<PreparedExecution> {
        prepare_execution(&self.runtime, &self.quote_req, &self.strategy).await
    }

    /// Drive this request to completion as a stream of events.
    ///
    /// Owning consumption: dropping the returned stream cancels everything
    /// downstream (broadcast subscribers, tonic streams, the executor's
    /// per-running cancel token).
    pub fn stream(self) -> impl Stream<Item = anyhow::Result<ExecutionEvent>> + Send {
        try_stream! {
            let prepared = self.prepare().await?;
            let inner = prepared.stream();
            tokio::pin!(inner);
            while let Some(event) = inner.next().await {
                yield event?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PreparedExecution — primary + optional shadow for Verify
// ---------------------------------------------------------------------------

pub struct PreparedExecution {
    primary: PreparedRoute,
    shadow: Option<PreparedRoute>,
}

async fn prepare_execution(
    runtime: &ExecutionRuntime,
    quote_req: &GetQuoteRequest,
    strategy: &ExecutionStrategy,
) -> anyhow::Result<PreparedExecution> {
    match strategy {
        ExecutionStrategy::Run(route) => Ok(PreparedExecution {
            primary: PreparedRoute::prepare(runtime, quote_req, route).await?,
            shadow: None,
        }),
        ExecutionStrategy::Verify { primary, shadow } => Ok(PreparedExecution {
            primary: PreparedRoute::prepare(runtime, quote_req, primary).await?,
            shadow: Some(PreparedRoute::prepare(runtime, quote_req, shadow).await?),
        }),
    }
}

impl PreparedExecution {
    /// See [`PreparedRoute::provenance`] — this delegates to the primary
    /// route. Shadow's provenance is intentionally not exposed (verify is
    /// internal; the primary is what the user sees).
    pub fn provenance(&self) -> Option<&ExecutionProvenance> {
        self.primary.provenance()
    }

    /// Stream primary's events live. If a shadow is configured, run it
    /// after primary completes and only emit primary's `Done` once the two
    /// receipts agree. Mismatch is reported as a `Done(Failed)` so the
    /// terminal frame is honest about the disagreement.
    pub fn stream(self) -> impl Stream<Item = anyhow::Result<ExecutionEvent>> + Send {
        let Self { primary, shadow } = self;
        try_stream! {
            // Yield primary's chunks live; hold its Done back until shadow
            // (if any) agrees.
            let mut primary_done: Option<Outcome> = None;
            {
                let primary = primary.stream();
                tokio::pin!(primary);
                while let Some(event) = primary.next().await {
                    match event? {
                        ExecutionEvent::Chunk { position, tokens } => {
                            yield ExecutionEvent::Chunk { position, tokens };
                        }
                        ExecutionEvent::Done(outcome) => {
                            primary_done = Some(outcome);
                            break;
                        }
                    }
                }
            }
            let primary_outcome = primary_done
                .ok_or_else(|| anyhow!("primary stream ended without terminal outcome"))?;

            let final_outcome = match shadow {
                None => primary_outcome,
                Some(shadow_route) => verify_shadow(primary_outcome, shadow_route).await?,
            };
            yield ExecutionEvent::Done(final_outcome);
        }
    }
}

/// Run the shadow stream to completion (discarding its chunks), extract
/// its terminal outcome, and return the reconciled outcome.
///
/// Cases:
///   - Primary Failed → return primary unchanged. Shadow doesn't run; no
///     point burning verification compute on a failure.
///   - Primary Completed + shadow Completed + matching receipt CIDs →
///     primary unchanged.
///   - Primary Completed + shadow Completed + mismatched receipts →
///     synthetic Failed describing the divergence.
///   - Primary Completed + shadow Failed → synthetic Failed: the run is
///     unverified, even though the bytes the user saw were real. The
///     terminal frame is honest about that.
///
/// Transport errors from the shadow stream propagate via `?` and surface
/// as stream-level errors (not Outcome::Failed) — they're also unverified
/// situations but distinguished for diagnostics.
async fn verify_shadow(primary: Outcome, shadow: PreparedRoute) -> anyhow::Result<Outcome> {
    let primary_cid = match &primary {
        Outcome::Completed { receipt_cid, .. } => *receipt_cid,
        Outcome::Failed { .. } => return Ok(primary),
    };

    let shadow_outcome = drain_to_outcome(shadow.stream()).await?;
    match shadow_outcome {
        Outcome::Completed {
            receipt_cid: shadow_cid,
            ..
        } => {
            if primary_cid == shadow_cid {
                Ok(primary)
            } else {
                Ok(Outcome::Failed {
                    position: primary.position(),
                    error: format!(
                        "verify mismatch: primary receipt {primary_cid} ≠ shadow receipt {shadow_cid}"
                    ),
                })
            }
        }
        Outcome::Failed {
            error: shadow_error,
            ..
        } => Ok(Outcome::Failed {
            position: primary.position(),
            error: format!("shadow verification failed: {shadow_error}"),
        }),
    }
}

/// Consume a stream to its terminal `Done`, discarding chunks. Errors if
/// the stream ends without a terminal event.
async fn drain_to_outcome(
    stream: impl Stream<Item = anyhow::Result<ExecutionEvent>>,
) -> anyhow::Result<Outcome> {
    tokio::pin!(stream);
    while let Some(event) = stream.next().await {
        if let ExecutionEvent::Done(outcome) = event? {
            return Ok(outcome);
        }
    }
    Err(anyhow!("shadow stream ended without terminal outcome"))
}

// ---------------------------------------------------------------------------
// PreparedRoute — Local | RemoteDirect | RemoteDiscovery
// ---------------------------------------------------------------------------

enum PreparedRoute {
    #[cfg(feature = "hellas-executor")]
    Local {
        executor: ExecutorHandle,
        quote_id: String,
        provenance: ExecutionProvenance,
    },
    RemoteDirect(RemoteExecution),
    RemoteDiscovery {
        quote_req: GetQuoteRequest,
        retries: usize,
        secret_key: Option<SecretKey>,
    },
}

impl PreparedRoute {
    /// Pre-flight provenance — `Some` when the route's quote has already
    /// happened (Local, RemoteDirect) so the gateway can attach
    /// `x-hellas-*` response headers before any stream events flow.
    /// `None` for `RemoteDiscovery`, where the quote is deferred until
    /// the first peer responds during streaming; in that case the gateway
    /// falls back to in-band SSE events for the same provenance.
    fn provenance(&self) -> Option<&ExecutionProvenance> {
        match self {
            #[cfg(feature = "hellas-executor")]
            PreparedRoute::Local { provenance, .. } => Some(provenance),
            PreparedRoute::RemoteDirect(remote) => Some(&remote.provenance),
            PreparedRoute::RemoteDiscovery { .. } => None,
        }
    }

    #[instrument(skip_all, fields(?route))]
    async fn prepare(
        runtime: &ExecutionRuntime,
        quote_req: &GetQuoteRequest,
        route: &ExecutionRoute,
    ) -> anyhow::Result<Self> {
        match route {
            #[cfg(feature = "hellas-executor")]
            ExecutionRoute::Local => {
                let mut executor = runtime.require_local_executor()?;
                executor
                    .preload_weights(local_model_spec(quote_req))
                    .await
                    .context("failed to preload local weights")?;
                let quoted = quote_with_driver(quote_req, &mut executor, || {
                    "local quote failed".to_string()
                })
                .await?;
                Ok(Self::Local {
                    executor,
                    quote_id: quoted.response.quote_id,
                    provenance: quoted.provenance,
                })
            }
            ExecutionRoute::RemoteDirect(target) => {
                let endpoint = bind_remote_endpoint(runtime.secret_key.as_ref()).await?;
                let quote = quote_remote_target(quote_req, &endpoint, target).await?;
                Ok(Self::RemoteDirect(RemoteExecution::from_quoted(
                    endpoint, quote,
                )))
            }
            ExecutionRoute::RemoteDiscovery { retries } => Ok(Self::RemoteDiscovery {
                quote_req: quote_req.clone(),
                retries: *retries,
                secret_key: runtime.secret_key.clone(),
            }),
        }
    }

    fn stream(self) -> BoxStream<'static, anyhow::Result<ExecutionEvent>> {
        match self {
            #[cfg(feature = "hellas-executor")]
            PreparedRoute::Local {
                executor,
                quote_id,
                provenance: _,
            } => execute_stream(executor, quote_id).boxed(),
            PreparedRoute::RemoteDirect(remote) => remote.stream().boxed(),
            PreparedRoute::RemoteDiscovery {
                quote_req,
                retries,
                secret_key,
            } => discovery_stream(quote_req, retries, secret_key).boxed(),
        }
    }
}

/// Discovery+retry across providers.
///
/// Per-attempt rules (matched off the inner Result so the failure-mode
/// distinction is visible):
///   - `Ok(Chunk)` → forward; mark `committed`.
///   - `Ok(Done)` → forward and finish (executor verdict, no retry).
///   - `Err(_)` before any `committed` chunk → exclude this peer, retry.
///   - `Err(_)` after `committed` chunks → propagate (can't retry committed work).
///
/// `prepare_discovered_remote` failure aborts immediately — that's a
/// "couldn't find anyone" condition that retrying won't help with.
fn discovery_stream(
    quote_req: GetQuoteRequest,
    retries: usize,
    secret_key: Option<SecretKey>,
) -> impl Stream<Item = anyhow::Result<ExecutionEvent>> + Send {
    try_stream! {
        let max_attempts = retries.saturating_add(1);
        let mut tried: HashSet<EndpointId> = HashSet::new();
        let mut last_peer_error: Option<anyhow::Error> = None;
        info!("No node ID provided, discovering executor");

        for attempt in 1..=max_attempts {
            let remote = prepare_discovered_remote(&quote_req, secret_key.as_ref(), &tried).await?;
            let peer_id = remote.peer_id;
            let mut committed = false;
            let mut transport_err: Option<anyhow::Error> = None;
            let mut got_terminal = false;
            {
                let inner = remote.stream();
                tokio::pin!(inner);
                while let Some(event) = inner.next().await {
                    match event {
                        Ok(ExecutionEvent::Chunk { position, tokens }) => {
                            committed = true;
                            yield ExecutionEvent::Chunk { position, tokens };
                        }
                        Ok(ExecutionEvent::Done(outcome)) => {
                            got_terminal = true;
                            yield ExecutionEvent::Done(outcome);
                        }
                        Err(e) => {
                            transport_err = Some(e);
                            break;
                        }
                    }
                }
            }
            if got_terminal { return; }

            // No terminal — must be a transport error. The "stream ended
            // without terminal" case manifests as None from the inner
            // generator without an Err item; treat it the same way.
            let err = transport_err
                .unwrap_or_else(|| anyhow!("stream from {peer_id} ended without terminal outcome"));
            if committed {
                Err(err.context(format!(
                    "execution failed on {peer_id} after output was emitted"
                )))?;
                unreachable!("Err(_)? always returns");
            }
            warn!(attempt, %peer_id, "execution failed before output, rediscovering: {err:#}");
            tried.insert(peer_id);
            last_peer_error = Some(err);
        }

        let err = last_peer_error
            .unwrap_or_else(|| anyhow!("no provider could serve the request"));
        Err(err.context(format!("max retries ({retries}) exceeded")))?;
    }
}

// ---------------------------------------------------------------------------
// RemoteExecution — owns one quoted remote driver + its endpoint
// ---------------------------------------------------------------------------

struct RemoteExecution {
    endpoint: Arc<Endpoint>,
    peer_id: EndpointId,
    quote_id: String,
    provenance: ExecutionProvenance,
    driver: TracedDriver,
}

impl RemoteExecution {
    fn from_quoted(endpoint: Arc<Endpoint>, quoted: QuotedRemoteDriver) -> Self {
        Self {
            endpoint,
            peer_id: quoted.peer_id,
            quote_id: quoted.quote.quote_id,
            provenance: quoted.provenance,
            driver: quoted.driver,
        }
    }

    fn stream(self) -> impl Stream<Item = anyhow::Result<ExecutionEvent>> + Send {
        let Self {
            endpoint,
            peer_id: _,
            quote_id,
            provenance: _,
            driver,
        } = self;
        try_stream! {
            // Hold the endpoint until the stream is dropped. Dropping the
            // endpoint while the underlying QUIC connection is in-flight
            // would tear down transport mid-execution.
            let _endpoint = endpoint;
            let inner = execute_stream(driver, quote_id);
            tokio::pin!(inner);
            while let Some(event) = inner.next().await {
                yield event?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// execute_stream — the bottom layer that maps wire events → ExecutionEvent
// ---------------------------------------------------------------------------

fn execute_stream<D: ExecuteDriver + Send + 'static>(
    mut driver: D,
    quote_id: String,
) -> impl Stream<Item = anyhow::Result<ExecutionEvent>> + Send {
    try_stream! {
        // Provenance arrives in `streamed.provenance` (from response
        // metadata server-side) but the gateway already has it from the
        // quote step, so we drop it here and only forward the event stream.
        let mut wire = driver
            .execute_streaming(ExecuteRequest {
                quote_id: quote_id.clone(),
                stream_batch_size: Some(1),
            })
            .await
            .context("failed to start execution stream")?
            .stream;

        let mut got_terminal = false;
        while let Some(item) = wire.next().await {
            let event = convert_wire_event(item.context("execution stream failed")?)?;
            let is_done = matches!(event, ExecutionEvent::Done(_));
            yield event;
            if is_done {
                got_terminal = true;
                break;
            }
        }

        if !got_terminal {
            Err(anyhow!("execution stream ended without terminal outcome"))?;
        }
        // Hold the driver until end of stream so the underlying transport
        // (tonic streaming response) stays attached.
        drop(driver);
    }
}

/// Translate one wire `ExecuteStreamEvent` into one `ExecutionEvent`.
fn convert_wire_event(event: ExecuteStreamEvent) -> anyhow::Result<ExecutionEvent> {
    let Some(event) = event.event else {
        bail!("wire event with no body");
    };
    match event {
        execute_stream_event::Event::Chunk(chunk) => Ok(ExecutionEvent::Chunk {
            position: chunk.position,
            tokens: chunk.tokens,
        }),
        execute_stream_event::Event::Outcome(outcome) => {
            Ok(ExecutionEvent::Done(parse_outcome(Some(outcome))?))
        }
    }
}

fn parse_outcome(outcome: Option<pb::Outcome>) -> anyhow::Result<Outcome> {
    let outcome = outcome.ok_or_else(|| anyhow!("outcome message with no body"))?;
    let kind = outcome
        .kind
        .ok_or_else(|| anyhow!("outcome with no kind"))?;
    match kind {
        pb::outcome::Kind::Completed(c) => {
            let receipt_cid = receipt_cid_from_bytes(&c.receipt_cid)?;
            let stop_reason = stop_reason_from_pb(c.stop_reason)?;
            Ok(Outcome::Completed {
                total_tokens: c.total_tokens,
                stop_reason,
                receipt_cid,
            })
        }
        pb::outcome::Kind::Failed(f) => Ok(Outcome::Failed {
            position: f.position,
            error: f.error,
        }),
    }
}

fn receipt_cid_from_bytes(bytes: &[u8]) -> anyhow::Result<Cid<TextReceipt>> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow!(
            "receipt_cid wire length {} bytes (expected 32)",
            bytes.len()
        )
    })?;
    Ok(Cid::from_bytes(arr))
}

fn stop_reason_from_pb(value: i32) -> anyhow::Result<StopReason> {
    let pb_value = pb::StopReason::try_from(value)
        .with_context(|| format!("unknown stop_reason value {value}"))?;
    match pb_value {
        pb::StopReason::Unspecified => bail!("wire stop_reason is unspecified"),
        pb::StopReason::EndOfSequence => Ok(StopReason::EndOfSequence),
        pb::StopReason::MaxNewTokens => Ok(StopReason::MaxNewTokens),
        pb::StopReason::Cancelled => Ok(StopReason::Cancelled),
    }
}

// ---------------------------------------------------------------------------
// Quote / discovery / endpoint helpers (largely unchanged)
// ---------------------------------------------------------------------------

struct QuotedRemoteDriver {
    peer_id: EndpointId,
    quote: hellas_rpc::pb::hellas::GetQuoteResponse,
    provenance: ExecutionProvenance,
    driver: TracedDriver,
}

#[derive(Debug)]
enum QuoteCandidateError {
    Declined(tonic::Status),
    Connect(anyhow::Error),
}

#[instrument(skip_all, fields(model = %quote_req.huggingface_model_id))]
async fn quote_with_driver<D>(
    quote_req: &GetQuoteRequest,
    driver: &mut D,
    context: impl FnOnce() -> String,
) -> anyhow::Result<QuotedResponse>
where
    D: ExecuteDriver,
{
    let quoted = driver
        .get_quote(quote_req.clone())
        .await
        .with_context(context)?;
    tracing::Span::current()
        .record("quote_id", tracing::field::display(&quoted.response.quote_id));
    Ok(quoted)
}

async fn bind_remote_endpoint(secret_key: Option<&SecretKey>) -> anyhow::Result<Arc<Endpoint>> {
    let (endpoint, _bindings) = bind_remote_endpoint_with_bindings(secret_key).await?;
    Ok(endpoint)
}

/// Bind a client endpoint and attach the full discovery stack (DNS + Pkarr
/// publisher + mDNS + DHT resolver). Without mDNS attached to the endpoint's
/// address lookup, peers on the same LAN can only be resolved via the Pkarr
/// DHT / n0 DNS relay, so LAN connections take minutes instead of milliseconds.
async fn bind_remote_endpoint_with_bindings(
    secret_key: Option<&SecretKey>,
) -> anyhow::Result<(Arc<Endpoint>, DiscoveryBindings)> {
    use tonic_iroh_transport::iroh::address_lookup::PkarrPublisher;
    use tonic_iroh_transport::iroh::endpoint::presets;

    let mut builder = Endpoint::builder(presets::N0)
        .clear_address_lookup()
        .address_lookup(DnsAddressLookup::n0_dns())
        .address_lookup(PkarrPublisher::n0_dns())
        .portmapper_config(PortmapperConfig::Disabled);
    if let Some(key) = secret_key {
        builder = builder.secret_key(key.clone());
    }
    let endpoint = builder
        .bind()
        .await
        .context("failed to create client transport endpoint")?;
    let bindings = DiscoveryBindings::attach(&endpoint, false, false)
        .context("failed to attach client discovery lookups")?;
    Ok((Arc::new(endpoint), bindings))
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
    let quoted = match driver.get_quote(quote_req.clone()).await {
        Ok(quoted) => quoted,
        Err(status) => return Err(QuoteCandidateError::Declined(status)),
    };
    Ok(QuotedRemoteDriver {
        peer_id,
        quote: quoted.response,
        provenance: quoted.provenance,
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
    let quoted = quote_with_driver(quote_req, &mut driver, || {
        format!("node {} declined quote", target.node_id)
    })
    .await?;

    Ok(QuotedRemoteDriver {
        peer_id: target.node_id,
        quote: quoted.response,
        provenance: quoted.provenance,
        driver,
    })
}

#[instrument(skip_all, fields(model = %quote_req.huggingface_model_id, excluded = exclude.len()))]
async fn discover_remote_quote(
    quote_req: &GetQuoteRequest,
    endpoint: &Endpoint,
    bindings: DiscoveryBindings,
    exclude: &HashSet<EndpointId>,
) -> anyhow::Result<QuotedRemoteDriver> {
    let mut registry = ServiceRegistry::new(endpoint);
    registry.with_pool_options(PoolOptions {
        connect_timeout: REMOTE_CONNECT_TIMEOUT,
        ..PoolOptions::default()
    });
    registry.add(MdnsBackend::new(bindings.mdns));
    registry.add(DhtBackend::with_dht(endpoint, bindings.dht));
    let pool = registry.pool::<ExecuteService>();

    let peers = Box::pin(registry.discover::<ExecuteService>());
    tokio::time::timeout(DISCOVERY_TIMEOUT, async {
        let mut last_decline: Option<tonic::Status> = None;
        let mut last_connect_error: Option<anyhow::Error> = None;
        let mut peers_done = false;
        let mut in_flight: FuturesUnordered<_> = FuturesUnordered::new();
        futures::pin_mut!(peers);

        loop {
            tokio::select! {
                biased;

                // Consume completed quote attempts first; an early success short-circuits.
                Some(result) = in_flight.next(), if !in_flight.is_empty() => {
                    match result {
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

                // Drain the mDNS/DHT stream as fast as we can, up to the concurrency cap,
                // so iroh's subscriber buffer doesn't fill up and start dropping items.
                peer = peers.next(), if !peers_done && in_flight.len() < MAX_CONCURRENT_QUOTES => {
                    match peer {
                        Some(Ok(peer)) => {
                            let peer_id = peer.id();
                            if exclude.contains(&peer_id) {
                                debug!(%peer_id, "skipping previously-failed peer");
                                continue;
                            }
                            let pool = pool.clone();
                            let req = quote_req.clone();
                            in_flight.push(async move {
                                quote_remote_endpoint(&req, &pool, peer_id).await
                            });
                        }
                        Some(Err(err)) => last_connect_error = Some(err.into()),
                        None => peers_done = true,
                    }
                }

                else => {
                    if peers_done && in_flight.is_empty() {
                        break;
                    }
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
    })
    .await
    .context("discovery timed out")?
}

async fn prepare_discovered_remote(
    quote_req: &GetQuoteRequest,
    secret_key: Option<&SecretKey>,
    exclude: &HashSet<EndpointId>,
) -> anyhow::Result<RemoteExecution> {
    let (endpoint, bindings) = bind_remote_endpoint_with_bindings(secret_key).await?;
    let quote = discover_remote_quote(quote_req, &endpoint, bindings, exclude).await?;
    Ok(RemoteExecution::from_quoted(endpoint, quote))
}

#[cfg(feature = "hellas-executor")]
fn local_model_spec(quote_req: &GetQuoteRequest) -> String {
    let revision = quote_req.huggingface_revision.trim();
    if revision.is_empty() {
        quote_req.huggingface_model_id.clone()
    } else {
        format!("{}@{revision}", quote_req.huggingface_model_id)
    }
}
