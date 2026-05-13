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
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "hellas-executor")]
use catgrad::prelude::Dtype;
use chatgrad::PreparedPrompt;
use futures::StreamExt;
use futures::stream::{BoxStream, FuturesUnordered, Stream};
#[cfg(feature = "hellas-executor")]
use hellas_core::ProducerSigningKey;
use hellas_core::{
    DeliveryOutput, DeliveryRequest, Digest, JsonBytes, OpaqueRequest as CoreOpaqueRequest,
    SchemeId, SignedReceipt as CoreSignedReceipt, decode_dag_cbor, verify_delivery, verify_receipt,
};
#[cfg(feature = "hellas-executor")]
use hellas_executor::{Executor, ExecutorHandle};
use hellas_pb::courtesy::QuotePreparedTextRequest;
use hellas_pb::hellas::{self as pb, FinishStatus, RunTicketRequest, WorkEvent, work_event};
use hellas_pb::opaque::OpaqueRequest as PbOpaqueRequest;
use hellas_rpc::discovery::DiscoveryBindings;
use hellas_rpc::driver::{
    ExecuteDriver, QuotedPreparedTextResponse, QuotedResponse, RemoteExecuteDriver,
};
use hellas_rpc::model::ModelAssets;
use hellas_rpc::peers::{IrohRpcPool, IrohTarget, IrohTransport, PeerManager};
#[cfg(feature = "hellas-executor")]
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::service::{CourtesyService, ExecuteService, OpaqueService, methods};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Duration;
use tonic_iroh_transport::iroh::address_lookup::DnsAddressLookup;
use tonic_iroh_transport::iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr, endpoint::PortmapperConfig,
};
use tonic_iroh_transport::swarm::{DhtBackend, MdnsBackend, ServiceRegistry};
use tonic_iroh_transport::{IrohChannel, PoolOptions};
use tracing::instrument;

// `TracedChannel` swaps under the `otel` feature: with otel on it wraps the
// channel in an interceptor that injects W3C traceparent headers; with otel
// off it's the bare channel. Construction sites use `traced(channel)`.
#[cfg(feature = "otel")]
type TracedChannel = tonic::service::interceptor::InterceptedService<
    IrohChannel,
    tonic_iroh_transport::otel::TraceContextInjector,
>;
#[cfg(not(feature = "otel"))]
type TracedChannel = IrohChannel;

type TracedDriver = RemoteExecuteDriver<TracedChannel>;

#[cfg(feature = "otel")]
fn traced(channel: IrohChannel) -> TracedChannel {
    tonic::service::interceptor::InterceptedService::new(
        channel,
        tonic_iroh_transport::otel::TraceContextInjector,
    )
}
#[cfg(not(feature = "otel"))]
fn traced(channel: IrohChannel) -> TracedChannel {
    channel
}

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
    peer_registry: PeerManager,
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
        receipt: ReceiptArtifact,
    },
    Failed {
        /// Tokens emitted before the failure (for honest usage reporting).
        position: u64,
        error: String,
    },
}

/// Verified signed receipt envelope bytes as delivered by the executor.
///
/// The gateway exposes these bytes directly as `hellas.receipt`. Symbolic
/// callers that need the symbolic result artifact digest can project it from
/// the verified envelope, but that digest is not the universal receipt
/// identity.
#[derive(Debug, Clone)]
pub struct ReceiptArtifact {
    dag_cbor: Vec<u8>,
    symbolic_text_artifact: Option<Digest>,
}

impl ReceiptArtifact {
    pub fn from_pb(envelope: Option<pb::ReceiptEnvelope>) -> anyhow::Result<Self> {
        let (dag_cbor, core) = decode_receipt_envelope(envelope)?;
        verify_receipt(&core).context("receipt signature verification failed")?;
        Ok(Self::from_verified_core(dag_cbor, &core))
    }

    pub fn encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.dag_cbor)
    }

    pub fn symbolic_text_artifact(&self) -> Option<Digest> {
        self.symbolic_text_artifact
    }

    fn from_verified_core(dag_cbor: Vec<u8>, core: &CoreSignedReceipt) -> Self {
        let symbolic_text_artifact = match core.body().scheme() {
            SchemeId::Symbolic => Some(core.body().result().digest()),
            _ => None,
        };
        Self {
            dag_cbor,
            symbolic_text_artifact,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(dag_cbor: Vec<u8>) -> Self {
        Self {
            dag_cbor,
            symbolic_text_artifact: None,
        }
    }
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

#[derive(Debug, Clone)]
pub enum OpaqueExecutionEvent {
    Chunk { position: u64, bytes: Vec<u8> },
    Done(OpaqueOutcome),
}

#[derive(Debug, Clone)]
pub enum OpaqueOutcome {
    Completed { output: Vec<u8> },
    Failed { error: String },
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
            peer_registry: PeerManager::default(),
        }
    }

    pub fn with_secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    #[cfg(feature = "hellas-executor")]
    pub fn spawn_default_local_with_producer_key(
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
        producer_key: ProducerSigningKey,
    ) -> anyhow::Result<Self> {
        let local_executor = Executor::spawn_with_producer_key(
            DownloadPolicy::Eager,
            ExecutePolicy::Eager,
            queue_capacity,
            supported_dtypes,
            producer_key,
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
    quote_req: QuotePreparedTextRequest,
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
            quote_req: assets.build_quote_prepared_text_request(&prepared_prompt, max_seq)?,
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

pub struct OpaqueExecutionRequest {
    runtime: ExecutionRuntime,
    request: PbOpaqueRequest,
    route: ExecutionRoute,
}

impl OpaqueExecutionRequest {
    pub fn new(runtime: ExecutionRuntime, request: PbOpaqueRequest, route: ExecutionRoute) -> Self {
        Self {
            runtime,
            request,
            route,
        }
    }

    pub fn uses_remote_transport(&self) -> bool {
        #[cfg(feature = "hellas-executor")]
        return !matches!(self.route, ExecutionRoute::Local);
        #[cfg(not(feature = "hellas-executor"))]
        return true;
    }

    pub fn stream(self) -> impl Stream<Item = anyhow::Result<OpaqueExecutionEvent>> + Send {
        try_stream! {
            let prepared = prepare_opaque_route(&self.runtime, &self.request, &self.route).await?;
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
    quote_req: &QuotePreparedTextRequest,
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
    let primary_digest = match &primary {
        Outcome::Completed { receipt, .. } => {
            receipt.symbolic_text_artifact().ok_or_else(|| {
                anyhow!("primary symbolic execution did not produce symbolic artifact digest")
            })?
        }
        Outcome::Failed { .. } => return Ok(primary),
    };

    let shadow_outcome = drain_to_outcome(shadow.stream()).await?;
    match shadow_outcome {
        Outcome::Completed {
            receipt: shadow_receipt,
            ..
        } => {
            let shadow_digest = shadow_receipt.symbolic_text_artifact().ok_or_else(|| {
                anyhow!("shadow symbolic execution did not produce symbolic artifact digest")
            })?;
            if primary_digest == shadow_digest {
                Ok(primary)
            } else {
                Ok(Outcome::Failed {
                    position: primary.position(),
                    error: format!(
                        "verify mismatch: primary symbolic artifact {primary_digest} != shadow symbolic artifact {shadow_digest}"
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

// `RemoteDirect` is boxed; `RemoteDiscovery` carries the full quote request and
// stays sizeable. The variant is short-lived (one per execution setup), so the
// remaining disparity isn't worth more boxing.
#[allow(clippy::large_enum_variant)]
enum PreparedRoute {
    #[cfg(feature = "hellas-executor")]
    Local {
        executor: ExecutorHandle,
        request_commitment: Vec<u8>,
        provenance: ExecutionProvenance,
    },
    RemoteDirect(Box<RemoteExecution>),
    RemoteDiscovery {
        quote_req: QuotePreparedTextRequest,
        retries: usize,
        secret_key: Option<SecretKey>,
        peer_registry: PeerManager,
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
        quote_req: &QuotePreparedTextRequest,
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
                let ticket = quoted
                    .response
                    .ticket
                    .ok_or_else(|| anyhow!("quote_prepared_text response missing ticket"))?;
                Ok(Self::Local {
                    executor,
                    request_commitment: ticket.request_commitment,
                    provenance: quoted.provenance,
                })
            }
            ExecutionRoute::RemoteDirect(target) => {
                let endpoint = bind_remote_endpoint(runtime.secret_key.as_ref()).await?;
                let quote = quote_remote_target(
                    quote_req,
                    &endpoint,
                    target,
                    runtime.peer_registry.clone(),
                )
                .await?;
                Ok(Self::RemoteDirect(Box::new(RemoteExecution::from_quoted(
                    endpoint, quote,
                ))))
            }
            ExecutionRoute::RemoteDiscovery { retries } => Ok(Self::RemoteDiscovery {
                quote_req: quote_req.clone(),
                retries: *retries,
                secret_key: runtime.secret_key.clone(),
                peer_registry: runtime.peer_registry.clone(),
            }),
        }
    }

    fn stream(self) -> BoxStream<'static, anyhow::Result<ExecutionEvent>> {
        match self {
            #[cfg(feature = "hellas-executor")]
            PreparedRoute::Local {
                executor,
                request_commitment,
                provenance: _,
            } => execute_stream(executor, request_commitment).boxed(),
            PreparedRoute::RemoteDirect(remote) => remote.stream().boxed(),
            PreparedRoute::RemoteDiscovery {
                quote_req,
                retries,
                secret_key,
                peer_registry,
            } => discovery_stream(quote_req, retries, secret_key, peer_registry).boxed(),
        }
    }
}

#[allow(clippy::large_enum_variant)] // see PreparedRoute
enum OpaquePreparedRoute {
    #[cfg(feature = "hellas-executor")]
    Local {
        executor: ExecutorHandle,
        request: PbOpaqueRequest,
        request_commitment: Vec<u8>,
    },
    RemoteDirect(Box<OpaqueRemoteExecution>),
    RemoteDiscovery {
        request: PbOpaqueRequest,
        retries: usize,
        secret_key: Option<SecretKey>,
        peer_registry: PeerManager,
    },
}

async fn prepare_opaque_route(
    runtime: &ExecutionRuntime,
    request: &PbOpaqueRequest,
    route: &ExecutionRoute,
) -> anyhow::Result<OpaquePreparedRoute> {
    match route {
        #[cfg(feature = "hellas-executor")]
        ExecutionRoute::Local => {
            let mut executor = runtime.require_local_executor()?;
            let quoted = quote_opaque_with_driver(request, &mut executor, || {
                "local opaque quote failed".to_string()
            })
            .await?;
            Ok(OpaquePreparedRoute::Local {
                executor,
                request: request.clone(),
                request_commitment: quoted.response.request_commitment,
            })
        }
        ExecutionRoute::RemoteDirect(target) => {
            let endpoint = bind_remote_endpoint(runtime.secret_key.as_ref()).await?;
            let quote = quote_opaque_remote_target(
                request,
                &endpoint,
                target,
                runtime.peer_registry.clone(),
            )
            .await?;
            Ok(OpaquePreparedRoute::RemoteDirect(Box::new(
                OpaqueRemoteExecution::from_quoted(endpoint, request.clone(), quote),
            )))
        }
        ExecutionRoute::RemoteDiscovery { retries } => Ok(OpaquePreparedRoute::RemoteDiscovery {
            request: request.clone(),
            retries: *retries,
            secret_key: runtime.secret_key.clone(),
            peer_registry: runtime.peer_registry.clone(),
        }),
    }
}

impl OpaquePreparedRoute {
    fn stream(self) -> BoxStream<'static, anyhow::Result<OpaqueExecutionEvent>> {
        match self {
            #[cfg(feature = "hellas-executor")]
            Self::Local {
                executor,
                request,
                request_commitment,
            } => execute_opaque_stream(executor, request_commitment, request).boxed(),
            Self::RemoteDirect(remote) => remote.stream().boxed(),
            Self::RemoteDiscovery {
                request,
                retries,
                secret_key,
                peer_registry,
            } => opaque_discovery_stream(request, retries, secret_key, peer_registry).boxed(),
        }
    }
}

fn opaque_discovery_stream(
    request: PbOpaqueRequest,
    retries: usize,
    secret_key: Option<SecretKey>,
    peer_registry: PeerManager,
) -> impl Stream<Item = anyhow::Result<OpaqueExecutionEvent>> + Send {
    try_stream! {
        let max_attempts = retries.saturating_add(1);
        let mut tried: HashSet<EndpointId> = HashSet::new();
        let mut last_peer_error: Option<anyhow::Error> = None;
        info!("No node ID provided, discovering opaque executor");

        for attempt in 1..=max_attempts {
            let remote = prepare_discovered_opaque_remote(
                &request,
                secret_key.as_ref(),
                &tried,
                peer_registry.clone(),
            ).await?;
            let peer_id = remote.peer_id;
            let mut committed = false;
            let mut transport_err: Option<anyhow::Error> = None;
            let mut got_terminal = false;
            {
                let inner = remote.stream();
                tokio::pin!(inner);
                while let Some(event) = inner.next().await {
                    match event {
                        Ok(OpaqueExecutionEvent::Chunk { position, bytes }) => {
                            committed = true;
                            yield OpaqueExecutionEvent::Chunk { position, bytes };
                        }
                        Ok(OpaqueExecutionEvent::Done(outcome)) => {
                            got_terminal = true;
                            yield OpaqueExecutionEvent::Done(outcome);
                        }
                        Err(e) => {
                            transport_err = Some(e);
                            break;
                        }
                    }
                }
            }
            if got_terminal { return; }

            let err = transport_err
                .unwrap_or_else(|| anyhow!("stream from {peer_id} ended without terminal outcome"));
            if committed {
                Err(err.context(format!(
                    "opaque execution failed on {peer_id} after output was emitted"
                )))?;
                unreachable!("Err(_)? always returns");
            }
            warn!(attempt, %peer_id, "opaque execution failed before output, rediscovering: {err:#}");
            tried.insert(peer_id);
            last_peer_error = Some(err);
        }

        let err = last_peer_error
            .unwrap_or_else(|| anyhow!("no opaque provider could serve the request"));
        Err(err.context(format!("max retries ({retries}) exceeded")))?;
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
    quote_req: QuotePreparedTextRequest,
    retries: usize,
    secret_key: Option<SecretKey>,
    peer_registry: PeerManager,
) -> impl Stream<Item = anyhow::Result<ExecutionEvent>> + Send {
    try_stream! {
        let max_attempts = retries.saturating_add(1);
        let mut tried: HashSet<EndpointId> = HashSet::new();
        let mut last_peer_error: Option<anyhow::Error> = None;
        info!("No node ID provided, discovering executor");

        for attempt in 1..=max_attempts {
            let remote = prepare_discovered_remote(
                &quote_req,
                secret_key.as_ref(),
                &tried,
                peer_registry.clone(),
            ).await?;
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
    peer_registry: PeerManager,
    request_commitment: Vec<u8>,
    provenance: ExecutionProvenance,
    driver: TracedDriver,
}

impl RemoteExecution {
    fn from_quoted(endpoint: Arc<Endpoint>, quoted: QuotedRemoteDriver) -> Self {
        Self {
            endpoint,
            peer_id: quoted.peer_id,
            peer_registry: quoted.peer_registry,
            request_commitment: quoted.quote.request_commitment,
            provenance: quoted.provenance,
            driver: quoted.driver,
        }
    }

    fn stream(self) -> impl Stream<Item = anyhow::Result<ExecutionEvent>> + Send {
        let Self {
            endpoint,
            peer_id,
            peer_registry,
            request_commitment,
            provenance: _,
            driver,
        } = self;
        track_remote_execution_stream(
            endpoint,
            peer_registry,
            peer_id,
            execute_stream(driver, request_commitment),
        )
    }
}

struct OpaqueRemoteExecution {
    endpoint: Arc<Endpoint>,
    peer_id: EndpointId,
    peer_registry: PeerManager,
    request: PbOpaqueRequest,
    request_commitment: Vec<u8>,
    driver: TracedDriver,
}

impl OpaqueRemoteExecution {
    fn from_quoted(
        endpoint: Arc<Endpoint>,
        request: PbOpaqueRequest,
        quoted: QuotedRemoteDriver,
    ) -> Self {
        Self {
            endpoint,
            peer_id: quoted.peer_id,
            peer_registry: quoted.peer_registry,
            request,
            request_commitment: quoted.quote.request_commitment,
            driver: quoted.driver,
        }
    }

    fn stream(self) -> impl Stream<Item = anyhow::Result<OpaqueExecutionEvent>> + Send {
        let Self {
            endpoint,
            peer_id,
            peer_registry,
            request,
            request_commitment,
            driver,
        } = self;
        track_remote_execution_stream(
            endpoint,
            peer_registry,
            peer_id,
            execute_opaque_stream(driver, request_commitment, request),
        )
    }
}

/// Last-yielded variant of a remote-execution event stream. Both
/// `ExecutionEvent` and `OpaqueExecutionEvent` carry a `Done(_)` terminal
/// — the `track_remote_execution_stream` helper consults this to flush
/// the permit before yielding the terminal event (so a consumer that
/// drops on Done doesn't trigger a spurious `Cancelled`).
trait IsTerminalExecutionEvent {
    fn is_terminal(&self) -> bool;
}

impl IsTerminalExecutionEvent for ExecutionEvent {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Done(_))
    }
}

impl IsTerminalExecutionEvent for OpaqueExecutionEvent {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Done(_))
    }
}

/// Wrap a per-execution stream with the registry's `RunTicket` permit
/// lifecycle: acquire on first poll, finish_ok before yielding the
/// terminal event, finish_err on a transport error, and (via the
/// `RpcPermitGuard` Drop) Cancelled if the consumer drops the stream
/// before it terminates. Holds the endpoint alive for the duration so a
/// concurrent endpoint drop doesn't tear down the underlying QUIC
/// connection mid-execution.
fn track_remote_execution_stream<E, S>(
    endpoint: Arc<Endpoint>,
    peer_registry: PeerManager,
    peer_id: EndpointId,
    inner: S,
) -> impl Stream<Item = anyhow::Result<E>> + Send
where
    E: IsTerminalExecutionEvent + Send + 'static,
    S: Stream<Item = anyhow::Result<E>> + Send + 'static,
{
    try_stream! {
        let _endpoint = endpoint;
        let mut permit = peer_registry.acquire_iroh_method::<methods::RunTicket>(peer_id)?;
        tokio::pin!(inner);
        while let Some(event) = inner.next().await {
            match event {
                Ok(event) => {
                    if event.is_terminal() {
                        permit.finish_ok();
                        yield event;
                        return;
                    }
                    yield event;
                }
                Err(err) => {
                    permit.finish_err(err.to_string());
                    Err(err)?;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// execute_stream — the bottom layer that maps wire events → ExecutionEvent
// ---------------------------------------------------------------------------

fn execute_stream<D: ExecuteDriver + Send + 'static>(
    mut driver: D,
    request_commitment: Vec<u8>,
) -> impl Stream<Item = anyhow::Result<ExecutionEvent>> + Send {
    try_stream! {
        // Provenance arrives in `streamed.provenance` (from response
        // metadata server-side) but the gateway already has it from the
        // quote step, so we drop it here and only forward the event stream.
        let mut wire = driver
            .execute_streaming(RunTicketRequest {
                request_commitment,
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

fn execute_opaque_stream<D: ExecuteDriver + Send + 'static>(
    mut driver: D,
    request_commitment: Vec<u8>,
    request: PbOpaqueRequest,
) -> impl Stream<Item = anyhow::Result<OpaqueExecutionEvent>> + Send {
    try_stream! {
        let core_request = core_opaque_request(&request)?;
        let mut wire = driver
            .execute_streaming(RunTicketRequest {
                request_commitment,
            })
            .await
            .context("failed to start opaque execution stream")?
            .stream;

        let mut got_terminal = false;
        while let Some(item) = wire.next().await {
            let event = convert_opaque_wire_event(
                item.context("opaque execution stream failed")?,
                &core_request,
            )?;
            let is_done = matches!(event, OpaqueExecutionEvent::Done(_));
            yield event;
            if is_done {
                got_terminal = true;
                break;
            }
        }

        if !got_terminal {
            Err(anyhow!("opaque execution stream ended without terminal outcome"))?;
        }
        drop(driver);
    }
}

/// Translate one wire `WorkEvent` into one `ExecutionEvent`.
fn convert_wire_event(event: WorkEvent) -> anyhow::Result<ExecutionEvent> {
    let Some(event) = event.kind else {
        bail!("wire event with no body");
    };
    match event {
        work_event::Kind::Chunk(chunk) => Ok(ExecutionEvent::Chunk {
            position: chunk.position,
            tokens: chunk.bytes,
        }),
        work_event::Kind::Finished(finished) => Ok(ExecutionEvent::Done(parse_finished(finished)?)),
        work_event::Kind::Failed(failed) => Ok(ExecutionEvent::Done(Outcome::Failed {
            position: failed.position,
            error: failed.error,
        })),
    }
}

fn convert_opaque_wire_event(
    event: WorkEvent,
    request: &CoreOpaqueRequest,
) -> anyhow::Result<OpaqueExecutionEvent> {
    let Some(event) = event.kind else {
        bail!("wire event with no body");
    };
    match event {
        work_event::Kind::Chunk(chunk) => Ok(OpaqueExecutionEvent::Chunk {
            position: chunk.position,
            bytes: chunk.bytes,
        }),
        work_event::Kind::Finished(finished) => Ok(OpaqueExecutionEvent::Done(
            parse_opaque_finished(finished, request)?,
        )),
        work_event::Kind::Failed(failed) => Ok(OpaqueExecutionEvent::Done(OpaqueOutcome::Failed {
            error: failed.error,
        })),
    }
}

fn parse_finished(finished: pb::WorkFinished) -> anyhow::Result<Outcome> {
    let receipt = ReceiptArtifact::from_pb(finished.receipt)?;
    if receipt.symbolic_text_artifact().is_none() {
        bail!("symbolic execution returned an opaque receipt");
    }
    let stop_reason = stop_reason_from_pb(finished.status)?;
    Ok(Outcome::Completed {
        total_tokens: finished.total_units,
        stop_reason,
        receipt,
    })
}

fn parse_opaque_finished(
    finished: pb::WorkFinished,
    request: &CoreOpaqueRequest,
) -> anyhow::Result<OpaqueOutcome> {
    stop_reason_from_pb(finished.status)?;
    serde_json::from_slice::<serde_json::Value>(&finished.output)
        .context("opaque output must be UTF-8 JSON")?;
    let output = JsonBytes::new(finished.output.clone());
    let (_dag_cbor, core) = decode_receipt_envelope(finished.receipt)?;
    verify_delivery(
        DeliveryRequest::Opaque(request),
        DeliveryOutput::Opaque(&output),
        &core,
    )
    .context("opaque receipt verification failed")?;
    if core.body().scheme() != SchemeId::Opaque {
        bail!("opaque execution returned a symbolic receipt");
    }
    Ok(OpaqueOutcome::Completed {
        output: output.into_bytes(),
    })
}

fn core_opaque_request(request: &PbOpaqueRequest) -> anyhow::Result<CoreOpaqueRequest> {
    if request.service.is_empty() {
        bail!("opaque service must not be empty");
    }
    if request.method.is_empty() {
        bail!("opaque method must not be empty");
    }
    serde_json::from_slice::<serde_json::Value>(&request.payload)
        .context("opaque payload must be UTF-8 JSON")?;
    Ok(CoreOpaqueRequest {
        service: request.service.clone(),
        method: request.method.clone(),
        payload: JsonBytes::new(request.payload.clone()),
    })
}

fn decode_receipt_envelope(
    envelope: Option<pb::ReceiptEnvelope>,
) -> anyhow::Result<(Vec<u8>, CoreSignedReceipt)> {
    let envelope = envelope.ok_or_else(|| anyhow!("finished event missing receipt envelope"))?;
    let core: CoreSignedReceipt = decode_dag_cbor(&envelope.dag_cbor)
        .context("failed to decode receipt envelope dag-cbor")?;
    Ok((envelope.dag_cbor, core))
}

fn stop_reason_from_pb(value: i32) -> anyhow::Result<StopReason> {
    let pb_value =
        FinishStatus::try_from(value).with_context(|| format!("unknown finish status {value}"))?;
    match pb_value {
        FinishStatus::Unspecified => bail!("wire finish status is unspecified"),
        FinishStatus::EndOfSequence => Ok(StopReason::EndOfSequence),
        FinishStatus::MaxOutput => Ok(StopReason::MaxNewTokens),
        FinishStatus::Cancelled => Ok(StopReason::Cancelled),
    }
}

// ---------------------------------------------------------------------------
// Quote / discovery / endpoint helpers (largely unchanged)
// ---------------------------------------------------------------------------

struct QuotedRemoteDriver {
    peer_id: EndpointId,
    peer_registry: PeerManager,
    quote: hellas_pb::hellas::Ticket,
    provenance: ExecutionProvenance,
    driver: TracedDriver,
}

#[derive(Debug)]
enum QuoteCandidateError {
    Declined(anyhow::Error),
    Connect(anyhow::Error),
}

#[instrument(skip_all, fields(model = %quote_req.huggingface_model_id))]
async fn quote_with_driver<D>(
    quote_req: &QuotePreparedTextRequest,
    driver: &mut D,
    context: impl FnOnce() -> String,
) -> anyhow::Result<QuotedPreparedTextResponse>
where
    D: ExecuteDriver,
{
    let quoted = driver
        .quote_prepared_text(quote_req.clone())
        .await
        .with_context(context)?;
    let ticket = quoted
        .response
        .ticket
        .as_ref()
        .ok_or_else(|| anyhow!("quote_prepared_text response missing ticket"))?;
    tracing::Span::current().record(
        "request_commitment",
        tracing::field::display(format_hex(&ticket.request_commitment)),
    );
    Ok(quoted)
}

#[instrument(skip_all, fields(service = %request.service, method = %request.method))]
async fn quote_opaque_with_driver<D>(
    request: &PbOpaqueRequest,
    driver: &mut D,
    context: impl FnOnce() -> String,
) -> anyhow::Result<QuotedResponse>
where
    D: ExecuteDriver,
{
    core_opaque_request(request)?;
    let quoted = driver
        .create_opaque_ticket(request.clone())
        .await
        .with_context(context)?;
    tracing::Span::current().record(
        "request_commitment",
        tracing::field::display(format_hex(&quoted.response.request_commitment)),
    );
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

/// Build an `IrohTransport` for outbound RPCs against remote nodes. The
/// quote/execute paths pull `pool::<ExecuteService>()` / `pool::<CourtesyService>()`
/// / `pool::<OpaqueService>()` off this transport on demand; pools are cached
/// so repeated lookups share a single underlying `ConnectionPool`.
fn bind_remote_transport(endpoint: &Endpoint, peer_registry: PeerManager) -> IrohTransport {
    IrohTransport::with_options(
        endpoint.clone(),
        peer_registry,
        PoolOptions {
            connect_timeout: REMOTE_CONNECT_TIMEOUT,
            ..PoolOptions::default()
        },
    )
}

/// Dial Execute + Courtesy at `target`, then issue `QuotePreparedText`
/// across the courtesy channel. Each dial acquires its own service-level
/// permit (billed to the representative method per service), so a failed
/// dial on one service can't cross-bill the other. `target.addrs` selects
/// direct vs discovered.
#[instrument(skip_all, fields(peer_id = %target.peer_id, model = %quote_req.huggingface_model_id))]
async fn quote_remote_via_pools(
    quote_req: &QuotePreparedTextRequest,
    execute_pool: &IrohRpcPool<ExecuteService>,
    courtesy_pool: &IrohRpcPool<CourtesyService>,
    target: IrohTarget,
    peer_registry: PeerManager,
) -> Result<QuotedRemoteDriver, QuoteCandidateError> {
    let peer_id = target.peer_id;
    let (execute_channel, mut execute_permit) = execute_pool
        .channel::<methods::RunTicket>(target.clone())
        .await
        .with_context(|| format!("failed to connect to node {peer_id}"))
        .map_err(QuoteCandidateError::Connect)?;
    let (courtesy_channel, mut courtesy_permit) = match courtesy_pool
        .channel::<methods::QuotePreparedText>(target)
        .await
    {
        Ok(channels) => channels,
        Err(err) => {
            // The Execute dial already succeeded — release its permit so the
            // RAII guard doesn't record Cancelled.
            execute_permit.finish_ok();
            return Err(QuoteCandidateError::Connect(
                anyhow::Error::from(err).context(format!("failed to connect to node {peer_id}")),
            ));
        }
    };
    let mut driver = RemoteExecuteDriver::with_execute_and_courtesy(
        traced(execute_channel),
        traced(courtesy_channel),
    );
    let quoted = match quote_with_driver(quote_req, &mut driver, || {
        format!("node {peer_id} declined ticket")
    })
    .await
    {
        Ok(quoted) => quoted,
        Err(err) => {
            execute_permit.finish_ok();
            courtesy_permit.finish_err(err.to_string());
            return Err(QuoteCandidateError::Declined(err));
        }
    };
    let Some(ticket) = quoted.response.ticket else {
        let err = anyhow!("quote_prepared_text response missing ticket");
        execute_permit.finish_ok();
        courtesy_permit.finish_err(err.to_string());
        return Err(QuoteCandidateError::Declined(err));
    };
    execute_permit.finish_ok();
    courtesy_permit.finish_ok();
    Ok(QuotedRemoteDriver {
        peer_id,
        peer_registry,
        quote: ticket,
        provenance: quoted.provenance,
        driver,
    })
}

/// Opaque counterpart of [`quote_remote_via_pools`].
#[instrument(skip_all, fields(peer_id = %target.peer_id, service = %request.service, method = %request.method))]
async fn quote_opaque_remote_via_pools(
    request: &PbOpaqueRequest,
    execute_pool: &IrohRpcPool<ExecuteService>,
    opaque_pool: &IrohRpcPool<OpaqueService>,
    target: IrohTarget,
    peer_registry: PeerManager,
) -> Result<QuotedRemoteDriver, QuoteCandidateError> {
    let peer_id = target.peer_id;
    let (execute_channel, mut execute_permit) = execute_pool
        .channel::<methods::RunTicket>(target.clone())
        .await
        .with_context(|| format!("failed to connect to node {peer_id}"))
        .map_err(QuoteCandidateError::Connect)?;
    let (opaque_channel, mut opaque_permit) = match opaque_pool
        .channel::<methods::OpaqueCreateTicket>(target)
        .await
    {
        Ok(channels) => channels,
        Err(err) => {
            execute_permit.finish_ok();
            return Err(QuoteCandidateError::Connect(
                anyhow::Error::from(err).context(format!("failed to connect to node {peer_id}")),
            ));
        }
    };
    let mut driver = RemoteExecuteDriver::with_execute_and_opaque(
        traced(execute_channel),
        traced(opaque_channel),
    );
    let quoted = match quote_opaque_with_driver(request, &mut driver, || {
        format!("node {peer_id} declined opaque ticket")
    })
    .await
    {
        Ok(quoted) => {
            execute_permit.finish_ok();
            opaque_permit.finish_ok();
            quoted
        }
        Err(err) => {
            execute_permit.finish_ok();
            opaque_permit.finish_err(err.to_string());
            return Err(QuoteCandidateError::Declined(err));
        }
    };
    Ok(QuotedRemoteDriver {
        peer_id,
        peer_registry,
        quote: quoted.response,
        provenance: quoted.provenance,
        driver,
    })
}

async fn quote_opaque_remote_target(
    request: &PbOpaqueRequest,
    endpoint: &Endpoint,
    target: &RemoteNodeTarget,
    peer_registry: PeerManager,
) -> anyhow::Result<QuotedRemoteDriver> {
    let transport = bind_remote_transport(endpoint, peer_registry.clone());
    let iroh_target = remote_node_iroh_target(target);
    quote_opaque_remote_via_pools(
        request,
        &transport.pool::<ExecuteService>(),
        &transport.pool::<OpaqueService>(),
        iroh_target,
        peer_registry,
    )
    .await
    .map_err(|err| match err {
        QuoteCandidateError::Declined(err) => {
            err.context(format!("node {} declined opaque quote", target.node_id))
        }
        QuoteCandidateError::Connect(err) => err,
    })
}

async fn quote_remote_target(
    quote_req: &QuotePreparedTextRequest,
    endpoint: &Endpoint,
    target: &RemoteNodeTarget,
    peer_registry: PeerManager,
) -> anyhow::Result<QuotedRemoteDriver> {
    let transport = bind_remote_transport(endpoint, peer_registry.clone());
    let iroh_target = remote_node_iroh_target(target);
    quote_remote_via_pools(
        quote_req,
        &transport.pool::<ExecuteService>(),
        &transport.pool::<CourtesyService>(),
        iroh_target,
        peer_registry,
    )
    .await
    .map_err(|err| match err {
        QuoteCandidateError::Declined(err) => {
            err.context(format!("node {} declined quote", target.node_id))
        }
        QuoteCandidateError::Connect(err) => err,
    })
}

fn remote_node_iroh_target(target: &RemoteNodeTarget) -> IrohTarget {
    if target.node_addrs.is_empty() {
        IrohTarget::discovered(target.node_id)
    } else {
        IrohTarget::direct(target.node_id, target.endpoint_addr())
    }
}

#[instrument(skip_all, fields(service = %request.service, method = %request.method, excluded = exclude.len()))]
async fn discover_opaque_remote_quote(
    request: &PbOpaqueRequest,
    endpoint: &Endpoint,
    bindings: DiscoveryBindings,
    exclude: &HashSet<EndpointId>,
    peer_registry: PeerManager,
) -> anyhow::Result<QuotedRemoteDriver> {
    let mut registry = ServiceRegistry::new(endpoint);
    registry.with_pool_options(PoolOptions {
        connect_timeout: REMOTE_CONNECT_TIMEOUT,
        ..PoolOptions::default()
    });
    registry.add(MdnsBackend::new(bindings.mdns));
    registry.add(DhtBackend::with_dht(endpoint, bindings.dht));
    let execute_pool = IrohRpcPool::<ExecuteService>::from_pool(
        endpoint.clone(),
        registry.pool::<ExecuteService>(),
        peer_registry.clone(),
    );
    let opaque_pool = IrohRpcPool::<OpaqueService>::from_pool(
        endpoint.clone(),
        registry.pool::<OpaqueService>(),
        peer_registry.clone(),
    );

    let peers = Box::pin(registry.discover::<OpaqueService>());
    tokio::time::timeout(DISCOVERY_TIMEOUT, async {
        let mut last_decline: Option<anyhow::Error> = None;
        let mut last_connect_error: Option<anyhow::Error> = None;
        let mut peers_done = false;
        let mut in_flight: FuturesUnordered<_> = FuturesUnordered::new();
        futures::pin_mut!(peers);

        loop {
            tokio::select! {
                biased;

                Some(result) = in_flight.next(), if !in_flight.is_empty() => {
                    match result {
                        Ok(accepted) => return Ok(accepted),
                        Err(QuoteCandidateError::Declined(err)) => {
                            info!("opaque provider declined quote: {err:#}");
                            last_decline = Some(err);
                        }
                        Err(QuoteCandidateError::Connect(err)) => {
                            debug!("opaque candidate connect error: {err:#}");
                            last_connect_error = Some(err);
                        }
                    }
                }

                peer = peers.next(), if !peers_done && in_flight.len() < MAX_CONCURRENT_QUOTES => {
                    match peer {
                        Some(Ok(peer)) => {
                            let peer_id = peer.id();
                            let _ = peer_registry.observe_iroh_service::<OpaqueService>(peer_id);
                            if exclude.contains(&peer_id) {
                                debug!(%peer_id, "skipping previously-failed opaque peer");
                                continue;
                            }
                            let execute_pool = execute_pool.clone();
                            let opaque_pool = opaque_pool.clone();
                            let peer_registry = peer_registry.clone();
                            let req = request.clone();
                            in_flight.push(async move {
                                quote_opaque_remote_via_pools(
                                    &req,
                                    &execute_pool,
                                    &opaque_pool,
                                    IrohTarget::discovered(peer_id),
                                    peer_registry,
                                ).await
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
            return Err(status).context("all discovered opaque providers declined the quote");
        }
        if let Some(err) = last_connect_error {
            return Err(err).context("failed to connect to discovered opaque providers");
        }

        anyhow::bail!("no opaque provider could serve the request");
    })
    .await
    .context("opaque discovery timed out")?
}

#[instrument(skip_all, fields(model = %quote_req.huggingface_model_id, excluded = exclude.len()))]
async fn discover_remote_quote(
    quote_req: &QuotePreparedTextRequest,
    endpoint: &Endpoint,
    bindings: DiscoveryBindings,
    exclude: &HashSet<EndpointId>,
    peer_registry: PeerManager,
) -> anyhow::Result<QuotedRemoteDriver> {
    let mut registry = ServiceRegistry::new(endpoint);
    registry.with_pool_options(PoolOptions {
        connect_timeout: REMOTE_CONNECT_TIMEOUT,
        ..PoolOptions::default()
    });
    registry.add(MdnsBackend::new(bindings.mdns));
    registry.add(DhtBackend::with_dht(endpoint, bindings.dht));
    let execute_pool = IrohRpcPool::<ExecuteService>::from_pool(
        endpoint.clone(),
        registry.pool::<ExecuteService>(),
        peer_registry.clone(),
    );
    let courtesy_pool = IrohRpcPool::<CourtesyService>::from_pool(
        endpoint.clone(),
        registry.pool::<CourtesyService>(),
        peer_registry.clone(),
    );

    let peers = Box::pin(registry.discover::<CourtesyService>());
    tokio::time::timeout(DISCOVERY_TIMEOUT, async {
        let mut last_decline: Option<anyhow::Error> = None;
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
                        Err(QuoteCandidateError::Declined(err)) => {
                            info!("provider declined quote: {err:#}");
                            last_decline = Some(err);
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
                            let _ = peer_registry.observe_iroh_service::<CourtesyService>(peer_id);
                            if exclude.contains(&peer_id) {
                                debug!(%peer_id, "skipping previously-failed peer");
                                continue;
                            }
                            let execute_pool = execute_pool.clone();
                            let courtesy_pool = courtesy_pool.clone();
                            let peer_registry = peer_registry.clone();
                            let req = quote_req.clone();
                            in_flight.push(async move {
                                quote_remote_via_pools(
                                    &req,
                                    &execute_pool,
                                    &courtesy_pool,
                                    IrohTarget::discovered(peer_id),
                                    peer_registry,
                                ).await
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
            return Err(status).context("all discovered providers declined the quote");
        }
        if let Some(err) = last_connect_error {
            return Err(err).context("failed to connect to discovered providers");
        }

        anyhow::bail!("no provider could serve the request");
    })
    .await
    .context("discovery timed out")?
}

async fn prepare_discovered_opaque_remote(
    request: &PbOpaqueRequest,
    secret_key: Option<&SecretKey>,
    exclude: &HashSet<EndpointId>,
    peer_registry: PeerManager,
) -> anyhow::Result<OpaqueRemoteExecution> {
    let (endpoint, bindings) = bind_remote_endpoint_with_bindings(secret_key).await?;
    let quote =
        discover_opaque_remote_quote(request, &endpoint, bindings, exclude, peer_registry).await?;
    Ok(OpaqueRemoteExecution::from_quoted(
        endpoint,
        request.clone(),
        quote,
    ))
}

async fn prepare_discovered_remote(
    quote_req: &QuotePreparedTextRequest,
    secret_key: Option<&SecretKey>,
    exclude: &HashSet<EndpointId>,
    peer_registry: PeerManager,
) -> anyhow::Result<RemoteExecution> {
    let (endpoint, bindings) = bind_remote_endpoint_with_bindings(secret_key).await?;
    let quote =
        discover_remote_quote(quote_req, &endpoint, bindings, exclude, peer_registry).await?;
    Ok(RemoteExecution::from_quoted(endpoint, quote))
}

#[cfg(feature = "hellas-executor")]
fn local_model_spec(quote_req: &QuotePreparedTextRequest) -> String {
    let revision = quote_req.huggingface_revision.trim();
    if revision.is_empty() {
        quote_req.huggingface_model_id.clone()
    } else {
        format!("{}@{revision}", quote_req.huggingface_model_id)
    }
}

fn format_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
