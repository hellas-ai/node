//! Stream-shaped execution layer.
//!
//! The fundamental shape: every layer returns
//! `impl Stream<Item = Result<ExecutionEvent, ExecutionError>>` or
//! `impl Stream<Item = Result<FetchExecutionEvent, ExecutionError>>`. Drop-cancellation
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
//!                                │   ├─ Local:        local stream over ExecutorHandle
//!                                │   ├─ RemoteDirect: ExecuteClientImpl over IrohTransport
//!                                │   └─ RemoteDiscovery: discover, quote, then execute
//!                                └─ shadow (verify):  same shape, run after primary
//! ```
//!
//! NOTE: RemoteDiscovery races peers from `ServiceRegistry::discover` and
//! takes the first that returns a successful quote. The run step then opens
//! an Execute service transport for the selected peer.

use async_stream::try_stream;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "hellas-executor")]
use catgrad::prelude::Dtype;
use chatgrad::PreparedPrompt;
use futures::StreamExt;
use futures::stream::{BoxStream, Stream};
#[cfg(feature = "hellas-executor")]
use hellas_core::ProducerSigningKey;
use hellas_core::{
    DagCborDecodeError, Digest, InputCommitment, SchemeId, SignedReceipt as CoreSignedReceipt,
    VerifyError, decode_dag_cbor, verify_receipt,
};
#[cfg(feature = "hellas-executor")]
use hellas_executor::{Executor, ExecutorHandle};
use hellas_rpc::fetch::{
    FetchInput, FetchProtocolError, verify_input_events, verify_output_events,
};
use hellas_rpc::model::{ModelAssets, ModelAssetsError};
use hellas_rpc::pb::courtesy::QuotePreparedTextRequest;
use hellas_rpc::pb::execute::{
    self as pb, FinishStatus, RunTicketRequest, WorkEvent, WorkFinished, work_event,
};
use hellas_rpc::pb::fetch::FetchRequest as PbFetchRequest;
#[cfg(feature = "hellas-executor")]
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::services::courtesy::Courtesy;
use hellas_rpc::services::execute::{Execute, ExecuteClientImpl};
use hellas_rpc::services::fetch::Fetch;
use hellas_rpc::stream::{input_event_from_pb, output_event_from_pb};
use hellas_wire::iroh::IrohTransport;
use hellas_wire::iroh::swarm::ServiceRegistry;
use hellas_wire::{ServiceMarker, WireStatus};
use iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
#[cfg(feature = "hellas-executor")]
use tokio_stream::wrappers::ReceiverStream;
use tracing::instrument;

use crate::commands::discovery;

pub type ExecutionResult<T> = Result<T, ExecutionError>;

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("{0}")]
    Protocol(String),
    #[error("{context}: {source}")]
    Source {
        context: String,
        #[source]
        source: Box<dyn StdError + Send + Sync + 'static>,
    },
    #[error("{context}: {source}")]
    Wire {
        context: String,
        #[source]
        source: WireStatus,
    },
    #[error(transparent)]
    ModelAssets(#[from] ModelAssetsError),
    #[error("finished event missing receipt envelope")]
    MissingReceiptEnvelope,
    #[error("failed to decode receipt envelope dag-cbor: {source}")]
    ReceiptDecode {
        #[source]
        source: DagCborDecodeError,
    },
    #[error("receipt signature verification failed: {source}")]
    ReceiptSignature {
        #[source]
        source: VerifyError,
    },
    #[error("unknown finish status {value}")]
    UnknownFinishStatus { value: i32 },
    #[error("wire finish status is unspecified")]
    UnspecifiedFinishStatus,
    #[error("symbolic execution returned a fetch receipt")]
    SymbolicReceiptExpected,
    #[error("fetch stream envelope decode failed: {source}")]
    FetchStreamEnvelope {
        #[source]
        source: hellas_rpc::stream::StreamEnvelopeError,
    },
    #[error("fetch transcript verification failed: {source}")]
    FetchTranscript {
        #[source]
        source: FetchProtocolError,
    },
}

impl ExecutionError {
    fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    fn source(context: impl Into<String>, source: impl StdError + Send + Sync + 'static) -> Self {
        Self::Source {
            context: context.into(),
            source: Box::new(source),
        }
    }

    fn wire(context: impl Into<String>, source: WireStatus) -> Self {
        Self::Wire {
            context: context.into(),
            source,
        }
    }
}

trait ExecutionContext<T> {
    fn exec_context(self, context: impl Into<String>) -> ExecutionResult<T>;
}

impl<T, E> ExecutionContext<T> for Result<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    fn exec_context(self, context: impl Into<String>) -> ExecutionResult<T> {
        self.map_err(|source| ExecutionError::source(context, source))
    }
}

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
    /// Build a remote route from CLI inputs: a peer id and optional
    /// direct-address hints. Hints become an `EndpointAddr` bundle
    /// consumed at dial time; they are not stored in peer state.
    pub fn remote(
        node_id: Option<EndpointId>,
        node_addrs: Vec<SocketAddr>,
        retries: usize,
    ) -> Self {
        match node_id {
            Some(node_id) => Self::RemoteDirect(RemoteNodeTarget {
                addr: EndpointAddr::from_parts(
                    node_id,
                    node_addrs.into_iter().map(TransportAddr::Ip),
                ),
            }),
            None => Self::RemoteDiscovery { retries },
        }
    }
}

/// A remote dial target: the canonical iroh identity plus optional
/// dial-time hints (direct sockaddrs, relay URLs, custom routes).
/// `EndpointAddr` is iroh's address-bundle type; an empty hints set
/// works because `presets::N0` configures pkarr/DNS address lookup.
///
/// Hints are *ephemeral*: they are passed to `Endpoint::connect`
/// once, then discarded. They never enter `PeerManager` /
/// `PeerDirectory`, which key on identity (`EndpointId`) only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteNodeTarget {
    pub addr: EndpointAddr,
}

impl RemoteNodeTarget {
    pub fn node_id(&self) -> EndpointId {
        self.addr.id
    }
}

impl From<EndpointId> for RemoteNodeTarget {
    fn from(node_id: EndpointId) -> Self {
        Self {
            addr: EndpointAddr::from(node_id),
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

/// All state needed to dial remote peers: the bound iroh `Endpoint`
/// (held so its lifetime is tied to the runtime) plus the
/// `ServiceRegistry` of pooled per-ALPN connections built atop it.
///
/// Constructed lazily by [`ExecutionRuntime::remote`] — no half-built
/// "secret key but no endpoint" state.
#[derive(Clone)]
pub struct RemoteRpc {
    _endpoint: iroh::Endpoint,
    registry: ServiceRegistry,
}

#[derive(Clone, Default)]
pub struct ExecutionRuntime {
    #[cfg(feature = "hellas-executor")]
    local_executor: Option<ExecutorHandle>,
    /// `Some` iff remote dialing is configured. `None` means a local-
    /// only runtime; any `*Direct::*` path on such a runtime returns
    /// a clear "remote dispatch on a local-only runtime" error.
    remote: Option<RemoteRpc>,
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
    pub fn from_pb(envelope: Option<pb::ReceiptEnvelope>) -> ExecutionResult<Self> {
        let (dag_cbor, core) = decode_receipt_envelope(envelope)?;
        verify_receipt(&core).map_err(|source| ExecutionError::ReceiptSignature { source })?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchExecutionEvent {
    Chunk { position: u64, bytes: Vec<u8> },
    Done(FetchOutcome),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    Completed { output: Vec<u8> },
    Failed { position: u64, error: String },
}

// ---------------------------------------------------------------------------
// ExecutionRuntime
// ---------------------------------------------------------------------------

impl ExecutionRuntime {
    /// Local-only runtime: dispatches all calls in-process via the
    /// executor handle. `*Direct` / `*Discovery` routes are not
    /// reachable on this runtime — use [`Self::remote`] for those.
    #[cfg(feature = "hellas-executor")]
    pub fn local(local_executor: ExecutorHandle) -> Self {
        Self {
            local_executor: Some(local_executor),
            remote: None,
        }
    }

    /// Remote-capable runtime: binds an iroh `Endpoint` keyed on
    /// `secret_key` and builds a `ServiceRegistry`.
    pub async fn remote(secret_key: SecretKey) -> ExecutionResult<Self> {
        Self::default().with_remote(secret_key).await
    }

    /// Add remote-capability to an existing runtime (typically one
    /// built via [`Self::local`] when verify-against-local is active).
    /// Builds the iroh `Endpoint` and `ServiceRegistry`.
    pub async fn with_remote(mut self, secret_key: SecretKey) -> ExecutionResult<Self> {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .bind()
            .await
            .exec_context("failed to bind iroh endpoint for ExecutionRuntime")?;
        let discovery = discovery::build_client_registry(&endpoint).map_err(|source| {
            ExecutionError::protocol(format!("failed to configure service discovery: {source:#}"))
        })?;
        self.remote = Some(RemoteRpc {
            _endpoint: endpoint,
            registry: discovery.registry,
        });
        Ok(self)
    }

    #[cfg(feature = "hellas-executor")]
    pub fn spawn_default_local_with_producer_key(
        queue_capacity: usize,
        supported_dtypes: Vec<Dtype>,
        producer_key: ProducerSigningKey,
    ) -> ExecutionResult<Self> {
        let local_executor = Executor::spawn_with_producer_key(
            DownloadPolicy::Eager,
            ExecutePolicy::Eager,
            queue_capacity,
            supported_dtypes,
            producer_key,
        )
        .exec_context("failed to initialize local execution backend")?;
        Ok(Self::local(local_executor))
    }

    #[cfg(feature = "hellas-executor")]
    fn require_local_executor(&self) -> ExecutionResult<ExecutorHandle> {
        self.local_executor.clone().ok_or_else(|| {
            ExecutionError::protocol(
                "local execution requested but no local executor is configured",
            )
        })
    }

    /// Get a typed `IrohTransport` for one service, dialing the
    /// supplied target. Every `*Direct::*` path in this file goes
    /// through here so address+pool plumbing is in one place.
    async fn remote_transport<S: ServiceMarker>(
        &self,
        target: &RemoteNodeTarget,
    ) -> ExecutionResult<IrohTransport> {
        let r = self.remote.as_ref().ok_or_else(|| {
            ExecutionError::protocol(
                "remote dispatch on a local-only runtime; construct via ExecutionRuntime::remote(...)",
            )
        })?;
        r.registry
            .pool::<S>()
            .transport(target.addr.clone())
            .await
            .map_err(|source| {
                ExecutionError::source(
                    format!("failed to dial {} on {}", S::ALPN, target.node_id()),
                    source,
                )
            })
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
    ) -> ExecutionResult<Self> {
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
    pub async fn prepare(self) -> ExecutionResult<PreparedExecution> {
        match self.strategy {
            ExecutionStrategy::Run(route) => Ok(PreparedExecution {
                primary: PreparedRoute::prepare(&self.runtime, &self.quote_req, &route).await?,
                shadow: None,
            }),
            ExecutionStrategy::Verify { primary, shadow } => Ok(PreparedExecution {
                primary: PreparedRoute::prepare(&self.runtime, &self.quote_req, &primary).await?,
                shadow: Some(
                    PreparedRoute::prepare(&self.runtime, &self.quote_req, &shadow).await?,
                ),
            }),
        }
    }

    /// Drive this request to completion as a stream of events.
    ///
    /// Owning consumption: dropping the returned stream cancels everything
    /// downstream (broadcast subscribers, wire streams, the executor's
    /// per-running cancel token).
    pub fn stream(self) -> impl Stream<Item = ExecutionResult<ExecutionEvent>> + Send {
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

pub struct FetchExecutionRequest {
    runtime: ExecutionRuntime,
    request: PbFetchRequest,
    route: ExecutionRoute,
}

impl FetchExecutionRequest {
    pub fn new(runtime: ExecutionRuntime, request: PbFetchRequest, route: ExecutionRoute) -> Self {
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

    pub async fn prepare(self) -> ExecutionResult<PreparedFetchExecution> {
        Ok(PreparedFetchExecution {
            route: FetchPreparedRoute::prepare(&self.runtime, &self.request, &self.route).await?,
        })
    }

    pub fn stream(self) -> impl Stream<Item = ExecutionResult<FetchExecutionEvent>> + Send {
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

pub struct PreparedFetchExecution {
    route: FetchPreparedRoute,
}

impl PreparedFetchExecution {
    pub fn stream(self) -> impl Stream<Item = ExecutionResult<FetchExecutionEvent>> + Send {
        self.route.stream()
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
    pub fn stream(self) -> impl Stream<Item = ExecutionResult<ExecutionEvent>> + Send {
        let Self { primary, shadow } = self;
        try_stream! {
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
                .ok_or_else(|| ExecutionError::protocol("primary stream ended without terminal outcome"))?;

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
async fn verify_shadow(primary: Outcome, shadow: PreparedRoute) -> ExecutionResult<Outcome> {
    let primary_digest = match &primary {
        Outcome::Completed { receipt, .. } => {
            receipt.symbolic_text_artifact().ok_or_else(|| {
                ExecutionError::protocol(
                    "primary symbolic execution did not produce symbolic artifact digest",
                )
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
                ExecutionError::protocol(
                    "shadow symbolic execution did not produce symbolic artifact digest",
                )
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

/// Consume a stream to its terminal `Done`, discarding chunks.
async fn drain_to_outcome(
    stream: impl Stream<Item = ExecutionResult<ExecutionEvent>>,
) -> ExecutionResult<Outcome> {
    tokio::pin!(stream);
    while let Some(event) = stream.next().await {
        if let ExecutionEvent::Done(outcome) = event? {
            return Ok(outcome);
        }
    }
    Err(ExecutionError::protocol(
        "shadow stream ended without terminal outcome",
    ))
}

// ---------------------------------------------------------------------------
// PreparedRoute
// ---------------------------------------------------------------------------

#[allow(clippy::large_enum_variant)]
enum PreparedRoute {
    #[cfg(feature = "hellas-executor")]
    Local {
        handle: ExecutorHandle,
        request_commitment: Vec<u8>,
        provenance: ExecutionProvenance,
    },
    RemoteDirect {
        transport: IrohTransport,
        request_commitment: Vec<u8>,
        provenance: ExecutionProvenance,
    },
}

impl PreparedRoute {
    fn provenance(&self) -> Option<&ExecutionProvenance> {
        match self {
            #[cfg(feature = "hellas-executor")]
            PreparedRoute::Local { provenance, .. } => Some(provenance),
            PreparedRoute::RemoteDirect { provenance, .. } => Some(provenance),
        }
    }

    #[instrument(skip_all, fields(?route))]
    async fn prepare(
        runtime: &ExecutionRuntime,
        quote_req: &QuotePreparedTextRequest,
        route: &ExecutionRoute,
    ) -> ExecutionResult<Self> {
        match route {
            #[cfg(feature = "hellas-executor")]
            ExecutionRoute::Local => {
                let handle = runtime.require_local_executor()?;
                handle
                    .load_model_metadata(local_model_spec(quote_req))
                    .await
                    .exec_context("failed to load local model metadata")?;
                let outcome = handle
                    .quote_prepared_text(quote_req.clone())
                    .await
                    .exec_context("local quote_prepared_text failed")?;
                let ticket = outcome.response.ticket.clone().ok_or_else(|| {
                    ExecutionError::protocol("local quote_prepared_text response missing ticket")
                })?;
                Ok(Self::Local {
                    handle,
                    request_commitment: ticket.request_commitment,
                    provenance: outcome.provenance,
                })
            }
            ExecutionRoute::RemoteDirect(target) => {
                let transport = runtime.remote_transport::<Courtesy>(target).await?;
                // Use unary_with_trailer to receive both the response and
                // the server's End-frame metadata (provenance headers).
                let with_trailer = hellas_rpc::call::unary_with_trailer::<
                    _,
                    hellas_rpc::services::courtesy::QuotePreparedText,
                >(
                    &transport, quote_req.clone(), hellas_wire::Metadata::new()
                )
                .await
                .map_err(|status| {
                    ExecutionError::wire(
                        format!("node {} declined quote_prepared_text", target.node_id()),
                        status,
                    )
                })?;
                let ticket = with_trailer.response.ticket.ok_or_else(|| {
                    ExecutionError::protocol(format!(
                        "quote_prepared_text response from {} missing ticket",
                        target.node_id()
                    ))
                })?;
                let provenance =
                    hellas_rpc::provenance::read_provenance_metadata(&with_trailer.metadata)
                        .map_err(|source| {
                            ExecutionError::source(
                                format!(
                                    "node {} response missing provenance metadata",
                                    target.node_id()
                                ),
                                source,
                            )
                        })?;

                // Open a fresh Execute-ALPN transport for the run step.
                let execute_transport = runtime.remote_transport::<Execute>(target).await?;
                Ok(Self::RemoteDirect {
                    transport: execute_transport,
                    request_commitment: ticket.request_commitment,
                    provenance,
                })
            }
            ExecutionRoute::RemoteDiscovery { retries } => {
                let remote = runtime.remote.as_ref().ok_or_else(|| {
                    ExecutionError::protocol(
                        "remote dispatch on a local-only runtime; construct via ExecutionRuntime::remote(...)"
                    )
                })?;
                let (target, request_commitment, provenance) =
                    discover_and_quote(&remote.registry, quote_req, *retries).await?;
                let execute_transport = runtime.remote_transport::<Execute>(&target).await?;
                Ok(Self::RemoteDirect {
                    transport: execute_transport,
                    request_commitment,
                    provenance,
                })
            }
        }
    }

    fn stream(self) -> BoxStream<'static, ExecutionResult<ExecutionEvent>> {
        match self {
            #[cfg(feature = "hellas-executor")]
            PreparedRoute::Local {
                handle,
                request_commitment,
                provenance: _,
            } => local_execute_stream(handle, request_commitment).boxed(),
            PreparedRoute::RemoteDirect {
                transport,
                request_commitment,
                provenance: _,
            } => remote_execute_stream(transport, request_commitment).boxed(),
        }
    }
}

// ---------------------------------------------------------------------------
// FetchPreparedRoute
// ---------------------------------------------------------------------------

#[allow(clippy::large_enum_variant)]
enum FetchPreparedRoute {
    #[cfg(feature = "hellas-executor")]
    Local {
        handle: ExecutorHandle,
        input_commitment: InputCommitment,
        request_commitment: Vec<u8>,
    },
    RemoteDirect {
        transport: IrohTransport,
        input_commitment: InputCommitment,
        request_commitment: Vec<u8>,
    },
}

impl FetchPreparedRoute {
    async fn prepare(
        runtime: &ExecutionRuntime,
        request: &PbFetchRequest,
        route: &ExecutionRoute,
    ) -> ExecutionResult<Self> {
        let input_commitment = verified_fetch_input(request)?.input_commitment;
        match route {
            #[cfg(feature = "hellas-executor")]
            ExecutionRoute::Local => {
                let handle = runtime.require_local_executor()?;
                let outcome = handle
                    .create_fetch_ticket(request.clone())
                    .await
                    .exec_context("local create_fetch_ticket failed")?;
                let request_commitment =
                    validate_fetch_ticket(&outcome.response, input_commitment)?;
                Ok(Self::Local {
                    handle,
                    input_commitment,
                    request_commitment,
                })
            }
            ExecutionRoute::RemoteDirect(target) => {
                let fetch_transport = runtime.remote_transport::<Fetch>(target).await?;
                let client = hellas_rpc::services::fetch::FetchClientImpl::new(fetch_transport);
                let ticket = client
                    .create_ticket(request.clone())
                    .await
                    .map_err(|status| {
                        ExecutionError::wire(
                            format!("node {} declined fetch create_ticket", target.node_id()),
                            status,
                        )
                    })?;
                let request_commitment = validate_fetch_ticket(&ticket, input_commitment)?;
                let execute_transport = runtime.remote_transport::<Execute>(target).await?;
                Ok(Self::RemoteDirect {
                    transport: execute_transport,
                    input_commitment,
                    request_commitment,
                })
            }
            ExecutionRoute::RemoteDiscovery { retries } => {
                let remote = runtime.remote.as_ref().ok_or_else(|| {
                    ExecutionError::protocol(
                        "remote dispatch on a local-only runtime; construct via ExecutionRuntime::remote(...)"
                    )
                })?;
                let (target, request_commitment) =
                    discover_and_fetch_quote(&remote.registry, request, input_commitment, *retries)
                        .await?;
                let execute_transport = runtime.remote_transport::<Execute>(&target).await?;
                Ok(Self::RemoteDirect {
                    transport: execute_transport,
                    input_commitment,
                    request_commitment,
                })
            }
        }
    }

    fn stream(self) -> BoxStream<'static, ExecutionResult<FetchExecutionEvent>> {
        match self {
            #[cfg(feature = "hellas-executor")]
            Self::Local {
                handle,
                input_commitment,
                request_commitment,
            } => local_execute_fetch_stream(handle, request_commitment, input_commitment).boxed(),
            Self::RemoteDirect {
                transport,
                input_commitment,
                request_commitment,
            } => {
                remote_execute_fetch_stream(transport, request_commitment, input_commitment).boxed()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery — race the registry's Courtesy/Fetch feed and take the first
// peer that returns a successful quote.
// ---------------------------------------------------------------------------

/// Drain `ServiceRegistry::discover::<Courtesy>()` until we get a quote,
/// returning the responding peer and the resolved ticket commitment +
/// provenance.
async fn discover_and_quote(
    registry: &ServiceRegistry,
    quote_req: &QuotePreparedTextRequest,
    retries: usize,
) -> ExecutionResult<(RemoteNodeTarget, Vec<u8>, ExecutionProvenance)> {
    let mut stream = Box::pin(registry.discover::<Courtesy>());
    let pool = registry.pool::<Courtesy>();
    let mut last_error: Option<ExecutionError> = None;
    let mut attempts: usize = 0;
    let max_attempts = retries.saturating_add(1);

    while let Some(peer) = stream.next().await {
        let peer = match peer {
            Ok(p) => p,
            Err(err) => {
                last_error = Some(ExecutionError::source("discovery feed error", err));
                continue;
            }
        };
        let peer_id = peer.id();
        attempts += 1;

        let transport = match pool.transport(peer_id).await {
            Ok(t) => t,
            Err(err) => {
                last_error = Some(ExecutionError::source(
                    format!("failed to dial Courtesy on {peer_id}"),
                    err,
                ));
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        let with_trailer =
            match hellas_rpc::call::unary_with_trailer::<
                _,
                hellas_rpc::services::courtesy::QuotePreparedText,
            >(&transport, quote_req.clone(), hellas_wire::Metadata::new())
            .await
            {
                Ok(t) => t,
                Err(status) => {
                    last_error = Some(ExecutionError::wire(
                        format!("node {peer_id} declined quote_prepared_text"),
                        status,
                    ));
                    if attempts >= max_attempts {
                        break;
                    }
                    continue;
                }
            };

        let Some(ticket) = with_trailer.response.ticket else {
            last_error = Some(ExecutionError::protocol(format!(
                "quote_prepared_text response from {peer_id} missing ticket"
            )));
            if attempts >= max_attempts {
                break;
            }
            continue;
        };

        let provenance =
            match hellas_rpc::provenance::read_provenance_metadata(&with_trailer.metadata) {
                Ok(p) => p,
                Err(e) => {
                    last_error = Some(ExecutionError::source(
                        format!("peer {peer_id} response missing provenance metadata"),
                        e,
                    ));
                    if attempts >= max_attempts {
                        break;
                    }
                    continue;
                }
            };

        let target = RemoteNodeTarget::from(peer_id);
        return Ok((target, ticket.request_commitment, provenance));
    }

    Err(last_error.unwrap_or_else(|| {
        ExecutionError::protocol(
            "discovery stream exhausted without a successful quote (no peers found)",
        )
    }))
}

/// Same shape as [`discover_and_quote`] for fetch tickets.
async fn discover_and_fetch_quote(
    registry: &ServiceRegistry,
    request: &PbFetchRequest,
    input_commitment: InputCommitment,
    retries: usize,
) -> ExecutionResult<(RemoteNodeTarget, Vec<u8>)> {
    use hellas_rpc::services::fetch::FetchClientImpl;
    let mut stream = Box::pin(registry.discover::<Fetch>());
    let pool = registry.pool::<Fetch>();
    let mut last_error: Option<ExecutionError> = None;
    let mut attempts: usize = 0;
    let max_attempts = retries.saturating_add(1);

    while let Some(peer) = stream.next().await {
        let peer = match peer {
            Ok(p) => p,
            Err(err) => {
                last_error = Some(ExecutionError::source("discovery feed error", err));
                continue;
            }
        };
        let peer_id = peer.id();
        attempts += 1;

        let transport = match pool.transport(peer_id).await {
            Ok(t) => t,
            Err(err) => {
                last_error = Some(ExecutionError::source(
                    format!("failed to dial Fetch on {peer_id}"),
                    err,
                ));
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        let client = FetchClientImpl::new(transport);
        match client.create_ticket(request.clone()).await {
            Ok(ticket) => {
                let request_commitment = validate_fetch_ticket(&ticket, input_commitment)?;
                return Ok((RemoteNodeTarget::from(peer_id), request_commitment));
            }
            Err(status) => {
                last_error = Some(ExecutionError::wire(
                    format!("node {peer_id} declined fetch create_ticket"),
                    status,
                ));
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        ExecutionError::protocol("discovery stream exhausted without a successful fetch quote")
    }))
}

fn validate_fetch_ticket(
    ticket: &pb::Ticket,
    input_commitment: InputCommitment,
) -> ExecutionResult<Vec<u8>> {
    let request_commitment: [u8; 32] =
        ticket
            .request_commitment
            .as_slice()
            .try_into()
            .map_err(|_| {
                ExecutionError::protocol(format!(
                    "fetch ticket request_commitment must be 32 bytes, got {}",
                    ticket.request_commitment.len()
                ))
            })?;
    if request_commitment != *input_commitment.as_bytes() {
        return Err(ExecutionError::protocol(
            "fetch ticket request_commitment does not match signed input transcript",
        ));
    }
    Ok(ticket.request_commitment.clone())
}

// ---------------------------------------------------------------------------
// Local execute streams — talk directly to `ExecutorHandle`
// ---------------------------------------------------------------------------

#[cfg(feature = "hellas-executor")]
fn local_execute_stream(
    handle: ExecutorHandle,
    request_commitment: Vec<u8>,
) -> impl Stream<Item = ExecutionResult<ExecutionEvent>> + Send {
    try_stream! {
        let outcome = handle
            .run_ticket_handle(RunTicketRequest { request_commitment })
            .await
            .exec_context("failed to start local execution stream")?;
        let _provenance = outcome.provenance; // already surfaced from PreparedRoute::Local
        let mut events = ReceiverStream::new(outcome.events);
        let mut got_terminal = false;
        while let Some(item) = events.next().await {
            let wire = item
                .map_err(|status: WireStatus| ExecutionError::wire("local execution stream failed", status))?;
            let event = convert_wire_event(wire)?;
            let is_done = matches!(event, ExecutionEvent::Done(_));
            yield event;
            if is_done {
                got_terminal = true;
                break;
            }
        }
        if !got_terminal {
            Err(ExecutionError::protocol("local execution stream ended without terminal outcome"))?;
        }
        // Keep the handle alive for the lifetime of the stream so the
        // worker's per-execution sender doesn't trip the channel-closed
        // cancel path before the terminal event flushes.
        drop(handle);
    }
}

#[cfg(feature = "hellas-executor")]
fn local_execute_fetch_stream(
    handle: ExecutorHandle,
    request_commitment: Vec<u8>,
    input_commitment: InputCommitment,
) -> impl Stream<Item = ExecutionResult<FetchExecutionEvent>> + Send {
    try_stream! {
        let outcome = handle
            .run_ticket_handle(RunTicketRequest { request_commitment })
            .await
            .exec_context("failed to start local fetch execution stream")?;
        let _provenance = outcome.provenance;
        let mut events = ReceiverStream::new(outcome.events);
        let mut got_terminal = false;
        while let Some(item) = events.next().await {
            let wire = item
                .map_err(|status: WireStatus| ExecutionError::wire("local fetch execution stream failed", status))?;
            let event = convert_fetch_wire_event(wire, input_commitment)?;
            let is_done = matches!(event, FetchExecutionEvent::Done(_));
            yield event;
            if is_done {
                got_terminal = true;
                break;
            }
        }
        if !got_terminal {
            Err(ExecutionError::protocol(
                "local fetch execution stream ended without terminal outcome"
            ))?;
        }
        drop(handle);
    }
}

// ---------------------------------------------------------------------------
// Remote execute streams — dial Execute service via IrohTransport
// ---------------------------------------------------------------------------

fn remote_execute_stream(
    transport: IrohTransport,
    request_commitment: Vec<u8>,
) -> impl Stream<Item = ExecutionResult<ExecutionEvent>> + Send {
    try_stream! {
        let client = ExecuteClientImpl::new(transport);
        let mut wire = client
            .run_ticket(RunTicketRequest { request_commitment })
            .await
            .map_err(|status| ExecutionError::wire("failed to start remote execute stream", status))?;
        let mut got_terminal = false;
        while let Some(item) = wire.next().await {
            let event = convert_wire_event(
                item.map_err(|status: WireStatus| ExecutionError::wire("remote execute stream failed", status))?
            )?;
            let is_done = matches!(event, ExecutionEvent::Done(_));
            yield event;
            if is_done {
                got_terminal = true;
                break;
            }
        }
        // Stream EOF: surface the terminal trailer. A non-Ok trailer
        // (handler aborted mid-stream, transport-level abort, etc.)
        // becomes the call's error.
        wire.finish()
            .map_err(|status| ExecutionError::wire("remote execute stream trailer", status))?;
        if !got_terminal {
            Err(ExecutionError::protocol("remote execute stream ended Ok but emitted no Done event"))?;
        }
        drop(client);
    }
}

fn remote_execute_fetch_stream(
    transport: IrohTransport,
    request_commitment: Vec<u8>,
    input_commitment: InputCommitment,
) -> impl Stream<Item = ExecutionResult<FetchExecutionEvent>> + Send {
    try_stream! {
        let client = ExecuteClientImpl::new(transport);
        let mut wire = client
            .run_ticket(RunTicketRequest { request_commitment })
            .await
            .map_err(|status| ExecutionError::wire("failed to start remote fetch execute stream", status))?;
        let mut got_terminal = false;
        while let Some(item) = wire.next().await {
            let event = convert_fetch_wire_event(
                item.map_err(|status: WireStatus| {
                    ExecutionError::wire("remote fetch execute stream failed", status)
                })?,
                input_commitment,
            )?;
            let is_done = matches!(event, FetchExecutionEvent::Done(_));
            yield event;
            if is_done {
                got_terminal = true;
                break;
            }
        }
        wire.finish()
            .map_err(|status| {
                ExecutionError::wire("remote fetch execute stream trailer", status)
            })?;
        if !got_terminal {
            Err(ExecutionError::protocol(
                "remote fetch execute stream ended Ok but emitted no Done event"
            ))?;
        }
        drop(client);
    }
}

// ---------------------------------------------------------------------------
// WorkEvent → execution events
// ---------------------------------------------------------------------------

fn convert_wire_event(event: WorkEvent) -> ExecutionResult<ExecutionEvent> {
    let Some(event) = event.kind else {
        return Err(ExecutionError::protocol("wire event with no body"));
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

fn convert_fetch_wire_event(
    event: WorkEvent,
    input_commitment: InputCommitment,
) -> ExecutionResult<FetchExecutionEvent> {
    let Some(event) = event.kind else {
        return Err(ExecutionError::protocol("wire event with no body"));
    };
    match event {
        work_event::Kind::Chunk(chunk) => Ok(FetchExecutionEvent::Chunk {
            position: chunk.position,
            bytes: chunk.bytes,
        }),
        work_event::Kind::Finished(finished) => Ok(FetchExecutionEvent::Done(
            parse_fetch_finished(finished, input_commitment)?,
        )),
        work_event::Kind::Failed(failed) => Ok(FetchExecutionEvent::Done(FetchOutcome::Failed {
            position: failed.position,
            error: failed.error,
        })),
    }
}

fn parse_finished(finished: WorkFinished) -> ExecutionResult<Outcome> {
    let receipt = ReceiptArtifact::from_pb(finished.receipt)?;
    if receipt.symbolic_text_artifact().is_none() {
        return Err(ExecutionError::SymbolicReceiptExpected);
    }
    let stop_reason = stop_reason_from_pb(finished.status)?;
    Ok(Outcome::Completed {
        total_tokens: finished.total_units,
        stop_reason,
        receipt,
    })
}

fn parse_fetch_finished(
    finished: WorkFinished,
    input_commitment: InputCommitment,
) -> ExecutionResult<FetchOutcome> {
    stop_reason_from_pb(finished.status)?;
    let output_events = finished
        .output_events
        .into_iter()
        .map(output_event_from_pb)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ExecutionError::FetchStreamEnvelope { source })?;
    let output = verify_output_events(input_commitment, &output_events)
        .map_err(|source| ExecutionError::FetchTranscript { source })?;
    if finished.output != output.body.as_bytes() {
        return Err(ExecutionError::protocol(
            "fetch finished output does not match signed output transcript",
        ));
    }
    Ok(FetchOutcome::Completed {
        output: output.body.into_bytes(),
    })
}

fn stop_reason_from_pb(value: i32) -> ExecutionResult<StopReason> {
    let pb_value =
        FinishStatus::try_from(value).map_err(|_| ExecutionError::UnknownFinishStatus { value })?;
    match pb_value {
        FinishStatus::Unspecified => Err(ExecutionError::UnspecifiedFinishStatus),
        FinishStatus::EndOfSequence => Ok(StopReason::EndOfSequence),
        FinishStatus::MaxOutput => Ok(StopReason::MaxNewTokens),
        FinishStatus::Cancelled => Ok(StopReason::Cancelled),
    }
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

fn verified_fetch_input(request: &PbFetchRequest) -> ExecutionResult<FetchInput> {
    let input = request
        .input
        .iter()
        .cloned()
        .map(input_event_from_pb)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ExecutionError::FetchStreamEnvelope { source })?;
    verify_input_events(&input).map_err(|source| ExecutionError::FetchTranscript { source })
}

fn decode_receipt_envelope(
    envelope: Option<pb::ReceiptEnvelope>,
) -> ExecutionResult<(Vec<u8>, CoreSignedReceipt)> {
    let envelope = envelope.ok_or(ExecutionError::MissingReceiptEnvelope)?;
    let core: CoreSignedReceipt = decode_dag_cbor(&envelope.dag_cbor)
        .map_err(|source| ExecutionError::ReceiptDecode { source })?;
    Ok((envelope.dag_cbor, core))
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

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_core::ProducerSigningKey;
    use hellas_rpc::fetch::{build_input_events, build_output_events};
    use hellas_rpc::stream::{input_event_to_pb, output_event_to_pb};

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
    }

    fn fetch_request(
        caller: &ProducerSigningKey,
        service: &str,
        method: &str,
        payload: &[u8],
    ) -> PbFetchRequest {
        let events = build_input_events(service, method, payload, caller).unwrap();
        PbFetchRequest {
            input: events.iter().map(input_event_to_pb).collect(),
        }
    }

    fn fetch_finished(
        request: &PbFetchRequest,
        producer: &ProducerSigningKey,
        output: &[u8],
    ) -> WorkFinished {
        let input = verified_fetch_input(request).unwrap().input_commitment;
        let events = build_output_events(input, output, producer).unwrap();
        WorkFinished {
            output: output.to_vec(),
            receipt: None,
            status: FinishStatus::EndOfSequence as i32,
            total_units: output.len() as u64,
            output_events: events.iter().map(output_event_to_pb).collect(),
        }
    }

    #[test]
    fn fetch_finished_verifies_signed_output_transcript() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let finished = fetch_finished(&request, &producer, br#"{"x":1}"#);

        let input = verified_fetch_input(&request).unwrap().input_commitment;
        let outcome = parse_fetch_finished(finished, input).unwrap();

        assert_eq!(
            outcome,
            FetchOutcome::Completed {
                output: br#"{"x":1}"#.to_vec()
            }
        );
    }

    #[test]
    fn fetch_finished_rejects_unsigned_terminal_output_change() {
        let caller = key(1);
        let producer = key(2);
        let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
        let mut finished = fetch_finished(&request, &producer, br#"{"x":1}"#);
        finished.output = br#"{"x":2}"#.to_vec();

        assert!(matches!(
            parse_fetch_finished(
                finished,
                verified_fetch_input(&request).unwrap().input_commitment
            )
            .unwrap_err(),
            ExecutionError::Protocol(_)
        ));
    }
}
