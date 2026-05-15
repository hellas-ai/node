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
//!                                │   ├─ Local:        local stream over ExecutorHandle
//!                                │   ├─ RemoteDirect: ExecuteClientImpl over IrohTransport
//!                                │   └─ RemoteDiscovery: still stubbed (see CUTOVER_FINDINGS)
//!                                └─ shadow (verify):  same shape, run after primary
//! ```
//!
//! NOTE: RemoteDiscovery races peers from `ServiceRegistry::discover` and
//! takes the first that returns a successful quote. The pre-cutover impl
//! drove the same race over `IrohRpcPool::dial` + `discover_remote_quote`;
//! the new shape uses the wire crate's pooled `transport()` API directly.

// A few "kept for shape" helpers are reachable from one feature combination
// but not the other. Keep dead_code muted at the file level so we don't end
// up sprinkling cfg-gated allows everywhere.
#![allow(dead_code)]

use anyhow::{Context, anyhow, bail};
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
    DeliveryOutput, DeliveryRequest, Digest, JsonBytes, OpaqueRequest as CoreOpaqueRequest,
    SchemeId, SignedReceipt as CoreSignedReceipt, decode_dag_cbor, verify_delivery, verify_receipt,
};
#[cfg(feature = "hellas-executor")]
use hellas_executor::{Executor, ExecutorHandle};
use hellas_rpc::pb::courtesy::QuotePreparedTextRequest;
use hellas_rpc::pb::execute::{
    self as pb, FinishStatus, RunTicketRequest, WorkEvent, WorkFinished, work_event,
};
use hellas_rpc::pb::opaque::OpaqueRequest as PbOpaqueRequest;
use hellas_rpc::model::ModelAssets;
use hellas_rpc::peers::PeerManager;
#[cfg(feature = "hellas-executor")]
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::services::courtesy::Courtesy;
use hellas_rpc::services::execute::{Execute, ExecuteClient, ExecuteClientImpl};
use hellas_rpc::services::opaque::Opaque;
use hellas_wire::WireStatus;
use hellas_wire::iroh::swarm::ServiceRegistry;
use hellas_wire::iroh::{IrohTransport, PoolError};
use iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(feature = "hellas-executor")]
use tokio_stream::wrappers::ReceiverStream;
use tracing::instrument;

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
    #[allow(dead_code)] // used once the registry supports static-addr feeds
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
    /// Optional secret key for the iroh client endpoint. Held so callers can
    /// thread an identity through `with_secret_key` even if no registry is
    /// supplied; used by external code that constructs its own registry.
    #[allow(dead_code)]
    secret_key: Option<SecretKey>,
    /// Registry-backed connection pools per service ALPN. `None` means no
    /// remote dial path is configured; `RemoteDirect` quotes/streams will
    /// surface a clear error in that case.
    registry: Option<ServiceRegistry>,
    /// Carried for parity with the pre-cutover runtime; no longer load-
    /// bearing on the local hot path now that the executor's handle
    /// implements the service handler traits directly.
    #[allow(dead_code)]
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
            registry: None,
            peer_registry: PeerManager::default(),
        }
    }

    pub fn with_secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    /// Attach a `ServiceRegistry` (which owns pooled iroh connections per
    /// service ALPN). Required for `RemoteDirect` routes; `Local` works
    /// without one.
    pub fn with_registry(mut self, registry: ServiceRegistry) -> Self {
        self.registry = Some(registry);
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
    fn require_local_executor(&self) -> Result<ExecutorHandle, anyhow::Error> {
        self.local_executor
            .clone()
            .ok_or_else(|| anyhow!("local execution requested but no local executor is configured"))
    }

    fn require_registry(&self) -> Result<&ServiceRegistry, anyhow::Error> {
        self.registry
            .as_ref()
            .ok_or_else(|| anyhow!(
                "remote execution requested but no iroh ServiceRegistry is configured on the runtime"
            ))
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
            let prepared = OpaquePreparedRoute::prepare(
                &self.runtime,
                &self.request,
                &self.route,
            )
            .await?;
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

/// Consume a stream to its terminal `Done`, discarding chunks.
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
// PreparedRoute — Local | RemoteDirect | RemoteDiscovery (last still stubbed)
// ---------------------------------------------------------------------------

#[allow(clippy::large_enum_variant)] // see PreparedRoute (pre-cutover)
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
    ) -> anyhow::Result<Self> {
        match route {
            #[cfg(feature = "hellas-executor")]
            ExecutionRoute::Local => {
                let handle = runtime.require_local_executor()?;
                handle
                    .preload_weights(local_model_spec(quote_req))
                    .await
                    .context("failed to preload local weights")?;
                let outcome = handle
                    .quote_prepared_text(quote_req.clone())
                    .await
                    .context("local quote_prepared_text failed")?;
                let ticket = outcome.response.ticket.clone().ok_or_else(|| {
                    anyhow!("local quote_prepared_text response missing ticket")
                })?;
                Ok(Self::Local {
                    handle,
                    request_commitment: ticket.request_commitment,
                    provenance: outcome.provenance,
                })
            }
            ExecutionRoute::RemoteDirect(target) => {
                let registry = runtime.require_registry()?;
                let pool = registry.pool::<Courtesy>();
                let transport = pool
                    .transport(target.node_id)
                    .await
                    .map_err(|err: PoolError| {
                        anyhow!(err)
                            .context(format!("failed to dial Courtesy on {}", target.node_id))
                    })?;
                // Use unary_with_trailer to receive both the response and
                // the server's End-frame metadata (provenance headers).
                let with_trailer = hellas_rpc::call::unary_with_trailer::<
                    _,
                    hellas_rpc::services::courtesy::QuotePreparedText,
                >(&transport, quote_req.clone(), hellas_wire::Metadata::new())
                    .await
                    .map_err(|status| {
                        anyhow!(status).context(format!(
                            "node {} declined quote_prepared_text",
                            target.node_id
                        ))
                    })?;
                let ticket = with_trailer.response.ticket.ok_or_else(|| {
                    anyhow!("quote_prepared_text response from {} missing ticket", target.node_id)
                })?;
                // Pull provenance from the trailer. Missing/malformed
                // provenance is a hard failure: a zero digest silently
                // masquerades as a real commitment and hides trailer-
                // propagation bugs from this layer to the caller.
                let provenance =
                    hellas_rpc::provenance::read_provenance_metadata(&with_trailer.metadata)
                        .map_err(|e| {
                            anyhow!(e).context(format!(
                                "node {} response missing provenance metadata",
                                target.node_id
                            ))
                        })?;

                // Open a fresh Execute-ALPN transport for the run step.
                let execute_pool = registry.pool::<Execute>();
                let execute_transport =
                    execute_pool.transport(target.node_id).await.map_err(|err| {
                        anyhow!(err)
                            .context(format!("failed to dial Execute on {}", target.node_id))
                    })?;
                Ok(Self::RemoteDirect {
                    transport: execute_transport,
                    request_commitment: ticket.request_commitment,
                    provenance,
                })
            }
            ExecutionRoute::RemoteDiscovery { retries } => {
                let registry = runtime.require_registry()?;
                let (target, request_commitment, provenance) =
                    discover_and_quote(registry, quote_req, *retries).await?;
                let execute_pool = registry.pool::<Execute>();
                let execute_transport = execute_pool
                    .transport(target.node_id)
                    .await
                    .map_err(|err: PoolError| {
                        anyhow!(err)
                            .context(format!("failed to dial Execute on {}", target.node_id))
                    })?;
                Ok(Self::RemoteDirect {
                    transport: execute_transport,
                    request_commitment,
                    provenance,
                })
            }
        }
    }

    fn stream(self) -> BoxStream<'static, anyhow::Result<ExecutionEvent>> {
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
// OpaquePreparedRoute — Local | RemoteDirect | RemoteDiscovery (last stubbed)
// ---------------------------------------------------------------------------

#[allow(clippy::large_enum_variant)]
enum OpaquePreparedRoute {
    #[cfg(feature = "hellas-executor")]
    Local {
        handle: ExecutorHandle,
        request: PbOpaqueRequest,
        request_commitment: Vec<u8>,
    },
    RemoteDirect {
        transport: IrohTransport,
        request: PbOpaqueRequest,
        request_commitment: Vec<u8>,
    },
}

impl OpaquePreparedRoute {
    async fn prepare(
        runtime: &ExecutionRuntime,
        request: &PbOpaqueRequest,
        route: &ExecutionRoute,
    ) -> anyhow::Result<Self> {
        match route {
            #[cfg(feature = "hellas-executor")]
            ExecutionRoute::Local => {
                let handle = runtime.require_local_executor()?;
                let outcome = handle
                    .create_opaque_ticket(request.clone())
                    .await
                    .context("local create_opaque_ticket failed")?;
                Ok(Self::Local {
                    handle,
                    request: request.clone(),
                    request_commitment: outcome.response.request_commitment,
                })
            }
            ExecutionRoute::RemoteDirect(target) => {
                let registry = runtime.require_registry()?;
                let opaque_pool = registry.pool::<Opaque>();
                let opaque_transport = opaque_pool.transport(target.node_id).await.map_err(
                    |err: PoolError| {
                        anyhow!(err)
                            .context(format!("failed to dial Opaque on {}", target.node_id))
                    },
                )?;
                let client = hellas_rpc::services::opaque::OpaqueClientImpl::new(opaque_transport);
                use hellas_rpc::services::opaque::OpaqueClient;
                let ticket =
                    client
                        .create_ticket(request.clone())
                        .await
                        .map_err(|status| {
                            anyhow!(status).context(format!(
                                "node {} declined opaque create_ticket",
                                target.node_id
                            ))
                        })?;
                let execute_pool = registry.pool::<Execute>();
                let execute_transport = execute_pool.transport(target.node_id).await.map_err(
                    |err| {
                        anyhow!(err)
                            .context(format!("failed to dial Execute on {}", target.node_id))
                    },
                )?;
                Ok(Self::RemoteDirect {
                    transport: execute_transport,
                    request: request.clone(),
                    request_commitment: ticket.request_commitment,
                })
            }
            ExecutionRoute::RemoteDiscovery { retries } => {
                let registry = runtime.require_registry()?;
                let (target, request_commitment) =
                    discover_and_opaque_quote(registry, request, *retries).await?;
                let execute_pool = registry.pool::<Execute>();
                let execute_transport = execute_pool
                    .transport(target.node_id)
                    .await
                    .map_err(|err: PoolError| {
                        anyhow!(err)
                            .context(format!("failed to dial Execute on {}", target.node_id))
                    })?;
                Ok(Self::RemoteDirect {
                    transport: execute_transport,
                    request: request.clone(),
                    request_commitment,
                })
            }
        }
    }

    fn stream(self) -> BoxStream<'static, anyhow::Result<OpaqueExecutionEvent>> {
        match self {
            #[cfg(feature = "hellas-executor")]
            Self::Local {
                handle,
                request,
                request_commitment,
            } => local_execute_opaque_stream(handle, request_commitment, request).boxed(),
            Self::RemoteDirect {
                transport,
                request,
                request_commitment,
            } => remote_execute_opaque_stream(transport, request_commitment, request).boxed(),
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery — race the registry's Courtesy/Opaque feed and take the first
// peer that returns a successful quote.
// ---------------------------------------------------------------------------

/// Drain `ServiceRegistry::discover::<Courtesy>()` until we get a quote,
/// returning the responding peer and the resolved ticket commitment +
/// provenance.
async fn discover_and_quote(
    registry: &ServiceRegistry,
    quote_req: &QuotePreparedTextRequest,
    retries: usize,
) -> anyhow::Result<(RemoteNodeTarget, Vec<u8>, ExecutionProvenance)> {
    let mut stream = Box::pin(registry.discover::<Courtesy>());
    let pool = registry.pool::<Courtesy>();
    let mut last_error: Option<anyhow::Error> = None;
    let mut attempts: usize = 0;
    let max_attempts = retries.saturating_add(1);

    while let Some(peer) = stream.next().await {
        let peer = match peer {
            Ok(p) => p,
            Err(err) => {
                last_error = Some(anyhow!("discovery feed error: {err}"));
                continue;
            }
        };
        let peer_id = peer.id();
        attempts += 1;

        let transport = match pool.transport(peer_id).await {
            Ok(t) => t,
            Err(err) => {
                last_error = Some(
                    anyhow!(err).context(format!("failed to dial Courtesy on {peer_id}")),
                );
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        let with_trailer = match hellas_rpc::call::unary_with_trailer::<
            _,
            hellas_rpc::services::courtesy::QuotePreparedText,
        >(&transport, quote_req.clone(), hellas_wire::Metadata::new())
        .await
        {
            Ok(t) => t,
            Err(status) => {
                last_error = Some(
                    anyhow!(status)
                        .context(format!("node {peer_id} declined quote_prepared_text")),
                );
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        let Some(ticket) = with_trailer.response.ticket else {
            last_error = Some(anyhow!(
                "quote_prepared_text response from {peer_id} missing ticket"
            ));
            if attempts >= max_attempts {
                break;
            }
            continue;
        };

        let provenance =
            match hellas_rpc::provenance::read_provenance_metadata(&with_trailer.metadata) {
                Ok(p) => p,
                Err(e) => {
                    last_error = Some(anyhow!(e).context(format!(
                        "peer {peer_id} response missing provenance metadata"
                    )));
                    if attempts >= max_attempts {
                        break;
                    }
                    continue;
                }
            };

        let target = RemoteNodeTarget {
            node_id: peer_id,
            node_addrs: Vec::new(),
        };
        return Ok((target, ticket.request_commitment, provenance));
    }

    Err(last_error.unwrap_or_else(|| {
        anyhow!("discovery stream exhausted without a successful quote (no peers found)")
    }))
}

/// Same shape as [`discover_and_quote`] for opaque tickets.
async fn discover_and_opaque_quote(
    registry: &ServiceRegistry,
    request: &PbOpaqueRequest,
    retries: usize,
) -> anyhow::Result<(RemoteNodeTarget, Vec<u8>)> {
    use hellas_rpc::services::opaque::{OpaqueClient, OpaqueClientImpl};
    let mut stream = Box::pin(registry.discover::<Opaque>());
    let pool = registry.pool::<Opaque>();
    let mut last_error: Option<anyhow::Error> = None;
    let mut attempts: usize = 0;
    let max_attempts = retries.saturating_add(1);

    while let Some(peer) = stream.next().await {
        let peer = match peer {
            Ok(p) => p,
            Err(err) => {
                last_error = Some(anyhow!("discovery feed error: {err}"));
                continue;
            }
        };
        let peer_id = peer.id();
        attempts += 1;

        let transport = match pool.transport(peer_id).await {
            Ok(t) => t,
            Err(err) => {
                last_error = Some(
                    anyhow!(err).context(format!("failed to dial Opaque on {peer_id}")),
                );
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        let client = OpaqueClientImpl::new(transport);
        match client.create_ticket(request.clone()).await {
            Ok(ticket) => {
                let target = RemoteNodeTarget {
                    node_id: peer_id,
                    node_addrs: Vec::new(),
                };
                return Ok((target, ticket.request_commitment));
            }
            Err(status) => {
                last_error = Some(
                    anyhow!(status)
                        .context(format!("node {peer_id} declined opaque create_ticket")),
                );
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        anyhow!("discovery stream exhausted without a successful opaque quote")
    }))
}

// ---------------------------------------------------------------------------
// Local execute streams — talk directly to `ExecutorHandle`
// ---------------------------------------------------------------------------

#[cfg(feature = "hellas-executor")]
fn local_execute_stream(
    handle: ExecutorHandle,
    request_commitment: Vec<u8>,
) -> impl Stream<Item = anyhow::Result<ExecutionEvent>> + Send {
    try_stream! {
        let outcome = handle
            .run_ticket_handle(RunTicketRequest { request_commitment })
            .await
            .context("failed to start local execution stream")?;
        let _provenance = outcome.provenance; // already surfaced from PreparedRoute::Local
        let mut events = ReceiverStream::new(outcome.events);
        let mut got_terminal = false;
        while let Some(item) = events.next().await {
            let wire = item.map_err(|status: WireStatus| {
                anyhow!(status).context("local execution stream failed")
            })?;
            let event = convert_wire_event(wire)?;
            let is_done = matches!(event, ExecutionEvent::Done(_));
            yield event;
            if is_done {
                got_terminal = true;
                break;
            }
        }
        if !got_terminal {
            Err(anyhow!("local execution stream ended without terminal outcome"))?;
        }
        // Keep the handle alive for the lifetime of the stream so the
        // worker's per-execution sender doesn't trip the channel-closed
        // cancel path before the terminal event flushes.
        drop(handle);
    }
}

#[cfg(feature = "hellas-executor")]
fn local_execute_opaque_stream(
    handle: ExecutorHandle,
    request_commitment: Vec<u8>,
    request: PbOpaqueRequest,
) -> impl Stream<Item = anyhow::Result<OpaqueExecutionEvent>> + Send {
    try_stream! {
        let core_request = core_opaque_request(&request)?;
        let outcome = handle
            .run_ticket_handle(RunTicketRequest { request_commitment })
            .await
            .context("failed to start local opaque execution stream")?;
        let _provenance = outcome.provenance;
        let mut events = ReceiverStream::new(outcome.events);
        let mut got_terminal = false;
        while let Some(item) = events.next().await {
            let wire = item.map_err(|status: WireStatus| {
                anyhow!(status).context("local opaque execution stream failed")
            })?;
            let event = convert_opaque_wire_event(wire, &core_request)?;
            let is_done = matches!(event, OpaqueExecutionEvent::Done(_));
            yield event;
            if is_done {
                got_terminal = true;
                break;
            }
        }
        if !got_terminal {
            Err(anyhow!(
                "local opaque execution stream ended without terminal outcome"
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
) -> impl Stream<Item = anyhow::Result<ExecutionEvent>> + Send {
    try_stream! {
        let client = ExecuteClientImpl::new(transport);
        let mut wire = client
            .run_ticket(RunTicketRequest { request_commitment })
            .await
            .map_err(|status| anyhow!(status).context("failed to start remote execute stream"))?;
        let mut got_terminal = false;
        while let Some(item) = wire.next().await {
            let event = convert_wire_event(item.map_err(|status: WireStatus| {
                anyhow!(status).context("remote execute stream failed")
            })?)?;
            let is_done = matches!(event, ExecutionEvent::Done(_));
            yield event;
            if is_done {
                got_terminal = true;
                break;
            }
        }
        // Stream EOF: surface the terminal trailer. A non-Ok trailer
        // (handler aborted mid-stream, transport-level abort, etc.)
        // becomes the call's Err — much more informative than the old
        // "ended without terminal outcome" catch-all.
        wire.finish()
            .map_err(|status| anyhow!(status).context("remote execute stream trailer"))?;
        if !got_terminal {
            Err(anyhow!("remote execute stream ended Ok but emitted no Done event"))?;
        }
        drop(client);
    }
}

fn remote_execute_opaque_stream(
    transport: IrohTransport,
    request_commitment: Vec<u8>,
    request: PbOpaqueRequest,
) -> impl Stream<Item = anyhow::Result<OpaqueExecutionEvent>> + Send {
    try_stream! {
        let core_request = core_opaque_request(&request)?;
        let client = ExecuteClientImpl::new(transport);
        let mut wire = client
            .run_ticket(RunTicketRequest { request_commitment })
            .await
            .map_err(|status| {
                anyhow!(status).context("failed to start remote opaque execute stream")
            })?;
        let mut got_terminal = false;
        while let Some(item) = wire.next().await {
            let event = convert_opaque_wire_event(
                item.map_err(|status: WireStatus| {
                    anyhow!(status).context("remote opaque execute stream failed")
                })?,
                &core_request,
            )?;
            let is_done = matches!(event, OpaqueExecutionEvent::Done(_));
            yield event;
            if is_done {
                got_terminal = true;
                break;
            }
        }
        wire.finish()
            .map_err(|status| {
                anyhow!(status).context("remote opaque execute stream trailer")
            })?;
        if !got_terminal {
            Err(anyhow!(
                "remote opaque execute stream ended Ok but emitted no Done event"
            ))?;
        }
        drop(client);
    }
}

// ---------------------------------------------------------------------------
// WorkEvent → ExecutionEvent / OpaqueExecutionEvent
// ---------------------------------------------------------------------------

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

fn parse_finished(finished: WorkFinished) -> anyhow::Result<Outcome> {
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
    finished: WorkFinished,
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
// Misc helpers
// ---------------------------------------------------------------------------

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

#[cfg(feature = "hellas-executor")]
fn local_model_spec(quote_req: &QuotePreparedTextRequest) -> String {
    let revision = quote_req.huggingface_revision.trim();
    if revision.is_empty() {
        quote_req.huggingface_model_id.clone()
    } else {
        format!("{}@{revision}", quote_req.huggingface_model_id)
    }
}
