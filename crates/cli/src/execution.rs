//! Stream-shaped CLI execution layer.
//!
//! The fundamental shape: every layer returns
//! `impl Stream<Item = anyhow::Result<ExecutionEvent>>`. Drop-cancellation
//! propagates naturally — when a consumer drops the stream, the generator
//! is dropped, which drops every in-flight future, which drops every
//! resource, which (for local executions) drops the per-execution
//! `mpsc::Receiver` the worker pushes chunks into.
//!
//! NOTE (hellas-wire v2 cutover): the remote / discovery code paths in
//! this file are currently stubbed. The shape of the public API
//! (`ExecutionRequest`, `PreparedExecution`, `Outcome`,
//! `ReceiptArtifact`, `StopReason`, …) is preserved so the rest of the
//! CLI keeps compiling, but anything that needs to dial a remote
//! executor returns `Err`/`unimplemented!()` until the discovery + pool
//! port lands. See `HELLAS_WIRE_CUTOVER_FINDINGS.md` finding #5.

// Many public types here are unused by the current stub paths but kept
// in-shape for the gateway / cli consumers and will be reconstructed by
// the real impls once dial helpers return. Silence the warnings until
// then.
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
    Digest, JsonBytes, OpaqueRequest as CoreOpaqueRequest, SchemeId,
    SignedReceipt as CoreSignedReceipt, decode_dag_cbor, verify_receipt,
};
#[cfg(feature = "hellas-executor")]
use hellas_executor::{Executor, ExecutorHandle};
use hellas_rpc::pb::courtesy::QuotePreparedTextRequest;
use hellas_rpc::pb::execute as pb;
use hellas_rpc::pb::opaque::OpaqueRequest as PbOpaqueRequest;
use hellas_rpc::model::ModelAssets;
use hellas_rpc::peers::PeerManager;
#[cfg(feature = "hellas-executor")]
use hellas_rpc::policy::{DownloadPolicy, ExecutePolicy};
use hellas_rpc::provenance::ExecutionProvenance;
use std::net::SocketAddr;
use std::sync::Arc;
use iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};

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
    #[allow(dead_code)] // used once discovery port lands
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
    #[allow(dead_code)] // used once discovery port lands
    secret_key: Option<SecretKey>,
    #[allow(dead_code)] // used once discovery port lands
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
    #[allow(dead_code)] // referenced once remote path returns
    fn require_local_executor(&self) -> Result<ExecutorHandle, anyhow::Error> {
        self.local_executor
            .clone()
            .ok_or_else(|| anyhow!("local execution requested but no local executor is configured"))
    }
}

// ---------------------------------------------------------------------------
// ExecutionRequest — public entry point
// ---------------------------------------------------------------------------

pub struct ExecutionRequest {
    #[allow(dead_code)]
    runtime: ExecutionRuntime,
    #[allow(dead_code)]
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
        // Until the discovery/pool port lands we don't have a working
        // remote dial path. We still need to support the local-only path
        // so that `--local` / `--verify-local` keeps running.
        match self.strategy {
            ExecutionStrategy::Run(route) => Ok(PreparedExecution {
                primary: PreparedRoute::stub(route),
                shadow: None,
            }),
            ExecutionStrategy::Verify { primary, shadow } => Ok(PreparedExecution {
                primary: PreparedRoute::stub(primary),
                shadow: Some(PreparedRoute::stub(shadow)),
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
    #[allow(dead_code)]
    runtime: ExecutionRuntime,
    #[allow(dead_code)]
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
            let _ = &self.route;
            // Pending discovery/pool port — see CUTOVER_FINDINGS #5.
            Err(anyhow!(
                "opaque execution pending hellas-wire discovery/pool port"
            ))?;
            // Make the generator type-check as yielding `OpaqueExecutionEvent`s.
            #[allow(unreachable_code)]
            {
                yield OpaqueExecutionEvent::Done(OpaqueOutcome::Failed {
                    error: "unreachable".to_string(),
                });
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
// PreparedRoute — Local | RemoteDirect | RemoteDiscovery (all stubbed)
// ---------------------------------------------------------------------------

enum PreparedRoute {
    Stubbed { _route: ExecutionRoute },
}

impl PreparedRoute {
    fn stub(route: ExecutionRoute) -> Self {
        PreparedRoute::Stubbed { _route: route }
    }

    /// Pre-flight provenance — currently always `None` because no route is
    /// wired yet. Once the discovery / pool port lands this returns
    /// `Some` for Local + RemoteDirect.
    fn provenance(&self) -> Option<&ExecutionProvenance> {
        None
    }

    fn stream(self) -> BoxStream<'static, anyhow::Result<ExecutionEvent>> {
        Box::pin(stub_stream())
    }
}

fn stub_stream() -> impl Stream<Item = anyhow::Result<ExecutionEvent>> + Send {
    try_stream! {
        Err(anyhow!(
            "execution pending hellas-wire discovery/pool port — see CUTOVER_FINDINGS.md"
        ))?;
        #[allow(unreachable_code)]
        {
            yield ExecutionEvent::Done(Outcome::Failed {
                position: 0,
                error: "unreachable".to_string(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers retained for shape (receipt decoding)
// ---------------------------------------------------------------------------

#[allow(dead_code)] // becomes live once the wire paths return real receipts
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
