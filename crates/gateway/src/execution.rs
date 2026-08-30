//! Stream-shaped execution layer.
//!
//! The fundamental shape: every layer returns
//! `impl Stream<Item = Result<ExecutionEvent, ClientError>>` or
//! `impl Stream<Item = Result<FetchExecutionEvent, ClientError>>`. Drop-cancellation
//! propagates naturally — when a consumer drops the stream, the generator
//! is dropped, which drops every in-flight future, which drops every
//! resource, which (for local executions) drops the per-execution
//! `mpsc::Receiver` the worker pushes chunks into. The worker observes
//! the closed channel on its next chunk send and converts it into a
//! cancel that the runner sees between generation steps.
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
//! Remote bootstrap, discovery, quote retries, ticket signing, and signed
//! chunk verification live in `hellas-client`; this module retains local
//! executor dispatch plus package-execution and gateway response shaping.

use async_stream::try_stream;
use futures::StreamExt;
use futures::stream::BoxStream;
use futures::stream::Stream;
use hellas_client::ClientError as ExecutionError;
use hellas_client::ExecutionRuntime as ClientExecutionRuntime;
use hellas_client::signed_run_ticket_request;
use hellas_client::{ClientResult as ExecutionResult, ExecutionRoute};
use hellas_client::{
    EvaluateChunkVerifier, EvaluateExecutionEvent as ClientEvaluateEvent,
    EvaluateOutcome as ClientEvaluateOutcome, verify_evaluate_work_event,
};
#[cfg(feature = "evaluate")]
use hellas_executor::ExecutorHandle;
use hellas_rpc::Digest;
use hellas_rpc::ExecutionPackageId;
use hellas_rpc::InputCommitment;
use hellas_rpc::OutputEventEnvelope;
use hellas_rpc::ProducerSigningKey;
use hellas_rpc::PublicKey;
use hellas_rpc::Retention;
use hellas_rpc::evaluate::EvaluateStopReason;
use hellas_rpc::pb::courtesy::{
    EvaluateGenesisStart, EvaluateStart, QuoteTokensRequest, evaluate_start,
};
use hellas_rpc::pb::execute::Ticket;
use hellas_rpc::pb::execute::WorkEvent;
use hellas_rpc::protocol::artifacts::TextExecutionId;
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::services::execute::ExecuteClientImpl;
use hellas_wire::WireStatus;
use hellas_wire::iroh::IrohTransport;
#[cfg(feature = "evaluate")]
use std::error::Error as StdError;
use std::sync::Arc;
#[cfg(feature = "evaluate")]
use tokio_stream::wrappers::ReceiverStream;
use tracing::instrument;

#[cfg(feature = "evaluate")]
trait ExecutionContext<T> {
    fn exec_context(self, context: impl Into<String>) -> ExecutionResult<T>;
}

#[cfg(feature = "evaluate")]
impl<T, E> ExecutionContext<T> for Result<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    fn exec_context(self, context: impl Into<String>) -> ExecutionResult<T> {
        self.map_err(|source| ExecutionError::source(context, source))
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

#[cfg(feature = "evaluate")]
pub type CliRuntime = ClientExecutionRuntime<ExecutorHandle>;
#[cfg(not(feature = "evaluate"))]
pub type CliRuntime = ClientExecutionRuntime<()>;

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
        text_artifact: Digest,
        output_events: Vec<OutputEventEnvelope>,
    },
    Failed {
        /// Tokens emitted before the failure (for honest usage reporting).
        position: u64,
        error: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    StopToken,
    MaxNewTokens,
}

#[cfg(feature = "evaluate")]
fn require_local_executor(runtime: &CliRuntime) -> ExecutionResult<ExecutorHandle> {
    runtime.local_state().cloned().ok_or_else(|| {
        ExecutionError::protocol("local execution requested but no local executor is configured")
    })
}

fn ticket_assurance(ticket: &Ticket) -> ExecutionResult<hellas_rpc::Assurance> {
    hellas_rpc::run_ticket::job_terms_from_pb(ticket)
        .map(|terms| terms.assurance)
        .map_err(|source| ExecutionError::source("invalid evaluate ticket terms", source))
}

fn validate_evaluate_ticket(ticket: &Ticket, requested: i32) -> ExecutionResult<()> {
    let requested = hellas_rpc::run_ticket::assurance_from_pb(requested)
        .map_err(|source| ExecutionError::source("invalid requested assurance", source))?;
    if ticket_assurance(ticket)? == requested {
        Ok(())
    } else {
        Err(ExecutionError::protocol(
            "evaluate ticket assurance does not match request",
        ))
    }
}

// ---------------------------------------------------------------------------
// ExecutionRequest — public entry point
// ---------------------------------------------------------------------------

pub struct ExecutionRequest {
    runtime: CliRuntime,
    quote_req: QuoteTokensRequest,
    strategy: ExecutionStrategy,
    runner_key: Arc<ProducerSigningKey>,
}

#[derive(Debug, Clone, Copy)]
pub struct ExecutionRequestOptions {
    pub max_new_tokens: u32,
    pub execution_package: ExecutionPackageId,
    pub assurance: hellas_rpc::Assurance,
    pub retention: Retention,
}

#[derive(Clone)]
struct ExpectedTextArtifact {
    execution: TextExecutionId,
    input_ids: Vec<u32>,
    has_stop_tokens: bool,
}

fn expected_text_artifact(
    quote_req: &QuoteTokensRequest,
    execution: TextExecutionId,
) -> ExecutionResult<ExpectedTextArtifact> {
    match quote_req
        .start
        .as_ref()
        .and_then(|start| start.kind.as_ref())
    {
        Some(evaluate_start::Kind::Genesis(_)) => Ok(ExpectedTextArtifact {
            execution,
            input_ids: quote_req.prompt_token_ids.clone(),
            has_stop_tokens: !quote_req.stop_token_ids.is_empty(),
        }),
        Some(evaluate_start::Kind::Artifact(_)) => Err(ExecutionError::protocol(
            "artifact-start evaluate requires verified prior state tokens and is not exposed by this client",
        )),
        None => Err(ExecutionError::protocol(
            "evaluate request is missing its start state",
        )),
    }
}

impl ExecutionRequest {
    pub fn new(
        runtime: CliRuntime,
        package: String,
        prompt_token_ids: Vec<u32>,
        stop_token_ids: Vec<u32>,
        options: ExecutionRequestOptions,
        strategy: ExecutionStrategy,
        runner_key: ProducerSigningKey,
    ) -> ExecutionResult<Self> {
        if prompt_token_ids.is_empty() {
            return Err(ExecutionError::protocol(
                "prompt token IDs must not be empty",
            ));
        }
        if stop_token_ids.len() > hellas_rpc::MAX_STOP_TOKEN_IDS {
            return Err(ExecutionError::protocol(format!(
                "stop token list has {} entries, over the limit of {}",
                stop_token_ids.len(),
                hellas_rpc::MAX_STOP_TOKEN_IDS
            )));
        }
        if options.max_new_tokens == 0 {
            return Err(ExecutionError::protocol(
                "maximum new tokens must be greater than zero",
            ));
        }
        let mut stop_token_ids = stop_token_ids;
        hellas_rpc::normalize_stop_token_ids(&mut stop_token_ids);
        let quote_req = QuoteTokensRequest {
            package,
            execution_package: options.execution_package.as_bytes().to_vec(),
            prompt_token_ids,
            max_new_tokens: Some(options.max_new_tokens),
            stop_token_ids,
            start: Some(EvaluateStart {
                kind: Some(evaluate_start::Kind::Genesis(EvaluateGenesisStart {})),
            }),
            runner_public_key: Some(hellas_client::runner_public_key(&runner_key)),
            assurance: options.assurance.to_byte().into(),
            retain: Some(options.retention.should_retain()),
        };
        Ok(Self {
            runtime,
            quote_req,
            strategy,
            runner_key: Arc::new(runner_key),
        })
    }

    /// True if any leg of this strategy talks to a remote executor.
    pub fn uses_remote_transport(&self) -> bool {
        #[cfg(feature = "evaluate")]
        let is_remote = |r: &ExecutionRoute| !matches!(r, ExecutionRoute::Local);
        #[cfg(not(feature = "evaluate"))]
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
                primary: PreparedRoute::prepare(
                    &self.runtime,
                    &self.quote_req,
                    &route,
                    self.runner_key.clone(),
                )
                .await?,
                shadow: None,
                runtime: self.runtime,
            }),
            ExecutionStrategy::Verify { primary, shadow } => Ok(PreparedExecution {
                primary: PreparedRoute::prepare(
                    &self.runtime,
                    &self.quote_req,
                    &primary,
                    self.runner_key.clone(),
                )
                .await?,
                shadow: Some(
                    PreparedRoute::prepare(
                        &self.runtime,
                        &self.quote_req,
                        &shadow,
                        self.runner_key.clone(),
                    )
                    .await?,
                ),
                runtime: self.runtime,
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

// ---------------------------------------------------------------------------
// PreparedExecution — primary + optional shadow for Verify
// ---------------------------------------------------------------------------

pub struct PreparedExecution {
    primary: PreparedRoute,
    shadow: Option<PreparedRoute>,
    // Owns the remote endpoint from quote through the terminal Execute
    // trailer. A transport alone does not keep its endpoint alive.
    runtime: CliRuntime,
}

impl PreparedExecution {
    /// See [`PreparedRoute::provenance`] — this delegates to the primary
    /// route. Shadow's provenance is intentionally not exposed (verify is
    /// internal; the primary is what the user sees).
    pub fn provenance(&self) -> Option<&ExecutionProvenance> {
        self.primary.provenance()
    }

    /// Stream a primary live only when no shadow is configured. With a shadow,
    /// withhold every primary chunk until its terminal artifact matches; a
    /// mismatch exposes only `Done(Failed)`, never unverified text.
    pub fn stream(self) -> BoxStream<'static, ExecutionResult<ExecutionEvent>> {
        let Self {
            primary,
            shadow,
            runtime,
        } = self;
        let inner =
            reconcile_execution_streams(primary.stream(), shadow.map(PreparedRoute::stream));
        Box::pin(try_stream! {
            let _runtime = runtime;
            let mut inner = inner;
            while let Some(event) = inner.next().await {
                yield event?;
            }
        })
    }
}

fn reconcile_execution_streams(
    primary: BoxStream<'static, ExecutionResult<ExecutionEvent>>,
    shadow: Option<BoxStream<'static, ExecutionResult<ExecutionEvent>>>,
) -> BoxStream<'static, ExecutionResult<ExecutionEvent>> {
    Box::pin(try_stream! {
        match shadow {
            None => {
                let mut primary = primary;
                while let Some(event) = primary.next().await {
                    yield event?;
                }
            }
            Some(shadow) => {
                let mut buffered = Vec::new();
                let mut primary_token_bytes = Vec::new();
                let mut primary = primary;
                let mut primary_done: Option<Outcome> = None;
                while let Some(event) = primary.next().await {
                    match event? {
                        ExecutionEvent::Chunk { position, tokens } => {
                            primary_token_bytes.extend_from_slice(&tokens);
                            buffered.push(ExecutionEvent::Chunk { position, tokens });
                        }
                        ExecutionEvent::Done(outcome) => {
                            primary_done = Some(outcome);
                            break;
                        }
                    }
                }
                let primary_outcome = primary_done
                    .ok_or_else(|| ExecutionError::protocol("primary stream ended without terminal outcome"))?;

                let final_outcome =
                    verify_shadow(primary_outcome, primary_token_bytes, shadow).await?;
                if matches!(final_outcome, Outcome::Completed { .. }) {
                    for event in buffered {
                        yield event;
                    }
                }
                yield ExecutionEvent::Done(final_outcome);
            }
        }
    })
}

/// Run the shadow stream to completion, compare its verified token sequence
/// and terminal artifact with the primary, and return the reconciled outcome.
async fn verify_shadow(
    primary: Outcome,
    primary_token_bytes: Vec<u8>,
    shadow: BoxStream<'static, ExecutionResult<ExecutionEvent>>,
) -> ExecutionResult<Outcome> {
    let (primary_digest, primary_stop_reason, primary_total_tokens) = match &primary {
        Outcome::Completed {
            text_artifact,
            stop_reason,
            total_tokens,
            ..
        } => (*text_artifact, *stop_reason, *total_tokens),
        Outcome::Failed { .. } => return Ok(primary),
    };
    let primary_output_tokens = token_count(&primary_token_bytes)?;

    let (shadow_token_bytes, shadow_outcome) = drain_to_outcome(shadow).await?;
    match shadow_outcome {
        Outcome::Completed {
            text_artifact: shadow_digest,
            stop_reason: shadow_stop_reason,
            total_tokens: shadow_total_tokens,
            ..
        } => {
            if primary_token_bytes != shadow_token_bytes {
                Ok(Outcome::Failed {
                    position: primary_output_tokens,
                    error: "verify mismatch: primary and shadow emitted different token sequences"
                        .to_string(),
                })
            } else if primary_digest != shadow_digest {
                Ok(Outcome::Failed {
                    position: primary_output_tokens,
                    error: format!(
                        "verify mismatch: primary evaluate artifact {primary_digest} != shadow evaluate artifact {shadow_digest}"
                    ),
                })
            } else if primary_stop_reason != shadow_stop_reason
                || primary_total_tokens != shadow_total_tokens
            {
                Ok(Outcome::Failed {
                    position: primary_output_tokens,
                    error: "verify mismatch: primary and shadow terminal semantics differ"
                        .to_string(),
                })
            } else {
                Ok(primary)
            }
        }
        Outcome::Failed {
            error: shadow_error,
            ..
        } => Ok(Outcome::Failed {
            position: primary_output_tokens,
            error: format!("shadow verification failed: {shadow_error}"),
        }),
    }
}

fn token_count(bytes: &[u8]) -> ExecutionResult<u64> {
    if !bytes.len().is_multiple_of(std::mem::size_of::<u32>()) {
        return Err(ExecutionError::protocol(
            "execution stream carried malformed token bytes",
        ));
    }
    u64::try_from(bytes.len() / std::mem::size_of::<u32>())
        .map_err(|_| ExecutionError::protocol("execution token count exceeds u64 range"))
}

/// Consume a stream to its terminal `Done`, retaining its canonical token
/// sequence independently of chunk boundaries.
async fn drain_to_outcome(
    stream: impl Stream<Item = ExecutionResult<ExecutionEvent>>,
) -> ExecutionResult<(Vec<u8>, Outcome)> {
    tokio::pin!(stream);
    let mut token_bytes = Vec::new();
    while let Some(event) = stream.next().await {
        match event? {
            ExecutionEvent::Chunk { tokens, .. } => token_bytes.extend_from_slice(&tokens),
            ExecutionEvent::Done(outcome) => return Ok((token_bytes, outcome)),
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
    #[cfg(feature = "evaluate")]
    Local {
        handle: ExecutorHandle,
        ticket: Ticket,
        provenance: ExecutionProvenance,
        runner_key: Arc<ProducerSigningKey>,
        producer_key: PublicKey,
        max_new_tokens: u32,
        expected_text_artifact: ExpectedTextArtifact,
    },
    RemoteDirect {
        transport: IrohTransport,
        ticket: Ticket,
        provenance: ExecutionProvenance,
        runner_key: Arc<ProducerSigningKey>,
        producer_key: PublicKey,
        max_new_tokens: u32,
        expected_text_artifact: ExpectedTextArtifact,
    },
}

impl PreparedRoute {
    fn provenance(&self) -> Option<&ExecutionProvenance> {
        match self {
            #[cfg(feature = "evaluate")]
            PreparedRoute::Local { provenance, .. } => Some(provenance),
            PreparedRoute::RemoteDirect { provenance, .. } => Some(provenance),
        }
    }

    #[instrument(skip_all, fields(?route))]
    async fn prepare(
        runtime: &CliRuntime,
        quote_req: &QuoteTokensRequest,
        route: &ExecutionRoute,
        runner_key: Arc<ProducerSigningKey>,
    ) -> ExecutionResult<Self> {
        match route {
            ExecutionRoute::Local => {
                #[cfg(not(feature = "evaluate"))]
                return Err(ExecutionError::protocol(
                    "local execution requested but no local executor is configured",
                ));
                #[cfg(feature = "evaluate")]
                {
                    let handle = require_local_executor(runtime)?;
                    let outcome = handle
                        .quote_tokens(quote_req.clone())
                        .await
                        .exec_context("local quote_tokens failed")?;
                    let provenance = outcome.provenance.clone();
                    let validated = hellas_client::iroh::validate_evaluate_quote_response(
                        quote_req,
                        outcome.response,
                        None,
                    )?;
                    let provenance = hellas_client::iroh::validate_evaluate_quote_provenance(
                        &validated.ticket,
                        provenance,
                    )?;
                    let expected_text_artifact =
                        expected_text_artifact(quote_req, validated.text_execution)?;
                    Ok(Self::Local {
                        handle,
                        ticket: validated.ticket,
                        provenance,
                        runner_key,
                        producer_key: validated.producer_key,
                        max_new_tokens: quote_req
                            .max_new_tokens
                            .unwrap_or(hellas_rpc::DEFAULT_MAX_NEW_TOKENS),
                        expected_text_artifact,
                    })
                }
            }
            ExecutionRoute::RemoteDirect(target) => {
                let (transport, ticket, provenance, producer_key, text_execution) =
                    hellas_client::iroh::quote_tokens(runtime, target, quote_req).await?;
                validate_evaluate_ticket(&ticket, quote_req.assurance)?;
                Ok(Self::RemoteDirect {
                    transport,
                    ticket,
                    provenance,
                    runner_key,
                    producer_key,
                    max_new_tokens: quote_req
                        .max_new_tokens
                        .unwrap_or(hellas_rpc::DEFAULT_MAX_NEW_TOKENS),
                    expected_text_artifact: expected_text_artifact(quote_req, text_execution)?,
                })
            }
            ExecutionRoute::RemoteDiscovery {
                retries,
                provider_trust,
            } => {
                let (transport, ticket, provenance, producer_key, text_execution) =
                    hellas_client::iroh::discover_and_quote(
                        runtime.remote_registry()?,
                        quote_req,
                        *retries,
                        provider_trust,
                    )
                    .await?;
                validate_evaluate_ticket(&ticket, quote_req.assurance)?;
                Ok(Self::RemoteDirect {
                    transport,
                    ticket,
                    provenance,
                    runner_key,
                    producer_key,
                    max_new_tokens: quote_req
                        .max_new_tokens
                        .unwrap_or(hellas_rpc::DEFAULT_MAX_NEW_TOKENS),
                    expected_text_artifact: expected_text_artifact(quote_req, text_execution)?,
                })
            }
        }
    }

    fn stream(self) -> BoxStream<'static, ExecutionResult<ExecutionEvent>> {
        match self {
            #[cfg(feature = "evaluate")]
            PreparedRoute::Local {
                handle,
                ticket,
                provenance: _,
                runner_key,
                producer_key,
                max_new_tokens,
                expected_text_artifact,
            } => local_execute_stream(
                handle,
                ticket,
                runner_key,
                producer_key,
                max_new_tokens,
                expected_text_artifact,
            )
            .boxed(),
            PreparedRoute::RemoteDirect {
                transport,
                ticket,
                provenance: _,
                runner_key,
                producer_key,
                max_new_tokens,
                expected_text_artifact,
            } => remote_execute_stream(
                transport,
                ticket,
                runner_key,
                producer_key,
                max_new_tokens,
                expected_text_artifact,
            )
            .boxed(),
        }
    }
}

// ---------------------------------------------------------------------------
// Local execute streams — talk directly to `ExecutorHandle`
// ---------------------------------------------------------------------------

#[cfg(feature = "evaluate")]
fn local_execute_stream(
    handle: ExecutorHandle,
    ticket: Ticket,
    runner_key: Arc<ProducerSigningKey>,
    producer_key: PublicKey,
    max_new_tokens: u32,
    expected_text_artifact: ExpectedTextArtifact,
) -> impl Stream<Item = ExecutionResult<ExecutionEvent>> + Send {
    try_stream! {
        let request_commitment = ticket.request_commitment.clone();
        let assurance = ticket_assurance(&ticket)?;
        let run_ticket = signed_run_ticket_request(ticket, runner_key.as_ref())?;
        let outcome = handle
            .run_ticket_handle(run_ticket)
            .await
            .exec_context("failed to start local execution stream")?;
        let _provenance = outcome.provenance; // already surfaced from PreparedRoute::Local
        let mut events = ReceiverStream::new(outcome.events);
        let mut terminal = None;
        let input_commitment =
            hellas_client::evaluate_input_from_request_commitment(&request_commitment)?;
        let mut verifier = EvaluateChunkVerifier::new(
            input_commitment,
            assurance,
            producer_key,
            max_new_tokens,
        )
        .with_text_artifact_expectation(
            expected_text_artifact.execution,
            expected_text_artifact.input_ids,
            expected_text_artifact.has_stop_tokens,
        );
        while let Some(item) = events.next().await {
            let wire = item
                .map_err(|status: WireStatus| ExecutionError::wire("local execution stream failed", status))?;
            let event = convert_wire_event(wire, input_commitment, &mut verifier)?;
            match event {
                ExecutionEvent::Chunk { position, tokens } => {
                    yield ExecutionEvent::Chunk { position, tokens };
                }
                ExecutionEvent::Done(outcome) => {
                    terminal = Some(outcome);
                    break;
                }
            }
        }
        let terminal = terminal.ok_or_else(|| {
            ExecutionError::protocol("local execution stream ended without terminal outcome")
        })?;
        yield ExecutionEvent::Done(terminal);
        // Keep the handle alive for the lifetime of the stream so the
        // worker's per-execution sender doesn't trip the channel-closed
        // cancel path before the terminal event flushes.
        drop(handle);
    }
}

// ---------------------------------------------------------------------------
// Remote execute streams — run on the already Open-bound IrohTransport
// ---------------------------------------------------------------------------

fn remote_execute_stream(
    transport: IrohTransport,
    ticket: Ticket,
    runner_key: Arc<ProducerSigningKey>,
    producer_key: PublicKey,
    max_new_tokens: u32,
    expected_text_artifact: ExpectedTextArtifact,
) -> impl Stream<Item = ExecutionResult<ExecutionEvent>> + Send {
    try_stream! {
        let client = ExecuteClientImpl::new(transport);
        let request_commitment = ticket.request_commitment.clone();
        let assurance = ticket_assurance(&ticket)?;
        let run_ticket = signed_run_ticket_request(ticket, runner_key.as_ref())?;
        let mut wire = client
            .run_ticket(run_ticket)
            .await
            .map_err(|status| ExecutionError::wire("failed to start remote execute stream", status))?;
        let mut terminal = None;
        let input_commitment =
            hellas_client::evaluate_input_from_request_commitment(&request_commitment)?;
        let mut verifier = EvaluateChunkVerifier::new(
            input_commitment,
            assurance,
            producer_key,
            max_new_tokens,
        )
        .with_text_artifact_expectation(
            expected_text_artifact.execution,
            expected_text_artifact.input_ids,
            expected_text_artifact.has_stop_tokens,
        );
        while let Some(item) = wire.next().await {
            if terminal.is_some() {
                Err(ExecutionError::protocol(
                    "remote execute stream emitted an event after its terminal outcome"
                ))?;
            }
            let event = convert_wire_event(
                item.map_err(|status: WireStatus| ExecutionError::wire("remote execute stream failed", status))?,
                input_commitment,
                &mut verifier,
            )?;
            match event {
                ExecutionEvent::Chunk { position, tokens } => {
                    yield ExecutionEvent::Chunk { position, tokens };
                }
                ExecutionEvent::Done(outcome) => {
                    terminal = Some(outcome);
                }
            }
        }
        // Stream EOF: surface the terminal trailer. A non-Ok trailer
        // (handler aborted mid-stream, transport-level abort, etc.)
        // becomes the call's error.
        wire.finish()
            .map_err(|status| ExecutionError::wire("remote execute stream trailer", status))?;
        let terminal = terminal.ok_or_else(|| {
            ExecutionError::protocol("remote execute stream ended Ok but emitted no Done event")
        })?;
        yield ExecutionEvent::Done(terminal);
        drop(client);
    }
}

// ---------------------------------------------------------------------------
// WorkEvent → execution events
// ---------------------------------------------------------------------------

fn convert_wire_event(
    event: WorkEvent,
    input_commitment: InputCommitment,
    verifier: &mut EvaluateChunkVerifier,
) -> ExecutionResult<ExecutionEvent> {
    match verify_evaluate_work_event(verifier, event, input_commitment)? {
        ClientEvaluateEvent::Chunk { position, tokens } => {
            Ok(ExecutionEvent::Chunk { position, tokens })
        }
        ClientEvaluateEvent::Done(ClientEvaluateOutcome::Completed {
            output,
            output_events,
        }) => Ok(ExecutionEvent::Done(Outcome::Completed {
            total_tokens: output.terminal.billable_units,
            stop_reason: stop_reason_from_evaluate(output.terminal.stop_reason)?,
            text_artifact: output.terminal.text_artifact,
            output_events,
        })),
        ClientEvaluateEvent::Done(ClientEvaluateOutcome::Failed { position, error }) => {
            Ok(ExecutionEvent::Done(Outcome::Failed { position, error }))
        }
    }
}

fn stop_reason_from_evaluate(value: EvaluateStopReason) -> ExecutionResult<StopReason> {
    match value.as_u8() {
        1 => Ok(StopReason::StopToken),
        2 => Ok(StopReason::MaxNewTokens),
        other => Err(ExecutionError::EvaluateTranscript {
            source: hellas_rpc::evaluate::EvaluateProtocolError::UnknownStopReason(other),
        }),
    }
}

#[cfg(test)]
mod request_tests {
    use super::*;
    use futures::stream;

    fn completed(artifact: u8) -> Outcome {
        Outcome::Completed {
            total_tokens: 2,
            stop_reason: StopReason::MaxNewTokens,
            text_artifact: Digest::from_bytes([artifact; 32]),
            output_events: Vec::new(),
        }
    }

    fn event_stream(
        events: Vec<ExecutionEvent>,
    ) -> BoxStream<'static, ExecutionResult<ExecutionEvent>> {
        Box::pin(stream::iter(events.into_iter().map(Ok)))
    }

    #[test]
    fn explicit_zero_output_limit_is_rejected() {
        let result = ExecutionRequest::new(
            CliRuntime::default(),
            "package".to_string(),
            vec![1],
            Vec::new(),
            ExecutionRequestOptions {
                max_new_tokens: 0,
                execution_package: ExecutionPackageId::from_bytes([1; 32]),
                assurance: hellas_rpc::Assurance::ProducerSigned,
                retention: Retention::Retain,
            },
            ExecutionStrategy::Run(ExecutionRoute::Local),
            ProducerSigningKey::from_secret_bytes([2; 32]).expect("valid test key"),
        );
        let error = match result {
            Ok(_) => panic!("an explicit zero output limit must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("greater than zero"));
    }

    #[tokio::test]
    async fn verification_mismatch_exposes_no_primary_chunks() {
        let tokens = hellas_rpc::encode_token_ids(&[42]);
        let primary = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens: tokens.clone(),
            },
            ExecutionEvent::Done(completed(1)),
        ]);
        let shadow = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens,
            },
            ExecutionEvent::Done(completed(2)),
        ]);

        let output = reconcile_execution_streams(primary, Some(shadow))
            .collect::<Vec<_>>()
            .await;
        assert_eq!(output.len(), 1);
        assert!(matches!(
            &output[0],
            Ok(ExecutionEvent::Done(Outcome::Failed { error, .. }))
                if error.contains("verify mismatch")
        ));
    }

    #[tokio::test]
    async fn verified_primary_chunks_are_released_after_matching_shadow() {
        let tokens = hellas_rpc::encode_token_ids(&[42]);
        let primary = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens: tokens.clone(),
            },
            ExecutionEvent::Done(completed(1)),
        ]);
        let shadow = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens: tokens.clone(),
            },
            ExecutionEvent::Done(completed(1)),
        ]);

        let output = reconcile_execution_streams(primary, Some(shadow))
            .collect::<Vec<_>>()
            .await;
        assert_eq!(output.len(), 2);
        assert!(matches!(
            &output[0],
            Ok(ExecutionEvent::Chunk { position: 1, tokens: actual }) if actual == &tokens
        ));
        assert!(matches!(
            &output[1],
            Ok(ExecutionEvent::Done(Outcome::Completed { text_artifact, .. }))
                if *text_artifact == Digest::from_bytes([1; 32])
        ));
    }

    #[tokio::test]
    async fn matching_artifact_claim_cannot_hide_different_shadow_tokens() {
        let primary = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens: hellas_rpc::encode_token_ids(&[42]),
            },
            ExecutionEvent::Done(completed(1)),
        ]);
        let shadow = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens: hellas_rpc::encode_token_ids(&[43]),
            },
            ExecutionEvent::Done(completed(1)),
        ]);

        let output = reconcile_execution_streams(primary, Some(shadow))
            .collect::<Vec<_>>()
            .await;
        assert_eq!(output.len(), 1);
        assert!(matches!(
            &output[0],
            Ok(ExecutionEvent::Done(Outcome::Failed { error, .. }))
                if error.contains("different token sequences")
        ));
    }

    #[tokio::test]
    async fn verification_ignores_honest_chunk_boundaries() {
        let primary_tokens = hellas_rpc::encode_token_ids(&[1, 2]);
        let primary = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 2,
                tokens: primary_tokens.clone(),
            },
            ExecutionEvent::Done(completed(1)),
        ]);
        let shadow = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens: hellas_rpc::encode_token_ids(&[1]),
            },
            ExecutionEvent::Chunk {
                position: 2,
                tokens: hellas_rpc::encode_token_ids(&[2]),
            },
            ExecutionEvent::Done(completed(1)),
        ]);

        let output = reconcile_execution_streams(primary, Some(shadow))
            .collect::<Vec<_>>()
            .await;
        assert_eq!(output.len(), 2);
        assert!(matches!(
            &output[0],
            Ok(ExecutionEvent::Chunk { position: 2, tokens }) if tokens == &primary_tokens
        ));
        assert!(matches!(
            &output[1],
            Ok(ExecutionEvent::Done(Outcome::Completed { .. }))
        ));
    }
}

#[cfg(test)]
mod remote_lifetime_tests {
    use super::*;
    use futures::stream;
    use hellas_client::{ProviderTrustAnchor, RemoteNodeTarget};
    use hellas_rpc::call::WithTrailer;
    use hellas_rpc::open::{OpenDispatcher, OpenHandler};
    use hellas_rpc::pb::courtesy::{
        GetArtifactRequest, GetArtifactResponse, GetPackageStatsRequest, GetPackageStatsResponse,
        GetStatsRequest, GetStatsResponse, ListPackagesRequest, ListPackagesResponse,
        QuoteResponse,
    };
    use hellas_rpc::pb::execute::{
        OpenRequest, OpenResponse, RunTicketRequest, WorkFailed, open_response, work_event,
    };
    use hellas_rpc::protocol::artifacts::{
        BoundTermId, InputAddressed, OutputAddressed, SourceRef, TextArtifact, TextExecution,
        TextPolicy, TokenIds,
    };
    use hellas_rpc::serve::MethodDispatcher;
    use hellas_rpc::services::courtesy::{
        Courtesy, CourtesyHandler, CourtesyServer, Open as CourtesyOpen, QuoteTokens,
    };
    use hellas_rpc::services::execute::{ExecuteHandler, ExecuteServer, RunTicket};
    use hellas_rpc::{
        Assurance, Evaluate, EvaluateProgramManifest, JobTerms, PlatformCredential,
        PlatformEnrollment, ProgramManifest, ProviderEnrollmentBundle, ProviderGenesisStatement,
        RootKind, RootProof, SignedProviderGenesis,
    };
    use hellas_wire::{
        Dispatcher, Metadata, MethodMarker, ServiceMarker, StreamTransport, TransportContext,
    };
    use iroh::endpoint::{Connection, presets};
    use iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr};
    use std::time::Duration;
    use tokio::sync::oneshot;

    #[derive(Clone)]
    struct FixtureProvider {
        producer: ProducerSigningKey,
        enrollment: ProviderEnrollmentBundle,
    }

    impl FixtureProvider {
        fn new(transport_key: &SecretKey) -> Self {
            let root = ProducerSigningKey::from_secret_bytes([0x53; 32])
                .expect("the fixture root key is valid");
            let producer = ProducerSigningKey::from_secret_bytes([0x54; 32])
                .expect("the fixture producer key is valid");
            let statement = ProviderGenesisStatement {
                root_kind: RootKind::Software,
                root_public_key: root.public_key(),
                producer_public_key: producer.public_key(),
                transport_public_key: PublicKey::Ed25519(*transport_key.public().as_bytes()),
                platform_credential: PlatformCredential::Absent,
                installation_nonce: [0x55; 32],
            };
            let genesis = SignedProviderGenesis {
                root_proof: RootProof::Software(
                    root.sign_digest(Digest::hash(&statement.canonical_bytes()))
                        .expect("the fixture root signs"),
                ),
                statement,
            };
            Self {
                producer,
                enrollment: ProviderEnrollmentBundle {
                    genesis,
                    platform: PlatformEnrollment::Absent,
                },
            }
        }

        fn trust(&self) -> ProviderTrustAnchor {
            ProviderTrustAnchor {
                expected_genesis: self.enrollment.content_id(),
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            }
        }

        fn quote(&self, request: QuoteTokensRequest) -> WithTrailer<QuoteResponse> {
            let execution_package = ExecutionPackageId::from_bytes(
                request
                    .execution_package
                    .as_slice()
                    .try_into()
                    .expect("the fixture request has a package identity"),
            );
            let manifest = ProgramManifest::Evaluate(EvaluateProgramManifest { execution_package });
            let execution_environment = manifest.content_id();
            let identity = TextArtifact::identity(
                BoundTermId::from_digest(execution_environment.digest()),
                execution_package,
            );
            let prompt = TokenIds::from_u32s(request.prompt_token_ids.iter().copied());
            let max_new_tokens = request
                .max_new_tokens
                .unwrap_or(hellas_rpc::DEFAULT_MAX_NEW_TOKENS);
            let policy = TextPolicy::from_u32_stop_tokens(
                max_new_tokens,
                request.stop_token_ids.iter().copied(),
            );
            let text_execution = TextExecution::new(
                SourceRef::output(identity.output_id()),
                prompt.output_id(),
                policy.output_id(),
            );
            let runner_public_key = hellas_rpc::run_ticket::public_key_from_pb(
                request
                    .runner_public_key
                    .expect("the fixture request has a runner key"),
            )
            .expect("the fixture runner key decodes");
            let assurance = hellas_rpc::run_ticket::assurance_from_pb(request.assurance)
                .expect("the fixture assurance decodes");
            let evaluate = hellas_rpc::EvaluateRequest {
                text_execution: text_execution.input_id().digest(),
                runner_public_key,
                execution_environment,
                nonce: [0x56; 32],
                assurance,
                retain: request.retain.unwrap_or(true),
            };
            let request_commitment = Evaluate::commit_request(&evaluate);
            let provider_genesis = self.enrollment.canonical_bytes();
            let ticket = hellas_rpc::run_ticket::ticket_to_pb(
                JobTerms {
                    request: request_commitment,
                    provider_genesis: self.enrollment.content_id(),
                    assurance,
                    amount: 1,
                    ttl_ms: 1_000,
                },
                provider_genesis,
            )
            .expect("the fixture ticket matches its enrollment");
            let mut metadata = Metadata::new();
            hellas_rpc::provenance::write_provenance_metadata(
                &mut metadata,
                &ExecutionProvenance {
                    commitment_id: *request_commitment.as_bytes(),
                },
            );
            WithTrailer::with_metadata(
                QuoteResponse {
                    ticket: Some(ticket),
                    prompt_tokens: request.prompt_token_ids.len() as u32,
                    evaluate_request: Some(hellas_rpc::pb::evaluate::EvaluateRequest {
                        text_execution: evaluate.text_execution.as_bytes().to_vec(),
                        runner_public_key: Some(hellas_rpc::run_ticket::public_key_to_pb(
                            &evaluate.runner_public_key,
                        )),
                        execution_environment: evaluate.execution_environment.as_bytes().to_vec(),
                        nonce: evaluate.nonce.to_vec(),
                        assurance: evaluate.assurance.to_byte().into(),
                        retain: Some(evaluate.retain),
                    }),
                },
                metadata,
            )
        }
    }

    impl OpenHandler for FixtureProvider {
        async fn open(
            &self,
            request: OpenRequest,
            context: TransportContext,
            alpn: &'static [u8],
        ) -> Result<OpenResponse, WireStatus> {
            let nonce: [u8; 32] = request
                .nonce
                .try_into()
                .map_err(|_| WireStatus::internal("invalid fixture nonce"))?;
            let exporter = context
                .open_exporter
                .ok_or_else(|| WireStatus::internal("missing fixture exporter"))?;
            let binding = hellas_rpc::open_proof_binding(
                &exporter,
                &nonce,
                &self.enrollment.genesis.statement.producer_public_key,
                self.enrollment.content_id(),
                alpn,
            );
            let signature = self
                .producer
                .sign_digest(binding)
                .map_err(|_| WireStatus::internal("fixture signing failed"))?;
            Ok(OpenResponse {
                provider_genesis: self.enrollment.canonical_bytes(),
                proof: Some(open_response::Proof::ProducerSignature(
                    hellas_rpc::run_ticket::signature_to_pb(&signature),
                )),
            })
        }
    }

    #[allow(refining_impl_trait)]
    impl CourtesyHandler for FixtureProvider {
        async fn open(&self, _request: OpenRequest) -> Result<OpenResponse, WireStatus> {
            Err(WireStatus::internal("fixture Open dispatcher was bypassed"))
        }

        async fn quote_tokens(
            &self,
            request: QuoteTokensRequest,
        ) -> Result<WithTrailer<QuoteResponse>, WireStatus> {
            Ok(self.quote(request))
        }

        async fn get_artifact(
            &self,
            _request: GetArtifactRequest,
        ) -> Result<GetArtifactResponse, WireStatus> {
            Err(WireStatus::unimplemented(
                "unused by endpoint lifetime test",
            ))
        }

        async fn list_packages(
            &self,
            _request: ListPackagesRequest,
        ) -> Result<ListPackagesResponse, WireStatus> {
            Err(WireStatus::unimplemented(
                "unused by endpoint lifetime test",
            ))
        }

        async fn get_stats(
            &self,
            _request: GetStatsRequest,
        ) -> Result<GetStatsResponse, WireStatus> {
            Err(WireStatus::unimplemented(
                "unused by endpoint lifetime test",
            ))
        }

        async fn get_package_stats(
            &self,
            _request: GetPackageStatsRequest,
        ) -> Result<GetPackageStatsResponse, WireStatus> {
            Err(WireStatus::unimplemented(
                "unused by endpoint lifetime test",
            ))
        }
    }

    #[derive(Clone, Copy)]
    struct ExecuteWitness;

    impl ExecuteHandler for ExecuteWitness {
        async fn run_ticket(
            &self,
            _request: RunTicketRequest,
        ) -> Result<BoxStream<'static, Result<WorkEvent, WireStatus>>, WireStatus> {
            Ok(Box::pin(stream::iter([Ok(WorkEvent {
                kind: Some(work_event::Kind::Failed(WorkFailed {
                    position: 0,
                    error: "execute reached after prepare".to_string(),
                })),
            })])))
        }
    }

    async fn accept_alpn(endpoint: &Endpoint, expected: &'static str) -> Connection {
        let incoming = endpoint
            .accept()
            .await
            .expect("the fixture receives a dial");
        let accepting = incoming.accept().expect("the fixture accepts the dial");
        let connection = accepting.await.expect("the fixture handshake completes");
        assert_eq!(connection.alpn(), expected.as_bytes());
        connection
    }

    #[tokio::test]
    async fn prepared_remote_execution_keeps_endpoint_alive_until_execute() {
        let server_key = SecretKey::from_bytes(&[0x51; 32]);
        let provider = FixtureProvider::new(&server_key);
        let server = Endpoint::builder(presets::Minimal)
            .secret_key(server_key)
            .alpns(vec![Courtesy::ALPN.as_bytes().to_vec()])
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .expect("a loopback socket"),
            )
            .expect("the fixture has a valid bind address")
            .bind()
            .await
            .expect("the fixture server binds");
        let target = EndpointAddr::from_parts(
            server.id(),
            server.bound_sockets().into_iter().map(TransportAddr::Ip),
        );
        let (quote_dispatched, quote_is_dispatched) = oneshot::channel();
        let (release_run_ticket, run_ticket_released) = oneshot::channel();
        let (event_consumed, event_is_consumed) = oneshot::channel();
        let serving_endpoint = server.clone();
        let serving_provider = provider.clone();
        let serving = tokio::spawn(async move {
            let courtesy = IrohTransport::new(accept_alpn(&serving_endpoint, Courtesy::ALPN).await);
            let courtesy_server = OpenDispatcher::<_, _, CourtesyOpen>::new(
                MethodDispatcher::<_, _, RunTicket>::new(
                    ExecuteServer(ExecuteWitness),
                    CourtesyServer(serving_provider.clone()),
                ),
                serving_provider,
            );
            for expected_method in [CourtesyOpen::METHOD_ID, QuoteTokens::METHOD_ID] {
                let inbound = courtesy
                    .accept()
                    .await
                    .expect("Courtesy transport remains live")
                    .expect("Courtesy receives Open and QuoteTokens");
                assert_eq!(inbound.method_id, expected_method);
                Dispatcher::<IrohTransport>::dispatch(&courtesy_server, inbound)
                    .await
                    .expect("Courtesy request dispatches");
            }

            let _ = quote_dispatched.send(());
            let _ = run_ticket_released.await;
            let inbound = courtesy
                .accept()
                .await
                .expect("Courtesy transport remains live after prepare")
                .expect("Courtesy receives RunTicket");
            assert_eq!(inbound.method_id, RunTicket::METHOD_ID);
            Dispatcher::<IrohTransport>::dispatch(&courtesy_server, inbound)
                .await
                .expect("RunTicket dispatches on Courtesy");
            let _ = event_is_consumed.await;
        });

        let runtime = CliRuntime::remote(SecretKey::from_bytes(&[0x52; 32]))
            .await
            .expect("the fixture client binds");
        let request = ExecutionRequest::new(
            runtime,
            "fixture-package".to_string(),
            vec![1, 2],
            Vec::new(),
            ExecutionRequestOptions {
                max_new_tokens: 1,
                execution_package: ExecutionPackageId::from_bytes([0x57; 32]),
                assurance: Assurance::ProducerSigned,
                retention: Retention::Ephemeral,
            },
            ExecutionStrategy::Run(ExecutionRoute::RemoteDirect(RemoteNodeTarget {
                addr: target,
                provider_trust: provider.trust(),
            })),
            ProducerSigningKey::from_secret_bytes([0x58; 32])
                .expect("the fixture runner key is valid"),
        )
        .expect("the fixture request is valid");
        let prepared = tokio::time::timeout(Duration::from_secs(10), request.prepare())
            .await
            .expect("remote prepare does not hang")
            .expect("remote quote prepares");
        tokio::time::timeout(Duration::from_secs(10), quote_is_dispatched)
            .await
            .expect("the server reaches its post-quote barrier")
            .expect("the fixture reports that QuoteTokens dispatched");
        tokio::task::yield_now().await;
        let _ = release_run_ticket.send(());

        let mut output = prepared.stream();
        let event = tokio::time::timeout(Duration::from_secs(10), output.next())
            .await
            .expect("Execute response does not hang")
            .expect("Execute returns one terminal event")
            .expect("the fixture failure is a valid terminal event");
        assert!(matches!(
            event,
            ExecutionEvent::Done(Outcome::Failed { position: 0, error })
                if error == "execute reached after prepare"
        ));
        let _ = event_consumed.send(());
        drop(output);
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .expect("the fixture server finishes")
            .expect("the fixture server task succeeds");
        server.close().await;
    }
}

#[cfg(all(test, feature = "evaluate"))]
mod tests {
    use super::*;
    use hellas_rpc::ProducerSigningKey;
    use hellas_rpc::evaluate::{
        EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
        input_commitment as evaluate_input_commitment,
    };
    use hellas_rpc::pb::execute::{WorkChunk, WorkFinished, work_event};
    use hellas_rpc::stream::output_event_to_pb;

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
    }

    fn evaluate_request(runner: &ProducerSigningKey) -> hellas_rpc::EvaluateRequest {
        hellas_rpc::EvaluateRequest {
            text_execution: Digest::from_bytes([9; 32]),
            runner_public_key: runner.public_key(),
            execution_environment: hellas_rpc::ContentId::from_bytes([8; 32]),
            nonce: [7; 32],
            assurance: hellas_rpc::Assurance::ProducerSigned,
            retain: true,
        }
    }

    #[test]
    fn evaluate_chunk_projects_signed_event() {
        let runner = key(1);
        let producer = key(2);
        let request = evaluate_request(&runner);
        let input = evaluate_input_commitment(&request);
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, request.assurance, &producer);
        let token_event = builder.push_token_delta(vec![10, 11]).unwrap();

        let mut verifier =
            EvaluateChunkVerifier::new(input, request.assurance, producer.public_key(), 2);
        let event = WorkEvent {
            kind: Some(work_event::Kind::Chunk(WorkChunk {
                output_event: Some(output_event_to_pb(&token_event)),
            })),
        };

        let decoded = convert_wire_event(event, input, &mut verifier).unwrap();
        assert!(matches!(
            decoded,
            ExecutionEvent::Chunk {
                position: 2,
                tokens
            } if tokens == hellas_rpc::encode_token_ids(&[10, 11])
        ));
    }

    #[test]
    fn evaluate_finished_verifies_streamed_prefix_and_terminal_event() {
        let runner = key(1);
        let producer = key(2);
        let request = evaluate_request(&runner);
        let input = evaluate_input_commitment(&request);
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, request.assurance, &producer);
        let token_event = builder.push_token_delta(vec![10, 11]).unwrap();
        let output_events = builder
            .finish(EvaluateTerminal {
                final_position: 2,
                stop_reason: EvaluateStopReason::STOP_TOKEN,
                text_artifact: Digest::from_bytes([4; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 2,
                },
                billable_units: 5,
            })
            .unwrap();
        let mut verifier =
            EvaluateChunkVerifier::new(input, request.assurance, producer.public_key(), 2);
        let chunk = WorkEvent {
            kind: Some(work_event::Kind::Chunk(WorkChunk {
                output_event: Some(output_event_to_pb(&token_event)),
            })),
        };
        convert_wire_event(chunk, input, &mut verifier).unwrap();

        let finished = WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                output_events: output_events.iter().map(output_event_to_pb).collect(),
                assurance_evidence: Vec::new(),
            })),
        };

        let decoded = convert_wire_event(finished, input, &mut verifier).unwrap();
        assert!(matches!(
            decoded,
            ExecutionEvent::Done(Outcome::Completed {
                total_tokens: 5,
                stop_reason: StopReason::StopToken,
                ..
            })
        ));
    }
}
