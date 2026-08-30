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
//! Remote bootstrap, discovery, quote retries, ticket signing, and signed
//! chunk verification live in `hellas-client`; this module retains local
//! executor dispatch plus model and gateway response shaping.

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
use hellas_models::{ModelAssets, PreparedPrompt};
use hellas_rpc::Digest;
use hellas_rpc::InputCommitment;
use hellas_rpc::OutputEventEnvelope;
use hellas_rpc::ProducerSigningKey;
use hellas_rpc::Retention;
use hellas_rpc::evaluate::EvaluateStopReason;
use hellas_rpc::pb::courtesy::{
    EvaluateGenesisStart, EvaluateStart, QuoteTokensRequest, evaluate_start,
};
use hellas_rpc::pb::execute::Ticket;
use hellas_rpc::pb::execute::WorkEvent;
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
    pub max_seq: u32,
    pub assurance: hellas_rpc::Assurance,
    pub retention: Retention,
}

impl ExecutionRequest {
    pub fn new(
        runtime: CliRuntime,
        assets: Arc<ModelAssets>,
        prepared_prompt: PreparedPrompt,
        options: ExecutionRequestOptions,
        strategy: ExecutionStrategy,
        runner_key: ProducerSigningKey,
    ) -> ExecutionResult<Self> {
        let quote = assets.prepare_quote(&prepared_prompt);
        let revision = quote.huggingface_revision.trim();
        let package = if revision.is_empty() {
            quote.huggingface_model_id.clone()
        } else {
            format!("{}@{revision}", quote.huggingface_model_id)
        };
        let quote_req = QuoteTokensRequest {
            package,
            prompt_token_ids: quote.prompt_token_ids,
            max_new_tokens: options.max_seq,
            stop_token_ids: quote.stop_token_ids,
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
    #[cfg(feature = "evaluate")]
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
            }),
        }
    }

    /// Drive this request to completion as a stream of events.
    ///
    /// Owning consumption: dropping the returned stream cancels everything
    /// downstream (broadcast subscribers, wire streams, the executor's
    /// per-running cancel token).
    #[cfg(feature = "evaluate")]
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
    /// terminal artifact commitments agree. Mismatch is reported as a `Done(Failed)` so the
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
        Outcome::Completed { text_artifact, .. } => *text_artifact,
        Outcome::Failed { .. } => return Ok(primary),
    };

    let shadow_outcome = drain_to_outcome(shadow.stream()).await?;
    match shadow_outcome {
        Outcome::Completed {
            text_artifact: shadow_digest,
            ..
        } => {
            if primary_digest == shadow_digest {
                Ok(primary)
            } else {
                Ok(Outcome::Failed {
                    position: primary.position(),
                    error: format!(
                        "verify mismatch: primary evaluate artifact {primary_digest} != shadow evaluate artifact {shadow_digest}"
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
    #[cfg(feature = "evaluate")]
    Local {
        handle: ExecutorHandle,
        ticket: Ticket,
        provenance: ExecutionProvenance,
        runner_key: Arc<ProducerSigningKey>,
    },
    RemoteDirect {
        transport: IrohTransport,
        ticket: Ticket,
        provenance: ExecutionProvenance,
        runner_key: Arc<ProducerSigningKey>,
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
                    handle
                        .materialize_model(quote_req.package.clone())
                        .await
                        .exec_context("failed to load local model metadata")?;
                    let outcome = handle
                        .quote_tokens(quote_req.clone())
                        .await
                        .exec_context("local quote_tokens failed")?;
                    let ticket = outcome.response.ticket.clone().ok_or_else(|| {
                        ExecutionError::protocol("local quote_tokens response missing ticket")
                    })?;
                    let evaluate_response =
                        outcome.response.evaluate_request.as_ref().ok_or_else(|| {
                            ExecutionError::protocol(
                                "local quote_tokens response missing evaluate_request",
                            )
                        })?;
                    if evaluate_response.assurance != quote_req.assurance {
                        return Err(ExecutionError::protocol(
                            "evaluate response assurance does not match request",
                        ));
                    }
                    if evaluate_response.retain.unwrap_or(true) != quote_req.retain.unwrap_or(true)
                    {
                        return Err(ExecutionError::protocol(
                            "evaluate response retention does not match request",
                        ));
                    }
                    validate_evaluate_ticket(&ticket, quote_req.assurance)?;
                    Ok(Self::Local {
                        handle,
                        ticket,
                        provenance: outcome.provenance,
                        runner_key,
                    })
                }
            }
            ExecutionRoute::RemoteDirect(target) => {
                let (ticket, provenance) =
                    hellas_client::iroh::quote_tokens(runtime, target, quote_req).await?;
                validate_evaluate_ticket(&ticket, quote_req.assurance)?;
                let execute_transport =
                    hellas_client::iroh::execute_transport(runtime, target).await?;
                Ok(Self::RemoteDirect {
                    transport: execute_transport,
                    ticket,
                    provenance,
                    runner_key,
                })
            }
            ExecutionRoute::RemoteDiscovery {
                retries,
                provider_trust,
            } => {
                let (target, ticket, provenance) = hellas_client::iroh::discover_and_quote(
                    runtime.remote_registry()?,
                    quote_req,
                    *retries,
                    provider_trust,
                )
                .await?;
                validate_evaluate_ticket(&ticket, quote_req.assurance)?;
                let execute_transport =
                    hellas_client::iroh::execute_transport(runtime, &target).await?;
                Ok(Self::RemoteDirect {
                    transport: execute_transport,
                    ticket,
                    provenance,
                    runner_key,
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
            } => local_execute_stream(handle, ticket, runner_key).boxed(),
            PreparedRoute::RemoteDirect {
                transport,
                ticket,
                provenance: _,
                runner_key,
            } => remote_execute_stream(transport, ticket, runner_key).boxed(),
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
        let mut got_terminal = false;
        let input_commitment =
            hellas_client::evaluate_input_from_request_commitment(&request_commitment)?;
        let mut verifier = EvaluateChunkVerifier::new(input_commitment, assurance);
        while let Some(item) = events.next().await {
            let wire = item
                .map_err(|status: WireStatus| ExecutionError::wire("local execution stream failed", status))?;
            let event = convert_wire_event(wire, input_commitment, &mut verifier)?;
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

// ---------------------------------------------------------------------------
// Remote execute streams — dial Execute service via IrohTransport
// ---------------------------------------------------------------------------

fn remote_execute_stream(
    transport: IrohTransport,
    ticket: Ticket,
    runner_key: Arc<ProducerSigningKey>,
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
        let mut got_terminal = false;
        let input_commitment =
            hellas_client::evaluate_input_from_request_commitment(&request_commitment)?;
        let mut verifier = EvaluateChunkVerifier::new(input_commitment, assurance);
        while let Some(item) = wire.next().await {
            let event = convert_wire_event(
                item.map_err(|status: WireStatus| ExecutionError::wire("remote execute stream failed", status))?,
                input_commitment,
                &mut verifier,
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
        1 => Ok(StopReason::EndOfSequence),
        2 => Ok(StopReason::MaxNewTokens),
        other => Err(ExecutionError::EvaluateTranscript {
            source: hellas_rpc::evaluate::EvaluateProtocolError::UnknownStopReason(other),
        }),
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

        let mut verifier = EvaluateChunkVerifier::new(input, request.assurance);
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
                stop_reason: EvaluateStopReason::END_OF_SEQUENCE,
                text_artifact: Digest::from_bytes([4; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 2,
                },
                billable_units: 5,
            })
            .unwrap();
        let mut verifier = EvaluateChunkVerifier::new(input, request.assurance);
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
                stop_reason: StopReason::EndOfSequence,
                ..
            })
        ));
    }
}
