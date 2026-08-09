use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use crate::ExecutorError;
use async_trait::async_trait;
use hellas_models::{ChatMessage, ModelAssets, PreparedQuote, Reach};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::pb::courtesy::{
    EvaluateGenesisStart, EvaluateStart, GetArtifactRequest, GetArtifactResponse,
    ListModelsResponse, ModelInfo, ModelStatus, PutArtifactRequest, PutArtifactResponse,
    QuoteChatPromptRequest, QuoteChatPromptResponse, QuotePreparedTextRequest,
    QuotePreparedTextResponse, QuotePromptRequest, QuotePromptResponse, evaluate_start,
};
use hellas_rpc::pb::evaluate::EvaluateRequest as PbEvaluateRequest;
use hellas_rpc::pb::execute::{PublicKey as PbPublicKey, Ticket};
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::run_ticket::{public_key_from_pb, public_key_to_pb};
use hellas_rpc::spec::ModelSpec;
use hellas_rpc::{
    Assurance, Digest, Dtype, Evaluate, EvaluateRequest, OutputEventEnvelope, PublicKey,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::artifacts::{EvaluateArtifactStore, EvaluateArtifactStores};
use crate::executor::{ExecuteOutcome, ExecutorMessage, ProviderContext, TicketOutcome};
use crate::metrics::ExecutorMetrics;
use crate::scheme::{SchemeEngine, SchemeJob, SchemeRunContext};
use crate::state::{
    ExecutorState, Invocation, LocalModelStatus, ModelLocator, QUOTE_AMOUNT, QUOTE_TTL, QuoteKind,
    QuotePlan, QuoteRecord, StopReason, Termination, evaluate_request_to_pb, model_spec,
    quote_ticket, refusal_for, resolve_accept_dtypes,
};
use crate::worker::{
    EnqueueError, ExecuteJob, ExecuteWorker, WorkerCompletion, WorkerCompletionResult,
};

const PER_EXECUTION_CHANNEL_CAPACITY: usize = 64;

/// The opaque quote payload the executor core stores for an evaluate ticket.
#[derive(Clone)]
pub struct EvaluateJob {
    pub evaluate_request: EvaluateRequest,
    pub locator: ModelLocator,
    pub invocation: Invocation,
    pub model_id: String,
}

impl SchemeJob for EvaluateJob {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }

    fn clone_box(&self) -> Box<dyn SchemeJob> {
        Box::new(self.clone())
    }
}

impl crate::scheme::SchemeCompletion for WorkerCompletion {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

enum StartExecutionError {
    Busy(Box<ExecuteJob>),
    Closed,
}

pub struct EvaluateEngine {
    artifacts: EvaluateArtifactStores,
    supported_dtypes: Vec<Dtype>,
    models: HashMap<ModelLocator, LocalModelStatus>,
    completed: HashMap<[u8; 32], CompletedEvaluate>,
    worker: ExecuteWorker,
    pending_executions: VecDeque<ExecuteJob>,
    queue_capacity: usize,
    execute_policy: ExecutePolicy,
    metrics: Arc<ExecutorMetrics>,
    provider: ProviderContext,
}

#[derive(Clone)]
struct CompletedEvaluate {
    runner_public_key: PublicKey,
    assurance: Assurance,
    termination: Termination,
}

impl EvaluateEngine {
    pub fn new(
        artifacts: EvaluateArtifactStore,
        supported_dtypes: Vec<Dtype>,
        queue_capacity: usize,
        execute_policy: ExecutePolicy,
        metrics: Arc<ExecutorMetrics>,
        provider: ProviderContext,
        tx: mpsc::UnboundedSender<ExecutorMessage>,
    ) -> Self {
        Self {
            artifacts: EvaluateArtifactStores::new(artifacts),
            supported_dtypes,
            models: HashMap::new(),
            completed: HashMap::new(),
            worker: ExecuteWorker::spawn(tx),
            pending_executions: VecDeque::new(),
            queue_capacity,
            execute_policy,
            metrics,
            provider,
        }
    }

    fn preferred_dtype(&self) -> Dtype {
        self.supported_dtypes[0]
    }

    fn try_start_execution(&self, job: ExecuteJob) -> Result<(), StartExecutionError> {
        match self.worker.try_enqueue(job) {
            Ok(()) => Ok(()),
            Err(EnqueueError::Busy(job)) => Err(StartExecutionError::Busy(job)),
            Err(EnqueueError::Stopped(_job)) => Err(StartExecutionError::Closed),
        }
    }

    pub(super) async fn replay_completed(
        &self,
        request_commitment: [u8; 32],
        runner_public_key: &PublicKey,
        assurance: Assurance,
    ) -> Result<Option<ExecuteOutcome>, ExecutorError> {
        let Some(completed) = self.completed.get(&request_commitment) else {
            return Ok(None);
        };
        if completed.runner_public_key != *runner_public_key {
            return Err(ExecutorError::PolicyDenied(
                "run ticket signer is not authorized for this ticket".to_string(),
            ));
        }
        if completed.assurance != assurance {
            return Err(ExecutorError::InvalidQuoteRequest(
                "evaluate request assurance does not match ticket terms".to_string(),
            ));
        }
        let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
        sender
            .send(Ok(completed.termination.clone().into_pb()))
            .await
            .map_err(|_| ExecutorError::ChannelClosed)?;
        Ok(Some(ExecuteOutcome {
            provenance: ExecutionProvenance {
                commitment_id: request_commitment,
            },
            events: receiver,
        }))
    }

    fn dispatch_next_execution(&mut self) {
        while let Some(job) = self.pending_executions.pop_front() {
            if job.sender.is_closed() {
                tracing::debug!(
                    execution_id = %job.execution_id,
                    "dropping queued execution: consumer disconnected before dispatch"
                );
                continue;
            }
            match self.try_start_execution(job) {
                Ok(()) => return,
                Err(StartExecutionError::Busy(job)) => {
                    self.pending_executions.push_front(*job);
                    return;
                }
                Err(StartExecutionError::Closed) => {
                    warn!("failed to start queued execution: executor channel closed");
                }
            }
        }
    }

    async fn completed_evaluate_termination(
        &mut self,
        evaluate_request: &EvaluateRequest,
        invocation: &Invocation,
        stop_reason: StopReason,
        output_tokens: Vec<u32>,
        output_events: Vec<OutputEventEnvelope>,
    ) -> Result<(Termination, u64), ExecutorError> {
        let text_artifact = self
            .artifacts
            .for_retention(evaluate_request.retention())
            .record_completed_text(evaluate_request, invocation, &output_tokens)
            .await?;
        let input_units = invocation.input_ids.len() as u64;
        let output_units = output_tokens.len() as u64;
        let usage = EvaluateUsage {
            input_units,
            output_units,
        };
        let billable_units = usage.billable_units().map_err(|err| {
            ExecutorError::WeightsError(format!("evaluate billing failed: {err}"))
        })?;
        let terminal = EvaluateTerminal {
            final_position: output_units,
            stop_reason: evaluate_stop_reason(stop_reason),
            text_artifact,
            usage,
            billable_units,
        };
        let output_events = EvaluateOutputTranscriptBuilder::resume_verified(
            input_commitment(evaluate_request),
            evaluate_request.assurance,
            &self.provider.producer_key,
            output_events,
        )
        .map_err(|err| ExecutorError::WeightsError(format!("evaluate transcript failed: {err}")))?
        .finish(terminal)
        .map_err(|err| ExecutorError::WeightsError(format!("evaluate transcript failed: {err}")))?;
        Ok((Termination::Completed { output_events }, billable_units))
    }

    fn resolve_accept_dtypes(&self, prefs: &[String]) -> Result<Dtype, ExecutorError> {
        resolve_accept_dtypes(prefs, &self.supported_dtypes)
    }
}

fn evaluate_stop_reason(stop_reason: StopReason) -> EvaluateStopReason {
    match stop_reason {
        StopReason::EndOfSequence => EvaluateStopReason::END_OF_SEQUENCE,
        StopReason::MaxNewTokens => EvaluateStopReason::MAX_OUTPUT,
        StopReason::Cancelled => unreachable!("cancellation is not a success terminal"),
    }
}

#[async_trait]
impl SchemeEngine for EvaluateEngine {
    async fn quote_evaluate(
        &mut self,
        store: &mut ExecutorState,
        request: PbEvaluateRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        store.prune_expired_quotes(Instant::now());
        let evaluate_request = crate::state::evaluate_request_from_pb(request)?;
        ensure_supported_assurance(evaluate_request.assurance, self.provider.assurance)?;
        let resolved = self
            .artifacts
            .for_retention(evaluate_request.retention())
            .resolve_evaluate_request(evaluate_request.clone())
            .await?;
        if !self.supported_dtypes.contains(&resolved.locator.dtype) {
            return Err(ExecutorError::DtypeNotSupported {
                request: resolved.locator.dtype,
                supported: self.supported_dtypes.clone(),
            });
        }
        if !self.execute_policy.allows_execute(
            &resolved.locator.spec(),
            Some(resolved.locator.model_id.as_str()),
        ) {
            return Err(ExecutorError::PolicyDenied(format!(
                "execute policy denied model {}",
                resolved.locator.spec()
            )));
        }
        // The other way in. This quote does not build a manifest — the
        // model comes from a stored artifact, and an artifact can be put
        // here over the wire — so nothing above has yet established that
        // the model is on this disk. Without this, a ticket issued here
        // would be redeemed later by a worker whose loader downloads
        // whatever it does not find: the same hole, one round trip
        // further away.
        let spec = resolved.locator.spec();
        hellas_models::require_program_files(&spec).map_err(|err| refusal_for(&spec, err))?;
        let request_commitment = Evaluate::commit_request(&evaluate_request);
        let (terms, ticket) = quote_ticket(
            request_commitment,
            self.provider.genesis.as_slice(),
            evaluate_request.assurance,
        )?;
        let model_id = resolved.locator.spec();
        let request_commitment_bytes = store.create_quote(QuoteRecord {
            terms,
            expires_at: Instant::now() + QUOTE_TTL,
            model_id: model_id.clone(),
            runner_public_key: evaluate_request.runner_public_key,
            kind: QuoteKind::Scheme(Box::new(EvaluateJob {
                evaluate_request,
                locator: resolved.locator,
                invocation: resolved.invocation,
                model_id,
            })),
        });

        Ok(TicketOutcome {
            response: ticket,
            provenance: ExecutionProvenance {
                commitment_id: request_commitment_bytes,
            },
        })
    }

    async fn quote_prepared_text(
        &mut self,
        store: &mut ExecutorState,
        request: QuotePreparedTextRequest,
    ) -> Result<TicketOutcome<QuotePreparedTextResponse>, ExecutorError> {
        let total_start = Instant::now();
        store.prune_expired_quotes(Instant::now());
        // Off the actor task: building a plan resolves and may download
        // every model file, then reads each one to hash it. Run inline
        // it pins a runtime worker thread for the whole of that, so a
        // single quote degrades every other connection the process is
        // serving. (It does not remove the executor's own serialization
        // — the actor still awaits this before its next message.)
        let supported_dtypes = self.supported_dtypes.clone();
        let execute_policy = self.execute_policy.clone();
        let plan = tokio::task::spawn_blocking(move || {
            QuotePlan::from_prepared_text_request(request, &supported_dtypes, &execute_policy)
        })
        .await
        .map_err(|err| {
            ExecutorError::WeightsError(format!("quote planning task failed: {err}"))
        })??;
        ensure_supported_assurance(plan.assurance, self.provider.assurance)?;

        let resolved = self
            .artifacts
            .for_retention(plan.retention)
            .record_prepared_text(&plan)
            .await?;
        let evaluate_request = resolved.evaluate_request.clone();
        let evaluate_request_pb = evaluate_request_to_pb(&evaluate_request);
        let request_commitment = Evaluate::commit_request(&evaluate_request);
        let (terms, ticket) = quote_ticket(
            request_commitment,
            self.provider.genesis.as_slice(),
            evaluate_request.assurance,
        )?;
        let commitment_id = request_commitment.digest();
        let model_id = plan.locator.spec();
        let prompt_tokens = plan.invocation.input_ids.len() as u32;
        let dtype_wire = plan.locator.dtype.as_wire().to_string();
        let request_commitment_bytes = store.create_quote(QuoteRecord {
            terms,
            expires_at: Instant::now() + QUOTE_TTL,
            model_id: model_id.clone(),
            runner_public_key: evaluate_request.runner_public_key,
            kind: QuoteKind::Scheme(Box::new(EvaluateJob {
                evaluate_request,
                locator: resolved.locator,
                invocation: resolved.invocation,
                model_id,
            })),
        });

        info!(
            request_commitment = %hex32(&request_commitment_bytes),
            commitment_id = %commitment_id,
            prompt_tokens,
            amount = QUOTE_AMOUNT,
            total_ms = total_start.elapsed().as_millis(),
            "quoted prepared evaluate text execution"
        );

        Ok(TicketOutcome {
            response: QuotePreparedTextResponse {
                ticket: Some(ticket),
                prompt_tokens,
                dtype: dtype_wire,
                evaluate_request: Some(evaluate_request_pb),
            },
            provenance: ExecutionProvenance {
                commitment_id: *commitment_id.as_bytes(),
            },
        })
    }

    async fn quote_prompt(
        &mut self,
        store: &mut ExecutorState,
        request: QuotePromptRequest,
    ) -> Result<TicketOutcome<QuotePromptResponse>, ExecutorError> {
        let dtype = self.resolve_accept_dtypes(&request.accept_dtypes)?;
        let assets = load_assets(
            &request.huggingface_model_id,
            &request.huggingface_revision,
            dtype,
        )?;
        let prepared = assets.prepare_plain(&request.prompt)?;
        let prompt_tokens = prepared.input_ids.len() as u32;
        let runner_public_key = parse_runner_public_key(request.runner_public_key)?;
        let retention = hellas_rpc::Retention::from_retain(request.retain.unwrap_or(true));
        let quote = assets.prepare_quote(&prepared);
        let prepared_request = quote_prepared_text_request(
            quote,
            request.max_new_tokens,
            dtype.as_wire().to_string(),
            &runner_public_key,
            request.assurance,
            retention,
        );
        let inner = self.quote_prepared_text(store, prepared_request).await?;

        Ok(TicketOutcome {
            response: QuotePromptResponse {
                ticket: inner.response.ticket,
                prompt_tokens,
                dtype: inner.response.dtype,
                evaluate_request: inner.response.evaluate_request,
            },
            provenance: inner.provenance,
        })
    }

    async fn quote_chat_prompt(
        &mut self,
        store: &mut ExecutorState,
        request: QuoteChatPromptRequest,
    ) -> Result<TicketOutcome<QuoteChatPromptResponse>, ExecutorError> {
        let dtype = self.resolve_accept_dtypes(&request.accept_dtypes)?;
        let assets = load_assets(
            &request.huggingface_model_id,
            &request.huggingface_revision,
            dtype,
        )?;

        let mut messages = Vec::new();
        if !request.system_prompt.is_empty() {
            messages.push(ChatMessage::system(&request.system_prompt));
        }
        for m in &request.messages {
            let msg = match m.role.as_str() {
                "assistant" => ChatMessage::assistant(&m.content),
                _ => ChatMessage::user(&m.content),
            };
            messages.push(msg);
        }
        let prepared = assets.prepare_chat(&messages)?;
        let prompt_tokens = prepared.input_ids.len() as u32;
        let runner_public_key = parse_runner_public_key(request.runner_public_key)?;
        let retention = hellas_rpc::Retention::from_retain(request.retain.unwrap_or(true));
        let quote = assets.prepare_quote(&prepared);
        let prepared_request = quote_prepared_text_request(
            quote,
            request.max_new_tokens,
            dtype.as_wire().to_string(),
            &runner_public_key,
            request.assurance,
            retention,
        );
        let inner = self.quote_prepared_text(store, prepared_request).await?;

        Ok(TicketOutcome {
            response: QuoteChatPromptResponse {
                ticket: inner.response.ticket,
                prompt_tokens,
                dtype: inner.response.dtype,
                evaluate_request: inner.response.evaluate_request,
            },
            provenance: inner.provenance,
        })
    }

    async fn materialize_model(&mut self, model: String) -> Result<(), ExecutorError> {
        let spec = ModelSpec::parse(&model).map_err(hellas_models::ModelAssetsError::from)?;
        let locator = ModelLocator {
            model_id: spec.id().to_string(),
            revision: spec.revision().to_string(),
            dtype: self.preferred_dtype(),
        };
        let key = locator.clone();
        match ModelAssets::load(&locator.spec(), locator.dtype, Reach::Download).and_then(
            |assets| hellas_models::materialize_program_files(&key.spec()).map(|()| assets),
        ) {
            Ok(_) => {
                self.models.insert(key.clone(), LocalModelStatus::Ready);
                info!(
                    model = %key.model_id,
                    requested_revision = %key.revision,
                    dtype = %key.dtype,
                    "materialized model"
                );
                Ok(())
            }
            Err(err) => {
                self.models
                    .insert(key.clone(), LocalModelStatus::Failed(err.to_string()));
                Err(err.into())
            }
        }
    }

    async fn put_artifact(
        &mut self,
        request: PutArtifactRequest,
    ) -> Result<PutArtifactResponse, ExecutorError> {
        let digest = self
            .artifacts
            .retained()
            .publish_canonical_bytes(request.canonical_artifact)
            .await?;
        Ok(PutArtifactResponse {
            digest: digest.as_bytes().to_vec(),
        })
    }

    async fn get_artifact(
        &mut self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, ExecutorError> {
        // Courtesy only exposes the retained store. Ephemeral prompt and
        // token artifacts live in the separate memory store and are never
        // reachable through this API.
        let canonical_artifact = self
            .artifacts
            .retained()
            .get_canonical_bytes(digest_from_slice(&request.digest, "digest")?)
            .await?;
        Ok(GetArtifactResponse { canonical_artifact })
    }

    async fn list_models(&self) -> ListModelsResponse {
        let models = self
            .models
            .iter()
            .map(|(locator, status)| {
                let (proto_status, error) = match status {
                    LocalModelStatus::Ready => (ModelStatus::Ready, String::new()),
                    LocalModelStatus::Failed(err) => (ModelStatus::Failed, err.clone()),
                };
                ModelInfo {
                    model_id: locator.model_id.clone(),
                    revision: locator.revision.clone(),
                    status: proto_status.into(),
                    error,
                }
            })
            .collect();
        ListModelsResponse { models }
    }

    fn start(
        &mut self,
        job: Box<dyn SchemeJob>,
        ctx: SchemeRunContext,
    ) -> Result<ExecuteOutcome, ExecutorError> {
        let job = job
            .into_any()
            .downcast::<EvaluateJob>()
            .map_err(|_| ExecutorError::InvalidQuoteRequest("scheme job type mismatch".into()))?;
        let EvaluateJob {
            evaluate_request,
            locator,
            invocation,
            model_id,
        } = *job;
        let stat_prompt = invocation.input_ids.len() as u64;
        let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
        let execute_job = ExecuteJob {
            execution_id: ctx.execution_id.clone(),
            request_commitment: ctx.request_commitment,
            model_id: model_id.clone(),
            evaluate_request,
            locator,
            invocation,
            stream_batch_size: 1,
            accepted_at: Instant::now(),
            cancel: CancellationToken::new(),
            sender,
            producer_key: self.provider.producer_key.clone(),
        };

        let queued = match self.try_start_execution(execute_job) {
            Ok(()) => false,
            Err(StartExecutionError::Busy(job)) => {
                if self.pending_executions.len() >= self.queue_capacity {
                    return Err(ExecutorError::QueueFull {
                        capacity: self.queue_capacity,
                    });
                }
                self.pending_executions.push_back(*job);
                true
            }
            Err(StartExecutionError::Closed) => return Err(ExecutorError::ChannelClosed),
        };

        self.metrics.record_execution_started(
            &model_id,
            stat_prompt,
            /* cached_prompt= */ 0,
            /* cached_output= */ 0,
            /* prefill= */ stat_prompt,
        );

        info!(
            execution_id = %ctx.execution_id,
            request_commitment = %hex32(&ctx.request_commitment),
            queued,
            queue_len = self.pending_executions.len(),
            "accepted evaluate execution"
        );

        Ok(ExecuteOutcome {
            provenance: ExecutionProvenance {
                commitment_id: ctx.request_commitment,
            },
            events: receiver,
        })
    }

    async fn replay_completed(
        &self,
        request_commitment: [u8; 32],
        runner_public_key: &PublicKey,
        assurance: Assurance,
    ) -> Result<Option<ExecuteOutcome>, ExecutorError> {
        EvaluateEngine::replay_completed(self, request_commitment, runner_public_key, assurance)
            .await
    }

    async fn on_completion(&mut self, completion: Box<dyn crate::scheme::SchemeCompletion>) {
        let completion = match completion.into_any().downcast::<WorkerCompletion>() {
            Ok(completion) => *completion,
            Err(_) => {
                warn!("evaluate engine received a non-evaluate scheme completion");
                return;
            }
        };
        let WorkerCompletion {
            execution_id,
            request_commitment,
            model_id,
            evaluate_request,
            invocation,
            sender,
            result,
        } = completion;

        let generated = result.position();
        let (termination, billable_units) = match result {
            WorkerCompletionResult::Completed {
                stop_reason,
                output_tokens,
                output_events,
            } => {
                if stop_reason == StopReason::Cancelled {
                    (
                        Termination::Failed {
                            position: generated,
                            error: "execution cancelled".to_string(),
                        },
                        None,
                    )
                } else {
                    match self
                        .completed_evaluate_termination(
                            &evaluate_request,
                            &invocation,
                            stop_reason,
                            output_tokens,
                            output_events,
                        )
                        .await
                    {
                        Ok((termination, billable_units)) => (termination, Some(billable_units)),
                        Err(err) => {
                            let msg = format!("{err:#}");
                            warn!(
                                %execution_id,
                                "execute worker failed while recording/signing output transcript"
                            );
                            (
                                Termination::Failed {
                                    position: generated,
                                    error: msg,
                                },
                                None,
                            )
                        }
                    }
                }
            }
            WorkerCompletionResult::Failed { position, error } => {
                (Termination::Failed { position, error }, None)
            }
        };

        if let Some(billable_units) = billable_units {
            self.metrics
                .record_execution_completed(&model_id, billable_units);
            self.completed.insert(
                request_commitment,
                CompletedEvaluate {
                    runner_public_key: evaluate_request.runner_public_key,
                    assurance: evaluate_request.assurance,
                    termination: termination.clone(),
                },
            );
        } else {
            self.metrics.record_execution_failed(&model_id, generated);
        }

        let _ = sender.send(Ok(termination.into_pb())).await;
        self.dispatch_next_execution();
    }
}

/// Assemble the wire `QuotePreparedTextRequest` from the model-domain
/// [`PreparedQuote`] plus the protocol framing (genesis start marker,
/// runner key) the model layer deliberately leaves to callers.
fn quote_prepared_text_request(
    quote: PreparedQuote,
    max_new_tokens: u32,
    accept_dtype: String,
    runner_public_key: &hellas_rpc::PublicKey,
    assurance: i32,
    retention: hellas_rpc::Retention,
) -> QuotePreparedTextRequest {
    QuotePreparedTextRequest {
        huggingface_model_id: quote.huggingface_model_id,
        huggingface_revision: quote.huggingface_revision,
        prompt_token_ids: quote.prompt_token_ids,
        max_new_tokens,
        stop_token_ids: quote.stop_token_ids,
        start: Some(EvaluateStart {
            kind: Some(evaluate_start::Kind::Genesis(EvaluateGenesisStart {})),
        }),
        accept_dtypes: vec![accept_dtype],
        runner_public_key: Some(public_key_to_pb(runner_public_key)),
        assurance,
        retain: Some(retention.should_retain()),
    }
}

fn ensure_supported_assurance(
    request: Assurance,
    provider: Assurance,
) -> Result<(), ExecutorError> {
    if request == provider {
        Ok(())
    } else {
        Err(ExecutorError::InvalidQuoteRequest(
            "request assurance does not match provider assurance".to_string(),
        ))
    }
}

fn parse_runner_public_key(key: Option<PbPublicKey>) -> Result<PublicKey, ExecutorError> {
    key.ok_or_else(|| ExecutorError::InvalidQuoteRequest("missing runner_public_key".to_string()))
        .and_then(|key| {
            public_key_from_pb(key).map_err(|err| {
                ExecutorError::InvalidQuoteRequest(format!("invalid runner_public_key: {err}"))
            })
        })
}

fn digest_from_slice(bytes: &[u8], field: &str) -> Result<Digest, ExecutorError> {
    crate::chain::fixed::<32>(field, bytes)
        .map(Digest::from_bytes)
        .map_err(ExecutorError::InvalidQuoteRequest)
}

/// Tokenizer and config for a quote, from what this node already holds.
///
/// `quote_prompt` and `quote_chat_prompt` are reachable by any peer that
/// can dial us and take a model id from the request, so they get the
/// same local reach the manifest does. A repo's `tokenizer.json` is
/// small only because its author chose to make it small.
fn load_assets(model_id: &str, revision: &str, dtype: Dtype) -> Result<ModelAssets, ExecutorError> {
    let spec = model_spec(model_id, revision);
    ModelAssets::load(&spec, dtype, Reach::Local).map_err(|err| refusal_for(&spec, err))
}

fn hex32(bytes: &[u8; 32]) -> String {
    Digest::from_bytes(*bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::ProducerSigningKey;

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
    }

    fn test_engine(producer_key: Arc<ProducerSigningKey>) -> EvaluateEngine {
        let (tx, _rx) = mpsc::unbounded_channel();
        EvaluateEngine::new(
            EvaluateArtifactStore::memory(),
            vec![Dtype::F32],
            1,
            ExecutePolicy::Eager,
            Arc::new(ExecutorMetrics::default()),
            ProviderContext {
                producer_key,
                genesis: Arc::new(b"genesis".to_vec()),
                assurance: Assurance::ProducerSigned,
            },
            tx,
        )
    }

    /// The vulnerability, at the door it came in by: an unauthenticated
    /// peer names a model and the node must refuse without fetching it.
    ///
    /// `ExecutePolicy::Eager` is the default and permits everything, so
    /// the policy is deliberately left permissive here — what refuses
    /// this quote is that the node does not hold the model, and a quote
    /// may not make it hold one.
    ///
    /// The error variant is the assertion that carries the weight. A
    /// quote path that downloaded would report a fetch failure (or, with
    /// a real repository and a real network, would succeed after paying
    /// for it); only a path that never asks the hub can answer
    /// `ModelNotMaterialized`.
    #[tokio::test]
    async fn quoting_an_unmaterialized_model_is_refused_without_fetching_it() {
        let mut engine = test_engine(Arc::new(key(2)));
        let mut store = ExecutorState::new();
        let runner = key(3).public_key();

        let err = engine
            .quote_prepared_text(
                &mut store,
                QuotePreparedTextRequest {
                    huggingface_model_id: "hellas-test/not-on-this-node".to_string(),
                    // Pinned, and to a commit no cache holds: nothing but
                    // a download could resolve this.
                    huggingface_revision: "c1899de289a04d12100db370d81485cdf75e47ca".to_string(),
                    prompt_token_ids: vec![1, 2, 3],
                    max_new_tokens: 4,
                    stop_token_ids: Vec::new(),
                    start: Some(EvaluateStart {
                        kind: Some(evaluate_start::Kind::Genesis(EvaluateGenesisStart {})),
                    }),
                    accept_dtypes: vec![Dtype::F32.as_wire().to_string()],
                    runner_public_key: Some(public_key_to_pb(&runner)),
                    assurance: Assurance::ProducerSigned.to_byte().into(),
                    retain: Some(false),
                },
            )
            .await
            .expect_err("a model this node does not hold must not be quotable");

        match &err {
            ExecutorError::ModelNotMaterialized(message) => {
                assert!(
                    message.contains("hellas-test/not-on-this-node"),
                    "{message}"
                );
            }
            other => panic!("expected a not-materialized refusal, got {other:?}"),
        }
        // Answerable later, not forbidden: a client can ask the operator
        // for the model and come back.
        assert_eq!(
            hellas_wire::WireStatus::from(err).code,
            hellas_wire::WireCode::FailedPrecondition,
        );
        // A refused quote leaves nothing behind to be run against.
        assert!(
            store
                .get_quote(&[0; 32], Instant::now())
                .is_err_and(|err| matches!(err, crate::StateError::QuoteNotFound(_)))
        );
    }

    /// The same door, with a name instead of a model.
    ///
    /// A revision reaches `hf-hub`'s `refs/` lookup, which reads the file
    /// it names; an absolute one replaces the cache path outright. So the
    /// quote request below is not a request for a model at all — it is a
    /// request that this node read `/etc/passwd` and tell the caller
    /// something about it.
    ///
    /// `InvalidArgument` rather than `FailedPrecondition` is the
    /// assertion that separates this from the test above: a node that
    /// merely did not hold the model would say "not here yet", which is
    /// an invitation to try again with a different path.
    #[tokio::test]
    async fn quoting_a_revision_that_is_a_path_is_refused_as_a_bad_name() {
        for revision in ["/etc/passwd", "../../..", "refs/heads/../../../etc"] {
            let mut engine = test_engine(Arc::new(key(2)));
            let mut store = ExecutorState::new();
            let runner = key(3).public_key();

            let err = engine
                .quote_prepared_text(
                    &mut store,
                    QuotePreparedTextRequest {
                        huggingface_model_id: "hellas-test/not-on-this-node".to_string(),
                        huggingface_revision: revision.to_string(),
                        prompt_token_ids: vec![1, 2, 3],
                        max_new_tokens: 4,
                        stop_token_ids: Vec::new(),
                        start: Some(EvaluateStart {
                            kind: Some(evaluate_start::Kind::Genesis(EvaluateGenesisStart {})),
                        }),
                        accept_dtypes: vec![Dtype::F32.as_wire().to_string()],
                        runner_public_key: Some(public_key_to_pb(&runner)),
                        assurance: Assurance::ProducerSigned.to_byte().into(),
                        retain: Some(false),
                    },
                )
                .await
                .expect_err("a revision that is a path must not be resolved");

            assert!(
                matches!(
                    err,
                    ExecutorError::ModelAssets(hellas_models::ModelAssetsError::Spec(_)),
                ),
                "{revision:?} was refused, but not as a bad name: {err:?}",
            );
            assert_eq!(
                hellas_wire::WireStatus::from(err).code,
                hellas_wire::WireCode::InvalidArgument,
            );
            // A refused quote leaves nothing behind to be run against.
            assert!(
                store
                    .get_quote(&[0; 32], Instant::now())
                    .is_err_and(|err| matches!(err, crate::StateError::QuoteNotFound(_)))
            );
        }
    }

    /// The same door, one round trip further away: the evaluate quote
    /// takes its model from a stored artifact rather than from the
    /// request, and artifacts can be put here over the wire. A ticket
    /// issued for a model this node does not hold would be redeemed by a
    /// worker that downloads it, so the refusal has to happen here too.
    #[tokio::test]
    async fn quoting_an_artifact_bound_to_an_unmaterialized_model_is_refused() {
        let mut engine = test_engine(Arc::new(key(2)));
        let mut store = ExecutorState::new();
        let plan = QuotePlan {
            locator: ModelLocator {
                model_id: "hellas-test/not-on-this-node".to_string(),
                revision: "c1899de289a04d12100db370d81485cdf75e47ca".to_string(),
                dtype: Dtype::F32,
            },
            execution_environment: hellas_rpc::ContentId::from_bytes([9; 32]),
            invocation: Invocation {
                input_ids: vec![1, 2, 3],
                max_new_tokens: 8,
                stop_token_ids: Vec::new(),
            },
            initial_artifact_id: None,
            runner_public_key: key(3).public_key(),
            assurance: Assurance::ProducerSigned,
            retention: hellas_rpc::Retention::Retain,
        };
        let recorded = engine
            .artifacts
            .for_retention(plan.retention)
            .record_prepared_text(&plan)
            .await
            .expect("record the prepared text an artifact quote resolves through");

        let err = engine
            .quote_evaluate(
                &mut store,
                evaluate_request_to_pb(&recorded.evaluate_request),
            )
            .await
            .expect_err("a ticket must not be issued for a model this node does not hold");

        match &err {
            ExecutorError::ModelNotMaterialized(message) => {
                assert!(
                    message.contains("hellas-test/not-on-this-node"),
                    "{message}"
                );
            }
            other => panic!("expected a not-materialized refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn replay_completed_returns_stored_evaluate_transcript() {
        let producer = Arc::new(key(2));
        let runner = key(3).public_key();
        let mut engine = test_engine(producer.clone());
        let request_commitment = [7; 32];
        let input =
            hellas_rpc::InputCommitment::from_digest(Digest::from_bytes(request_commitment));
        let mut builder =
            EvaluateOutputTranscriptBuilder::new(input, Assurance::ProducerSigned, &producer);
        builder.push_token_delta(vec![10]).unwrap();
        let output_events = builder
            .finish(EvaluateTerminal {
                final_position: 1,
                stop_reason: EvaluateStopReason::END_OF_SEQUENCE,
                text_artifact: Digest::from_bytes([8; 32]),
                usage: EvaluateUsage {
                    input_units: 4,
                    output_units: 1,
                },
                billable_units: 5,
            })
            .unwrap();
        let termination = Termination::Completed { output_events };
        let expected = termination.clone().into_pb();
        engine.completed.insert(
            request_commitment,
            CompletedEvaluate {
                runner_public_key: runner,
                assurance: Assurance::ProducerSigned,
                termination,
            },
        );

        let mut outcome = engine
            .replay_completed(request_commitment, &runner, Assurance::ProducerSigned)
            .await
            .unwrap()
            .expect("stored completion should replay");
        let event = outcome
            .events
            .recv()
            .await
            .expect("replay emits terminal event")
            .unwrap();
        assert_eq!(event, expected);
        assert!(outcome.events.is_closed());
    }

    #[tokio::test]
    async fn replay_completed_rejects_wrong_runner_key() {
        let producer = Arc::new(key(2));
        let runner = key(3).public_key();
        let wrong_runner = key(4).public_key();
        let mut engine = test_engine(producer);
        let request_commitment = [7; 32];
        engine.completed.insert(
            request_commitment,
            CompletedEvaluate {
                runner_public_key: runner,
                assurance: Assurance::ProducerSigned,
                termination: Termination::Failed {
                    position: 0,
                    error: "not replayed".to_string(),
                },
            },
        );

        let err = engine
            .replay_completed(request_commitment, &wrong_runner, Assurance::ProducerSigned)
            .await
            .unwrap_err();
        assert!(matches!(err, ExecutorError::PolicyDenied(_)));
    }

    #[tokio::test]
    async fn replay_completed_rejects_wrong_assurance() {
        let producer = Arc::new(key(2));
        let runner = key(3).public_key();
        let mut engine = test_engine(producer);
        let request_commitment = [7; 32];
        engine.completed.insert(
            request_commitment,
            CompletedEvaluate {
                runner_public_key: runner,
                assurance: Assurance::ProducerSigned,
                termination: Termination::Failed {
                    position: 0,
                    error: "not replayed".to_string(),
                },
            },
        );

        let err = engine
            .replay_completed(request_commitment, &runner, Assurance::AppleAppAttest)
            .await
            .unwrap_err();
        assert!(matches!(err, ExecutorError::InvalidQuoteRequest(_)));
    }
}
