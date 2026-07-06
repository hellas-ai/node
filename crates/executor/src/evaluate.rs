use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chatgrad::types;
use hellas_rpc::ExecutorError;
use hellas_rpc::model::ModelAssets;
use hellas_rpc::pb::courtesy::{
    GetArtifactRequest, GetArtifactResponse, ListModelsResponse, ModelInfo, ModelStatus,
    PutArtifactRequest, PutArtifactResponse, QuoteChatPromptRequest, QuoteChatPromptResponse,
    QuotePreparedTextRequest, QuotePreparedTextResponse, QuotePromptRequest, QuotePromptResponse,
};
use hellas_rpc::pb::evaluate::EvaluateRequest as PbEvaluateRequest;
use hellas_rpc::pb::execute::{PublicKey as PbPublicKey, Ticket};
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::run_ticket::public_key_from_pb;
use hellas_rpc::spec::ModelSpec;
use hellas_rpc::{
    CommitmentScheme, Digest, Dtype, Evaluate, EvaluateOutput, EvaluateRequest, ProducerSigningKey,
    PublicKey, SignedReceipt, canonical_dag_cbor,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::artifacts::EvaluateArtifactStore;
use crate::executor::{ExecuteOutcome, ExecutorMessage, TicketOutcome};
use crate::metrics::ExecutorMetrics;
use crate::scheme::{SchemeEngine, SchemeJob, SchemeRunContext};
use crate::state::{
    ExecutorState, Invocation, LocalModelStatus, ModelLocator, QuoteKind, QuotePlan, QuoteRecord,
    StopReason, Termination, evaluate_request_to_pb, model_spec, resolve_accept_dtypes,
};
use crate::worker::{
    EnqueueError, ExecuteJob, ExecuteWorker, WorkerCompletion, WorkerCompletionResult,
};

const STATIC_QUOTE_AMOUNT: u64 = 1000;
const QUOTE_TTL: Duration = Duration::from_secs(30);
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
    artifacts: EvaluateArtifactStore,
    supported_dtypes: Vec<Dtype>,
    models: HashMap<ModelLocator, LocalModelStatus>,
    worker: ExecuteWorker,
    pending_executions: VecDeque<ExecuteJob>,
    queue_capacity: usize,
    execute_policy: ExecutePolicy,
    metrics: Arc<ExecutorMetrics>,
    producer_key: Arc<ProducerSigningKey>,
}

impl EvaluateEngine {
    pub fn new(
        artifacts: EvaluateArtifactStore,
        supported_dtypes: Vec<Dtype>,
        queue_capacity: usize,
        execute_policy: ExecutePolicy,
        metrics: Arc<ExecutorMetrics>,
        producer_key: Arc<ProducerSigningKey>,
        tx: mpsc::UnboundedSender<ExecutorMessage>,
    ) -> Self {
        Self {
            artifacts,
            supported_dtypes,
            models: HashMap::new(),
            worker: ExecuteWorker::spawn(tx),
            pending_executions: VecDeque::new(),
            queue_capacity,
            execute_policy,
            metrics,
            producer_key,
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
    ) -> Result<Termination, ExecutorError> {
        let text_artifact = self
            .artifacts
            .record_completed_text(evaluate_request, invocation, &output_tokens)
            .await?;
        let evaluate_output = EvaluateOutput { text_artifact };
        let receipt =
            SignedReceipt::sign::<Evaluate>(evaluate_request, &evaluate_output, &self.producer_key)
                .map_err(|err| {
                    ExecutorError::WeightsError(format!("receipt signing failed: {err}"))
                })?;
        let receipt_dag_cbor = canonical_dag_cbor(&receipt).map_err(|err| {
            ExecutorError::WeightsError(format!("receipt encoding failed: {err}"))
        })?;
        Ok(Termination::Completed {
            stop_reason,
            output_tokens,
            receipt_dag_cbor,
        })
    }

    fn resolve_accept_dtypes(&self, prefs: &[String]) -> Result<Dtype, ExecutorError> {
        resolve_accept_dtypes(prefs, &self.supported_dtypes)
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
        let resolved = self
            .artifacts
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
        let request_commitment = Evaluate::commit_request(&evaluate_request);
        let model_id = resolved.locator.spec();
        let request_commitment_bytes = store.create_quote(QuoteRecord {
            request_commitment,
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
            response: Ticket {
                request_commitment: request_commitment_bytes.to_vec(),
                amount: STATIC_QUOTE_AMOUNT,
                ttl_ms: QUOTE_TTL.as_millis() as u64,
            },
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
        let plan = QuotePlan::from_prepared_text_request(request, &self.supported_dtypes)?;

        if !self
            .execute_policy
            .allows_execute(&plan.locator.spec(), Some(plan.locator.model_id.as_str()))
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "execute policy denied model {}",
                plan.locator.spec()
            )));
        }

        let resolved = self.artifacts.record_prepared_text(&plan).await?;
        let evaluate_request = resolved.evaluate_request.clone();
        let evaluate_request_pb = evaluate_request_to_pb(&evaluate_request);
        let request_commitment = Evaluate::commit_request(&evaluate_request);
        let commitment_id = request_commitment.digest();
        let model_id = plan.locator.spec();
        let prompt_tokens = plan.invocation.input_ids.len() as u32;
        let dtype_wire = plan.locator.dtype.as_wire().to_string();
        let request_commitment_bytes = store.create_quote(QuoteRecord {
            request_commitment,
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
            amount = STATIC_QUOTE_AMOUNT,
            total_ms = total_start.elapsed().as_millis(),
            "quoted prepared evaluate text execution"
        );

        Ok(TicketOutcome {
            response: QuotePreparedTextResponse {
                ticket: Some(Ticket {
                    request_commitment: request_commitment_bytes.to_vec(),
                    amount: STATIC_QUOTE_AMOUNT,
                    ttl_ms: QUOTE_TTL.as_millis() as u64,
                }),
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
        let mut prepared_request = assets.build_quote_prepared_text_request(
            &prepared,
            request.max_new_tokens,
            &runner_public_key,
        )?;
        prepared_request.accept_dtypes = vec![dtype.as_wire().to_string()];
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

        let mut messages: Vec<types::Message> = Vec::new();
        if !request.system_prompt.is_empty() {
            messages.push(types::Message::openai(types::openai::ChatMessage::system(
                &request.system_prompt,
            )));
        }
        for m in &request.messages {
            let msg = match m.role.as_str() {
                "assistant" => types::openai::ChatMessage::assistant(&m.content),
                _ => types::openai::ChatMessage::user(&m.content),
            };
            messages.push(types::Message::openai(msg));
        }
        let prepared = assets.prepare_chat(&messages)?;
        let prompt_tokens = prepared.input_ids.len() as u32;
        let runner_public_key = parse_runner_public_key(request.runner_public_key)?;
        let mut prepared_request = assets.build_quote_prepared_text_request(
            &prepared,
            request.max_new_tokens,
            &runner_public_key,
        )?;
        prepared_request.accept_dtypes = vec![dtype.as_wire().to_string()];
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

    async fn load_model_metadata(&mut self, model: String) -> Result<(), ExecutorError> {
        let spec = ModelSpec::parse(&model).map_err(hellas_rpc::ModelAssetsError::from)?;
        let locator = ModelLocator {
            model_id: spec.id,
            revision: spec.revision,
            dtype: self.preferred_dtype(),
        };
        let key = locator.clone();
        match ModelAssets::load(&locator.spec(), locator.dtype) {
            Ok(_) => {
                self.models.insert(key.clone(), LocalModelStatus::Ready);
                info!(
                    model = %key.model_id,
                    requested_revision = %key.revision,
                    dtype = %key.dtype,
                    "loaded model metadata"
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
        let canonical_artifact = self
            .artifacts
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
            model_id: model_id.clone(),
            evaluate_request,
            locator,
            invocation,
            stream_batch_size: 1,
            accepted_at: Instant::now(),
            cancel: CancellationToken::new(),
            sender,
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
            model_id,
            evaluate_request,
            invocation,
            sender,
            result,
        } = completion;

        let generated = result.position();
        let termination = match result {
            WorkerCompletionResult::Completed {
                stop_reason,
                output_tokens,
            } => {
                match self
                    .completed_evaluate_termination(
                        &evaluate_request,
                        &invocation,
                        stop_reason,
                        output_tokens,
                    )
                    .await
                {
                    Ok(termination) => termination,
                    Err(err) => {
                        let msg = format!("{err:#}");
                        warn!(
                            "execute worker job {execution_id} failed while recording/signing receipt: {msg}"
                        );
                        Termination::Failed {
                            position: generated,
                            error: msg,
                        }
                    }
                }
            }
            WorkerCompletionResult::Failed { position, error } => {
                Termination::Failed { position, error }
            }
        };

        if termination.is_completed() {
            self.metrics
                .record_execution_completed(&model_id, generated);
        } else {
            self.metrics.record_execution_failed(&model_id, generated);
        }

        let _ = sender.send(Ok(termination.into_pb())).await;
        self.dispatch_next_execution();
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
    Digest::from_slice(bytes).map_err(|_| {
        ExecutorError::InvalidQuoteRequest(format!("{field} must be 32 bytes, got {}", bytes.len()))
    })
}

fn load_assets(
    model_id: &str,
    revision: &str,
    dtype: Dtype,
) -> Result<ModelAssets, hellas_rpc::ModelAssetsError> {
    ModelAssets::load(&model_spec(model_id, revision), dtype)
}

fn hex32(bytes: &[u8; 32]) -> String {
    Digest::from_bytes(*bytes).to_string()
}
