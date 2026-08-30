use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use crate::ExecutorError;
use hellas_rpc::ExecutionPackageId;
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::pb::courtesy::{
    GetArtifactRequest, GetArtifactResponse, ListPackagesResponse, PackageInfo, PackageStatus,
    QuoteResponse, QuoteTokensRequest,
};
use hellas_rpc::pb::evaluate::EvaluateRequest as PbEvaluateRequest;
use hellas_rpc::pb::execute::Ticket;
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::protocol::artifacts::{OutputAddressed, TextExecutionId, completed_text};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::{Assurance, Digest, Evaluate, EvaluateRequest, OutputEventEnvelope, PublicKey};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::artifacts::{EvaluateArtifactStore, PreparedTextArtifacts};
use crate::executor::{ExecuteOutcome, ExecutorMessage, ProviderContext, TicketOutcome};
use crate::metrics::ExecutorMetrics;
use crate::package::PackageSource;
use crate::state::{
    ExecutorState, Invocation, LocalPackageStatus, QUOTE_AMOUNT, QUOTE_TTL, QuoteKind, QuotePlan,
    QuoteRecord, StopReason, Termination, evaluate_request_to_pb, new_execution_id, quote_ticket,
};
use crate::worker::{
    EnqueueError, ExecuteJob, ExecuteWorker, WorkerCompletion, WorkerCompletionResult,
};

const PER_EXECUTION_CHANNEL_CAPACITY: usize = 64;
const COMPLETED_EXECUTION_CACHE_CAPACITY: usize = 1024;

/// The opaque quote payload the executor core stores for an evaluate ticket.
#[derive(Clone)]
pub struct EvaluateJob {
    pub evaluate_request: EvaluateRequest,
    pub execution_package: ExecutionPackageId,
    pub invocation: Invocation,
    pub package_name: String,
    pub prepared_artifacts: Option<PreparedTextArtifacts>,
}

enum StartExecutionError {
    Busy(Box<ExecuteJob>),
    Closed,
}

pub struct EvaluateEngine {
    artifacts: EvaluateArtifactStore,
    packages: HashMap<String, LocalPackageStatus>,
    completed: HashMap<[u8; 32], CompletedEvaluate>,
    completed_order: VecDeque<[u8; 32]>,
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
        queue_capacity: usize,
        execute_policy: ExecutePolicy,
        metrics: Arc<ExecutorMetrics>,
        provider: ProviderContext,
        tx: mpsc::UnboundedSender<ExecutorMessage>,
    ) -> Self {
        Self {
            artifacts,
            packages: HashMap::new(),
            completed: HashMap::new(),
            completed_order: VecDeque::new(),
            worker: ExecuteWorker::spawn(tx),
            pending_executions: VecDeque::new(),
            queue_capacity,
            execute_policy,
            metrics,
            provider,
        }
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
        prepared_artifacts: Option<&PreparedTextArtifacts>,
    ) -> Result<(Termination, u64), ExecutorError> {
        let text_artifact = if evaluate_request.retention().should_retain() {
            self.artifacts
                .record_completed_text_with_prepared(
                    evaluate_request,
                    invocation,
                    &output_tokens,
                    prepared_artifacts,
                )
                .await?
        } else {
            completed_text(
                TextExecutionId::from_digest(evaluate_request.text_execution),
                &invocation.input_ids,
                &output_tokens,
            )
            .artifact
            .output_id()
            .digest()
        };
        let input_units = invocation.input_ids.len() as u64;
        let output_units = output_tokens.len() as u64;
        let usage = EvaluateUsage {
            input_units,
            output_units,
        };
        let billable_units = usage
            .billable_units()
            .map_err(|err| ExecutorError::Execution(format!("evaluate billing failed: {err}")))?;
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
        .map_err(|err| ExecutorError::Execution(format!("evaluate transcript failed: {err}")))?
        .finish(terminal)
        .map_err(|err| ExecutorError::Execution(format!("evaluate transcript failed: {err}")))?;
        Ok((Termination::Completed { output_events }, billable_units))
    }

    /// Resolves one request into the job that would execute it, and
    /// refuses it if this node may not.
    ///
    /// Every admission this engine has that is about the *request* — the
    /// assurance it was made under, the artifacts it names, the execute
    /// policy, and whether the exact package is loaded —
    /// runs here, once, so the quoted path and the paid path cannot
    /// disagree about what this node will run.
    ///
    /// It says nothing about payment. Whether the job may run at all is
    /// the paid endpoint's question, and it is answered before this is
    /// reached.
    async fn prepare_job(
        &mut self,
        evaluate_request: EvaluateRequest,
    ) -> Result<EvaluateJob, ExecutorError> {
        ensure_supported_assurance(evaluate_request.assurance, self.provider.assurance)?;
        let resolved = self
            .artifacts
            .resolve_evaluate_request(evaluate_request.clone())
            .await?;
        let execution_package = resolved.execution_package;
        let loaded = self
            .loaded_package_for(execution_package)
            .ok_or_else(|| ExecutorError::PackageNotLoaded(execution_package.to_string()))?;
        loaded.validate_invocation(&resolved.invocation)?;
        let execution_package = execution_package.to_string();
        if !self
            .execute_policy
            .allows_execution_package(&execution_package)
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "execute policy denied exact package {execution_package}; artifact-addressed requests require an id/... rule",
            )));
        }
        let package_name = self
            .package_names_for(resolved.execution_package)
            .into_iter()
            .next()
            .expect("a resolved loaded package has at least one local alias");
        Ok(EvaluateJob {
            evaluate_request,
            execution_package: resolved.execution_package,
            invocation: resolved.invocation,
            package_name,
            prepared_artifacts: resolved.prepared_artifacts,
        })
    }

    fn package_names_for(&self, execution_package: ExecutionPackageId) -> Vec<String> {
        let mut names = self
            .packages
            .iter()
            .filter_map(|(name, status)| match status {
                LocalPackageStatus::Ready(loaded)
                    if loaded.execution_package == execution_package =>
                {
                    Some(name.clone())
                }
                LocalPackageStatus::Ready(_) | LocalPackageStatus::Failed(_) => None,
            })
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn loaded_package_for(
        &self,
        execution_package: ExecutionPackageId,
    ) -> Option<crate::state::LoadedPackage> {
        self.packages.values().find_map(|status| match status {
            LocalPackageStatus::Ready(loaded) if loaded.execution_package == execution_package => {
                Some(*loaded)
            }
            LocalPackageStatus::Ready(_) | LocalPackageStatus::Failed(_) => None,
        })
    }
}

fn evaluate_stop_reason(stop_reason: StopReason) -> EvaluateStopReason {
    match stop_reason {
        StopReason::StopToken => EvaluateStopReason::STOP_TOKEN,
        StopReason::MaxNewTokens => EvaluateStopReason::MAX_OUTPUT,
    }
}

impl EvaluateEngine {
    pub(crate) async fn quote_evaluate(
        &mut self,
        store: &mut ExecutorState,
        request: PbEvaluateRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        store.prune_expired_quotes(Instant::now());
        let evaluate_request = crate::state::evaluate_request_from_pb(request)?;
        let job = self.prepare_job(evaluate_request).await?;
        let request_commitment = Evaluate::commit_request(&job.evaluate_request);
        let (terms, ticket) = quote_ticket(
            request_commitment,
            self.provider.genesis.as_slice(),
            job.evaluate_request.assurance,
        )?;
        let request_commitment_bytes = store.create_quote(QuoteRecord {
            terms,
            expires_at: Instant::now() + QUOTE_TTL,
            runner_public_key: job.evaluate_request.runner_public_key,
            kind: QuoteKind::Evaluate(Box::new(job)),
        })?;

        Ok(TicketOutcome {
            response: ticket,
            provenance: ExecutionProvenance {
                commitment_id: request_commitment_bytes,
            },
        })
    }

    pub(crate) async fn quote_tokens(
        &mut self,
        store: &mut ExecutorState,
        request: QuoteTokensRequest,
    ) -> Result<TicketOutcome<QuoteResponse>, ExecutorError> {
        let total_start = Instant::now();
        store.prune_expired_quotes(Instant::now());
        let package_name = request.package.trim().to_string();
        if package_name.is_empty() {
            return Err(ExecutorError::InvalidQuoteRequest(
                "missing package".to_string(),
            ));
        }
        let package = match self.packages.get(&package_name) {
            Some(LocalPackageStatus::Ready(package)) => *package,
            Some(LocalPackageStatus::Failed(error)) => {
                return Err(ExecutorError::PackageNotLoaded(format!(
                    "{package_name}: {error}"
                )));
            }
            None => {
                return Err(ExecutorError::PackageNotLoaded(package_name.to_string()));
            }
        };
        if !self
            .execute_policy
            .allows_execute(&package.execution_package.to_string(), Some(&package_name))
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "execute policy denied package {package_name} ({})",
                package.execution_package,
            )));
        }
        let plan = QuotePlan::from_tokens_request(request, package)?;
        ensure_supported_assurance(plan.assurance, self.provider.assurance)?;

        let resolved = self.artifacts.prepare_text(&plan).await?;
        let evaluate_request = resolved.evaluate_request.clone();
        let evaluate_request_pb = evaluate_request_to_pb(&evaluate_request);
        let request_commitment = Evaluate::commit_request(&evaluate_request);
        let (terms, ticket) = quote_ticket(
            request_commitment,
            self.provider.genesis.as_slice(),
            evaluate_request.assurance,
        )?;
        let commitment_id = request_commitment.digest();
        let prompt_tokens = u32::try_from(plan.invocation.input_ids.len()).map_err(|_| {
            ExecutorError::InvalidTokenPayload(
                "prompt token count exceeds the RPC representation".to_string(),
            )
        })?;
        let request_commitment_bytes = store.create_quote(QuoteRecord {
            terms,
            expires_at: Instant::now() + QUOTE_TTL,
            runner_public_key: evaluate_request.runner_public_key,
            kind: QuoteKind::Evaluate(Box::new(EvaluateJob {
                evaluate_request,
                execution_package: resolved.execution_package,
                invocation: resolved.invocation,
                package_name,
                prepared_artifacts: resolved.prepared_artifacts,
            })),
        })?;

        info!(
            request_commitment = %hex32(&request_commitment_bytes),
            commitment_id = %commitment_id,
            prompt_tokens,
            amount = QUOTE_AMOUNT,
            total_ms = total_start.elapsed().as_millis(),
            "quoted token evaluate execution"
        );

        Ok(TicketOutcome {
            response: QuoteResponse {
                ticket: Some(ticket),
                prompt_tokens,
                evaluate_request: Some(evaluate_request_pb),
            },
            provenance: ExecutionProvenance {
                commitment_id: *commitment_id.as_bytes(),
            },
        })
    }

    /// Fetches, verifies, and loads one Catena package on this node.
    ///
    /// This is the one serving-process path that may spend bandwidth on a
    /// package. It is deliberately not an RPC: peer-reachable paths consult
    /// only the exact-identity registry populated here.
    pub(crate) async fn materialize_package(
        &mut self,
        source: PackageSource,
    ) -> Result<hellas_rpc::ExecutionPackageId, ExecutorError> {
        let name = source.name().to_string();
        if matches!(self.packages.get(&name), Some(LocalPackageStatus::Ready(_))) {
            return Err(ExecutorError::InvalidPackageSource(format!(
                "package alias {name:?} is already loaded"
            )));
        }
        match self.worker.load_package(source).await {
            Ok(loaded) => {
                self.packages
                    .insert(name.clone(), LocalPackageStatus::Ready(loaded));
                info!(
                    package = %name,
                    execution_package = %loaded.execution_package,
                    "loaded Catena package"
                );
                Ok(loaded.execution_package)
            }
            Err(error) => {
                self.packages
                    .insert(name, LocalPackageStatus::Failed(error.to_string()));
                Err(error)
            }
        }
    }

    /// Publishes one canonical artifact through the owner-only handle path.
    pub(crate) async fn publish_canonical_artifact(
        &mut self,
        canonical_artifact: Vec<u8>,
    ) -> Result<Digest, ExecutorError> {
        self.artifacts
            .publish_canonical_bytes(canonical_artifact)
            .await
    }

    pub(crate) async fn get_artifact(
        &mut self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, ExecutorError> {
        // Courtesy only exposes the retained store. Ephemeral prompt and
        // token artifacts live in the separate memory store and are never
        // reachable through this API.
        let canonical_artifact = self
            .artifacts
            .get_canonical_bytes(digest_from_slice(&request.digest, "digest")?)
            .await?;
        Ok(GetArtifactResponse { canonical_artifact })
    }

    pub(crate) async fn list_packages(&self) -> ListPackagesResponse {
        let packages = self
            .packages
            .iter()
            .map(|(name, status)| {
                let (proto_status, execution_package, error) = match status {
                    LocalPackageStatus::Ready(loaded) => (
                        PackageStatus::Ready,
                        loaded.execution_package.as_bytes().to_vec(),
                        String::new(),
                    ),
                    LocalPackageStatus::Failed(err) => {
                        (PackageStatus::Failed, Vec::new(), err.clone())
                    }
                };
                PackageInfo {
                    name: name.clone(),
                    execution_package,
                    status: proto_status.into(),
                    error,
                }
            })
            .collect();
        ListPackagesResponse { packages }
    }

    pub(crate) fn start(
        &mut self,
        job: EvaluateJob,
        execution_id: String,
        request_commitment: [u8; 32],
    ) -> Result<ExecuteOutcome, ExecutorError> {
        let EvaluateJob {
            evaluate_request,
            execution_package,
            invocation,
            package_name,
            prepared_artifacts,
        } = job;
        let stat_prompt = invocation.input_ids.len() as u64;
        let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
        let execute_job = ExecuteJob {
            execution_id: execution_id.clone(),
            request_commitment,
            package_name: package_name.clone(),
            evaluate_request,
            execution_package,
            invocation,
            prepared_artifacts,
            accepted_at: Instant::now(),
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
            "evaluate",
            &package_name,
            stat_prompt,
            /* prefill= */ stat_prompt,
        );

        info!(
            execution_id = %execution_id,
            request_commitment = %hex32(&request_commitment),
            queued,
            queue_len = self.pending_executions.len(),
            "accepted evaluate execution"
        );

        Ok(ExecuteOutcome {
            provenance: ExecutionProvenance {
                commitment_id: request_commitment,
            },
            events: receiver,
        })
    }

    /// Resolves and starts a paid request without a quote or ticket lookup.
    ///
    /// The paid endpoint's durable journal, rather than the transient quote
    /// store, admits this call. The owner-only handle is its sole entry point.
    pub(crate) async fn start_request(
        &mut self,
        request: EvaluateRequest,
    ) -> Result<ExecuteOutcome, ExecutorError> {
        let request_commitment = *Evaluate::commit_request(&request).as_bytes();
        let job = self.prepare_job(request).await?;
        // Deliberately not `replay_completed`: that map is keyed by
        // request commitment and would answer a second paid job for the
        // same request out of the first one's transcript, without
        // invoking anything. A paid job is invoked because its journal
        // says so, and this is the invocation.
        self.start(job, new_execution_id(), request_commitment)
    }

    pub(crate) async fn on_completion(&mut self, completion: WorkerCompletion) {
        let WorkerCompletion {
            execution_id,
            request_commitment,
            package_name,
            evaluate_request,
            invocation,
            prepared_artifacts,
            sender,
            result,
        } = completion;

        let generated = result.position();
        let (termination, billable_units) = match result {
            WorkerCompletionResult::Completed {
                stop_reason,
                output_tokens,
                output_events,
            } => match self
                .completed_evaluate_termination(
                    &evaluate_request,
                    &invocation,
                    stop_reason,
                    output_tokens,
                    output_events,
                    prepared_artifacts.as_ref(),
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
            },
            WorkerCompletionResult::Failed { position, error } => {
                (Termination::Failed { position, error }, None)
            }
        };

        if billable_units.is_some() {
            self.metrics
                .record_execution_completed("evaluate", &package_name, generated);
            if evaluate_request.retention().should_retain() {
                if !self.completed.contains_key(&request_commitment) {
                    while self.completed.len() >= COMPLETED_EXECUTION_CACHE_CAPACITY {
                        let Some(oldest) = self.completed_order.pop_front() else {
                            break;
                        };
                        self.completed.remove(&oldest);
                    }
                    self.completed_order.push_back(request_commitment);
                }
                self.completed.insert(
                    request_commitment,
                    CompletedEvaluate {
                        runner_public_key: evaluate_request.runner_public_key,
                        assurance: evaluate_request.assurance,
                        termination: termination.clone(),
                    },
                );
            }
        } else {
            self.metrics
                .record_execution_failed("evaluate", &package_name, generated);
        }

        // Completion runs on the actor itself. A stalled consumer must never
        // wedge package loads, quotes, or every later execution behind an
        // awaited send into its already-full per-run channel.
        let _ = sender.try_send(Ok(termination.into_pb()));
        self.dispatch_next_execution();
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

fn digest_from_slice(bytes: &[u8], field: &str) -> Result<Digest, ExecutorError> {
    crate::state::fixed::<32>(field, bytes)
        .map(Digest::from_bytes)
        .map_err(ExecutorError::InvalidQuoteRequest)
}

fn hex32(bytes: &[u8; 32]) -> String {
    Digest::from_bytes(*bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::ProducerSigningKey;
    use hellas_rpc::pb::courtesy::{EvaluateGenesisStart, EvaluateStart, evaluate_start};
    use hellas_rpc::run_ticket::public_key_to_pb;

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
    }

    fn test_engine(producer_key: Arc<ProducerSigningKey>) -> EvaluateEngine {
        let (tx, _rx) = mpsc::unbounded_channel();
        EvaluateEngine::new(
            EvaluateArtifactStore::memory(),
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

    fn artifact_plan(execution_package: ExecutionPackageId) -> QuotePlan {
        QuotePlan {
            execution_package,
            vocabulary_size: u64::from(u32::MAX) + 1,
            maximum_capacity: u64::MAX,
            execution_environment: QuotePlan::execution_environment(execution_package),
            invocation: Invocation {
                input_ids: vec![1, 2, 3],
                max_new_tokens: 8,
                stop_token_ids: Vec::new(),
            },
            initial_artifact_id: None,
            runner_public_key: key(3).public_key(),
            assurance: Assurance::ProducerSigned,
            retention: hellas_rpc::Retention::Retain,
        }
    }

    fn token_request(execution_package: hellas_rpc::ExecutionPackageId) -> QuoteTokensRequest {
        QuoteTokensRequest {
            package: "smollm2-135m".to_string(),
            execution_package: execution_package.as_bytes().to_vec(),
            prompt_token_ids: vec![1, 2, 3],
            max_new_tokens: Some(4),
            stop_token_ids: vec![9, 2, 9],
            start: Some(EvaluateStart {
                kind: Some(evaluate_start::Kind::Genesis(EvaluateGenesisStart {})),
            }),
            runner_public_key: Some(public_key_to_pb(&key(3).public_key())),
            assurance: Assurance::ProducerSigned.to_byte().into(),
            retain: Some(false),
        }
    }

    #[test]
    fn token_quote_pins_the_exact_package_and_normalizes_stop_ids() {
        let actual = hellas_rpc::ExecutionPackageId::from_bytes([6; 32]);
        let loaded = crate::state::LoadedPackage {
            execution_package: actual,
            vocabulary_size: 100,
            maximum_capacity: 100,
        };
        let plan = QuotePlan::from_tokens_request(token_request(actual), loaded).unwrap();
        assert_eq!(plan.invocation.stop_token_ids, [2, 9]);

        let pinned_other = hellas_rpc::ExecutionPackageId::from_bytes([7; 32]);
        let Err(error) = QuotePlan::from_tokens_request(token_request(pinned_other), loaded) else {
            panic!("a different exact package pin must be rejected");
        };
        assert!(error.to_string().contains("caller pinned"), "{error}");
    }

    #[test]
    fn token_quote_defaults_only_an_absent_output_limit() {
        let execution_package = hellas_rpc::ExecutionPackageId::from_bytes([6; 32]);
        let loaded = crate::state::LoadedPackage {
            execution_package,
            vocabulary_size: 100,
            maximum_capacity: 100,
        };
        let mut absent = token_request(execution_package);
        absent.max_new_tokens = None;
        let plan = QuotePlan::from_tokens_request(absent, loaded).unwrap();
        assert_eq!(
            plan.invocation.max_new_tokens,
            hellas_rpc::DEFAULT_MAX_NEW_TOKENS
        );

        let mut zero = token_request(execution_package);
        zero.max_new_tokens = Some(0);
        let Err(error) = QuotePlan::from_tokens_request(zero, loaded) else {
            panic!("an explicit zero limit must not select the default");
        };
        assert!(error.to_string().contains("greater than zero"), "{error}");
    }

    #[test]
    fn token_quote_bounds_stop_policy_work_before_normalizing() {
        let actual = hellas_rpc::ExecutionPackageId::from_bytes([6; 32]);
        let loaded = crate::state::LoadedPackage {
            execution_package: actual,
            vocabulary_size: 100,
            maximum_capacity: 100,
        };
        let mut request = token_request(actual);
        request.stop_token_ids = vec![2; hellas_rpc::MAX_STOP_TOKEN_IDS + 1];
        let Err(error) = QuotePlan::from_tokens_request(request, loaded) else {
            panic!("an oversized stop policy must be rejected");
        };
        assert!(error.to_string().contains("over the limit"), "{error}");
    }

    /// The vulnerability, at the door it came in by: an unauthenticated
    /// peer names a package and the node must refuse without resolving a path
    /// or fetching anything.
    ///
    /// `ExecutePolicy::Eager` is the default and permits everything, so
    /// the policy is deliberately left permissive here — what refuses
    /// this quote is that the alias is absent from the owner-populated local
    /// registry. A quote may not add it.
    #[tokio::test]
    async fn quoting_an_unloaded_package_is_refused_without_fetching_it() {
        let mut engine = test_engine(Arc::new(key(2)));
        let mut store = ExecutorState::new();
        let runner = key(3).public_key();

        let err = engine
            .quote_tokens(
                &mut store,
                QuoteTokensRequest {
                    package: "not-on-this-node".to_string(),
                    execution_package: vec![8; 32],
                    prompt_token_ids: vec![1, 2, 3],
                    max_new_tokens: Some(4),
                    stop_token_ids: Vec::new(),
                    start: Some(EvaluateStart {
                        kind: Some(evaluate_start::Kind::Genesis(EvaluateGenesisStart {})),
                    }),
                    runner_public_key: Some(public_key_to_pb(&runner)),
                    assurance: Assurance::ProducerSigned.to_byte().into(),
                    retain: Some(false),
                },
            )
            .await
            .expect_err("a package this node has not loaded must not be quotable");

        match &err {
            ExecutorError::PackageNotLoaded(message) => {
                assert!(message.contains("not-on-this-node"), "{message}");
            }
            other => panic!("expected a not-loaded refusal, got {other:?}"),
        }
        // Answerable later, not forbidden: a client can ask the operator
        // for the package and come back.
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

    /// Package aliases are opaque registry keys. Path-shaped attacker input
    /// is never interpreted as a filesystem location.
    #[tokio::test]
    async fn quoting_a_path_shaped_alias_is_only_a_registry_miss() {
        for package in ["/etc/passwd", "../../..", "refs/heads/../../../etc"] {
            let mut engine = test_engine(Arc::new(key(2)));
            let mut store = ExecutorState::new();
            let runner = key(3).public_key();

            let err = engine
                .quote_tokens(
                    &mut store,
                    QuoteTokensRequest {
                        package: package.to_string(),
                        execution_package: vec![8; 32],
                        prompt_token_ids: vec![1, 2, 3],
                        max_new_tokens: Some(4),
                        stop_token_ids: Vec::new(),
                        start: Some(EvaluateStart {
                            kind: Some(evaluate_start::Kind::Genesis(EvaluateGenesisStart {})),
                        }),
                        runner_public_key: Some(public_key_to_pb(&runner)),
                        assurance: Assurance::ProducerSigned.to_byte().into(),
                        retain: Some(false),
                    },
                )
                .await
                .expect_err("a path-shaped alias must not be resolved");

            assert!(
                matches!(err, ExecutorError::PackageNotLoaded(_)),
                "{package:?} was not treated as an opaque registry miss: {err:?}",
            );
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
    }

    /// The same door, one round trip further away: the evaluate quote
    /// takes its exact package identity from a stored artifact rather than
    /// from an alias. Wire-uploaded artifacts cannot make the worker load it.
    #[tokio::test]
    async fn quoting_an_artifact_bound_to_an_unloaded_package_is_refused() {
        let mut engine = test_engine(Arc::new(key(2)));
        let mut store = ExecutorState::new();
        let execution_package = hellas_rpc::ExecutionPackageId::from_bytes([6; 32]);
        let plan = artifact_plan(execution_package);
        let recorded = engine
            .artifacts
            .record_prepared_text(&plan)
            .await
            .expect("record the prepared text an artifact quote resolves through");

        let err = engine
            .quote_evaluate(
                &mut store,
                evaluate_request_to_pb(&recorded.evaluate_request),
            )
            .await
            .expect_err("a ticket must not be issued for a package this node has not loaded");

        match &err {
            ExecutorError::PackageNotLoaded(message) => {
                assert!(
                    message.contains(&execution_package.to_string()),
                    "{message}"
                );
            }
            other => panic!("expected a not-loaded refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn artifact_quote_requires_an_exact_id_policy_rule() {
        let mut engine = test_engine(Arc::new(key(2)));
        let mut store = ExecutorState::new();
        let execution_package = hellas_rpc::ExecutionPackageId::from_bytes([6; 32]);
        let plan = artifact_plan(execution_package);
        let recorded = engine.artifacts.record_prepared_text(&plan).await.unwrap();
        engine.packages.insert(
            "smollm2-135m".to_string(),
            LocalPackageStatus::Ready(crate::state::LoadedPackage {
                execution_package,
                vocabulary_size: plan.vocabulary_size,
                maximum_capacity: plan.maximum_capacity,
            }),
        );

        engine.execute_policy = "allow(package/smollm2-135m)".parse().unwrap();
        let error = engine
            .quote_evaluate(
                &mut store,
                evaluate_request_to_pb(&recorded.evaluate_request),
            )
            .await
            .expect_err("an alias rule cannot authorize an alias-free artifact request");
        assert!(matches!(error, ExecutorError::PolicyDenied(_)));

        engine.execute_policy = format!("allow(id/{execution_package})").parse().unwrap();
        engine
            .quote_evaluate(
                &mut store,
                evaluate_request_to_pb(&recorded.evaluate_request),
            )
            .await
            .expect("the exact package identity authorizes the artifact request");
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
                stop_reason: EvaluateStopReason::STOP_TOKEN,
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
