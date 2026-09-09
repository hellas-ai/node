use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::ExecutorError;
use hellas_rpc::{ContentId, Digest, EvaluateRequest, ProgramManifest};

use crate::artifact_store::{ArtifactStorage, ArtifactStoreConfig};
use crate::state::{Invocation, QuotePlan, validate_invocation};

use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical, CanonicalDecode, InputAddressed, OutputAddressed,
    PreparedPaidInputParts, SourceRef, TextArtifact, TextArtifactId, TextExecution,
    TextExecutionId, TextPolicy, TextPolicyId, TextSource, TextState, TextStateId, TokenIds,
    TokenIdsId, completed_text,
};

const CANONICAL_PARTITION: &str = "evaluate_canonical";
const EXECUTION_OUTPUT_PARTITION: &str = "evaluate_execution_outputs";
const RETAINED_EXECUTION_PARTITION: &str = "evaluate_retained_executions";
/// An execution publishes at most four input and four output canonical
/// objects. A durable reservation comes first, so this also bounds crash
/// orphans without having to inspect any canonical body at startup.
const MAX_CANONICAL_OBJECTS_PER_RETAINED_EXECUTION: usize = 8;
const MAX_TEXT_ARTIFACT_CHAIN_DEPTH: usize = 1024;

#[derive(Clone, Debug)]
pub(crate) struct ResolvedEvaluateExecution {
    pub evaluate_request: EvaluateRequest,
    pub invocation: Invocation,
    pub prepared_artifacts: Option<PreparedTextArtifacts>,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedTextArtifacts {
    identity: Option<TextArtifact>,
    prompt_tokens: TokenIds,
    policy: TextPolicy,
    execution: TextExecution,
}

impl PreparedTextArtifacts {
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        self.prompt_tokens
            .retained_heap_bytes()?
            .checked_add(self.policy.retained_heap_bytes()?)
    }
}

/// Reconstructs the exact invocation carried by one accepted paid job.
///
/// Unlike [`EvaluateArtifactStore::resolve_evaluate_request`], this path reads
/// no Courtesy artifact state: all graph bodies came from the durable bundle
/// the parties signed. It validates their links again before anything reaches
/// the worker and returns them unpublished; retention is decided only after a
/// successful execution.
pub(crate) fn resolve_prepared_paid_input(
    parts: PreparedPaidInputParts,
) -> Result<(ProgramManifest, ResolvedEvaluateExecution), ExecutorError> {
    let PreparedPaidInputParts {
        evaluate_request,
        manifest,
        text_execution,
        prompt_tokens,
        text_policy,
        identity_artifact,
    } = parts;

    if manifest.content_id() != evaluate_request.execution_environment {
        return Err(invalid_prepared_graph("manifest content id"));
    }
    let TextArtifact::Identity { bound_term } = &identity_artifact else {
        return Err(invalid_prepared_graph("identity artifact kind"));
    };
    if bound_term.as_bytes() != evaluate_request.execution_environment.as_bytes() {
        return Err(invalid_prepared_graph("identity artifact bound term"));
    }
    if text_execution.from() != &SourceRef::output(identity_artifact.output_id()) {
        return Err(invalid_prepared_graph("text execution source"));
    }
    if text_execution.input_id().digest() != evaluate_request.text_execution {
        return Err(invalid_prepared_graph("text execution id"));
    }
    if text_execution.prompt_tokens() != prompt_tokens.output_id() {
        return Err(invalid_prepared_graph("prompt tokens id"));
    }
    if text_execution.policy() != text_policy.output_id() {
        return Err(invalid_prepared_graph("text policy id"));
    }

    let invocation = Invocation {
        input_ids: token_ids_to_u32(&prompt_tokens),
        max_new_tokens: text_policy.max_new_tokens(),
        stop_token_ids: text_policy
            .stop_token_ids()
            .iter()
            .map(|token| token.as_u32())
            .collect(),
    };
    Ok((
        manifest,
        ResolvedEvaluateExecution {
            evaluate_request,
            invocation,
            prepared_artifacts: Some(PreparedTextArtifacts {
                identity: Some(identity_artifact),
                prompt_tokens,
                policy: text_policy,
                execution: text_execution,
            }),
        },
    ))
}

fn invalid_prepared_graph(field: &'static str) -> ExecutorError {
    ExecutorError::InvalidQuoteRequest(format!("journaled paid input has mismatched {field}"))
}

pub(crate) struct EvaluateArtifactStore {
    storage: Option<Arc<dyn ArtifactStorage>>,
    // The root handle owns the advisory lock for exactly this store's
    // lifetime. It is deliberately otherwise unused.
    _root: Option<Arc<crate::artifact_store::ArtifactStoreRoot>>,
    retained_execution_capacity: usize,
    canonical_keys: HashSet<Digest>,
    execution_output_keys: HashSet<TextExecutionId>,
    retained_executions: HashSet<TextExecutionId>,
    /// The in-process backend has no filesystem to re-read. It is still
    /// bounded by the same reservation/object accounting as disk storage.
    memory_blobs: HashMap<Digest, Vec<u8>>,
    /// Memory stores have no output partition. Persistent stores use this as
    /// a bounded lazy decode cache, never as canonical-body retention.
    outputs_by_execution: HashMap<TextExecutionId, TextArtifactId>,
}

struct MaterializedTextSource {
    execution_environment: hellas_rpc::ContentId,
    tokens: Vec<u32>,
}

impl Default for EvaluateArtifactStore {
    fn default() -> Self {
        Self::memory()
    }
}

macro_rules! typed_canonical_artifacts {
    ($(
        $load:ident,
        $insert:ident,
        $id:ty,
        $value:ty,
        $cache:ident,
        $identity:ident;
    )+) => {
        $(
            async fn $load(&mut self, id: $id) -> Result<$value, ExecutorError> {
                let value = self
                    .decode_canonical::<$value>(id.digest(), stringify!($value))
                    .await?;
                if value.$identity() != id {
                    return Err(canonical_type_mismatch(stringify!($value), id.digest()));
                }
                Ok(value)
            }

            async fn $insert(&mut self, value: $value) -> Result<$id, ExecutorError> {
                let id = value.$identity();
                self.insert_canonical(id.digest(), &value).await?;
                Ok(id)
            }
        )+
    };
}

impl EvaluateArtifactStore {
    pub(crate) fn memory() -> Self {
        Self::new(
            None,
            None,
            crate::artifact_store::DEFAULT_EVALUATE_RETAINED_EXECUTION_CAPACITY,
        )
    }

    pub(crate) async fn open(config: ArtifactStoreConfig) -> Result<Self, ExecutorError> {
        let retained_execution_capacity = config.retained_execution_capacity();
        let Some(storage) = config.storage() else {
            return Ok(Self::new(None, config.root(), retained_execution_capacity));
        };
        let canonical_keys = scan_digests(&storage, CANONICAL_PARTITION).await?;
        let execution_output_keys: HashSet<TextExecutionId> =
            scan_digests(&storage, EXECUTION_OUTPUT_PARTITION)
                .await?
                .into_iter()
                .map(TextExecutionId::from_digest)
                .collect();
        let retained_executions = scan_digests(&storage, RETAINED_EXECUTION_PARTITION)
            .await?
            .into_iter()
            .map(TextExecutionId::from_digest)
            .collect::<HashSet<_>>();
        let maximum_canonical_objects = retained_execution_capacity
            .checked_mul(MAX_CANONICAL_OBJECTS_PER_RETAINED_EXECUTION)
            .ok_or_else(|| {
                ExecutorError::ArtifactStore(
                    "retained Evaluate capacity overflows canonical object bound".to_string(),
                )
            })?;
        if retained_executions.len() > retained_execution_capacity
            || execution_output_keys.len() > retained_execution_capacity
            || canonical_keys.len() > maximum_canonical_objects
            || !execution_output_keys.is_subset(&retained_executions)
        {
            return Err(ExecutorError::ArtifactStore(format!(
                "retained Evaluate artifact store exceeds or contradicts its {retained_execution_capacity}-execution bound"
            )));
        }
        for execution in &retained_executions {
            let bytes = storage
                .read(RETAINED_EXECUTION_PARTITION, execution.as_bytes().to_vec())
                .await
                .map_err(storage_error)?;
            decode_execution_reservation(&bytes, *execution)?;
        }
        Ok(Self {
            storage: Some(storage),
            _root: config.root(),
            retained_execution_capacity,
            canonical_keys,
            execution_output_keys,
            retained_executions,
            memory_blobs: HashMap::new(),
            outputs_by_execution: HashMap::new(),
        })
    }

    /// Fail before GPU admission when a successful retained execution could
    /// not be published. The Evaluate actor runs at most one GPU job at a
    /// time, and calls this again when dispatching queued work, so a job that
    /// fills the final slot cannot make the next queued job waste GPU work.
    pub(crate) fn ensure_retention_available(
        &self,
        evaluate_request: &EvaluateRequest,
    ) -> Result<(), ExecutorError> {
        if !evaluate_request.retention().should_retain() {
            return Ok(());
        }
        let execution = TextExecutionId::from_digest(evaluate_request.text_execution);
        if self.retained_executions.contains(&execution) {
            return Ok(());
        }
        if self.retained_executions.len() >= self.retained_execution_capacity {
            return Err(ExecutorError::ResourceExhausted(format!(
                "retained Evaluate execution capacity of {} is exhausted",
                self.retained_execution_capacity
            )));
        }
        Ok(())
    }

    fn new(
        storage: Option<Arc<dyn ArtifactStorage>>,
        root: Option<Arc<crate::artifact_store::ArtifactStoreRoot>>,
        retained_execution_capacity: usize,
    ) -> Self {
        Self {
            storage,
            _root: root,
            retained_execution_capacity,
            canonical_keys: HashSet::new(),
            execution_output_keys: HashSet::new(),
            retained_executions: HashSet::new(),
            memory_blobs: HashMap::new(),
            outputs_by_execution: HashMap::new(),
        }
    }

    async fn persist_blob(&mut self, digest: Digest, bytes: &[u8]) -> Result<(), ExecutorError> {
        if Digest::hash(bytes) != digest {
            return Err(ExecutorError::ArtifactStore(format!(
                "canonical bytes do not match digest {digest}"
            )));
        }
        if !self.canonical_keys.contains(&digest)
            && self.canonical_keys.len()
                >= self
                    .retained_execution_capacity
                    .checked_mul(MAX_CANONICAL_OBJECTS_PER_RETAINED_EXECUTION)
                    .ok_or_else(|| {
                        ExecutorError::ArtifactStore(
                            "retained Evaluate canonical object bound overflows".to_string(),
                        )
                    })?
        {
            return Err(ExecutorError::ResourceExhausted(format!(
                "retained Evaluate canonical object capacity of {} is exhausted",
                self.retained_execution_capacity * MAX_CANONICAL_OBJECTS_PER_RETAINED_EXECUTION
            )));
        }
        let Some(storage) = &self.storage else {
            self.canonical_keys.insert(digest);
            self.memory_blobs
                .entry(digest)
                .or_insert_with(|| bytes.to_vec());
            return Ok(());
        };
        let existing = storage
            .write_once(
                CANONICAL_PARTITION,
                digest.as_bytes().to_vec(),
                bytes.to_vec(),
            )
            .await
            .map_err(storage_error)?;
        if let Some(existing) = existing
            && existing != bytes
        {
            if Digest::hash(&existing) == digest {
                return Err(ExecutorError::ArtifactStore(format!(
                    "stored artifact {digest} has conflicting canonical bytes"
                )));
            }
            storage
                .replace(
                    CANONICAL_PARTITION,
                    digest.as_bytes().to_vec(),
                    bytes.to_vec(),
                )
                .await
                .map_err(storage_error)?;
        }
        self.canonical_keys.insert(digest);
        Ok(())
    }

    async fn read_blob(&self, digest: Digest) -> Result<Option<Vec<u8>>, ExecutorError> {
        if !self.canonical_keys.contains(&digest) {
            return Ok(None);
        }
        if self.storage.is_none() {
            return self
                .memory_blobs
                .get(&digest)
                .cloned()
                .map(Some)
                .ok_or_else(|| {
                    ExecutorError::ArtifactStore(format!(
                        "in-memory canonical index is missing bytes for {digest}"
                    ))
                });
        }
        let storage = self.storage.as_ref().ok_or_else(|| {
            ExecutorError::ArtifactStore("canonical artifact storage is unavailable".to_string())
        })?;
        let bytes = storage
            .read(CANONICAL_PARTITION, digest.as_bytes().to_vec())
            .await
            .map_err(storage_error)?;
        if Digest::hash(&bytes) != digest {
            return Err(ExecutorError::ArtifactStore(format!(
                "stored artifact does not match requested digest {digest}"
            )));
        }
        Ok(Some(bytes))
    }

    /// Build the canonical input graph for a token quote without publishing
    /// any of it. A quote is unauthenticated and may expire unused; retained
    /// storage begins only after the corresponding execution succeeds.
    pub async fn prepare_text(
        &mut self,
        plan: &QuotePlan,
    ) -> Result<ResolvedEvaluateExecution, ExecutorError> {
        let execution_environment = plan.execution_environment;
        let bound_term_id = BoundTermId::from_digest(execution_environment.digest());

        let (from, prior_tokens, identity_to_insert) = match plan.initial_artifact_id {
            Some(artifact_id) => {
                let artifact_id = TextArtifactId::from_digest(artifact_id);
                let source = self.materialize_artifact(artifact_id).await?;
                if source.execution_environment != execution_environment {
                    return Err(ExecutorError::InvalidQuoteRequest(
                        "initial artifact belongs to a different execution environment".to_string(),
                    ));
                }
                (SourceRef::output(artifact_id), source.tokens, None)
            }
            None => {
                let identity = TextArtifact::identity(bound_term_id);
                let identity_id = identity.output_id();
                (SourceRef::output(identity_id), Vec::new(), Some(identity))
            }
        };

        let mut invocation = plan.invocation.clone();
        if !prior_tokens.is_empty() {
            let mut full_input = prior_tokens;
            full_input.extend(invocation.input_ids);
            invocation.input_ids = full_input;
        }
        validate_invocation(&invocation, plan.vocabulary_size, plan.maximum_capacity)?;

        let prompt_tokens = TokenIds::from(plan.invocation.input_ids.clone());
        let prompt_tokens_id = prompt_tokens.output_id();
        let policy = TextPolicy::from_u32_stop_tokens(
            plan.invocation.max_new_tokens,
            plan.invocation.stop_token_ids.iter().copied(),
        );
        let policy_id = policy.output_id();
        let execution = TextExecution::new(from, prompt_tokens_id, policy_id);
        let execution_id = execution.input_id();
        let evaluate_request = EvaluateRequest {
            text_execution: execution_id.digest(),
            runner_public_key: plan.runner_public_key,
            execution_environment,
            nonce: rand::random(),
            assurance: plan.assurance,
            retain: plan.retention.should_retain(),
        };

        Ok(ResolvedEvaluateExecution {
            evaluate_request,
            invocation,
            prepared_artifacts: Some(PreparedTextArtifacts {
                identity: identity_to_insert,
                prompt_tokens,
                policy,
                execution,
            }),
        })
    }

    async fn publish_prepared_text(
        &mut self,
        prepared: &PreparedTextArtifacts,
    ) -> Result<(), ExecutorError> {
        if let Some(identity) = prepared.identity.clone() {
            self.insert_text_artifact(identity).await?;
        }
        self.insert_token_ids(prepared.prompt_tokens.clone())
            .await?;
        self.insert_policy(prepared.policy.clone()).await?;
        self.insert_text_execution(prepared.execution.clone())
            .await?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn record_prepared_text(
        &mut self,
        plan: &QuotePlan,
    ) -> Result<ResolvedEvaluateExecution, ExecutorError> {
        let resolved = self.prepare_text(plan).await?;
        self.reserve_retained_execution(TextExecutionId::from_digest(
            resolved.evaluate_request.text_execution,
        ))
        .await?;
        self.publish_prepared_text(
            resolved
                .prepared_artifacts
                .as_ref()
                .expect("a token plan always builds prepared artifacts"),
        )
        .await?;
        Ok(resolved)
    }

    pub async fn resolve_evaluate_request(
        &mut self,
        evaluate_request: EvaluateRequest,
    ) -> Result<ResolvedEvaluateExecution, ExecutorError> {
        let execution_id = TextExecutionId::from_digest(evaluate_request.text_execution);
        let execution = self.text_execution(execution_id).await?;
        let source = self.materialize_source(execution.from()).await?;
        if source.execution_environment != evaluate_request.execution_environment {
            return Err(ExecutorError::InvalidQuoteRequest(
                "execution environment does not match the bound program manifest".to_string(),
            ));
        }
        let prompt_tokens = self.token_ids(execution.prompt_tokens()).await?;
        let policy = self.text_policy(execution.policy()).await?;
        let mut input_ids = source.tokens;
        input_ids.extend(token_ids_to_u32(&prompt_tokens));
        let stop_token_ids = policy
            .stop_token_ids()
            .iter()
            .map(|token| token.as_u32())
            .collect();

        Ok(ResolvedEvaluateExecution {
            evaluate_request,
            invocation: Invocation {
                input_ids,
                max_new_tokens: policy.max_new_tokens(),
                stop_token_ids,
            },
            prepared_artifacts: None,
        })
    }

    pub async fn get_canonical_bytes(&mut self, digest: Digest) -> Result<Vec<u8>, ExecutorError> {
        self.read_blob(digest)
            .await?
            .ok_or_else(|| ExecutorError::ArtifactNotFound(digest.to_string()))
    }

    /// Records what one finished execution produced, and returns the id
    /// of the artifact naming it.
    ///
    /// The ids are not computed here. [`completed_text`] is the one
    /// definition of what a finished execution produces, and it is
    /// shared with the client-side re-execution that has to arrive at the
    /// same artifact id without this store; what is done here is storing
    /// the bodies it derived.
    pub async fn record_completed_text_with_prepared(
        &mut self,
        evaluate_request: &EvaluateRequest,
        invocation: &Invocation,
        output_tokens: &[u32],
        prepared: Option<&PreparedTextArtifacts>,
    ) -> Result<Digest, ExecutorError> {
        let execution_id = TextExecutionId::from_digest(evaluate_request.text_execution);
        if let Some(prepared) = prepared {
            let prepared_id = prepared.execution.input_id();
            if prepared_id != execution_id {
                return Err(ExecutorError::ArtifactStore(
                    "prepared execution does not match evaluate request".to_string(),
                ));
            }
        }
        // The marker is durable before the first graph object. A crash at any
        // later point loses capacity rather than permitting a new execution to
        // grow the root past its configured bound.
        self.reserve_retained_execution(execution_id).await?;
        if let Some(prepared) = prepared {
            self.publish_prepared_text(prepared).await?;
        }
        let _ = self.text_execution(execution_id).await?;

        let completed = completed_text(execution_id, &invocation.input_ids, output_tokens);
        self.insert_token_ids(completed.generated_tokens).await?;
        self.insert_token_ids(completed.state_tokens).await?;
        self.insert_text_state(completed.state).await?;
        let artifact_id = self.insert_text_artifact(completed.artifact).await?;
        if self.execution_output_keys.contains(&execution_id) {
            let stored = self.output_artifact_for_execution(execution_id).await?;
            if stored != artifact_id {
                return Err(ExecutorError::ArtifactStore(format!(
                    "retained execution {execution_id} already names a different output artifact"
                )));
            }
        } else {
            let stored = self
                .persist_execution_output(execution_id, artifact_id)
                .await?;
            if stored != artifact_id {
                return Err(ExecutorError::ArtifactStore(format!(
                    "retained execution {execution_id} already names a different output artifact"
                )));
            }
        }
        self.outputs_by_execution.insert(execution_id, artifact_id);
        Ok(artifact_id.digest())
    }

    #[cfg(test)]
    async fn record_completed_text(
        &mut self,
        evaluate_request: &EvaluateRequest,
        invocation: &Invocation,
        output_tokens: &[u32],
    ) -> Result<Digest, ExecutorError> {
        self.record_completed_text_with_prepared(evaluate_request, invocation, output_tokens, None)
            .await
    }

    async fn materialize_source(
        &mut self,
        source: &TextSource,
    ) -> Result<MaterializedTextSource, ExecutorError> {
        match source {
            SourceRef::Input(execution_id) => {
                let artifact_id = self.output_artifact_for_execution(*execution_id).await?;
                let artifact = self.text_artifact(artifact_id).await?;
                validate_execution_output_mapping(*execution_id, artifact_id, &artifact)?;
                self.materialize_artifact(artifact_id).await
            }
            SourceRef::Output(artifact_id) => self.materialize_artifact(*artifact_id).await,
        }
    }

    async fn materialize_artifact(
        &mut self,
        artifact_id: TextArtifactId,
    ) -> Result<MaterializedTextSource, ExecutorError> {
        struct OutputStep {
            artifact: TextArtifact,
            execution: TextExecutionId,
            prompt_tokens: TokenIds,
            generated_tokens: TokenIds,
            state_tokens: TokenIds,
        }

        let mut current = artifact_id;
        let mut visited_artifacts = HashSet::new();
        let mut visited_executions = HashSet::new();
        let mut steps = Vec::new();
        let execution_environment = loop {
            if !visited_artifacts.insert(current) {
                return Err(ExecutorError::InvalidQuoteRequest(format!(
                    "evaluate artifact graph contains a cycle at {current}"
                )));
            }
            let artifact = self.text_artifact(current).await?;
            match artifact {
                TextArtifact::Identity { bound_term } => {
                    break ContentId::from_bytes(*bound_term.as_bytes());
                }
                TextArtifact::Output(output) => {
                    if steps.len() >= MAX_TEXT_ARTIFACT_CHAIN_DEPTH {
                        return Err(ExecutorError::InvalidQuoteRequest(format!(
                            "evaluate artifact graph exceeds {MAX_TEXT_ARTIFACT_CHAIN_DEPTH} outputs"
                        )));
                    }
                    let execution_id = output.execution();
                    if !visited_executions.insert(execution_id) {
                        return Err(ExecutorError::InvalidQuoteRequest(format!(
                            "evaluate artifact graph repeats execution {execution_id}"
                        )));
                    }
                    let execution = self.text_execution(execution_id).await?;
                    let prompt_tokens = self.token_ids(execution.prompt_tokens()).await?;
                    let generated_tokens = self.token_ids(output.generated_tokens()).await?;
                    let state = self.text_state(output.state()).await?;
                    let state_tokens = self.token_ids(state.tokens()).await?;
                    current = match execution.from() {
                        SourceRef::Output(parent) => *parent,
                        SourceRef::Input(parent_execution) => {
                            let parent = self
                                .output_artifact_for_execution(*parent_execution)
                                .await?;
                            let parent_artifact = self.text_artifact(parent).await?;
                            validate_execution_output_mapping(
                                *parent_execution,
                                parent,
                                &parent_artifact,
                            )?;
                            parent
                        }
                    };
                    steps.push(OutputStep {
                        artifact: TextArtifact::Output(output),
                        execution: execution_id,
                        prompt_tokens,
                        generated_tokens,
                        state_tokens,
                    });
                }
            }
        };

        let mut tokens = Vec::new();
        for step in steps.into_iter().rev() {
            let mut input = tokens;
            input.extend(token_ids_to_u32(&step.prompt_tokens));
            let generated = token_ids_to_u32(&step.generated_tokens);
            let expected = completed_text(step.execution, &input, &generated);
            if expected.artifact != step.artifact || expected.state_tokens != step.state_tokens {
                return Err(ExecutorError::InvalidQuoteRequest(format!(
                    "evaluate output artifact for {} is inconsistent with its execution and token bodies",
                    step.execution
                )));
            }
            tokens = token_ids_to_u32(&step.state_tokens);
        }

        Ok(MaterializedTextSource {
            execution_environment,
            tokens,
        })
    }

    async fn output_artifact_for_execution(
        &mut self,
        execution_id: TextExecutionId,
    ) -> Result<TextArtifactId, ExecutorError> {
        if let Some(artifact) = self.outputs_by_execution.get(&execution_id) {
            return Ok(*artifact);
        }
        if !self.execution_output_keys.contains(&execution_id) {
            return Err(ExecutorError::InvalidQuoteRequest(format!(
                "lazy evaluate source {execution_id} has no cached output artifact"
            )));
        }
        let storage = self.storage.as_ref().ok_or_else(|| {
            ExecutorError::ArtifactStore("execution output storage is unavailable".to_string())
        })?;
        let bytes = storage
            .read(EXECUTION_OUTPUT_PARTITION, execution_id.as_bytes().to_vec())
            .await
            .map_err(storage_error)?;
        let artifact = decode_artifact_id(&bytes, execution_id)?;
        self.outputs_by_execution.insert(execution_id, artifact);
        Ok(artifact)
    }

    typed_canonical_artifacts! {
        token_ids, insert_token_ids, TokenIdsId, TokenIds, token_ids, output_id;
        text_policy, insert_policy, TextPolicyId, TextPolicy, policies, output_id;
        text_execution, insert_text_execution, TextExecutionId, TextExecution, text_executions, input_id;
        text_state, insert_text_state, TextStateId, TextState, text_states, output_id;
        text_artifact, insert_text_artifact, TextArtifactId, TextArtifact, text_artifacts, output_id;
    }

    async fn decode_canonical<T: CanonicalDecode>(
        &mut self,
        digest: Digest,
        kind: &str,
    ) -> Result<T, ExecutorError> {
        let bytes = self.load_canonical(digest, kind).await?;
        T::from_canonical_bytes(&bytes).map_err(|err| {
            ExecutorError::ArtifactStore(format!("invalid {kind} artifact {digest}: {err}"))
        })
    }

    async fn load_canonical(
        &mut self,
        digest: Digest,
        kind: &str,
    ) -> Result<Vec<u8>, ExecutorError> {
        self.read_blob(digest).await?.ok_or_else(|| {
            ExecutorError::InvalidQuoteRequest(format!("missing {kind} artifact {digest}"))
        })
    }

    async fn insert_canonical(
        &mut self,
        digest: Digest,
        value: &impl Canonical,
    ) -> Result<(), ExecutorError> {
        if self.canonical_keys.contains(&digest) {
            return Ok(());
        }

        let bytes = value.canonical_bytes();
        self.persist_blob(digest, &bytes).await?;
        Ok(())
    }

    async fn reserve_retained_execution(
        &mut self,
        execution: TextExecutionId,
    ) -> Result<(), ExecutorError> {
        if self.retained_executions.contains(&execution) {
            return Ok(());
        }
        if self.retained_executions.len() >= self.retained_execution_capacity {
            return Err(ExecutorError::ResourceExhausted(format!(
                "retained Evaluate execution capacity of {} is exhausted",
                self.retained_execution_capacity
            )));
        }
        let Some(storage) = &self.storage else {
            self.retained_executions.insert(execution);
            return Ok(());
        };
        let existing = storage
            .write_once(
                RETAINED_EXECUTION_PARTITION,
                execution.as_bytes().to_vec(),
                encode_execution_reservation(execution),
            )
            .await
            .map_err(storage_error)?;
        if let Some(bytes) = existing {
            decode_execution_reservation(&bytes, execution)?;
        }
        self.retained_executions.insert(execution);
        Ok(())
    }

    async fn persist_execution_output(
        &mut self,
        execution: TextExecutionId,
        artifact: TextArtifactId,
    ) -> Result<TextArtifactId, ExecutorError> {
        let Some(storage) = &self.storage else {
            self.execution_output_keys.insert(execution);
            return Ok(artifact);
        };
        let existing = storage
            .write_once(
                EXECUTION_OUTPUT_PARTITION,
                execution.as_bytes().to_vec(),
                encode_artifact_id(artifact),
            )
            .await
            .map_err(storage_error)?;
        self.execution_output_keys.insert(execution);
        let Some(existing) = existing else {
            return Ok(artifact);
        };
        match decode_artifact_id(&existing, execution) {
            Ok(existing) => Ok(existing),
            Err(_) => {
                storage
                    .replace(
                        EXECUTION_OUTPUT_PARTITION,
                        execution.as_bytes().to_vec(),
                        encode_artifact_id(artifact),
                    )
                    .await
                    .map_err(storage_error)?;
                Ok(artifact)
            }
        }
    }
}

fn canonical_type_mismatch(kind: &str, digest: Digest) -> ExecutorError {
    ExecutorError::ArtifactStore(format!(
        "decoded {kind} artifact does not re-address to requested digest {digest}"
    ))
}

fn validate_execution_output_mapping(
    execution_id: TextExecutionId,
    artifact_id: TextArtifactId,
    artifact: &TextArtifact,
) -> Result<(), ExecutorError> {
    match artifact {
        TextArtifact::Output(output) if output.execution() == execution_id => Ok(()),
        TextArtifact::Output(output) => Err(ExecutorError::InvalidQuoteRequest(format!(
            "lazy evaluate source {execution_id} maps to artifact {artifact_id}, but that artifact realizes {}",
            output.execution()
        ))),
        TextArtifact::Identity { .. } => Err(ExecutorError::InvalidQuoteRequest(format!(
            "lazy evaluate source {execution_id} maps to identity artifact {artifact_id}"
        ))),
    }
}

async fn scan_digests(
    storage: &Arc<dyn ArtifactStorage>,
    partition: &'static str,
) -> Result<HashSet<Digest>, ExecutorError> {
    storage
        .scan(partition)
        .await
        .map_err(storage_error)?
        .into_iter()
        .map(|name| {
            let len = name.len();
            let bytes = name.try_into().map_err(|_| {
                ExecutorError::ArtifactStore(format!(
                    "invalid {partition} key length {len}, expected 32"
                ))
            })?;
            Ok(Digest::from_bytes(bytes))
        })
        .collect()
}

fn decode_artifact_id(
    bytes: &[u8],
    execution: TextExecutionId,
) -> Result<TextArtifactId, ExecutorError> {
    let record: &[u8; 64] = bytes.try_into().map_err(|_| {
        ExecutorError::ArtifactStore(format!(
            "invalid output mapping for {execution}: expected 64 bytes, got {}",
            bytes.len()
        ))
    })?;
    let artifact: [u8; 32] = record[..32].try_into().expect("fixed record prefix");
    let checksum: [u8; 32] = record[32..].try_into().expect("fixed record suffix");
    if Digest::hash(&artifact) != Digest::from_bytes(checksum) {
        return Err(ExecutorError::ArtifactStore(format!(
            "invalid output mapping checksum for {execution}"
        )));
    }
    Ok(TextArtifactId::from_bytes(artifact))
}

fn encode_artifact_id(artifact: TextArtifactId) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(artifact.as_bytes());
    bytes.extend_from_slice(Digest::hash(artifact.as_bytes()).as_bytes());
    bytes
}

fn decode_execution_reservation(
    bytes: &[u8],
    execution: TextExecutionId,
) -> Result<(), ExecutorError> {
    let record: &[u8; 64] = bytes.try_into().map_err(|_| {
        ExecutorError::ArtifactStore(format!(
            "invalid retained execution reservation for {execution}: expected 64 bytes, got {}",
            bytes.len()
        ))
    })?;
    let named: [u8; 32] = record[..32].try_into().expect("fixed record prefix");
    let checksum: [u8; 32] = record[32..].try_into().expect("fixed record suffix");
    if named != *execution.as_bytes() || Digest::hash(&named) != Digest::from_bytes(checksum) {
        return Err(ExecutorError::ArtifactStore(format!(
            "invalid retained execution reservation for {execution}"
        )));
    }
    Ok(())
}

fn encode_execution_reservation(execution: TextExecutionId) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(execution.as_bytes());
    bytes.extend_from_slice(Digest::hash(execution.as_bytes()).as_bytes());
    bytes
}

fn storage_error(message: String) -> ExecutorError {
    ExecutorError::ArtifactStore(message)
}

fn token_ids_to_u32(tokens: &TokenIds) -> Vec<u32> {
    tokens
        .as_slice()
        .iter()
        .map(|token| token.as_u32())
        .collect()
}

#[cfg(test)]
mod tests;
