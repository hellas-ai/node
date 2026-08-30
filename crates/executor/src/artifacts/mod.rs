use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::ExecutorError;
use hellas_rpc::{ContentId, Digest, EvaluateRequest};

use crate::artifact_store::{ArtifactStorage, ArtifactStoreConfig};
use crate::state::{Invocation, PackageLocator, QuotePlan};

use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical, CanonicalDecode, InputAddressed, OutputAddressed, SourceRef,
    TextArtifact, TextArtifactId, TextExecution, TextExecutionId, TextPolicy, TextPolicyId,
    TextSource, TextState, TextStateId, TokenIds, TokenIdsId, completed_text,
};

const CANONICAL_PARTITION: &str = "evaluate_canonical";
const EXECUTION_OUTPUT_PARTITION: &str = "evaluate_execution_outputs";
const MAX_TEXT_ARTIFACT_CHAIN_DEPTH: usize = 1024;

#[derive(Clone, Debug)]
pub(crate) struct ResolvedEvaluateExecution {
    pub evaluate_request: EvaluateRequest,
    pub locator: PackageLocator,
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

pub(crate) struct EvaluateArtifactStore {
    storage: Option<Arc<dyn ArtifactStorage>>,
    canonical_keys: HashSet<Digest>,
    execution_output_keys: HashSet<TextExecutionId>,
    canonical_blobs: HashMap<Digest, Vec<u8>>,
    token_ids: HashMap<TokenIdsId, TokenIds>,
    policies: HashMap<TextPolicyId, TextPolicy>,
    text_executions: HashMap<TextExecutionId, TextExecution>,
    text_states: HashMap<TextStateId, TextState>,
    text_artifacts: HashMap<TextArtifactId, TextArtifact>,
    outputs_by_execution: HashMap<TextExecutionId, TextArtifactId>,
}

struct MaterializedTextSource {
    locator: PackageLocator,
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
                if let Some(value) = self.$cache.get(&id).cloned() {
                    return Ok(value);
                }
                let value = self
                    .decode_canonical::<$value>(id.digest(), stringify!($value))
                    .await?;
                if value.$identity() != id {
                    return Err(canonical_type_mismatch(stringify!($value), id.digest()));
                }
                self.$cache.insert(id, value.clone());
                Ok(value)
            }

            async fn $insert(&mut self, value: $value) -> Result<$id, ExecutorError> {
                let id = value.$identity();
                self.insert_canonical(id.digest(), &value).await?;
                self.$cache.entry(id).or_insert(value);
                Ok(id)
            }
        )+
    };
}

impl EvaluateArtifactStore {
    pub(crate) fn memory() -> Self {
        Self::new(None)
    }

    pub(crate) async fn open(config: ArtifactStoreConfig) -> Result<Self, ExecutorError> {
        let Some(storage) = config.storage() else {
            return Ok(Self::memory());
        };
        let canonical_keys = scan_digests(&storage, CANONICAL_PARTITION).await?;
        let execution_output_keys = scan_digests(&storage, EXECUTION_OUTPUT_PARTITION)
            .await?
            .into_iter()
            .map(TextExecutionId::from_digest)
            .collect();
        Ok(Self {
            storage: Some(storage),
            canonical_keys,
            execution_output_keys,
            canonical_blobs: HashMap::new(),
            token_ids: HashMap::new(),
            policies: HashMap::new(),
            text_executions: HashMap::new(),
            text_states: HashMap::new(),
            text_artifacts: HashMap::new(),
            outputs_by_execution: HashMap::new(),
        })
    }

    fn new(storage: Option<Arc<dyn ArtifactStorage>>) -> Self {
        Self {
            storage,
            canonical_keys: HashSet::new(),
            execution_output_keys: HashSet::new(),
            canonical_blobs: HashMap::new(),
            token_ids: HashMap::new(),
            policies: HashMap::new(),
            text_executions: HashMap::new(),
            text_states: HashMap::new(),
            text_artifacts: HashMap::new(),
            outputs_by_execution: HashMap::new(),
        }
    }

    async fn persist_blob(&mut self, digest: Digest, bytes: &[u8]) -> Result<(), ExecutorError> {
        if Digest::hash(bytes) != digest {
            return Err(ExecutorError::ArtifactStore(format!(
                "canonical bytes do not match digest {digest}"
            )));
        }
        let Some(storage) = &self.storage else {
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
                if source.locator != plan.locator
                    || source.execution_environment != execution_environment
                {
                    return Err(ExecutorError::InvalidQuoteRequest(
                        "initial artifact belongs to a different Catena package".to_string(),
                    ));
                }
                (SourceRef::output(artifact_id), source.tokens, None)
            }
            None => {
                let identity =
                    TextArtifact::identity(bound_term_id, plan.locator.execution_package);
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
        plan.validate_invocation(&invocation)?;

        let prompt_tokens = TokenIds::from(plan.invocation.input_ids.clone());
        let prompt_tokens_id = prompt_tokens.output_id();
        let policy = text_policy(&plan.invocation);
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
            locator: plan.locator,
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
            locator: source.locator,
            invocation: Invocation {
                input_ids,
                max_new_tokens: policy.max_new_tokens(),
                stop_token_ids,
            },
            prepared_artifacts: None,
        })
    }

    pub async fn publish_canonical_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<Digest, ExecutorError> {
        let digest = Digest::hash(&bytes);
        if !self.canonical_blobs.contains_key(&digest) {
            self.persist_blob(digest, &bytes).await?;
            self.canonical_blobs.insert(digest, bytes);
        }
        Ok(digest)
    }

    pub async fn get_canonical_bytes(&mut self, digest: Digest) -> Result<Vec<u8>, ExecutorError> {
        if let Some(bytes) = self.canonical_blobs.get(&digest) {
            return Ok(bytes.clone());
        }
        let bytes = self
            .read_blob(digest)
            .await?
            .ok_or_else(|| ExecutorError::ArtifactNotFound(digest.to_string()))?;
        self.canonical_blobs.insert(digest, bytes.clone());
        Ok(bytes)
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
            self.publish_prepared_text(prepared).await?;
            let prepared_id = prepared.execution.input_id();
            if prepared_id != execution_id {
                return Err(ExecutorError::ArtifactStore(
                    "prepared execution does not match evaluate request".to_string(),
                ));
            }
        }
        let _ = self.text_execution(execution_id).await?;

        let completed = completed_text(execution_id, &invocation.input_ids, output_tokens);
        self.insert_token_ids(completed.generated_tokens).await?;
        self.insert_token_ids(completed.state_tokens).await?;
        self.insert_text_state(completed.state).await?;
        let artifact_id = self.insert_text_artifact(completed.artifact).await?;
        if !self.outputs_by_execution.contains_key(&execution_id) {
            let stored = self
                .persist_execution_output(execution_id, artifact_id)
                .await?;
            self.outputs_by_execution.insert(execution_id, stored);
        }
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
                self.materialize_execution_output(*execution_id, artifact_id)
                    .await
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
        let (locator, execution_environment) = loop {
            if !visited_artifacts.insert(current) {
                return Err(ExecutorError::InvalidQuoteRequest(format!(
                    "evaluate artifact graph contains a cycle at {current}"
                )));
            }
            let artifact = self.text_artifact(current).await?;
            match artifact {
                TextArtifact::Identity {
                    bound_term,
                    execution_package,
                } => {
                    let locator = PackageLocator { execution_package };
                    let execution_environment = ContentId::from_bytes(*bound_term.as_bytes());
                    if execution_environment != QuotePlan::execution_environment(locator) {
                        return Err(ExecutorError::InvalidQuoteRequest(
                            "identity artifact bound term does not match its Catena package"
                                .to_string(),
                        ));
                    }
                    break (locator, execution_environment);
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
            locator,
            execution_environment,
            tokens,
        })
    }

    async fn materialize_execution_output(
        &mut self,
        execution_id: TextExecutionId,
        artifact_id: TextArtifactId,
    ) -> Result<MaterializedTextSource, ExecutorError> {
        let artifact = self.text_artifact(artifact_id).await?;
        validate_execution_output_mapping(execution_id, artifact_id, &artifact)?;
        self.materialize_artifact(artifact_id).await
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
        if let Some(bytes) = self.canonical_blobs.get(&digest) {
            return Ok(bytes.clone());
        }
        let bytes = self.read_blob(digest).await?.ok_or_else(|| {
            ExecutorError::InvalidQuoteRequest(format!("missing {kind} artifact {digest}"))
        })?;
        self.canonical_blobs.insert(digest, bytes.clone());
        Ok(bytes)
    }

    async fn insert_canonical(
        &mut self,
        digest: Digest,
        value: &impl Canonical,
    ) -> Result<(), ExecutorError> {
        if self.canonical_blobs.contains_key(&digest) {
            return Ok(());
        }

        let bytes = value.canonical_bytes();
        self.persist_blob(digest, &bytes).await?;
        self.canonical_blobs.insert(digest, bytes);
        Ok(())
    }

    async fn persist_execution_output(
        &mut self,
        execution: TextExecutionId,
        artifact: TextArtifactId,
    ) -> Result<TextArtifactId, ExecutorError> {
        let Some(storage) = &self.storage else {
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

fn text_policy(invocation: &Invocation) -> TextPolicy {
    TextPolicy::from_u32_stop_tokens(
        invocation.max_new_tokens,
        invocation.stop_token_ids.iter().copied(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        Blob as _, Runner as _, Storage as _, Supervisor as _, deterministic,
    };
    use hellas_rpc::ExecutionPackageId;

    fn runner_public_key() -> hellas_rpc::PublicKey {
        hellas_rpc::ProducerSigningKey::from_secret_bytes([8; 32])
            .expect("valid test key")
            .public_key()
    }

    fn evaluate_request(text_execution: Digest) -> EvaluateRequest {
        EvaluateRequest {
            text_execution,
            runner_public_key: runner_public_key(),
            execution_environment: plan().execution_environment,
            nonce: [7; 32],
            assurance: hellas_rpc::Assurance::ProducerSigned,
            retain: true,
        }
    }

    fn plan() -> QuotePlan {
        let locator = PackageLocator {
            execution_package: ExecutionPackageId::from_bytes([8; 32]),
        };
        QuotePlan {
            locator,
            vocabulary_size: u64::from(u32::MAX) + 1,
            maximum_capacity: u64::MAX,
            execution_environment: QuotePlan::execution_environment(locator),
            invocation: Invocation {
                input_ids: vec![1, 2, 3],
                max_new_tokens: 8,
                stop_token_ids: vec![4, 5],
            },
            initial_artifact_id: None,
            runner_public_key: runner_public_key(),
            assurance: hellas_rpc::Assurance::ProducerSigned,
            retention: hellas_rpc::Retention::Retain,
        }
    }

    #[tokio::test]
    async fn prepared_text_round_trips_through_store() {
        let mut store = EvaluateArtifactStore::default();
        let recorded = store.record_prepared_text(&plan()).await.unwrap();
        let resolved = store
            .resolve_evaluate_request(recorded.evaluate_request.clone())
            .await
            .unwrap();

        assert_eq!(resolved.evaluate_request, recorded.evaluate_request);
        assert_eq!(resolved.locator, recorded.locator);
        assert_eq!(resolved.invocation.input_ids, recorded.invocation.input_ids);
        assert_eq!(
            resolved.invocation.max_new_tokens,
            recorded.invocation.max_new_tokens
        );
        assert_eq!(
            resolved.invocation.stop_token_ids,
            recorded.invocation.stop_token_ids
        );
    }

    #[tokio::test]
    async fn completed_text_artifact_can_start_a_followup() {
        let mut store = EvaluateArtifactStore::default();
        let first = store.record_prepared_text(&plan()).await.unwrap();
        let first_artifact = store
            .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
            .await
            .unwrap();
        let mut next_plan = plan();
        next_plan.invocation.input_ids = vec![20];
        next_plan.initial_artifact_id = Some(first_artifact);
        let next = store.record_prepared_text(&next_plan).await.unwrap();
        assert_eq!(next.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
        let resolved = store
            .resolve_evaluate_request(next.evaluate_request)
            .await
            .unwrap();

        assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
    }

    #[tokio::test]
    async fn followup_rejects_an_output_artifact_with_inconsistent_state() {
        let mut store = EvaluateArtifactStore::default();
        let first = store.record_prepared_text(&plan()).await.unwrap();
        let execution = TextExecutionId::from_digest(first.evaluate_request.text_execution);
        let generated = store
            .insert_token_ids(TokenIds::from([10, 11]))
            .await
            .unwrap();
        let wrong_state_tokens = store.insert_token_ids(TokenIds::from([99])).await.unwrap();
        let wrong_state = store
            .insert_text_state(TextState::new(wrong_state_tokens))
            .await
            .unwrap();
        let inconsistent = store
            .insert_text_artifact(TextArtifact::output(execution, 2, wrong_state, generated))
            .await
            .unwrap();
        let mut next_plan = plan();
        next_plan.initial_artifact_id = Some(inconsistent.digest());

        let error = store.prepare_text(&next_plan).await.unwrap_err();
        assert!(error.to_string().contains("is inconsistent"), "{error}");
    }

    #[tokio::test]
    async fn followup_revalidates_full_context_capacity() {
        let mut store = EvaluateArtifactStore::default();
        let first = store.record_prepared_text(&plan()).await.unwrap();
        let first_artifact = store
            .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
            .await
            .unwrap();
        let mut next_plan = plan();
        next_plan.invocation.input_ids = vec![20];
        next_plan.maximum_capacity = 13;
        next_plan.initial_artifact_id = Some(first_artifact);

        let error = store.record_prepared_text(&next_plan).await.unwrap_err();
        assert!(error.to_string().contains("package capacity is 13"));
    }

    #[tokio::test]
    async fn followup_rejects_an_artifact_from_another_package() {
        let mut store = EvaluateArtifactStore::default();
        let mut other = plan();
        other.locator.execution_package = ExecutionPackageId::from_bytes([9; 32]);
        other.execution_environment = QuotePlan::execution_environment(other.locator);
        let first = store.record_prepared_text(&other).await.unwrap();
        let first_artifact = store
            .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
            .await
            .unwrap();
        let mut next_plan = plan();
        next_plan.initial_artifact_id = Some(first_artifact);

        let error = store.record_prepared_text(&next_plan).await.unwrap_err();
        assert!(error.to_string().contains("different Catena package"));
    }

    #[tokio::test]
    async fn lazy_input_source_uses_cached_output_artifact() {
        let mut store = EvaluateArtifactStore::default();
        let first = store.record_prepared_text(&plan()).await.unwrap();
        store
            .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
            .await
            .unwrap();
        let first_execution = TextExecutionId::from_digest(first.evaluate_request.text_execution);
        let prompt_tokens = store.insert_token_ids(TokenIds::from([20])).await.unwrap();
        let policy = store
            .insert_policy(TextPolicy::from_u32_stop_tokens(4, []))
            .await
            .unwrap();
        let lazy = TextExecution::new(SourceRef::input(first_execution), prompt_tokens, policy);
        let lazy_id = store.insert_text_execution(lazy).await.unwrap();
        let resolved = store
            .resolve_evaluate_request(evaluate_request(lazy_id.digest()))
            .await
            .unwrap();

        assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
    }

    #[tokio::test]
    async fn lazy_input_rejects_metadata_that_does_not_realize_execution() {
        let mut store = EvaluateArtifactStore::default();
        let first = store.record_prepared_text(&plan()).await.unwrap();
        let first_execution = TextExecutionId::from_digest(first.evaluate_request.text_execution);
        let first_execution_value = store.text_execution(first_execution).await.unwrap();
        let identity_id = match first_execution_value.from() {
            SourceRef::Output(id) => *id,
            SourceRef::Input(_) => panic!("prepared genesis text should start at output"),
        };
        store
            .outputs_by_execution
            .insert(first_execution, identity_id);
        let prompt_tokens = store.insert_token_ids(TokenIds::from([20])).await.unwrap();
        let policy = store
            .insert_policy(TextPolicy::from_u32_stop_tokens(4, []))
            .await
            .unwrap();
        let lazy = TextExecution::new(SourceRef::input(first_execution), prompt_tokens, policy);
        let lazy_id = store.insert_text_execution(lazy).await.unwrap();
        let err = store
            .resolve_evaluate_request(evaluate_request(lazy_id.digest()))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("maps to identity artifact"));
    }

    #[tokio::test]
    async fn unknown_text_execution_is_rejected() {
        let mut store = EvaluateArtifactStore::default();
        let err = store
            .resolve_evaluate_request(evaluate_request(Digest::from_bytes([7; 32])))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("missing TextExecution artifact"));
    }

    #[tokio::test]
    async fn canonical_artifact_bytes_can_be_published_and_fetched() {
        let mut store = EvaluateArtifactStore::default();
        let tokens = TokenIds::from([1, 2, 3]);
        let bytes = tokens.canonical_bytes();
        let digest = store.publish_canonical_bytes(bytes.clone()).await.unwrap();

        assert_eq!(digest, tokens.output_id().digest());
        assert_eq!(store.get_canonical_bytes(digest).await.unwrap(), bytes);
    }

    #[test]
    fn quotes_publish_nothing_and_successful_retained_execution_publishes_its_graph() {
        deterministic::Runner::default().start(|context| async move {
            let config = ArtifactStoreConfig::new(context.child("retained"));
            let mut store = EvaluateArtifactStore::open(config.clone()).await.unwrap();

            let mut ephemeral_plan = plan();
            ephemeral_plan.retention = hellas_rpc::Retention::Ephemeral;
            let ephemeral = store.prepare_text(&ephemeral_plan).await.unwrap();

            assert!(
                store
                    .get_canonical_bytes(ephemeral.evaluate_request.text_execution)
                    .await
                    .is_err(),
                "an unused quote must publish no token graph"
            );
            let mut reopened = EvaluateArtifactStore::open(config.clone()).await.unwrap();
            assert!(
                reopened
                    .get_canonical_bytes(ephemeral.evaluate_request.text_execution)
                    .await
                    .is_err(),
                "ephemeral token graph must not enter persistent storage"
            );

            let retained = store.prepare_text(&plan()).await.unwrap();
            store
                .record_completed_text_with_prepared(
                    &retained.evaluate_request,
                    &retained.invocation,
                    &[10, 11],
                    retained.prepared_artifacts.as_ref(),
                )
                .await
                .unwrap();

            let mut reopened = EvaluateArtifactStore::open(config).await.unwrap();
            assert!(
                reopened
                    .get_canonical_bytes(retained.evaluate_request.text_execution)
                    .await
                    .is_ok(),
                "retained artifacts must remain available from persistent storage"
            );
        });
    }

    #[test]
    fn commonware_store_rejects_corrupt_canonical_blob() {
        deterministic::Runner::default().start(|context| async move {
            let config = ArtifactStoreConfig::new(context.child("artifacts"));
            let digest = {
                let mut store = EvaluateArtifactStore::open(config.clone()).await.unwrap();
                store
                    .publish_canonical_bytes(b"valid".to_vec())
                    .await
                    .unwrap()
            };
            let (blob, _) = context
                .open(CANONICAL_PARTITION, digest.as_bytes())
                .await
                .unwrap();
            blob.resize(0).await.unwrap();
            blob.write_at_sync(0, b"corrupt".to_vec()).await.unwrap();

            let mut store = EvaluateArtifactStore::open(config).await.unwrap();
            let err = store.get_canonical_bytes(digest).await.unwrap_err();
            assert!(err.to_string().contains("does not match requested digest"));
        });
    }

    #[test]
    fn commonware_store_reopens_typed_artifacts_from_canonical_blobs() {
        deterministic::Runner::default().start(|context| async move {
            let config = ArtifactStoreConfig::new(context);
            let first_artifact;
            let first_request;
            {
                let mut store = EvaluateArtifactStore::open(config.clone()).await.unwrap();
                let first = store.record_prepared_text(&plan()).await.unwrap();
                first_artifact = store
                    .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
                    .await
                    .unwrap();
                first_request = first.evaluate_request;
            }

            let mut store = EvaluateArtifactStore::open(config).await.unwrap();
            let resolved = store.resolve_evaluate_request(first_request).await.unwrap();
            assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3]);

            let mut next_plan = plan();
            next_plan.invocation.input_ids = vec![20];
            next_plan.initial_artifact_id = Some(first_artifact);
            let next = store.record_prepared_text(&next_plan).await.unwrap();
            let resolved = store
                .resolve_evaluate_request(next.evaluate_request)
                .await
                .unwrap();
            assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
        });
    }

    #[test]
    fn commonware_store_reopens_cached_lazy_substitutions() {
        deterministic::Runner::default().start(|context| async move {
            let config = ArtifactStoreConfig::new(context);
            let first_execution;
            {
                let mut store = EvaluateArtifactStore::open(config.clone()).await.unwrap();
                let first = store.record_prepared_text(&plan()).await.unwrap();
                store
                    .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
                    .await
                    .unwrap();
                first_execution =
                    TextExecutionId::from_digest(first.evaluate_request.text_execution);
            }

            let mut store = EvaluateArtifactStore::open(config).await.unwrap();
            let prompt_tokens = store.insert_token_ids(TokenIds::from([20])).await.unwrap();
            let policy = store
                .insert_policy(TextPolicy::from_u32_stop_tokens(4, []))
                .await
                .unwrap();
            let lazy = TextExecution::new(SourceRef::input(first_execution), prompt_tokens, policy);
            let lazy_id = store.insert_text_execution(lazy).await.unwrap();
            let resolved = store
                .resolve_evaluate_request(evaluate_request(lazy_id.digest()))
                .await
                .unwrap();

            assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
        });
    }
}
