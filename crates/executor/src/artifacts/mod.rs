use std::collections::{HashMap, hash_map::Entry};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use hellas_rpc::ExecutorError;
use hellas_rpc::{Digest, EvaluateRequest, hash_tuple};
use serde::{Deserialize, Serialize};

use crate::state::{Invocation, ModelLocator, QuotePlan};

mod schema;

use schema::{
    BoundTermId, Canonical, CanonicalDecode, Digest as ArtifactDigest, InputAddressed,
    OutputAddressed, SourceRef, TextArtifact, TextArtifactId, TextExecution, TextExecutionId,
    TextPolicy, TextPolicyId, TextSource, TextState, TextStateId, TokenId, TokenIds, TokenIdsId,
};

const EVALUATE_INDEX_FILE: &str = "evaluate-index.json";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactStoreConfig {
    Memory,
    Fs(PathBuf),
}

impl ArtifactStoreConfig {
    pub fn memory() -> Self {
        Self::Memory
    }

    pub fn fs(path: impl Into<PathBuf>) -> Self {
        Self::Fs(path.into())
    }
}

enum ArtifactBlobStore {
    Memory(iroh_blobs::store::mem::MemStore),
    Fs(iroh_blobs::store::fs::FsStore),
}

impl Default for ArtifactBlobStore {
    fn default() -> Self {
        Self::memory()
    }
}

impl ArtifactBlobStore {
    fn memory() -> Self {
        Self::Memory(iroh_blobs::store::mem::MemStore::default())
    }

    async fn fs(path: impl AsRef<Path>) -> Result<Self, ExecutorError> {
        let path = path.as_ref();
        let store = iroh_blobs::store::fs::FsStore::load(path)
            .await
            .map_err(|err| {
                ExecutorError::ArtifactStore(format!(
                    "failed to open artifact blob store {}: {err}",
                    path.display()
                ))
            })?;
        Ok(Self::Fs(store))
    }

    async fn insert_canonical(
        &self,
        digest: ArtifactDigest,
        bytes: &[u8],
    ) -> Result<(), ExecutorError> {
        let expected = iroh_hash(digest);
        let tag = match self {
            Self::Memory(store) => store.add_slice(bytes).await,
            Self::Fs(store) => store.add_slice(bytes).await,
        }
        .map_err(|err| ExecutorError::ArtifactStore(format!("blob insert failed: {err}")))?;

        if tag.hash != expected {
            return Err(ExecutorError::ArtifactStore(format!(
                "blob store hash mismatch: expected {}, got {}",
                expected.to_hex(),
                tag.hash.to_hex()
            )));
        }

        Ok(())
    }

    async fn get_canonical(
        &self,
        digest: ArtifactDigest,
    ) -> Result<Option<Vec<u8>>, ExecutorError> {
        let hash = iroh_hash(digest);
        let has_blob = match self {
            Self::Memory(store) => store.has(hash).await,
            Self::Fs(store) => store.has(hash).await,
        }
        .map_err(|err| ExecutorError::ArtifactStore(format!("blob lookup failed: {err}")))?;
        if !has_blob {
            return Ok(None);
        }

        let bytes = match self {
            Self::Memory(store) => store.get_bytes(hash).await,
            Self::Fs(store) => store.get_bytes(hash).await,
        }
        .map_err(|err| ExecutorError::ArtifactStore(format!("blob read failed: {err}")))?
        .to_vec();

        if ArtifactDigest::from_canonical_bytes(&bytes) != digest {
            return Err(ExecutorError::ArtifactStore(format!(
                "blob store returned bytes that do not match requested digest {digest}"
            )));
        }

        Ok(Some(bytes))
    }

    #[cfg(test)]
    async fn shutdown(&self) -> Result<(), ExecutorError> {
        match self {
            Self::Memory(store) => store.shutdown().await,
            Self::Fs(store) => store.shutdown().await,
        }
        .map_err(|err| ExecutorError::ArtifactStore(format!("blob store shutdown failed: {err}")))
    }
}

#[derive(Default)]
struct EvaluateIndexData {
    bound_terms: HashMap<BoundTermId, ModelLocator>,
    outputs_by_execution: HashMap<TextExecutionId, TextArtifactId>,
}

#[derive(Default, Serialize, Deserialize)]
struct PersistedEvaluateIndex {
    #[serde(default)]
    bound_terms: Vec<PersistedBoundTerm>,
    #[serde(default)]
    outputs_by_execution: Vec<PersistedExecutionOutput>,
}

#[derive(Serialize, Deserialize)]
struct PersistedBoundTerm {
    bound_term: String,
    model_id: String,
    revision: String,
    dtype: String,
}

#[derive(Serialize, Deserialize)]
struct PersistedExecutionOutput {
    execution: String,
    artifact: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedEvaluateExecution {
    pub evaluate_request: EvaluateRequest,
    pub locator: ModelLocator,
    pub invocation: Invocation,
}

pub(crate) struct EvaluateArtifactStore {
    blob_store: ArtifactBlobStore,
    index_path: Option<PathBuf>,
    canonical_blobs: HashMap<ArtifactDigest, Vec<u8>>,
    bound_terms: HashMap<BoundTermId, ModelLocator>,
    token_ids: HashMap<TokenIdsId, TokenIds>,
    policies: HashMap<TextPolicyId, TextPolicy>,
    text_executions: HashMap<TextExecutionId, TextExecution>,
    text_states: HashMap<TextStateId, TextState>,
    text_artifacts: HashMap<TextArtifactId, TextArtifact>,
    outputs_by_execution: HashMap<TextExecutionId, TextArtifactId>,
}

struct MaterializedTextSource {
    locator: ModelLocator,
    tokens: Vec<u32>,
}

impl Default for EvaluateArtifactStore {
    fn default() -> Self {
        Self::memory()
    }
}

impl EvaluateArtifactStore {
    pub(crate) fn memory() -> Self {
        Self::new(ArtifactBlobStore::memory())
    }

    pub(crate) async fn open(config: ArtifactStoreConfig) -> Result<Self, ExecutorError> {
        match config {
            ArtifactStoreConfig::Memory => Ok(Self::memory()),
            ArtifactStoreConfig::Fs(path) => {
                let index_path = path.join(EVALUATE_INDEX_FILE);
                let index = load_evaluate_index(&index_path)?;
                Ok(Self::with_index(
                    ArtifactBlobStore::fs(path).await?,
                    Some(index_path),
                    index,
                ))
            }
        }
    }

    fn new(blob_store: ArtifactBlobStore) -> Self {
        Self::with_index(blob_store, None, EvaluateIndexData::default())
    }

    fn with_index(
        blob_store: ArtifactBlobStore,
        index_path: Option<PathBuf>,
        index: EvaluateIndexData,
    ) -> Self {
        Self {
            blob_store,
            index_path,
            canonical_blobs: HashMap::new(),
            bound_terms: index.bound_terms,
            token_ids: HashMap::new(),
            policies: HashMap::new(),
            text_executions: HashMap::new(),
            text_states: HashMap::new(),
            text_artifacts: HashMap::new(),
            outputs_by_execution: index.outputs_by_execution,
        }
    }

    pub async fn record_prepared_text(
        &mut self,
        plan: &QuotePlan,
    ) -> Result<ResolvedEvaluateExecution, ExecutorError> {
        let bound_term_id =
            BoundTermId::from_digest(to_artifact_digest(binding_digest(&plan.locator)));
        if let Entry::Vacant(entry) = self.bound_terms.entry(bound_term_id) {
            entry.insert(plan.locator.clone());
            self.persist_evaluate_index()?;
        }

        let from = match plan.initial_artifact_id {
            Some(artifact_id) => {
                let artifact_id = TextArtifactId::from_digest(to_artifact_digest(artifact_id));
                let _ = self.materialize_artifact(artifact_id).await?;
                SourceRef::output(artifact_id)
            }
            None => {
                let identity = TextArtifact::identity(bound_term_id);
                let identity_id = identity.output_id();
                self.insert_text_artifact(identity).await?;
                SourceRef::output(identity_id)
            }
        };

        let prompt_tokens = TokenIds::from(plan.invocation.input_ids.clone());
        let prompt_tokens_id = self.insert_token_ids(prompt_tokens).await?;
        let policy = text_policy(&plan.invocation)?;
        let policy_id = self.insert_policy(policy).await?;
        let execution = TextExecution::new(from, prompt_tokens_id, policy_id);
        let execution_id = self.insert_text_execution(execution).await?;
        let evaluate_request = EvaluateRequest {
            text_execution: from_artifact_digest(execution_id.digest()),
            runner_public_key: plan.runner_public_key,
        };

        Ok(ResolvedEvaluateExecution {
            evaluate_request,
            locator: plan.locator.clone(),
            invocation: plan.invocation.clone(),
        })
    }

    pub async fn resolve_evaluate_request(
        &mut self,
        evaluate_request: EvaluateRequest,
    ) -> Result<ResolvedEvaluateExecution, ExecutorError> {
        let execution_id =
            TextExecutionId::from_digest(to_artifact_digest(evaluate_request.text_execution));
        let execution = self.text_execution(execution_id).await?;
        let source = self.materialize_source(execution.from()).await?;
        let prompt_tokens = self.token_ids(execution.prompt_tokens()).await?;
        let policy = self.text_policy(execution.policy()).await?;
        let mut input_ids = source.tokens;
        input_ids.extend(token_ids_to_u32(&prompt_tokens));
        let stop_token_ids = policy
            .stop_token_ids()
            .iter()
            .map(|token| {
                i32::try_from(token.as_u32()).map_err(|_| {
                    ExecutorError::InvalidTokenPayload(format!(
                        "stop token id {} exceeds i32 range",
                        token.as_u32()
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ResolvedEvaluateExecution {
            evaluate_request,
            locator: source.locator,
            invocation: Invocation {
                input_ids,
                max_new_tokens: policy.max_new_tokens(),
                stop_token_ids,
            },
        })
    }

    pub async fn publish_canonical_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<Digest, ExecutorError> {
        let digest = ArtifactDigest::from_canonical_bytes(&bytes);
        if !self.canonical_blobs.contains_key(&digest) {
            self.blob_store.insert_canonical(digest, &bytes).await?;
            self.canonical_blobs.insert(digest, bytes);
        }
        Ok(from_artifact_digest(digest))
    }

    pub async fn get_canonical_bytes(&mut self, digest: Digest) -> Result<Vec<u8>, ExecutorError> {
        let digest = to_artifact_digest(digest);
        if let Some(bytes) = self.canonical_blobs.get(&digest) {
            return Ok(bytes.clone());
        }
        let bytes = self
            .blob_store
            .get_canonical(digest)
            .await?
            .ok_or_else(|| ExecutorError::ArtifactNotFound(digest.to_string()))?;
        self.canonical_blobs.insert(digest, bytes.clone());
        Ok(bytes)
    }

    pub async fn record_completed_text(
        &mut self,
        evaluate_request: &EvaluateRequest,
        invocation: &Invocation,
        output_tokens: &[u32],
    ) -> Result<Digest, ExecutorError> {
        let execution_id =
            TextExecutionId::from_digest(to_artifact_digest(evaluate_request.text_execution));
        let _ = self.text_execution(execution_id).await?;

        let generated_tokens_id = self
            .insert_token_ids(TokenIds::from(output_tokens.to_vec()))
            .await?;
        let mut state_tokens = invocation.input_ids.clone();
        state_tokens.extend_from_slice(output_tokens);
        let state_tokens_id = self.insert_token_ids(TokenIds::from(state_tokens)).await?;
        let state_id = self
            .insert_text_state(TextState::new(state_tokens_id))
            .await?;
        let artifact = TextArtifact::output(
            execution_id,
            output_tokens.len() as u64,
            state_id,
            generated_tokens_id,
        );
        let artifact_id = self.insert_text_artifact(artifact).await?;
        if let Entry::Vacant(entry) = self.outputs_by_execution.entry(execution_id) {
            entry.insert(artifact_id);
            self.persist_evaluate_index()?;
        }
        Ok(from_artifact_digest(artifact_id.digest()))
    }

    async fn materialize_source(
        &mut self,
        source: &TextSource,
    ) -> Result<MaterializedTextSource, ExecutorError> {
        match source {
            SourceRef::Input(execution_id) => {
                let artifact_id = self.output_artifact_for_execution(*execution_id)?;
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
        let artifact = self.text_artifact(artifact_id).await?;
        self.materialize_decoded_artifact(artifact).await
    }

    async fn materialize_execution_output(
        &mut self,
        execution_id: TextExecutionId,
        artifact_id: TextArtifactId,
    ) -> Result<MaterializedTextSource, ExecutorError> {
        let artifact = self.text_artifact(artifact_id).await?;
        validate_execution_output_mapping(execution_id, artifact_id, &artifact)?;
        self.materialize_decoded_artifact(artifact).await
    }

    async fn materialize_decoded_artifact(
        &mut self,
        artifact: TextArtifact,
    ) -> Result<MaterializedTextSource, ExecutorError> {
        match artifact {
            TextArtifact::Identity { bound_term } => {
                let locator = self.bound_term_locator(bound_term)?;
                Ok(MaterializedTextSource {
                    locator,
                    tokens: Vec::new(),
                })
            }
            TextArtifact::Output(output) => {
                let execution = self.text_execution(output.execution()).await?;
                let locator = self.source_locator(execution.from().clone()).await?;
                let state = self.text_state(output.state()).await?;
                let tokens = self.token_ids(state.tokens()).await?;
                Ok(MaterializedTextSource {
                    locator,
                    tokens: token_ids_to_u32(&tokens),
                })
            }
        }
    }

    async fn source_locator(&mut self, source: TextSource) -> Result<ModelLocator, ExecutorError> {
        let mut source = source;
        loop {
            let (artifact_id, expected_execution) = match source {
                SourceRef::Input(id) => (self.output_artifact_for_execution(id)?, Some(id)),
                SourceRef::Output(id) => (id, None),
            };
            let artifact = self.text_artifact(artifact_id).await?;
            if let Some(expected_execution) = expected_execution {
                validate_execution_output_mapping(expected_execution, artifact_id, &artifact)?;
            }
            match artifact {
                TextArtifact::Identity { bound_term } => {
                    return self.bound_term_locator(bound_term);
                }
                TextArtifact::Output(output) => {
                    source = self
                        .text_execution(output.execution())
                        .await?
                        .from()
                        .clone();
                }
            }
        }
    }

    fn bound_term_locator(&self, bound_term: BoundTermId) -> Result<ModelLocator, ExecutorError> {
        self.bound_terms.get(&bound_term).cloned().ok_or_else(|| {
            ExecutorError::InvalidQuoteRequest(format!("missing bound term metadata {bound_term}"))
        })
    }

    fn output_artifact_for_execution(
        &self,
        execution_id: TextExecutionId,
    ) -> Result<TextArtifactId, ExecutorError> {
        self.outputs_by_execution
            .get(&execution_id)
            .copied()
            .ok_or_else(|| {
                ExecutorError::InvalidQuoteRequest(format!(
                    "lazy evaluate source {execution_id} has no cached output artifact"
                ))
            })
    }

    async fn token_ids(&mut self, id: TokenIdsId) -> Result<TokenIds, ExecutorError> {
        if let Some(value) = self.token_ids.get(&id) {
            return Ok(value.clone());
        }
        let value = self
            .decode_canonical::<TokenIds>(id.digest(), "TokenIds")
            .await?;
        if value.output_id() != id {
            return Err(canonical_type_mismatch("TokenIds", id.digest()));
        }
        self.token_ids.insert(id, value.clone());
        Ok(value)
    }

    async fn text_policy(&mut self, id: TextPolicyId) -> Result<TextPolicy, ExecutorError> {
        if let Some(value) = self.policies.get(&id) {
            return Ok(value.clone());
        }
        let value = self
            .decode_canonical::<TextPolicy>(id.digest(), "TextPolicy")
            .await?;
        if value.output_id() != id {
            return Err(canonical_type_mismatch("TextPolicy", id.digest()));
        }
        self.policies.insert(id, value.clone());
        Ok(value)
    }

    async fn text_execution(
        &mut self,
        id: TextExecutionId,
    ) -> Result<TextExecution, ExecutorError> {
        if let Some(value) = self.text_executions.get(&id) {
            return Ok(value.clone());
        }
        let value = self
            .decode_canonical::<TextExecution>(id.digest(), "TextExecution")
            .await?;
        if value.input_id() != id {
            return Err(canonical_type_mismatch("TextExecution", id.digest()));
        }
        self.text_executions.insert(id, value.clone());
        Ok(value)
    }

    async fn text_state(&mut self, id: TextStateId) -> Result<TextState, ExecutorError> {
        if let Some(value) = self.text_states.get(&id) {
            return Ok(*value);
        }
        let value = self
            .decode_canonical::<TextState>(id.digest(), "TextState")
            .await?;
        if value.output_id() != id {
            return Err(canonical_type_mismatch("TextState", id.digest()));
        }
        self.text_states.insert(id, value);
        Ok(value)
    }

    async fn text_artifact(&mut self, id: TextArtifactId) -> Result<TextArtifact, ExecutorError> {
        if let Some(value) = self.text_artifacts.get(&id) {
            return Ok(*value);
        }
        let value = self
            .decode_canonical::<TextArtifact>(id.digest(), "TextArtifact")
            .await?;
        if value.output_id() != id {
            return Err(canonical_type_mismatch("TextArtifact", id.digest()));
        }
        self.text_artifacts.insert(id, value);
        Ok(value)
    }

    async fn decode_canonical<T: CanonicalDecode>(
        &mut self,
        digest: ArtifactDigest,
        kind: &str,
    ) -> Result<T, ExecutorError> {
        let bytes = self.load_canonical(digest, kind).await?;
        T::from_canonical_bytes(&bytes).map_err(|err| {
            ExecutorError::ArtifactStore(format!("invalid {kind} artifact {digest}: {err}"))
        })
    }

    async fn load_canonical(
        &mut self,
        digest: ArtifactDigest,
        kind: &str,
    ) -> Result<Vec<u8>, ExecutorError> {
        if let Some(bytes) = self.canonical_blobs.get(&digest) {
            return Ok(bytes.clone());
        }
        let bytes = self
            .blob_store
            .get_canonical(digest)
            .await?
            .ok_or_else(|| {
                ExecutorError::InvalidQuoteRequest(format!("missing {kind} artifact {digest}"))
            })?;
        self.canonical_blobs.insert(digest, bytes.clone());
        Ok(bytes)
    }

    async fn insert_token_ids(&mut self, value: TokenIds) -> Result<TokenIdsId, ExecutorError> {
        let id = value.output_id();
        self.insert_canonical(id.digest(), &value).await?;
        self.token_ids.entry(id).or_insert(value);
        Ok(id)
    }

    async fn insert_policy(&mut self, value: TextPolicy) -> Result<TextPolicyId, ExecutorError> {
        let id = value.output_id();
        self.insert_canonical(id.digest(), &value).await?;
        self.policies.entry(id).or_insert(value);
        Ok(id)
    }

    async fn insert_text_execution(
        &mut self,
        value: TextExecution,
    ) -> Result<TextExecutionId, ExecutorError> {
        let id = value.input_id();
        self.insert_canonical(id.digest(), &value).await?;
        self.text_executions.entry(id).or_insert(value);
        Ok(id)
    }

    async fn insert_text_state(&mut self, value: TextState) -> Result<TextStateId, ExecutorError> {
        let id = value.output_id();
        self.insert_canonical(id.digest(), &value).await?;
        self.text_states.entry(id).or_insert(value);
        Ok(id)
    }

    async fn insert_text_artifact(
        &mut self,
        value: TextArtifact,
    ) -> Result<TextArtifactId, ExecutorError> {
        let id = value.output_id();
        self.insert_canonical(id.digest(), &value).await?;
        self.text_artifacts.entry(id).or_insert(value);
        Ok(id)
    }

    async fn insert_canonical(
        &mut self,
        digest: ArtifactDigest,
        value: &impl Canonical,
    ) -> Result<(), ExecutorError> {
        if self.canonical_blobs.contains_key(&digest) {
            return Ok(());
        }

        let bytes = value.canonical_bytes();
        self.blob_store.insert_canonical(digest, &bytes).await?;
        self.canonical_blobs.insert(digest, bytes);
        Ok(())
    }

    fn persist_evaluate_index(&self) -> Result<(), ExecutorError> {
        let Some(path) = &self.index_path else {
            return Ok(());
        };
        persist_evaluate_index(path, self)
    }

    #[cfg(test)]
    async fn shutdown(&self) -> Result<(), ExecutorError> {
        self.blob_store.shutdown().await
    }
}

fn canonical_type_mismatch(kind: &str, digest: ArtifactDigest) -> ExecutorError {
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

fn load_evaluate_index(path: &Path) -> Result<EvaluateIndexData, ExecutorError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(EvaluateIndexData::default());
        }
        Err(err) => {
            return Err(ExecutorError::ArtifactStore(format!(
                "failed to read evaluate artifact index {}: {err}",
                path.display()
            )));
        }
    };
    let persisted: PersistedEvaluateIndex = serde_json::from_slice(&bytes).map_err(|err| {
        ExecutorError::ArtifactStore(format!(
            "failed to decode evaluate artifact index {}: {err}",
            path.display()
        ))
    })?;
    persisted.try_into_index()
}

fn persist_evaluate_index(path: &Path, store: &EvaluateArtifactStore) -> Result<(), ExecutorError> {
    let persisted = PersistedEvaluateIndex::from_store(store);
    let bytes = serde_json::to_vec_pretty(&persisted).map_err(|err| {
        ExecutorError::ArtifactStore(format!("failed to encode evaluate artifact index: {err}"))
    })?;
    let parent = path.parent().ok_or_else(|| {
        ExecutorError::ArtifactStore(format!(
            "evaluate artifact index path {} has no parent",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|err| {
        ExecutorError::ArtifactStore(format!(
            "failed to create evaluate artifact index directory {}: {err}",
            parent.display()
        ))
    })?;
    let tmp = path.with_file_name(format!(
        ".{}.tmp.{}",
        EVALUATE_INDEX_FILE,
        std::process::id()
    ));
    fs::write(&tmp, bytes).map_err(|err| {
        ExecutorError::ArtifactStore(format!(
            "failed to write evaluate artifact index temp file {}: {err}",
            tmp.display()
        ))
    })?;
    fs::rename(&tmp, path).map_err(|err| {
        let _ = fs::remove_file(&tmp);
        ExecutorError::ArtifactStore(format!(
            "failed to persist evaluate artifact index {}: {err}",
            path.display()
        ))
    })
}

impl PersistedEvaluateIndex {
    fn from_store(store: &EvaluateArtifactStore) -> Self {
        let mut bound_terms: Vec<_> = store
            .bound_terms
            .iter()
            .map(|(bound_term, locator)| PersistedBoundTerm {
                bound_term: bound_term.to_string(),
                model_id: locator.model_id.clone(),
                revision: locator.revision.clone(),
                dtype: dtype_to_wire(locator.dtype),
            })
            .collect();
        bound_terms.sort_by(|a, b| a.bound_term.cmp(&b.bound_term));

        let mut outputs_by_execution: Vec<_> = store
            .outputs_by_execution
            .iter()
            .map(|(execution, artifact)| PersistedExecutionOutput {
                execution: execution.to_string(),
                artifact: artifact.to_string(),
            })
            .collect();
        outputs_by_execution.sort_by(|a, b| a.execution.cmp(&b.execution));

        Self {
            bound_terms,
            outputs_by_execution,
        }
    }

    fn try_into_index(self) -> Result<EvaluateIndexData, ExecutorError> {
        let mut index = EvaluateIndexData::default();
        for entry in self.bound_terms {
            let bound_term =
                BoundTermId::from_digest(parse_artifact_digest(&entry.bound_term, "bound_term")?);
            let dtype = catgrad::prelude::Dtype::from_str(&entry.dtype).map_err(|err| {
                ExecutorError::ArtifactStore(format!(
                    "invalid dtype {:?} in evaluate artifact index: {err}",
                    entry.dtype
                ))
            })?;
            index.bound_terms.insert(
                bound_term,
                ModelLocator {
                    model_id: entry.model_id,
                    revision: entry.revision,
                    dtype,
                },
            );
        }

        for entry in self.outputs_by_execution {
            let execution =
                TextExecutionId::from_digest(parse_artifact_digest(&entry.execution, "execution")?);
            let artifact =
                TextArtifactId::from_digest(parse_artifact_digest(&entry.artifact, "artifact")?);
            index.outputs_by_execution.insert(execution, artifact);
        }

        Ok(index)
    }
}

fn parse_artifact_digest(raw: &str, field: &str) -> Result<ArtifactDigest, ExecutorError> {
    if raw.len() != 64 {
        return Err(ExecutorError::ArtifactStore(format!(
            "invalid {field} digest length {}, expected 64 hex chars",
            raw.len()
        )));
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(chunk[0]).ok_or_else(|| invalid_hex(field, raw))?;
        let low = hex_value(chunk[1]).ok_or_else(|| invalid_hex(field, raw))?;
        bytes[index] = (high << 4) | low;
    }
    Ok(ArtifactDigest::from_bytes(bytes))
}

fn invalid_hex(field: &str, raw: &str) -> ExecutorError {
    ExecutorError::ArtifactStore(format!("invalid {field} digest hex {raw:?}"))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn token_ids_to_u32(tokens: &TokenIds) -> Vec<u32> {
    tokens
        .as_slice()
        .iter()
        .map(|token| token.as_u32())
        .collect()
}

fn text_policy(invocation: &Invocation) -> Result<TextPolicy, ExecutorError> {
    let stop_token_ids = invocation
        .stop_token_ids
        .iter()
        .copied()
        .map(TokenId::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| ExecutorError::InvalidTokenPayload(err.to_string()))?;
    Ok(TextPolicy::new(invocation.max_new_tokens, stop_token_ids))
}

fn binding_digest(locator: &ModelLocator) -> Digest {
    hash_tuple(
        "hellas.executor.synthetic_binding.v1",
        &[
            locator.model_id.as_bytes(),
            locator.revision.as_bytes(),
            dtype_to_wire(locator.dtype).as_bytes(),
        ],
    )
}

fn dtype_to_wire(dtype: catgrad::prelude::Dtype) -> String {
    match dtype {
        catgrad::prelude::Dtype::F32 => "f32".to_string(),
        catgrad::prelude::Dtype::F16 => "f16".to_string(),
        catgrad::prelude::Dtype::BF16 => "bf16".to_string(),
        catgrad::prelude::Dtype::F8 => "f8".to_string(),
        catgrad::prelude::Dtype::U32 => "u32".to_string(),
    }
}

fn to_artifact_digest(digest: Digest) -> ArtifactDigest {
    ArtifactDigest::from_bytes(digest.into_bytes())
}

fn from_artifact_digest(digest: ArtifactDigest) -> Digest {
    Digest::from_bytes(*digest.as_bytes())
}

fn iroh_hash(digest: ArtifactDigest) -> iroh_blobs::Hash {
    iroh_blobs::Hash::from_bytes(*digest.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use catgrad::prelude::Dtype;

    fn runner_public_key() -> hellas_rpc::PublicKey {
        hellas_rpc::ProducerSigningKey::from_secret_bytes([8; 32])
            .expect("valid test key")
            .public_key()
    }

    fn evaluate_request(text_execution: Digest) -> EvaluateRequest {
        EvaluateRequest {
            text_execution,
            runner_public_key: runner_public_key(),
        }
    }

    fn plan() -> QuotePlan {
        QuotePlan {
            locator: ModelLocator {
                model_id: "model".to_string(),
                revision: "main".to_string(),
                dtype: Dtype::F32,
            },
            invocation: Invocation {
                input_ids: vec![1, 2, 3],
                max_new_tokens: 8,
                stop_token_ids: vec![4, 5],
            },
            initial_artifact_id: None,
            runner_public_key: runner_public_key(),
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
        let resolved = store
            .resolve_evaluate_request(next.evaluate_request)
            .await
            .unwrap();

        assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
    }

    #[tokio::test]
    async fn lazy_input_source_uses_cached_output_artifact() {
        let mut store = EvaluateArtifactStore::default();
        let first = store.record_prepared_text(&plan()).await.unwrap();
        store
            .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
            .await
            .unwrap();
        let first_execution =
            TextExecutionId::from_digest(to_artifact_digest(first.evaluate_request.text_execution));
        let prompt_tokens = store.insert_token_ids(TokenIds::from([20])).await.unwrap();
        let policy = store
            .insert_policy(TextPolicy::from_u32_stop_tokens(4, []))
            .await
            .unwrap();
        let lazy = TextExecution::new(SourceRef::input(first_execution), prompt_tokens, policy);
        let lazy_id = store.insert_text_execution(lazy).await.unwrap();
        let resolved = store
            .resolve_evaluate_request(evaluate_request(from_artifact_digest(lazy_id.digest())))
            .await
            .unwrap();

        assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
    }

    #[tokio::test]
    async fn lazy_input_rejects_metadata_that_does_not_realize_execution() {
        let mut store = EvaluateArtifactStore::default();
        let first = store.record_prepared_text(&plan()).await.unwrap();
        let first_execution =
            TextExecutionId::from_digest(to_artifact_digest(first.evaluate_request.text_execution));
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
            .resolve_evaluate_request(evaluate_request(from_artifact_digest(lazy_id.digest())))
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

        assert_eq!(digest, from_artifact_digest(tokens.output_id().digest()));
        assert_eq!(store.get_canonical_bytes(digest).await.unwrap(), bytes);
    }

    #[tokio::test]
    async fn fs_store_reopens_typed_artifacts_from_canonical_blobs() {
        let path = temp_artifact_store_path("reopen");
        let _ = std::fs::remove_dir_all(&path);

        let first_artifact;
        let first_request;
        {
            let mut store = EvaluateArtifactStore::open(ArtifactStoreConfig::fs(&path))
                .await
                .unwrap();
            let first = store.record_prepared_text(&plan()).await.unwrap();
            first_artifact = store
                .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
                .await
                .unwrap();
            first_request = first.evaluate_request;
            store.shutdown().await.unwrap();
        }

        {
            let mut store = EvaluateArtifactStore::open(ArtifactStoreConfig::fs(&path))
                .await
                .unwrap();
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
            store.shutdown().await.unwrap();
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[tokio::test]
    async fn fs_store_reopens_cached_lazy_substitutions() {
        let path = temp_artifact_store_path("lazy");
        let _ = std::fs::remove_dir_all(&path);

        let first_execution;
        {
            let mut store = EvaluateArtifactStore::open(ArtifactStoreConfig::fs(&path))
                .await
                .unwrap();
            let first = store.record_prepared_text(&plan()).await.unwrap();
            store
                .record_completed_text(&first.evaluate_request, &first.invocation, &[10, 11])
                .await
                .unwrap();
            first_execution = TextExecutionId::from_digest(to_artifact_digest(
                first.evaluate_request.text_execution,
            ));
            store.shutdown().await.unwrap();
        }

        {
            let mut store = EvaluateArtifactStore::open(ArtifactStoreConfig::fs(&path))
                .await
                .unwrap();
            let prompt_tokens = store.insert_token_ids(TokenIds::from([20])).await.unwrap();
            let policy = store
                .insert_policy(TextPolicy::from_u32_stop_tokens(4, []))
                .await
                .unwrap();
            let lazy = TextExecution::new(SourceRef::input(first_execution), prompt_tokens, policy);
            let lazy_id = store.insert_text_execution(lazy).await.unwrap();
            let resolved = store
                .resolve_evaluate_request(evaluate_request(from_artifact_digest(lazy_id.digest())))
                .await
                .unwrap();

            assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
            store.shutdown().await.unwrap();
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    fn temp_artifact_store_path(test: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hellas-executor-artifacts-{test}-{}-{nanos}",
            std::process::id()
        ))
    }
}
