use std::collections::HashMap;

use catnix::{Canonical, InputAddressed, OutputAddressed};
use hellas_core::{Digest, SymbolicRequest, hash_tuple};
use hellas_rpc::ExecutorError;

use crate::state::{Invocation, ModelLocator, QuotePlan};

#[derive(Clone, Debug)]
pub(crate) struct ResolvedSymbolicExecution {
    pub symbolic_request: SymbolicRequest,
    pub locator: ModelLocator,
    pub invocation: Invocation,
}

#[derive(Default)]
pub(crate) struct SymbolicArtifactStore {
    blob_store: iroh_blobs::store::mem::MemStore,
    canonical_blobs: HashMap<catnix::Digest, Vec<u8>>,
    bound_terms: HashMap<catnix::BoundTermId, ModelLocator>,
    token_ids: HashMap<catnix::TokenIdsId, catnix::TokenIds>,
    policies: HashMap<catnix::TextPolicyId, catnix::TextPolicy>,
    text_executions: HashMap<catnix::TextExecutionId, catnix::TextExecution>,
    text_states: HashMap<catnix::TextStateId, catnix::TextState>,
    text_artifacts: HashMap<catnix::TextArtifactId, catnix::TextArtifact>,
    outputs_by_execution: HashMap<catnix::TextExecutionId, catnix::TextArtifactId>,
}

struct MaterializedTextSource {
    locator: ModelLocator,
    tokens: Vec<u32>,
}

impl SymbolicArtifactStore {
    pub async fn record_prepared_text(
        &mut self,
        plan: &QuotePlan,
    ) -> Result<ResolvedSymbolicExecution, ExecutorError> {
        let bound_term_id =
            catnix::BoundTermId::from_digest(to_catnix_digest(binding_digest(&plan.locator)));
        self.bound_terms
            .entry(bound_term_id)
            .or_insert_with(|| plan.locator.clone());

        let from = match plan.initial_artifact_id {
            Some(artifact_id) => {
                let artifact_id =
                    catnix::TextArtifactId::from_digest(to_catnix_digest(artifact_id));
                let _ = self.materialize_artifact(artifact_id)?;
                catnix::SourceRef::output(artifact_id)
            }
            None => {
                let identity = catnix::TextArtifact::identity(bound_term_id);
                let identity_id = identity.output_id();
                self.insert_text_artifact(identity).await?;
                catnix::SourceRef::output(identity_id)
            }
        };

        let prompt_tokens = catnix::TokenIds::from(plan.invocation.input_ids.clone());
        let prompt_tokens_id = self.insert_token_ids(prompt_tokens).await?;
        let policy = text_policy(&plan.invocation)?;
        let policy_id = self.insert_policy(policy).await?;
        let execution = catnix::TextExecution::new(from, prompt_tokens_id, policy_id);
        let execution_id = self.insert_text_execution(execution).await?;
        let symbolic_request = SymbolicRequest {
            text_execution_cid: from_catnix_digest(execution_id.digest()),
        };

        Ok(ResolvedSymbolicExecution {
            symbolic_request,
            locator: plan.locator.clone(),
            invocation: plan.invocation.clone(),
        })
    }

    pub fn resolve_symbolic_request(
        &self,
        symbolic_request: SymbolicRequest,
    ) -> Result<ResolvedSymbolicExecution, ExecutorError> {
        let execution_id = catnix::TextExecutionId::from_digest(to_catnix_digest(
            symbolic_request.text_execution_cid,
        ));
        let execution = self.text_executions.get(&execution_id).ok_or_else(|| {
            ExecutorError::InvalidQuoteRequest(format!(
                "unknown symbolic text execution CID {}",
                symbolic_request.text_execution_cid
            ))
        })?;
        let source = self.materialize_source(execution.from())?;
        let prompt_tokens = self
            .token_ids
            .get(&execution.prompt_tokens())
            .ok_or_else(|| {
                ExecutorError::InvalidQuoteRequest(format!(
                    "missing prompt TokenIds artifact {}",
                    execution.prompt_tokens()
                ))
            })?;
        let policy = self.policies.get(&execution.policy()).ok_or_else(|| {
            ExecutorError::InvalidQuoteRequest(format!(
                "missing TextPolicy artifact {}",
                execution.policy()
            ))
        })?;
        let mut input_ids = source.tokens;
        input_ids.extend(token_ids_to_u32(prompt_tokens));
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

        Ok(ResolvedSymbolicExecution {
            symbolic_request,
            locator: source.locator,
            invocation: Invocation {
                input_ids,
                max_new_tokens: policy.max_new_tokens(),
                stop_token_ids,
            },
        })
    }

    pub async fn record_completed_text(
        &mut self,
        symbolic_request: &SymbolicRequest,
        invocation: &Invocation,
        output_tokens: &[u32],
    ) -> Result<Digest, ExecutorError> {
        let execution_id = catnix::TextExecutionId::from_digest(to_catnix_digest(
            symbolic_request.text_execution_cid,
        ));
        if !self.text_executions.contains_key(&execution_id) {
            return Err(ExecutorError::InvalidQuoteRequest(format!(
                "unknown completed text execution CID {}",
                symbolic_request.text_execution_cid
            )));
        }

        let generated_tokens_id = self
            .insert_token_ids(catnix::TokenIds::from(output_tokens.to_vec()))
            .await?;
        let mut state_tokens = invocation.input_ids.clone();
        state_tokens.extend_from_slice(output_tokens);
        let state_tokens_id = self
            .insert_token_ids(catnix::TokenIds::from(state_tokens))
            .await?;
        let state_id = self
            .insert_text_state(catnix::TextState::new(state_tokens_id))
            .await?;
        let artifact = catnix::TextArtifact::output(
            execution_id,
            output_tokens.len() as u64,
            state_id,
            generated_tokens_id,
        );
        let artifact_id = self.insert_text_artifact(artifact).await?;
        self.outputs_by_execution
            .entry(execution_id)
            .or_insert(artifact_id);
        Ok(from_catnix_digest(artifact_id.digest()))
    }

    fn materialize_source(
        &self,
        source: &catnix::TextSource,
    ) -> Result<MaterializedTextSource, ExecutorError> {
        match source {
            catnix::SourceRef::Input(id) => {
                let artifact_id = self.outputs_by_execution.get(id).ok_or_else(|| {
                    ExecutorError::InvalidQuoteRequest(format!(
                        "lazy symbolic source {id} has no cached output artifact"
                    ))
                })?;
                self.materialize_artifact(*artifact_id)
            }
            catnix::SourceRef::Output(id) => self.materialize_artifact(*id),
        }
    }

    fn materialize_artifact(
        &self,
        artifact_id: catnix::TextArtifactId,
    ) -> Result<MaterializedTextSource, ExecutorError> {
        let artifact = self.text_artifacts.get(&artifact_id).ok_or_else(|| {
            ExecutorError::InvalidQuoteRequest(format!("missing source TextArtifact {artifact_id}"))
        })?;
        match artifact {
            catnix::TextArtifact::Identity { bound_term } => {
                let locator = self.bound_terms.get(bound_term).cloned().ok_or_else(|| {
                    ExecutorError::InvalidQuoteRequest(format!(
                        "missing bound term metadata {bound_term}"
                    ))
                })?;
                Ok(MaterializedTextSource {
                    locator,
                    tokens: Vec::new(),
                })
            }
            catnix::TextArtifact::Output(output) => {
                let execution = self
                    .text_executions
                    .get(&output.execution())
                    .ok_or_else(|| {
                        ExecutorError::InvalidQuoteRequest(format!(
                            "missing TextExecution {} for artifact {artifact_id}",
                            output.execution()
                        ))
                    })?;
                let locator = self.materialize_source(execution.from())?.locator;
                let state = self.text_states.get(&output.state()).ok_or_else(|| {
                    ExecutorError::InvalidQuoteRequest(format!(
                        "missing TextState {} for artifact {artifact_id}",
                        output.state()
                    ))
                })?;
                let tokens = self.token_ids.get(&state.tokens()).ok_or_else(|| {
                    ExecutorError::InvalidQuoteRequest(format!(
                        "missing TokenIds artifact {} for state {}",
                        state.tokens(),
                        output.state()
                    ))
                })?;
                Ok(MaterializedTextSource {
                    locator,
                    tokens: token_ids_to_u32(tokens),
                })
            }
        }
    }

    async fn insert_token_ids(
        &mut self,
        value: catnix::TokenIds,
    ) -> Result<catnix::TokenIdsId, ExecutorError> {
        let id = value.output_id();
        self.insert_canonical(id.digest(), &value).await?;
        self.token_ids.entry(id).or_insert(value);
        Ok(id)
    }

    async fn insert_policy(
        &mut self,
        value: catnix::TextPolicy,
    ) -> Result<catnix::TextPolicyId, ExecutorError> {
        let id = value.output_id();
        self.insert_canonical(id.digest(), &value).await?;
        self.policies.entry(id).or_insert(value);
        Ok(id)
    }

    async fn insert_text_execution(
        &mut self,
        value: catnix::TextExecution,
    ) -> Result<catnix::TextExecutionId, ExecutorError> {
        let id = value.input_id();
        self.insert_canonical(id.digest(), &value).await?;
        self.text_executions.entry(id).or_insert(value);
        Ok(id)
    }

    async fn insert_text_state(
        &mut self,
        value: catnix::TextState,
    ) -> Result<catnix::TextStateId, ExecutorError> {
        let id = value.output_id();
        self.insert_canonical(id.digest(), &value).await?;
        self.text_states.entry(id).or_insert(value);
        Ok(id)
    }

    async fn insert_text_artifact(
        &mut self,
        value: catnix::TextArtifact,
    ) -> Result<catnix::TextArtifactId, ExecutorError> {
        let id = value.output_id();
        self.insert_canonical(id.digest(), &value).await?;
        self.text_artifacts.entry(id).or_insert(value);
        Ok(id)
    }

    async fn insert_canonical(
        &mut self,
        digest: catnix::Digest,
        value: &impl Canonical,
    ) -> Result<(), ExecutorError> {
        if self.canonical_blobs.contains_key(&digest) {
            return Ok(());
        }

        let bytes = value.canonical_bytes();
        let expected = iroh_hash(digest);
        let tag = self
            .blob_store
            .add_slice(&bytes)
            .await
            .map_err(|err| ExecutorError::WeightsError(format!("blob insert failed: {err}")))?;
        if tag.hash != expected {
            return Err(ExecutorError::WeightsError(format!(
                "blob store hash mismatch: expected {}, got {}",
                expected.to_hex(),
                tag.hash.to_hex()
            )));
        }
        self.canonical_blobs.insert(digest, bytes);
        Ok(())
    }
}

fn token_ids_to_u32(tokens: &catnix::TokenIds) -> Vec<u32> {
    tokens
        .as_slice()
        .iter()
        .map(|token| token.as_u32())
        .collect()
}

fn text_policy(invocation: &Invocation) -> Result<catnix::TextPolicy, ExecutorError> {
    let stop_token_ids = invocation
        .stop_token_ids
        .iter()
        .copied()
        .map(catnix::TokenId::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| ExecutorError::InvalidTokenPayload(err.to_string()))?;
    Ok(catnix::TextPolicy::new(
        invocation.max_new_tokens,
        stop_token_ids,
    ))
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

fn to_catnix_digest(digest: Digest) -> catnix::Digest {
    catnix::Digest::from_bytes(digest.into_bytes())
}

fn from_catnix_digest(digest: catnix::Digest) -> Digest {
    Digest::from_bytes(*digest.as_bytes())
}

fn iroh_hash(digest: catnix::Digest) -> iroh_blobs::Hash {
    iroh_blobs::Hash::from_bytes(*digest.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use catgrad::prelude::Dtype;

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
        }
    }

    #[tokio::test]
    async fn prepared_text_round_trips_through_store() {
        let mut store = SymbolicArtifactStore::default();
        let recorded = store.record_prepared_text(&plan()).await.unwrap();
        let resolved = store
            .resolve_symbolic_request(recorded.symbolic_request.clone())
            .unwrap();

        assert_eq!(resolved.symbolic_request, recorded.symbolic_request);
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
        let mut store = SymbolicArtifactStore::default();
        let first = store.record_prepared_text(&plan()).await.unwrap();
        let first_artifact = store
            .record_completed_text(&first.symbolic_request, &first.invocation, &[10, 11])
            .await
            .unwrap();
        let mut next_plan = plan();
        next_plan.invocation.input_ids = vec![20];
        next_plan.initial_artifact_id = Some(first_artifact);
        let next = store.record_prepared_text(&next_plan).await.unwrap();
        let resolved = store
            .resolve_symbolic_request(next.symbolic_request)
            .unwrap();

        assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
    }

    #[tokio::test]
    async fn lazy_input_source_uses_cached_output_artifact() {
        let mut store = SymbolicArtifactStore::default();
        let first = store.record_prepared_text(&plan()).await.unwrap();
        store
            .record_completed_text(&first.symbolic_request, &first.invocation, &[10, 11])
            .await
            .unwrap();
        let first_execution = catnix::TextExecutionId::from_digest(to_catnix_digest(
            first.symbolic_request.text_execution_cid,
        ));
        let prompt_tokens = store
            .insert_token_ids(catnix::TokenIds::from([20]))
            .await
            .unwrap();
        let policy = store
            .insert_policy(catnix::TextPolicy::from_u32_stop_tokens(4, []))
            .await
            .unwrap();
        let lazy = catnix::TextExecution::new(
            catnix::SourceRef::input(first_execution),
            prompt_tokens,
            policy,
        );
        let lazy_id = store.insert_text_execution(lazy).await.unwrap();
        let resolved = store
            .resolve_symbolic_request(SymbolicRequest {
                text_execution_cid: from_catnix_digest(lazy_id.digest()),
            })
            .unwrap();

        assert_eq!(resolved.invocation.input_ids, vec![1, 2, 3, 10, 11, 20]);
    }

    #[tokio::test]
    async fn unknown_text_execution_is_rejected() {
        let store = SymbolicArtifactStore::default();
        let err = store
            .resolve_symbolic_request(SymbolicRequest {
                text_execution_cid: Digest::from_bytes([7; 32]),
            })
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("unknown symbolic text execution CID")
        );
    }
}
