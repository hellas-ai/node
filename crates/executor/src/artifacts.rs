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
    text_artifacts: HashMap<catnix::TextArtifactId, catnix::TextArtifact>,
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
                self.ensure_supported_start(artifact_id)?;
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
        let locator = self.resolve_start_locator(execution.from())?;
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
        let input_ids = prompt_tokens
            .as_slice()
            .iter()
            .map(|token| token.as_u32())
            .collect();
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
            locator,
            invocation: Invocation {
                input_ids,
                max_new_tokens: policy.max_new_tokens(),
                stop_token_ids,
            },
        })
    }

    fn ensure_supported_start(
        &self,
        artifact_id: catnix::TextArtifactId,
    ) -> Result<(), ExecutorError> {
        let artifact = self.text_artifacts.get(&artifact_id).ok_or_else(|| {
            ExecutorError::InvalidQuoteRequest(format!(
                "unknown starting TextArtifact CID {artifact_id}"
            ))
        })?;
        match artifact {
            catnix::TextArtifact::Identity { .. } => Ok(()),
            catnix::TextArtifact::Output(_) => Err(ExecutorError::InvalidQuoteRequest(
                "continuation from a prior TextArtifact output needs persisted text state"
                    .to_string(),
            )),
        }
    }

    fn resolve_start_locator(
        &self,
        source: &catnix::TextSource,
    ) -> Result<ModelLocator, ExecutorError> {
        match source {
            catnix::SourceRef::Input(id) => Err(ExecutorError::InvalidQuoteRequest(format!(
                "lazy symbolic source {id} needs recursive artifact resolution"
            ))),
            catnix::SourceRef::Output(id) => {
                let artifact = self.text_artifacts.get(id).ok_or_else(|| {
                    ExecutorError::InvalidQuoteRequest(format!("missing source TextArtifact {id}"))
                })?;
                match artifact {
                    catnix::TextArtifact::Identity { bound_term } => {
                        self.bound_terms.get(bound_term).cloned().ok_or_else(|| {
                            ExecutorError::InvalidQuoteRequest(format!(
                                "missing bound term metadata {bound_term}"
                            ))
                        })
                    }
                    catnix::TextArtifact::Output(_) => Err(ExecutorError::InvalidQuoteRequest(
                        "continuation from a prior TextArtifact output needs persisted text state"
                            .to_string(),
                    )),
                }
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
