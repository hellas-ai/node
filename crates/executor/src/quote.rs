use hellas_rpc::decode_token_ids;
use hellas_rpc::pb::hellas::{GetQuoteRequest, GetQuoteResponse};

use crate::model::validate_execution_config;
use crate::state::ExecutionPlan;
use crate::weights::{
    weights_cached, EnsureDisposition, WeightsError, WeightsLocator, DEFAULT_REF,
};
use crate::{Executor, ExecutorError, DEFAULT_MAX_SEQ};

impl Executor {
    pub(super) async fn handle_quote(
        &mut self,
        request: GetQuoteRequest,
    ) -> Result<GetQuoteResponse, ExecutorError> {
        let model_id = request.huggingface_model_id.trim();
        if model_id.is_empty() {
            return Err(ExecutorError::InvalidQuoteRequest(
                "missing huggingface_model_id".to_string(),
            ));
        }

        let requested_revision = request.huggingface_revision.trim();
        let requested_revision = if requested_revision.is_empty() {
            DEFAULT_REF.to_string()
        } else {
            requested_revision.to_string()
        };

        if request.graph.is_empty() {
            return Err(ExecutorError::InvalidQuoteRequest(
                "missing graph bytes".to_string(),
            ));
        }
        if request.model_config_json.is_empty() {
            return Err(ExecutorError::InvalidQuoteRequest(
                "missing model_config_json".to_string(),
            ));
        }

        let max_new_tokens = if request.max_new_tokens == 0 {
            DEFAULT_MAX_SEQ
        } else {
            request.max_new_tokens
        };
        let graph_id = blake3::hash(&request.graph).to_hex().to_string();
        if !self
            .execute_policy
            .allows_execute(&graph_id, Some(model_id))
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "execute policy denied graph {graph_id} for model {model_id}"
            )));
        }

        let input_ids = decode_token_ids(&request.input)
            .map_err(|err| ExecutorError::InvalidTokenPayload(err.to_string()))?;
        let stop_token_ids = request
            .stop_token_ids
            .iter()
            .copied()
            .map(|token| {
                i32::try_from(token).map_err(|_| {
                    ExecutorError::InvalidTokenPayload(format!(
                        "stop token id {token} exceeds i32 range"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let expected_prompt_tokens = usize::try_from(request.prompt_tokens).unwrap_or(usize::MAX);
        if input_ids.len() != expected_prompt_tokens {
            return Err(ExecutorError::InvalidTokenPayload(format!(
                "prompt token count mismatch: request says {}, input decodes to {}",
                request.prompt_tokens,
                input_ids.len()
            )));
        }

        validate_execution_config(&request.model_config_json, input_ids.len(), max_new_tokens)?;

        let model_id = model_id.to_string();
        let weights_key = WeightsLocator {
            model_id: model_id.clone(),
            revision: requested_revision.clone(),
        };
        let disposition = self.weights.ensure_ready(weights_key.clone()).await;

        match disposition {
            EnsureDisposition::Ready => {}
            EnsureDisposition::Queued | EnsureDisposition::InFlight => {
                if weights_cached(&weights_key) {
                    self.weights
                        .ensure_ready_wait(weights_key.clone(), tokio::time::Duration::from_secs(2))
                        .await
                        .map_err(|e| match e {
                            WeightsError::NotReady => {
                                ExecutorError::WeightsNotReady(weights_key.to_string())
                            }
                            other => ExecutorError::WeightsError(other.to_string()),
                        })?;
                } else {
                    return Err(ExecutorError::WeightsNotReady(weights_key.to_string()));
                }
            }
            EnsureDisposition::Failed(err) => {
                return Err(ExecutorError::WeightsError(err));
            }
        }

        let plan = ExecutionPlan {
            graph: request.graph,
            model_config_json: request.model_config_json,
            weights_key: weights_key.clone(),
            input: request.input,
            prompt_tokens: request.prompt_tokens,
            max_new_tokens,
            stop_token_ids,
        };
        let amount = 1000; // stub
        let quote_id = self.state.create_quote(plan);

        info!(
            %quote_id,
            %graph_id,
            amount,
            model = model_id,
            requested_revision,
            prompt_tokens = request.prompt_tokens,
            max_new_tokens,
            "quoted graph execution"
        );

        Ok(GetQuoteResponse { quote_id, amount })
    }
}
