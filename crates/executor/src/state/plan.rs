use hellas_rpc::decode_token_ids;
use hellas_rpc::pb::hellas::GetQuoteRequest;

use crate::model::{validate_execution_config, DEFAULT_MODEL_REVISION};
use crate::weights::WeightsLocator;
use crate::{ExecutorError, DEFAULT_MAX_SEQ};

#[derive(Clone)]
pub struct ExecutionPlan {
    pub graph: Vec<u8>,
    pub model_config_json: Vec<u8>,
    pub weights_key: WeightsLocator,
    pub input_ids: Vec<u32>,
    pub max_new_tokens: u32,
    pub stop_token_ids: Vec<i32>,
}

impl ExecutionPlan {
    pub fn from_quote_request(request: GetQuoteRequest) -> Result<(Self, String), ExecutorError> {
        let model_id = request.huggingface_model_id.trim();
        if model_id.is_empty() {
            return Err(ExecutorError::InvalidQuoteRequest(
                "missing huggingface_model_id".to_string(),
            ));
        }

        let requested_revision = request.huggingface_revision.trim();
        let requested_revision = if requested_revision.is_empty() {
            DEFAULT_MODEL_REVISION
        } else {
            requested_revision
        }
        .to_string();

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

        let input_ids = decode_token_ids(&request.input)
            .map_err(|error| ExecutorError::InvalidTokenPayload(error.to_string()))?;
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

        Ok((
            Self {
                graph: request.graph,
                model_config_json: request.model_config_json,
                weights_key: WeightsLocator {
                    model_id: model_id.to_string(),
                    revision: requested_revision,
                },
                input_ids,
                max_new_tokens,
                stop_token_ids,
            },
            graph_id,
        ))
    }
}
