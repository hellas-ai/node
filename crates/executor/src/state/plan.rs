use hellas_rpc::decode_token_ids;
use hellas_rpc::pb::hellas::GetQuoteRequest;

use crate::model::DEFAULT_MODEL_REVISION;
use crate::weights::WeightsLocator;
use crate::{ExecutorError, DEFAULT_MAX_SEQ};
use catgrad_llm::Program;

#[derive(Clone)]
pub struct ExecutionPlan {
    pub program: Vec<u8>,
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

        if request.program.is_empty() {
            return Err(ExecutorError::InvalidQuoteRequest(
                "missing program bytes".to_string(),
            ));
        }

        let max_new_tokens = if request.max_new_tokens == 0 {
            DEFAULT_MAX_SEQ
        } else {
            request.max_new_tokens
        };
        let program: Program =
            serde_json::from_slice(&request.program).map_err(ExecutorError::InvalidProgram)?;
        let program_bytes = program.normalized_json()?;
        let program_id = blake3::hash(&program_bytes).to_hex().to_string();

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
        let expected_max_sequence_length = input_ids.len().saturating_add(max_new_tokens as usize);
        if program.max_sequence_length != expected_max_sequence_length {
            return Err(ExecutorError::InvalidQuoteRequest(format!(
                "program max_sequence_length mismatch: request implies {expected_max_sequence_length}, program declares {}",
                program.max_sequence_length
            )));
        }

        Ok((
            Self {
                program: program_bytes,
                weights_key: WeightsLocator {
                    model_id: model_id.to_string(),
                    revision: requested_revision,
                },
                input_ids,
                max_new_tokens,
                stop_token_ids,
            },
            program_id,
        ))
    }
}
