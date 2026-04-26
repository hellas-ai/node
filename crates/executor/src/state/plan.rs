use hellas_rpc::decode_token_ids;
use hellas_rpc::pb::hellas::GetQuoteRequest;

use crate::DEFAULT_MAX_SEQ;
use crate::inputs::HuggingFaceLocator;
use catgrad::prelude::Dtype;
use catgrad::runtime::Program;
use hellas_rpc::ExecutorError;
use hellas_rpc::spec::DEFAULT_MODEL_REVISION;

#[derive(Clone)]
pub struct Invocation {
    pub input_ids: Vec<u32>,
    pub max_new_tokens: u32,
    pub stop_token_ids: Vec<i32>,
}

pub(crate) struct QuotePlan {
    pub program: Program,
    pub weights_key: HuggingFaceLocator,
    pub invocation: Invocation,
}

impl QuotePlan {
    pub(crate) fn from_quote_request(
        request: GetQuoteRequest,
        supported_dtypes: &[Dtype],
    ) -> Result<Self, ExecutorError> {
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
        let program: Program = serde_json::from_slice(&request.program)
            .map_err(|e| ExecutorError::InvalidQuoteRequest(format!("invalid program: {e}")))?;

        // Detect requests whose program was built for a dtype this executor
        // doesn't accept. Every shipped text model tags `empty_state_type`
        // entries with the model's dtype, so we read the first state tensor's
        // dtype as the program's dtype. Programs with no state (vision-only
        // graphs, not part of node's text path today) are accepted: there's
        // nothing to mismatch on.
        let program_dtype = program
            .empty_state_type
            .first()
            .map(|&(dtype, _)| dtype);
        if let Some(program_dtype) = program_dtype
            && !supported_dtypes.contains(&program_dtype)
        {
            return Err(ExecutorError::DtypeNotSupported {
                request: program_dtype,
                supported: supported_dtypes.to_vec(),
            });
        }
        // The cache is scoped per-(model, revision, dtype) via HuggingFaceLocator,
        // so a multi-dtype executor holds an independent bundle for each
        // dtype it has been asked to serve. Use the program's actual dtype
        // here, not the executor's preferred default.
        let request_dtype = program_dtype.unwrap_or_else(|| supported_dtypes[0]);

        let input_ids = decode_token_ids(&request.input)
            .map_err(|error| ExecutorError::InvalidTokenPayload(error.to_string()))?;
        if input_ids.is_empty() {
            return Err(ExecutorError::InvalidTokenPayload(
                "prompt is empty after decoding".to_string(),
            ));
        }
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

        Ok(Self {
            program,
            weights_key: HuggingFaceLocator::new(
                model_id.to_string(),
                requested_revision,
                request_dtype,
            ),
            invocation: Invocation {
                input_ids,
                max_new_tokens,
                stop_token_ids,
            },
        })
    }
}
