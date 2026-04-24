use catgrad_llm::Program;
use serde_json::Value;

use super::{ModelAssetsError, Result};

pub(super) fn encode_i32_tokens(
    token_ids: &[i32],
    make_error: impl Fn(i32) -> ModelAssetsError,
) -> Result<Vec<u32>> {
    token_ids
        .iter()
        .map(|&token| u32::try_from(token).map_err(|_| make_error(token)))
        .collect()
}

pub(super) fn build_program_bytes(
    config: &Value,
    prompt_tokens: usize,
    max_sequence_length: usize,
) -> Result<Vec<u8>> {
    let spec = Program::text_from_config(config, max_sequence_length)
        .map_err(|source| ModelAssetsError::BuildProgramModel { source })?;
    validate_prefill_prompt_length(&spec, config, prompt_tokens)?;
    serde_json::to_vec(&spec).map_err(|source| ModelAssetsError::SerializeProgram {
        source: catgrad_llm::LLMError::from(source),
    })
}

fn validate_prefill_prompt_length(
    program: &Program,
    config: &Value,
    prompt_tokens: usize,
) -> Result<()> {
    let Some(chunk_size) = program.extra_nat_chunk_size else {
        return Ok(());
    };
    if prompt_tokens <= chunk_size {
        return Ok(());
    }
    let architecture = config
        .get("architectures")
        .and_then(|a| a.get(0))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    Err(ModelAssetsError::PromptTooLong {
        architecture,
        prompt_tokens,
        limit: chunk_size,
    })
}

#[cfg(test)]
mod tests {
    use super::validate_prefill_prompt_length;
    use crate::model::ModelAssetsError;
    use catgrad::category::lang::{Term, TypedTerm};
    use catgrad::path::Path;
    use catgrad_llm::Program;
    use catgrad_llm::helpers::{GATED_DELTA_CHUNK_SIZE, WeightPostProcess};
    use serde_json::json;

    fn program_with_chunk_size(chunk_size: Option<usize>) -> Program {
        Program::new(
            TypedTerm {
                term: Term::empty(),
                source_type: vec![],
                target_type: vec![],
            },
            Path::empty(),
            vec![],
            chunk_size.unwrap_or(0).max(1),
            WeightPostProcess::None,
            chunk_size,
        )
    }

    #[test]
    fn rejects_gated_delta_prefill_over_chunk_limit() {
        let program = program_with_chunk_size(Some(GATED_DELTA_CHUNK_SIZE));
        let config = json!({ "architectures": ["Qwen3_5ForConditionalGeneration"] });

        let err =
            validate_prefill_prompt_length(&program, &config, GATED_DELTA_CHUNK_SIZE + 1).unwrap_err();
        assert!(matches!(
            err,
            ModelAssetsError::PromptTooLong { limit, architecture, .. }
                if limit == GATED_DELTA_CHUNK_SIZE
                    && architecture == "Qwen3_5ForConditionalGeneration"
        ));
    }

    #[test]
    fn allows_gated_delta_prefill_within_chunk_limit() {
        let program = program_with_chunk_size(Some(GATED_DELTA_CHUNK_SIZE));
        let config = json!({ "architectures": ["Qwen3_5ForConditionalGeneration"] });

        validate_prefill_prompt_length(&program, &config, GATED_DELTA_CHUNK_SIZE).unwrap();
    }

    #[test]
    fn allows_long_prefill_for_non_chunked_models() {
        let program = program_with_chunk_size(None);
        let config = json!({ "architectures": ["Qwen3ForCausalLM"] });

        validate_prefill_prompt_length(&program, &config, GATED_DELTA_CHUNK_SIZE * 100).unwrap();
    }
}
