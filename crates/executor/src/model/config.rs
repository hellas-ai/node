use catgrad_llm::Program;
use catgrad_llm::helpers::GATED_DELTA_CHUNK_SIZE;
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

pub(super) fn build_program_bytes(config: &Value, max_sequence_length: usize) -> Result<Vec<u8>> {
    let spec = Program::text_from_config(config, max_sequence_length)
        .map_err(|source| ModelAssetsError::BuildProgramModel { source })?;
    serde_json::to_vec(&spec).map_err(|source| ModelAssetsError::SerializeProgram {
        source: catgrad_llm::LLMError::from(source),
    })
}

pub(super) fn validate_prefill_prompt_length(config: &Value, prompt_tokens: usize) -> Result<()> {
    let Some((architecture, limit)) = prefill_prompt_limit(config) else {
        return Ok(());
    };

    if prompt_tokens > limit {
        return Err(ModelAssetsError::PromptTooLong {
            architecture: architecture.to_string(),
            prompt_tokens,
            limit,
        });
    }

    Ok(())
}

fn prefill_prompt_limit(config: &Value) -> Option<(&str, usize)> {
    let architecture = config.get("architectures")?.get(0)?.as_str()?;
    match architecture {
        "Qwen3_5ForConditionalGeneration" | "OlmoHybridForCausalLM" => {
            Some((architecture, GATED_DELTA_CHUNK_SIZE))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::validate_prefill_prompt_length;
    use crate::model::ModelAssetsError;
    use catgrad_llm::helpers::GATED_DELTA_CHUNK_SIZE;
    use serde_json::json;

    #[test]
    fn rejects_qwen3_5_prefill_over_chunk_limit() {
        let config = json!({
            "architectures": ["Qwen3_5ForConditionalGeneration"]
        });

        let err = validate_prefill_prompt_length(&config, GATED_DELTA_CHUNK_SIZE + 1).unwrap_err();
        assert!(matches!(
            err,
            ModelAssetsError::PromptTooLong { limit, .. } if limit == GATED_DELTA_CHUNK_SIZE
        ));
    }

    #[test]
    fn rejects_olmo_hybrid_prefill_over_chunk_limit() {
        let config = json!({
            "architectures": ["OlmoHybridForCausalLM"]
        });

        let err = validate_prefill_prompt_length(&config, GATED_DELTA_CHUNK_SIZE + 1).unwrap_err();
        assert!(matches!(
            err,
            ModelAssetsError::PromptTooLong { limit, .. } if limit == GATED_DELTA_CHUNK_SIZE
        ));
    }

    #[test]
    fn allows_long_prefill_for_non_chunked_models() {
        let config = json!({
            "architectures": ["Qwen3ForCausalLM"]
        });

        validate_prefill_prompt_length(&config, GATED_DELTA_CHUNK_SIZE + 1).unwrap();
    }
}
