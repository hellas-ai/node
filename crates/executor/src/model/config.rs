use catgrad_llm::helpers::GATED_DELTA_CHUNK_SIZE;
use catgrad_llm::utils::get_model;
use serde_json::Value;

use super::{ModelAssetsError, Result};

pub(crate) fn validate_execution_config(
    model_config_json: &[u8],
    prompt_tokens: usize,
    max_new_tokens: u32,
) -> Result<()> {
    let config: Value = serde_json::from_slice(model_config_json)
        .map_err(|source| ModelAssetsError::ParseModelConfig { source })?;
    validate_prefill_prompt_length(&config, prompt_tokens)?;
    let max_sequence_length = prompt_tokens.saturating_add(max_new_tokens as usize);
    let _ = get_model(&config, max_sequence_length)
        .map_err(|source| ModelAssetsError::ConstructModelConfig { source })?;
    Ok(())
}

pub(super) fn encode_i32_tokens(
    token_ids: &[i32],
    make_error: impl Fn(i32) -> ModelAssetsError,
) -> Result<Vec<u32>> {
    token_ids
        .iter()
        .map(|&token| u32::try_from(token).map_err(|_| make_error(token)))
        .collect()
}

pub(super) fn build_graph_bytes(config: &Value, max_sequence_length: usize) -> Result<Vec<u8>> {
    let model = get_model(config, max_sequence_length)
        .map_err(|source| ModelAssetsError::BuildGraphModel { source })?;
    let typed_term = model
        .term()
        .ok_or(ModelAssetsError::MissingTypedGraphTerm)?;
    serde_json::to_vec(&typed_term).map_err(|source| ModelAssetsError::SerializeGraph { source })
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
