use catgrad::prelude::Dtype;
use hellas_runtime::runtime::text_program_from_config;
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
    max_sequence_length: usize,
    dtype: Dtype,
) -> Result<Vec<u8>> {
    let spec = text_program_from_config(config, max_sequence_length, dtype)
        .map_err(|source| ModelAssetsError::BuildProgramModel { source })?;
    serde_json::to_vec(&spec).map_err(|source| ModelAssetsError::SerializeProgram {
        source: hellas_runtime::LLMError::from(source),
    })
}
