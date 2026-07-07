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
