//! Catena package execution engine.

use anyhow::{Context, Result};
use catena_runner::{
    GenerationControl, GenerationTermination as CatenaTermination, PackageRunner,
    TokenGenerationOptions, VerifiedPackage,
};

/// One exact, verified Catena package loaded once for repeated independent
/// token-generation sessions.
pub(crate) struct PackageEngine {
    runner: PackageRunner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenerationTermination {
    StopToken,
    MaxTokens,
    Cancelled,
}

impl PackageEngine {
    pub(crate) fn load(package: VerifiedPackage) -> Result<Self> {
        Ok(Self {
            runner: PackageRunner::from_verified(package)?,
        })
    }

    pub(crate) fn vocabulary_size(&self) -> u64 {
        self.runner.vocabulary_size()
    }

    pub(crate) fn maximum_capacity(&self) -> u64 {
        self.runner.maximum_capacity()
    }

    pub(crate) fn generate(
        &self,
        input_ids: &[u32],
        stop_token_ids: &[u32],
        max_tokens: u32,
        mut on_token: impl FnMut(u32) -> bool,
    ) -> Result<GenerationTermination> {
        let input_ids = input_ids.iter().copied().map(u64::from).collect::<Vec<_>>();
        let stop_tokens = stop_token_ids
            .iter()
            .copied()
            .map(u64::from)
            .collect::<Vec<_>>();
        let max_new_tokens =
            usize::try_from(max_tokens).context("max token count exceeds usize")?;
        let result = self.runner.generate_tokens_streaming(
            &input_ids,
            TokenGenerationOptions {
                max_new_tokens,
                stop_tokens,
            },
            |token| {
                let token = u32::try_from(token).context("Catena produced a token above u32")?;
                Ok(if on_token(token) {
                    GenerationControl::Continue
                } else {
                    GenerationControl::Cancel
                })
            },
        )?;
        Ok(match result.termination {
            CatenaTermination::StopToken(_) => GenerationTermination::StopToken,
            CatenaTermination::MaxNewTokens => GenerationTermination::MaxTokens,
            CatenaTermination::Cancelled => GenerationTermination::Cancelled,
        })
    }
}
