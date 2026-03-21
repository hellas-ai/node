use std::path::PathBuf;

use hf_hub::api::sync::ApiBuilder;
use hf_hub::{Repo, RepoType};

use super::spec::ModelSpec;
use super::{ModelAssetsError, Result};

pub(super) fn get_model_metadata_files(model: &ModelSpec) -> Result<(PathBuf, PathBuf)> {
    let mut builder = ApiBuilder::from_env();
    let env_token = std::env::var("HF_TOKEN")
        .ok()
        .or_else(|| std::env::var("HUGGING_FACE_HUB_TOKEN").ok())
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty());
    if let Some(token) = env_token {
        builder = builder.with_token(Some(token));
    }

    let api = builder
        .build()
        .map_err(|source| ModelAssetsError::BuildHfApi { source })?;
    let repo = api.repo(Repo::with_revision(
        model.id.clone(),
        RepoType::Model,
        model.revision.clone(),
    ));

    let config =
        repo.get("config.json")
            .map_err(|source| ModelAssetsError::FetchModelMetadata {
                model_id: model.id.clone(),
                revision: model.revision.clone(),
                file: "config.json",
                source,
            })?;
    let tokenizer =
        repo.get("tokenizer.json")
            .map_err(|source| ModelAssetsError::FetchModelMetadata {
                model_id: model.id.clone(),
                revision: model.revision.clone(),
                file: "tokenizer.json",
                source,
            })?;

    Ok((config, tokenizer))
}
