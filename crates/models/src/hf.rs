use std::collections::HashSet;
use std::path::PathBuf;

use hf_hub::api::sync::{ApiBuilder, ApiRepo};
use hf_hub::{Repo, RepoType};

use super::{ModelAssetsError, Result};
use hellas_rpc::spec::ModelSpec;

fn model_repo(model: &ModelSpec) -> Result<ApiRepo> {
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
    Ok(api.repo(Repo::with_revision(
        model.id.clone(),
        RepoType::Model,
        model.revision.clone(),
    )))
}

fn fetch(repo: &ApiRepo, model: &ModelSpec, file: &str) -> Result<PathBuf> {
    repo.get(file)
        .map_err(|source| ModelAssetsError::FetchModelAsset {
            model_id: model.id.clone(),
            revision: model.revision.clone(),
            file: file.to_string(),
            source,
        })
}

pub(super) fn get_model_metadata_files(
    model: &ModelSpec,
) -> Result<(PathBuf, PathBuf, PathBuf, Option<PathBuf>)> {
    let repo = model_repo(model)?;
    let config = fetch(&repo, model, "config.json")?;
    let tokenizer = fetch(&repo, model, "tokenizer.json")?;
    let tokenizer_config = fetch(&repo, model, "tokenizer_config.json")?;
    let chat_template = repo.get("chat_template.jinja").ok();

    Ok((config, tokenizer, tokenizer_config, chat_template))
}

pub(super) fn get_program_files(
    model: &ModelSpec,
) -> Result<(Vec<PathBuf>, PathBuf, PathBuf, PathBuf)> {
    let repo = model_repo(model)?;
    let weights = if let Ok(index_path) = repo.get("model.safetensors.index.json") {
        let bytes = std::fs::read(&index_path).map_err(|source| ModelAssetsError::ReadAsset {
            path: index_path,
            source,
        })?;
        let index: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|source| ModelAssetsError::ParseModelMetadata { source })?;
        let weight_map = index
            .get("weight_map")
            .and_then(serde_json::Value::as_object)
            .ok_or(ModelAssetsError::InvalidModelIndex)?;
        let mut files = HashSet::new();
        for file in weight_map.values() {
            let file = file.as_str().ok_or(ModelAssetsError::InvalidModelIndex)?;
            files.insert(fetch(&repo, model, file)?);
        }
        files.into_iter().collect()
    } else {
        vec![fetch(&repo, model, "model.safetensors")?]
    };
    Ok((
        weights,
        fetch(&repo, model, "config.json")?,
        fetch(&repo, model, "tokenizer.json")?,
        fetch(&repo, model, "tokenizer_config.json")?,
    ))
}
