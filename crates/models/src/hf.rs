use std::collections::HashSet;
use std::path::{Path, PathBuf};

use hf_hub::api::sync::{ApiBuilder, ApiRepo};
use hf_hub::{Cache, Repo, RepoType};

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
    if let Some(path) = immutable_snapshot_file(model, file) {
        return Ok(path);
    }

    repo.get(file)
        .map_err(|source| ModelAssetsError::FetchModelAsset {
            model_id: model.id.clone(),
            revision: model.revision.clone(),
            file: file.to_string(),
            source,
        })
}

fn immutable_snapshot_file(model: &ModelSpec, file: &str) -> Option<PathBuf> {
    let path = immutable_snapshot_root(Cache::from_env().path(), model)?.join(file);
    path.is_file().then_some(path)
}

fn immutable_snapshot_root(cache: &Path, model: &ModelSpec) -> Option<PathBuf> {
    if model.revision.len() != 40 || !model.revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }

    let repo = Repo::with_revision(model.id.clone(), RepoType::Model, model.revision.clone());
    Some(
        cache
            .join(repo.folder_name())
            .join("snapshots")
            .join(&model.revision),
    )
}

fn fetch_optional(repo: &ApiRepo, model: &ModelSpec, file: &str) -> Option<PathBuf> {
    if immutable_snapshot_root(Cache::from_env().path(), model).is_some() {
        immutable_snapshot_file(model, file)
    } else {
        repo.get(file).ok()
    }
}

pub(super) fn get_model_metadata_files(
    model: &ModelSpec,
) -> Result<(PathBuf, PathBuf, PathBuf, Option<PathBuf>)> {
    let repo = model_repo(model)?;
    let config = fetch(&repo, model, "config.json")?;
    let tokenizer = fetch(&repo, model, "tokenizer.json")?;
    let tokenizer_config = fetch(&repo, model, "tokenizer_config.json")?;
    let chat_template = fetch_optional(&repo, model, "chat_template.jinja");

    Ok((config, tokenizer, tokenizer_config, chat_template))
}

pub(super) fn get_program_files(
    model: &ModelSpec,
) -> Result<(Vec<PathBuf>, PathBuf, PathBuf, PathBuf)> {
    let repo = model_repo(model)?;
    let weights = if let Some(index_path) =
        fetch_optional(&repo, model, "model.safetensors.index.json")
    {
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

#[cfg(test)]
mod tests {
    use super::*;

    const REVISION: &str = "c1899de289a04d12100db370d81485cdf75e47ca";

    #[test]
    fn immutable_revision_maps_directly_to_snapshot() {
        let model =
            ModelSpec::parse(&format!("Qwen/Qwen3-0.6B@{REVISION}")).expect("valid model spec");

        assert_eq!(
            immutable_snapshot_root(Path::new("/cache/hub"), &model),
            Some(
                Path::new("/cache/hub")
                    .join("models--Qwen--Qwen3-0.6B")
                    .join("snapshots")
                    .join(REVISION)
            )
        );
    }

    #[test]
    fn mutable_or_malformed_revision_uses_hub_refs() {
        for revision in ["main", "../snapshots/escape", "abc123"] {
            let model =
                ModelSpec::parse(&format!("Qwen/Qwen3-0.6B@{revision}")).expect("valid model spec");
            assert_eq!(
                immutable_snapshot_root(Path::new("/cache/hub"), &model),
                None
            );
        }
    }
}
