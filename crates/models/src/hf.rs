use std::collections::HashSet;
use std::path::{Path, PathBuf};

use hf_hub::api::sync::{ApiBuilder, ApiRepo};
use hf_hub::{Cache, Repo, RepoType};

use super::{ModelAssetsError, Result};
use hellas_rpc::spec::ModelSpec;

/// How far resolving a model's files may go.
///
/// The same split the content store draws between `have` and
/// `materialize`, one layer down: [`Reach::Local`] answers from this
/// disk and can spend no bandwidth, [`Reach::Download`] may fetch what
/// is missing.
///
/// It exists because resolving a HuggingFace file path *is* downloading
/// it: `ApiRepo::get` returns a path by fetching the bytes when they are
/// not cached. So "which files does this model have" cannot be asked of
/// the hub without paying for the answer, and a quote — which any peer
/// that can dial us may ask for — must never be the thing that pays.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reach {
    /// Only files already on this disk. No network, ever.
    Local,
    /// May download from HuggingFace on a cache miss. Deliberate,
    /// operator-initiated work only.
    Download,
}

/// A model repo's files, resolved to on-disk paths within one [`Reach`].
///
/// The HTTP client exists only under [`Reach::Download`]: a local
/// resolver holds `None`, so it cannot download even by mistake. That is
/// the point of the type — locality is structural here, not a boolean
/// someone can forget to consult.
pub(super) struct RepoFiles {
    model: ModelSpec,
    api: Option<ApiRepo>,
}

impl RepoFiles {
    pub(super) fn open(model: &ModelSpec, reach: Reach) -> Result<Self> {
        let api = match reach {
            Reach::Local => None,
            Reach::Download => Some(model_repo(model)?),
        };
        Ok(Self {
            model: model.clone(),
            api,
        })
    }

    /// The path to `file`, which this model cannot do without.
    ///
    /// Under [`Reach::Local`] a missing file is
    /// [`ModelAssetsError::NotMaterialized`] — a refusal naming what the
    /// operator would have to make available, not an attempt to make it
    /// available.
    fn require(&self, file: &str) -> Result<PathBuf> {
        if let Some(path) = self.local(file) {
            return Ok(path);
        }
        let Some(api) = self.api.as_ref() else {
            return Err(ModelAssetsError::NotMaterialized {
                model_id: self.model.id.clone(),
                revision: self.model.revision.clone(),
                file: file.to_string(),
            });
        };
        api.get(file)
            .map_err(|source| ModelAssetsError::FetchModelAsset {
                model_id: self.model.id.clone(),
                revision: self.model.revision.clone(),
                file: file.to_string(),
                source,
            })
    }

    /// The path to `file` when this model has one, `None` when it does
    /// not — for files whose absence is a fact about the repo rather
    /// than a failure.
    fn optional(&self, file: &str) -> Option<PathBuf> {
        if let Some(path) = self.local(file) {
            return Some(path);
        }
        if self.is_pinned() {
            // A pinned revision's snapshot directory is the whole truth
            // about it; asking the hub would only re-derive a path we
            // already know is empty.
            return None;
        }
        self.api.as_ref()?.get(file).ok()
    }

    /// Where `file` already is on this disk, if it is here at all.
    ///
    /// Exactly the lookup `ApiRepo::get` makes before it decides to
    /// download, so what is local here is what a download would have
    /// skipped.
    fn local(&self, file: &str) -> Option<PathBuf> {
        if self.is_pinned() {
            return immutable_snapshot_file(&self.model, file);
        }
        Cache::from_env().repo(repo_of(&self.model)).get(file)
    }

    fn is_pinned(&self) -> bool {
        immutable_snapshot_root(Cache::from_env().path(), &self.model).is_some()
    }
}

fn repo_of(model: &ModelSpec) -> Repo {
    Repo::with_revision(model.id.clone(), RepoType::Model, model.revision.clone())
}

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
    Ok(api.repo(repo_of(model)))
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

pub(super) fn get_model_metadata_files(
    model: &ModelSpec,
    reach: Reach,
) -> Result<(PathBuf, PathBuf, PathBuf, Option<PathBuf>)> {
    let repo = RepoFiles::open(model, reach)?;
    let config = repo.require("config.json")?;
    let tokenizer = repo.require("tokenizer.json")?;
    let tokenizer_config = repo.require("tokenizer_config.json")?;
    let chat_template = repo.optional("chat_template.jinja");

    Ok((config, tokenizer, tokenizer_config, chat_template))
}

pub(super) fn get_program_files(
    model: &ModelSpec,
    reach: Reach,
) -> Result<(Vec<PathBuf>, PathBuf, PathBuf, PathBuf)> {
    let repo = RepoFiles::open(model, reach)?;
    let weights = if let Some(index_path) = repo.optional("model.safetensors.index.json") {
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
            files.insert(repo.require(file)?);
        }
        files.into_iter().collect()
    } else {
        vec![repo.require("model.safetensors")?]
    };
    Ok((
        weights,
        repo.require("config.json")?,
        repo.require("tokenizer.json")?,
        repo.require("tokenizer_config.json")?,
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
