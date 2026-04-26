use super::{Bundle, HuggingFaceLocator};
use crate::backend::create_backend;
use catgrad::runtime::Inputs;
use catgrad_llm::utils::{get_model_files, load_model_weights};
use hellas_rpc::ExecutorError;
use hf_hub::{Cache, Repo, RepoType};
use std::path::Path;
use std::sync::Arc;

pub(crate) struct Loaded {
    pub resolved_revision: String,
    pub bundle: Arc<Bundle>,
}

/// Cheap pre-check: do we already have config + weight files for this
/// locator in the local HF cache? Used by [`crate::programs::Cache`] to
/// decide whether `download-policy=skip` should refuse the load or let it
/// hit the existing cache hit-path.
pub(crate) fn is_cached_locally(locator: &HuggingFaceLocator) -> bool {
    let repo = Cache::default().repo(Repo::with_revision(
        locator.model_id.clone(),
        RepoType::Model,
        locator.revision.clone(),
    ));
    let has_config = repo.get("config.json").is_some();
    let has_weights = repo.get("model.safetensors").is_some()
        || repo.get("model.safetensors.index.json").is_some();
    has_config && has_weights
}

pub(crate) fn load_bundle(locator: &HuggingFaceLocator) -> Result<Loaded, ExecutorError> {
    let backend = create_backend()?;
    let (model_paths, config_path, _tokenizer_path, _tokenizer_config_path) =
        get_model_files(&locator.model_id, &locator.revision)?;
    let resolved_revision = extract_revision_from_snapshot_path(&config_path).ok_or_else(|| {
        ExecutorError::WeightsError(format!(
            "unexpected hf cache path (no snapshots/<sha>): {}",
            config_path.display()
        ))
    })?;

    let (parameter_values, parameter_types, _total_params) =
        load_model_weights(model_paths, &backend, locator.dtype)?;
    let inputs = Inputs::new(backend, parameter_values, parameter_types)
        .map_err(catgrad_llm::LLMError::from)?;
    let bundle = Arc::new(Bundle { inputs });

    Ok(Loaded {
        resolved_revision,
        bundle,
    })
}

fn extract_revision_from_snapshot_path(path: &Path) -> Option<String> {
    let mut components = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy());
    components.find(|c| c == "snapshots")?;
    let revision = components.next()?.to_string();
    (!revision.trim().is_empty()).then_some(revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn extracts_revision_from_snapshot_path() {
        let path = PathBuf::from(
            "/x/.cache/huggingface/hub/models--foo--bar/snapshots/abcd1234/config.json",
        );
        assert_eq!(
            extract_revision_from_snapshot_path(&path).unwrap(),
            "abcd1234"
        );
    }

    #[test]
    fn no_snapshot_segment_returns_none() {
        let path = PathBuf::from("/x/config.json");
        assert!(extract_revision_from_snapshot_path(&path).is_none());
    }
}
