use super::{WeightsBundle, WeightsLocator};
use crate::backend::create_backend;
use crate::ExecutorError;
use catgrad_llm::utils::{get_model_files, load_model_weights};
use hf_hub::{Cache, Repo, RepoType};
use std::path::Path;
use std::sync::Arc;

pub(crate) struct LoadedWeights {
    pub resolved_revision: String,
    pub bundle: Arc<WeightsBundle>,
}

pub(crate) fn has_cached_weights(locator: &WeightsLocator) -> bool {
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

pub(crate) fn load_weights_bundle(
    locator: &WeightsLocator,
) -> Result<LoadedWeights, ExecutorError> {
    let backend = create_backend()?;
    let (model_paths, config_path, _tokenizer_path, _tokenizer_config_path) =
        get_model_files(&locator.model_id, &locator.revision)?;
    let resolved_revision = extract_revision_from_snapshot_path(&config_path).ok_or_else(|| {
        ExecutorError::WeightsError(format!(
            "unexpected hf cache path (no snapshots/<sha>): {config_path:?}"
        ))
    })?;

    let (parameter_values, parameter_types, _total_params) =
        load_model_weights(model_paths, &backend)?;
    let bundle = Arc::new(WeightsBundle {
        parameter_values,
        parameter_types,
    });

    Ok(LoadedWeights {
        resolved_revision,
        bundle,
    })
}

fn extract_revision_from_snapshot_path(path: &Path) -> Option<String> {
    let mut components = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy());
    while let Some(component) = components.next() {
        if component == "snapshots" {
            let revision = components.next()?.to_string();
            return (!revision.trim().is_empty()).then_some(revision);
        }
    }
    None
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
