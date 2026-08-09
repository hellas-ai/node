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
    /// Every HuggingFace cache this node answers about, in the order
    /// they are consulted. Read once, so a resolver answers about one
    /// set of caches rather than about whatever the environment and the
    /// registry happen to say per call.
    caches: Vec<Cache>,
    api: Option<ApiRepo>,
}

impl RepoFiles {
    pub(super) fn open(model: &ModelSpec, reach: Reach) -> Result<Self> {
        let api = match reach {
            Reach::Local => None,
            Reach::Download => Some(model_repo(model)?),
        };
        Ok(Self::with_caches(model, local_caches(), api))
    }

    fn with_caches(model: &ModelSpec, caches: Vec<Cache>, api: Option<ApiRepo>) -> Self {
        Self {
            model: model.clone(),
            caches,
            api,
        }
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
        self.api.as_ref()?.get(file).ok()
    }

    /// Where `file` already is on this disk, if it is here at all.
    fn local(&self, file: &str) -> Option<PathBuf> {
        self.caches
            .iter()
            .find_map(|cache| local_file(cache, &self.model, file))
    }
}

/// Every cache a local resolution may look in.
///
/// The environment's cache first — that is the one a download would
/// write to, so it is where the freshest copy of anything is — and then
/// every cache `hellas store adopt` was pointed at.
///
/// This is the whole of the store/gate convergence: `adopt` records a
/// root, and the gate resolves against it. Note what it is *not*. It
/// carries no content ids and makes no claim that any file is present or
/// unmodified; it only widens where "is this file on this disk?" is
/// asked. The answer is still a `stat`, and the bytes are still hashed
/// later when the manifest is built.
///
/// Reading the registry spends no network, which is the property
/// [`Reach::Local`] exists to guarantee.
fn local_caches() -> Vec<Cache> {
    let mut caches = vec![Cache::from_env()];
    for root in hellas_store::hf_cache::adopted_caches() {
        if !caches.iter().any(|cache| cache.path() == &root) {
            caches.push(Cache::new(root));
        }
    }
    caches
}

/// Resolves `file` against a HuggingFace cache, and nothing else.
///
/// Two layouts, because a revision is either pinned or a branch:
///
/// - A 40-hex revision names a snapshot directory directly. This is also
///   the no-network fast path a download would take, since `hf-hub`
///   keeps no `refs/` entry for a commit sha and would otherwise ask the
///   hub to re-derive what the path already says.
/// - Anything else is a ref, resolved through `refs/<revision>` to the
///   snapshot it currently points at — exactly the lookup `ApiRepo::get`
///   makes before it decides to download.
///
/// So what this finds is what a download would have skipped, and what it
/// does not find is what a download would have paid for.
fn local_file(cache: &Cache, model: &ModelSpec, file: &str) -> Option<PathBuf> {
    if let Some(root) = immutable_snapshot_root(cache.path(), model) {
        let path = root.join(file);
        return path.is_file().then_some(path);
    }
    cache.repo(repo_of(model)).get(file)
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

/// `file` as a name that can only ever land inside the snapshot.
///
/// The names in a weight map come from the repository the *caller*
/// chose, and every one of them is joined onto a snapshot root and then
/// read and hashed. `..` in that string walks out of the snapshot, out
/// of the cache, and up to anything this process can read.
///
/// No oracle was demonstrated — the per-file id is not returned to the
/// caller, only the manifest's aggregate `ContentId` — and rejecting the
/// name is cheaper than establishing that no oracle exists. Ordinary
/// names are untouched: every component must simply be a plain name, so
/// a repository that keeps its shards in a subdirectory still resolves,
/// and one that names `../..` is refused before anything is opened.
fn inside_the_snapshot(file: &str) -> Result<&str> {
    let path = Path::new(file);
    let plain = path.components().count() > 0
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)));
    if plain {
        Ok(file)
    } else {
        Err(ModelAssetsError::WeightFileOutsideSnapshot {
            file: file.to_string(),
        })
    }
}

pub(super) fn get_program_files(
    model: &ModelSpec,
    reach: Reach,
) -> Result<(Vec<PathBuf>, PathBuf, PathBuf, PathBuf)> {
    program_files_of(&RepoFiles::open(model, reach)?)
}

fn program_files_of(repo: &RepoFiles) -> Result<(Vec<PathBuf>, PathBuf, PathBuf, PathBuf)> {
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
            files.insert(repo.require(inside_the_snapshot(file)?)?);
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

    /// A scratch cache root, unique per test so these run in parallel and
    /// never read the developer's real HuggingFace cache.
    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hellas-hf-local-{}-{name}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch cache root");
        root
    }

    fn put(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().expect("file has a parent")).expect("cache dirs");
        std::fs::write(path, bytes).expect("write cache file");
    }

    /// Materializes `files` for `model` in `root`, in the layout the
    /// HuggingFace client writes: a snapshot directory per commit, plus
    /// a `refs/<branch>` pointer when the revision is a branch.
    fn materialize(root: &Path, model: &ModelSpec, commit: &str, files: &[(&str, &[u8])]) {
        let repo = root.join(repo_of(model).folder_name());
        for (file, bytes) in files {
            put(&repo.join("snapshots").join(commit).join(file), bytes);
        }
        if model.revision != commit {
            put(&repo.join("refs").join(&model.revision), commit.as_bytes());
        }
    }

    fn local_only(model: &ModelSpec, root: &Path) -> RepoFiles {
        RepoFiles::with_caches(model, vec![Cache::new(root.to_path_buf())], None)
    }

    #[test]
    fn a_local_resolver_has_no_client_to_download_with() {
        let model = ModelSpec::parse("Qwen/Qwen3-0.6B").expect("valid model spec");
        assert!(
            RepoFiles::open(&model, Reach::Local)
                .expect("local resolver")
                .api
                .is_none(),
            "Reach::Local must not build a hub client at all",
        );
        assert!(
            RepoFiles::open(&model, Reach::Download)
                .expect("download resolver")
                .api
                .is_some(),
        );
    }

    #[test]
    fn pinned_revision_resolves_inside_its_snapshot() {
        let root = scratch("pinned");
        let model =
            ModelSpec::parse(&format!("Qwen/Qwen3-0.6B@{REVISION}")).expect("valid model spec");
        materialize(&root, &model, REVISION, &[("config.json", b"{}")]);

        let repo = local_only(&model, &root);
        assert_eq!(
            repo.require("config.json").expect("materialized file"),
            root.join("models--Qwen--Qwen3-0.6B")
                .join("snapshots")
                .join(REVISION)
                .join("config.json"),
        );
        assert!(matches!(
            repo.require("tokenizer.json"),
            Err(ModelAssetsError::NotMaterialized { ref file, .. }) if file == "tokenizer.json",
        ));
        assert_eq!(repo.optional("chat_template.jinja"), None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn branch_revision_resolves_through_its_ref() {
        let root = scratch("branch");
        let model = ModelSpec::parse("Qwen/Qwen3-0.6B").expect("valid model spec");
        materialize(&root, &model, REVISION, &[("config.json", b"{}")]);

        let repo = local_only(&model, &root);
        assert_eq!(
            repo.require("config.json").expect("materialized file"),
            root.join("models--Qwen--Qwen3-0.6B")
                .join("snapshots")
                .join(REVISION)
                .join("config.json"),
        );
        assert!(matches!(
            repo.require("model.safetensors"),
            Err(ModelAssetsError::NotMaterialized { ref file, .. }) if file == "model.safetensors",
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An empty cache is a refusal, not a download — and the refusal
    /// names the model and the file the operator would have to supply.
    #[test]
    fn an_empty_cache_refuses_by_name() {
        let root = scratch("empty");
        let model = ModelSpec::parse("evil/enormous-repo").expect("valid model spec");

        match local_only(&model, &root).require("config.json") {
            Err(ModelAssetsError::NotMaterialized {
                model_id,
                revision,
                file,
            }) => {
                assert_eq!(model_id, "evil/enormous-repo");
                assert_eq!(revision, "main");
                assert_eq!(file, "config.json");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The other half of the property: local reach refuses what is
    /// missing *and* accepts what is present. A guard that refused
    /// everything would pass the tests above and serve nothing.
    #[test]
    fn a_materialized_model_resolves_every_file_a_manifest_needs() {
        let root = scratch("materialized");
        let model = ModelSpec::parse("Qwen/Qwen3-0.6B").expect("valid model spec");
        let index = br#"{"weight_map":{"a":"model-00001-of-00002.safetensors","b":"model-00002-of-00002.safetensors"}}"#;
        materialize(
            &root,
            &model,
            REVISION,
            &[
                ("config.json", b"{}"),
                ("tokenizer.json", b"{}"),
                ("tokenizer_config.json", b"{}"),
                ("model.safetensors.index.json", index),
                ("model-00001-of-00002.safetensors", b"shard one"),
                ("model-00002-of-00002.safetensors", b"shard two"),
            ],
        );

        let repo = local_only(&model, &root);
        let snapshot = root
            .join("models--Qwen--Qwen3-0.6B")
            .join("snapshots")
            .join(REVISION);
        assert_eq!(
            repo.optional("model.safetensors.index.json"),
            Some(snapshot.join("model.safetensors.index.json")),
        );
        for file in [
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
            "model-00001-of-00002.safetensors",
            "model-00002-of-00002.safetensors",
        ] {
            assert_eq!(repo.require(file).expect(file), snapshot.join(file));
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A file in an adopted cache resolves even when the environment's
    /// cache is empty — and the environment's copy wins when both hold
    /// it, because that is the one a download would have refreshed.
    #[test]
    fn a_second_cache_is_resolved_against_after_the_first() {
        let first = scratch("two-caches-first");
        let second = scratch("two-caches-second");
        let model = ModelSpec::parse("Qwen/Qwen3-0.6B").expect("valid model spec");
        materialize(&first, &model, REVISION, &[("config.json", b"{}")]);
        materialize(
            &second,
            &model,
            REVISION,
            &[("config.json", b"{}"), ("tokenizer.json", b"{}")],
        );

        let repo = RepoFiles::with_caches(
            &model,
            vec![Cache::new(first.clone()), Cache::new(second.clone())],
            None,
        );
        let snapshot = |root: &Path| {
            root.join("models--Qwen--Qwen3-0.6B")
                .join("snapshots")
                .join(REVISION)
        };
        assert_eq!(
            repo.require("config.json").expect("in both caches"),
            snapshot(&first).join("config.json"),
            "the first cache listed answers when it can",
        );
        assert_eq!(
            repo.require("tokenizer.json").expect("only in the second"),
            snapshot(&second).join("tokenizer.json"),
            "a file only the adopted cache holds must still resolve",
        );
        assert!(matches!(
            repo.require("model.safetensors"),
            Err(ModelAssetsError::NotMaterialized { .. }),
        ));

        let _ = std::fs::remove_dir_all(&first);
        let _ = std::fs::remove_dir_all(&second);
    }

    /// A weight map is repository content, and the repository is the
    /// caller's choice. A name that walks out of the snapshot is refused
    /// before the file is opened — and the file it would have reached is
    /// real here, so this fails rather than passing for want of a target.
    #[test]
    fn a_weight_map_cannot_name_a_file_outside_the_snapshot() {
        let root = scratch("escape");
        let model =
            ModelSpec::parse(&format!("Qwen/Qwen3-0.6B@{REVISION}")).expect("valid model spec");
        // `snapshots/<commit>/../../../` is the cache root.
        let escape = "../../../outside.safetensors";
        put(&root.join("outside.safetensors"), b"not this model's");
        let index = format!(r#"{{"weight_map":{{"a":"{escape}"}}}}"#);
        materialize(
            &root,
            &model,
            REVISION,
            &[
                ("config.json", b"{}"),
                ("tokenizer.json", b"{}"),
                ("tokenizer_config.json", b"{}"),
                ("model.safetensors.index.json", index.as_bytes()),
            ],
        );
        assert!(
            root.join("models--Qwen--Qwen3-0.6B")
                .join("snapshots")
                .join(REVISION)
                .join(escape)
                .is_file(),
            "the escaping name must resolve to a real file, or this test proves nothing",
        );

        match program_files_of(&local_only(&model, &root)) {
            Err(ModelAssetsError::WeightFileOutsideSnapshot { file }) => {
                assert_eq!(file, escape);
            }
            other => panic!("expected the escaping name to be refused, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The other half: ordinary names, including a repository that keeps
    /// its shards in a subdirectory, still resolve.
    #[test]
    fn ordinary_weight_names_are_untouched() {
        for name in [
            "model-00001-of-00002.safetensors",
            "shards/model.safetensors",
        ] {
            assert_eq!(inside_the_snapshot(name).expect("an ordinary name"), name);
        }
        for name in ["", ".", "..", "../escape", "/etc/passwd", "a/../../b"] {
            assert!(
                matches!(
                    inside_the_snapshot(name),
                    Err(ModelAssetsError::WeightFileOutsideSnapshot { .. }),
                ),
                "{name:?} must be refused",
            );
        }
    }

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
