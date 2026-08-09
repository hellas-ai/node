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

/// One snapshot of one repository in one cache.
///
/// The unit of resolution, and the reason this type exists at all: a
/// snapshot directory is a set of files that were written for the *same
/// commit*, so taking every file from one of these is what makes a
/// manifest's `resolved_revision` true about its bytes.
#[derive(Clone, Debug)]
struct Snapshot {
    /// `<cache>/models--org--name/snapshots/<commit>`.
    dir: PathBuf,
    commit: String,
}

impl Snapshot {
    /// Where `file` is in this snapshot, if this snapshot has it.
    fn file(&self, file: &str) -> Option<PathBuf> {
        let path = self.dir.join(file);
        path.is_file().then_some(path)
    }
}

/// Where one resolution's files come from — all of them.
///
/// Not a per-file choice. Cache selection used to happen once per file,
/// which meant `main` could resolve `config.json` out of one cache at
/// commit X and the weights out of another at commit Y, and the signed
/// manifest then said X while committing to Y's bytes. A model is a
/// snapshot, so a source is a snapshot.
enum Source<'a> {
    /// One snapshot already on this disk.
    Local(Snapshot),
    /// The hub, which writes into the environment's cache. Reachable
    /// only under [`Reach::Download`], because resolving a path here is
    /// downloading it.
    Hub(&'a ApiRepo),
}

impl Source<'_> {
    /// The path to `file`, which this model cannot do without.
    ///
    /// A missing file in a local snapshot is
    /// [`ModelAssetsError::NotMaterialized`] — a refusal naming what the
    /// operator would have to make available, not an attempt to make it
    /// available, and not a licence to look in the next cache.
    fn require(&self, model: &ModelSpec, file: &str) -> Result<PathBuf> {
        match self {
            Self::Local(snapshot) => {
                snapshot
                    .file(file)
                    .ok_or_else(|| ModelAssetsError::NotMaterialized {
                        model_id: model.id().to_string(),
                        revision: model.revision().to_string(),
                        file: file.to_string(),
                    })
            }
            Self::Hub(api) => api
                .get(file)
                .map_err(|source| ModelAssetsError::FetchModelAsset {
                    model_id: model.id().to_string(),
                    revision: model.revision().to_string(),
                    file: file.to_string(),
                    source,
                }),
        }
    }

    /// The path to `file` when this model has one, `None` when it does
    /// not — for files whose absence is a fact about the repo rather
    /// than a failure.
    fn optional(&self, file: &str) -> Option<PathBuf> {
        match self {
            Self::Local(snapshot) => snapshot.file(file),
            Self::Hub(api) => api.get(file).ok(),
        }
    }

    /// The commit these files came from.
    ///
    /// For a local snapshot it is structural: every path was joined onto
    /// one snapshot directory, so there is nothing to derive and nothing
    /// to check. For the hub it has to be read back off the paths the
    /// download landed at, and checked, because a branch can move
    /// between two `get` calls.
    ///
    /// `paths` must be files at the root of the snapshot — a repository
    /// that keeps its shards in a subdirectory has weight paths one level
    /// further down, and they are covered by the fact that one `ApiRepo`
    /// writes into one repository directory.
    fn commit(&self, paths: &[&Path]) -> Result<String> {
        match self {
            Self::Local(snapshot) => Ok(snapshot.commit.clone()),
            Self::Hub(_) => one_commit(paths),
        }
    }
}

/// The single snapshot directory every one of `paths` lies in.
///
/// Taken from the directory the file actually resolved through, never
/// from the requested revision: `main` moves, and the manifest must name
/// the commit whose bytes were read.
fn one_commit(paths: &[&Path]) -> Result<String> {
    let mut commit: Option<&str> = None;
    for path in paths {
        let name = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .ok_or(ModelAssetsError::UnresolvedRevision)?;
        match commit {
            None => commit = Some(name),
            Some(first) if first != name => {
                return Err(ModelAssetsError::MixedSnapshots {
                    first: first.to_string(),
                    second: name.to_string(),
                });
            }
            Some(_) => {}
        }
    }
    commit
        .map(str::to_string)
        .ok_or(ModelAssetsError::UnresolvedRevision)
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

    /// Every snapshot of this model's revision on this disk, in cache
    /// order.
    fn snapshots(&self) -> Vec<Snapshot> {
        self.caches
            .iter()
            .filter_map(|cache| snapshot_in(cache, &self.model))
            .collect()
    }

    /// Resolves a whole file set out of a *single* snapshot.
    ///
    /// Each cache is asked for the complete model and taken or left as a
    /// whole. A cache holding half of one is not half an answer; it is a
    /// cache that does not have this model, and the next one is asked
    /// from scratch.
    ///
    /// Only a missing file moves on. A snapshot whose index will not
    /// parse, or whose weight map names a file outside itself, is an
    /// error about this node's disk — reporting it beats quietly serving
    /// whatever the next cache happens to hold.
    ///
    /// The refusal reported is the first cache's, since that is the one
    /// a download would have written to and the one an operator is most
    /// likely to be looking at.
    fn resolve<T>(&self, files_of: impl Fn(&Source<'_>) -> Result<T>) -> Result<T> {
        let mut refusal = None;
        for snapshot in self.snapshots() {
            match files_of(&Source::Local(snapshot)) {
                Ok(files) => return Ok(files),
                Err(err @ ModelAssetsError::NotMaterialized { .. }) => {
                    refusal.get_or_insert(err);
                }
                Err(other) => return Err(other),
            }
        }
        if let Some(api) = self.api.as_ref() {
            return files_of(&Source::Hub(api));
        }
        Err(
            refusal.unwrap_or_else(|| ModelAssetsError::NotMaterialized {
                model_id: self.model.id().to_string(),
                revision: self.model.revision().to_string(),
                file: "config.json".to_string(),
            }),
        )
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
/// unmodified; it only widens where "does this disk hold this model?" is
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

/// The snapshot this cache holds for this model's revision, if it holds
/// one.
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
/// The contents of a `refs/` file become a path segment, so they are
/// required to be a plain name. A cache is not a trusted input just
/// because it is local.
fn snapshot_in(cache: &Cache, model: &ModelSpec) -> Option<Snapshot> {
    let repo = cache.path().join(repo_of(model).folder_name());
    let commit = if is_commit(model.revision()) {
        model.revision().to_string()
    } else {
        let named = std::fs::read_to_string(repo.join("refs").join(model.revision())).ok()?;
        let named = named.trim().to_string();
        if !is_plain_name(&named) {
            return None;
        }
        named
    };
    let dir = repo.join("snapshots").join(&commit);
    dir.is_dir().then_some(Snapshot { dir, commit })
}

/// True for a revision that names a commit rather than a branch or tag.
fn is_commit(revision: &str) -> bool {
    revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// True for a string that is one ordinary path component.
fn is_plain_name(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

fn repo_of(model: &ModelSpec) -> Repo {
    Repo::with_revision(
        model.id().to_string(),
        RepoType::Model,
        model.revision().to_string(),
    )
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

/// The metadata files a tokenizer and a chat template are built from.
pub(super) struct MetadataFiles {
    pub config: PathBuf,
    pub tokenizer: PathBuf,
    pub tokenizer_config: PathBuf,
    pub chat_template: Option<PathBuf>,
}

/// Everything a program manifest is built from, and the commit they all
/// came from.
pub(super) struct ProgramFiles {
    pub commit: String,
    pub weights: Vec<PathBuf>,
    pub config: PathBuf,
    pub tokenizer: PathBuf,
    pub tokenizer_config: PathBuf,
}

pub(super) fn get_model_metadata_files(model: &ModelSpec, reach: Reach) -> Result<MetadataFiles> {
    RepoFiles::open(model, reach)?.resolve(|source| metadata_files_of(model, source))
}

fn metadata_files_of(model: &ModelSpec, source: &Source<'_>) -> Result<MetadataFiles> {
    Ok(MetadataFiles {
        config: source.require(model, "config.json")?,
        tokenizer: source.require(model, "tokenizer.json")?,
        tokenizer_config: source.require(model, "tokenizer_config.json")?,
        chat_template: source.optional("chat_template.jinja"),
    })
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

pub(super) fn get_program_files(model: &ModelSpec, reach: Reach) -> Result<ProgramFiles> {
    RepoFiles::open(model, reach)?.resolve(|source| program_files_of(model, source))
}

fn program_files_of(model: &ModelSpec, source: &Source<'_>) -> Result<ProgramFiles> {
    let weights = if let Some(index_path) = source.optional("model.safetensors.index.json") {
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
            files.insert(source.require(model, inside_the_snapshot(file)?)?);
        }
        files.into_iter().collect()
    } else {
        vec![source.require(model, "model.safetensors")?]
    };
    let config = source.require(model, "config.json")?;
    let tokenizer = source.require(model, "tokenizer.json")?;
    let tokenizer_config = source.require(model, "tokenizer_config.json")?;
    let commit = source.commit(&[&config, &tokenizer, &tokenizer_config])?;
    Ok(ProgramFiles {
        commit,
        weights,
        config,
        tokenizer,
        tokenizer_config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REVISION: &str = "c1899de289a04d12100db370d81485cdf75e47ca";
    const OTHER_REVISION: &str = "0e4b1f6a9c2d8b7e5a3f1c0d9b8a7e6f5d4c3b2a";

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
        if model.revision() != commit {
            put(&repo.join("refs").join(model.revision()), commit.as_bytes());
        }
    }

    fn snapshot_of(root: &Path, commit: &str) -> PathBuf {
        root.join("models--Qwen--Qwen3-0.6B")
            .join("snapshots")
            .join(commit)
    }

    /// The three files every resolution needs, so a cache written with
    /// them is a cache that holds a whole model.
    fn metadata(config: &[u8]) -> Vec<(&str, &[u8])> {
        vec![
            ("config.json", config),
            ("tokenizer.json", b"{}"),
            ("tokenizer_config.json", b"{}"),
        ]
    }

    fn local_only(model: &ModelSpec, root: &Path) -> RepoFiles {
        RepoFiles::with_caches(model, vec![Cache::new(root.to_path_buf())], None)
    }

    fn metadata_files(repo: &RepoFiles, model: &ModelSpec) -> Result<MetadataFiles> {
        repo.resolve(|source| metadata_files_of(model, source))
    }

    fn program_files(repo: &RepoFiles, model: &ModelSpec) -> Result<ProgramFiles> {
        repo.resolve(|source| program_files_of(model, source))
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
        materialize(&root, &model, REVISION, &metadata(b"{}"));

        let repo = local_only(&model, &root);
        let files = metadata_files(&repo, &model).expect("a materialized model");
        assert_eq!(
            files.config,
            snapshot_of(&root, REVISION).join("config.json"),
        );
        assert_eq!(files.chat_template, None);

        // A snapshot missing a file this model cannot do without is a
        // refusal naming that file.
        assert!(matches!(
            program_files(&repo, &model),
            Err(ModelAssetsError::NotMaterialized { ref file, .. }) if file == "model.safetensors",
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn branch_revision_resolves_through_its_ref() {
        let root = scratch("branch");
        let model = ModelSpec::parse("Qwen/Qwen3-0.6B").expect("valid model spec");
        materialize(&root, &model, REVISION, &metadata(b"{}"));

        let repo = local_only(&model, &root);
        let files = metadata_files(&repo, &model).expect("a materialized model");
        assert_eq!(
            files.config,
            snapshot_of(&root, REVISION).join("config.json"),
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An empty cache is a refusal, not a download — and the refusal
    /// names the model and the file the operator would have to supply.
    #[test]
    fn an_empty_cache_refuses_by_name() {
        let root = scratch("empty");
        let model = ModelSpec::parse("evil/enormous-repo").expect("valid model spec");

        match metadata_files(&local_only(&model, &root), &model) {
            Err(ModelAssetsError::NotMaterialized {
                model_id,
                revision,
                file,
            }) => {
                assert_eq!(model_id, "evil/enormous-repo");
                assert_eq!(revision, "main");
                assert_eq!(file, "config.json");
            }
            other => panic!("expected a refusal, got {}", described(other)),
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
        let mut files = metadata(b"{}");
        files.extend_from_slice(&[
            ("model.safetensors.index.json", index.as_slice()),
            ("model-00001-of-00002.safetensors", b"shard one"),
            ("model-00002-of-00002.safetensors", b"shard two"),
        ]);
        materialize(&root, &model, REVISION, &files);

        let snapshot = snapshot_of(&root, REVISION);
        let resolved = program_files(&local_only(&model, &root), &model).expect("a whole model");
        assert_eq!(resolved.commit, REVISION);
        assert_eq!(resolved.config, snapshot.join("config.json"));
        assert_eq!(resolved.tokenizer, snapshot.join("tokenizer.json"));
        assert_eq!(
            resolved.tokenizer_config,
            snapshot.join("tokenizer_config.json"),
        );
        let mut weights = resolved.weights;
        weights.sort();
        assert_eq!(
            weights,
            vec![
                snapshot.join("model-00001-of-00002.safetensors"),
                snapshot.join("model-00002-of-00002.safetensors"),
            ],
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A model is never assembled out of two caches.
    ///
    /// This is the case that used to produce a manifest that lied.
    /// Selection happened per file, so `main` took `config.json` from the
    /// first cache — at commit A — and everything else from the second,
    /// at commit B; the commit was then read off the config path, so the
    /// signed manifest said A while committing to B's bytes.
    ///
    /// The first cache here is deliberately the incomplete one, so
    /// "answers from the first cache that has anything" fails and only
    /// "answers from the first cache that has *everything*" passes.
    #[test]
    fn a_model_is_never_assembled_out_of_two_caches() {
        let first = scratch("split-first");
        let second = scratch("split-second");
        let model = ModelSpec::parse("Qwen/Qwen3-0.6B").expect("valid model spec");

        // A branch, because that is what can point at two commits.
        materialize(&first, &model, REVISION, &[("config.json", b"{}")]);
        let mut whole = metadata(b"{}");
        whole.push(("model.safetensors", b"the weights"));
        materialize(&second, &model, OTHER_REVISION, &whole);

        let repo = RepoFiles::with_caches(
            &model,
            vec![Cache::new(first.clone()), Cache::new(second.clone())],
            None,
        );
        let resolved = program_files(&repo, &model).expect("the second cache holds a whole model");

        assert_eq!(
            resolved.commit, OTHER_REVISION,
            "the manifest must name the commit every file came from",
        );
        let snapshot = snapshot_of(&second, OTHER_REVISION);
        for path in [
            &resolved.config,
            &resolved.tokenizer,
            &resolved.tokenizer_config,
            &resolved.weights[0],
        ] {
            assert_eq!(
                path.parent(),
                Some(snapshot.as_path()),
                "{} came from outside the snapshot the manifest names",
                path.display(),
            );
        }

        let _ = std::fs::remove_dir_all(&first);
        let _ = std::fs::remove_dir_all(&second);
    }

    /// The other half: an adopted cache is still consulted, and the
    /// first cache that holds the whole model wins.
    #[test]
    fn the_first_cache_holding_a_whole_model_answers() {
        let first = scratch("two-caches-first");
        let second = scratch("two-caches-second");
        let model = ModelSpec::parse("Qwen/Qwen3-0.6B").expect("valid model spec");
        materialize(&second, &model, REVISION, &metadata(b"{}"));

        let both = |model: &ModelSpec| {
            RepoFiles::with_caches(
                model,
                vec![Cache::new(first.clone()), Cache::new(second.clone())],
                None,
            )
        };

        // Only the second cache holds it: an adopted cache must still be
        // an answer.
        assert_eq!(
            metadata_files(&both(&model), &model)
                .expect("a model only the adopted cache holds")
                .config,
            snapshot_of(&second, REVISION).join("config.json"),
        );

        // Both hold it: the environment's cache is the one a download
        // would have refreshed, so it answers.
        materialize(&first, &model, REVISION, &metadata(b"{}"));
        assert_eq!(
            metadata_files(&both(&model), &model)
                .expect("a model both caches hold")
                .config,
            snapshot_of(&first, REVISION).join("config.json"),
        );

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
        let mut files = metadata(b"{}");
        files.push(("model.safetensors.index.json", index.as_bytes()));
        materialize(&root, &model, REVISION, &files);
        assert!(
            snapshot_of(&root, REVISION).join(escape).is_file(),
            "the escaping name must resolve to a real file, or this test proves nothing",
        );

        match program_files(&local_only(&model, &root), &model) {
            Err(ModelAssetsError::WeightFileOutsideSnapshot { file }) => {
                assert_eq!(file, escape);
            }
            other => panic!(
                "expected the escaping name to be refused, got {}",
                described(other)
            ),
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
    fn a_pinned_revision_is_its_own_snapshot() {
        let root = scratch("pin-maps");
        let model =
            ModelSpec::parse(&format!("Qwen/Qwen3-0.6B@{REVISION}")).expect("valid model spec");
        materialize(&root, &model, REVISION, &[("config.json", b"{}")]);

        let found = snapshot_in(&Cache::new(root.clone()), &model).expect("the snapshot");
        assert_eq!(found.commit, REVISION);
        assert_eq!(found.dir, snapshot_of(&root, REVISION));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Anything that is not a commit sha goes through `refs/`, and what
    /// that file says becomes a path segment — so a cache is not a
    /// trusted input just because it is local.
    #[test]
    fn a_ref_that_names_something_other_than_a_snapshot_resolves_to_nothing() {
        let root = scratch("bad-ref");
        let model = ModelSpec::parse("Qwen/Qwen3-0.6B").expect("valid model spec");
        materialize(&root, &model, REVISION, &[("config.json", b"{}")]);
        let refs = root
            .join("models--Qwen--Qwen3-0.6B")
            .join("refs")
            .join("main");

        // The control: an honest ref resolves.
        assert!(snapshot_in(&Cache::new(root.clone()), &model).is_some());

        for named in ["../snapshots", "..", ".", "a/b", "", "no-such-commit"] {
            put(&refs, named.as_bytes());
            assert!(
                snapshot_in(&Cache::new(root.clone()), &model).is_none(),
                "a ref naming {named:?} must resolve to nothing",
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The hub cannot be asked in a test, so the check that its files all
    /// landed in one snapshot is asserted where it lives.
    #[test]
    fn files_from_two_snapshots_are_not_one_model() {
        let a = Path::new("/cache/models--org--m/snapshots/aaa");
        let b = Path::new("/cache/models--org--m/snapshots/bbb");
        assert_eq!(
            one_commit(&[&a.join("config.json"), &a.join("tokenizer.json")]).expect("one snapshot"),
            "aaa",
        );
        assert!(matches!(
            one_commit(&[&a.join("config.json"), &b.join("tokenizer.json")]),
            Err(ModelAssetsError::MixedSnapshots { .. }),
        ));
        assert!(matches!(
            one_commit(&[]),
            Err(ModelAssetsError::UnresolvedRevision),
        ));
    }

    /// `ModelAssetsError` is not `Debug`-comparable in a `match` arm's
    /// fallthrough without moving it, so failures describe themselves.
    fn described<T>(result: Result<T>) -> String {
        match result {
            Ok(_) => "a successful resolution".to_string(),
            Err(err) => format!("{err:?}"),
        }
    }
}
