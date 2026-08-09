//! Using an existing HuggingFace cache as a populated store.
//!
//! This is the payoff for reusing HuggingFace's hashing byte-for-byte:
//! the model files already on disk are already named by ids we can
//! compute. Adopting a cache is a read, not a download, and it needs no
//! copy — the store points at the files where they lie.
//!
//! # The layout, and the parts of it that are not content
//!
//! A hub cache looks like:
//!
//! ```text
//! models--org--name/
//!   blobs/<etag>              the actual bytes
//!   blobs/<etag>.lock         NOT content (Rust hf-hub writes locks here)
//!   refs/<branch>             a commit sha, one line
//!   snapshots/<commit>/<file> symlinks into ../../blobs/
//!   trees/<commit>.json       per-file metadata, incl. xet_hash
//!   .no_exist/<commit>/<file> zero-byte "this 404s" markers
//! ```
//!
//! A `--local-dir` download instead has real files at their repo paths
//! plus `.cache/huggingface/download/*.metadata` and `*.incomplete`.
//!
//! Indexing `blobs/` directly is what we want: it is the deduplicated
//! form, so a file shared by two revisions is hashed once. The snapshot
//! symlinks would hash the same bytes again under a different path.
//!
//! # Why the advertised `xet_hash` is not used as a key
//!
//! `trees/<commit>.json` carries a `xet_hash` per file, which looks like
//! exactly what we want and mostly is. But for legacy-LFS content
//! bridged into Xet, HuggingFace advertises an id that is **not** the
//! Xet hash of the bytes — measured, on real files, with sha256
//! confirming the bytes were the ones HF meant.
//!
//! So the tree is not read at all. It could serve as a hint — "this is
//! probably content we already hold" — but a hint we must verify anyway
//! saves nothing, and code that reads an id we have decided not to
//! trust invites someone to trust it later. Ids in the store are ones
//! we computed.
//!
//! # Which caches this node adopted
//!
//! [`remember_adopted`] and [`adopted_caches`] persist the *roots* that
//! `adopt` was pointed at. This is the seam the quote path resolves
//! against, so that adopting a cache and quoting a model in it are one
//! question with one answer rather than two subsystems each right about
//! a different disk.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use hellas_xet::XetHash;

use crate::{ContentStore, StoreError, Substituter};

/// An on-disk HuggingFace cache.
#[derive(Debug)]
pub struct HfCache {
    root: PathBuf,
    /// Ids we have confirmed by hashing, mapped to where the bytes are.
    known: RwLock<HashMap<XetHash, PathBuf>>,
}

impl HfCache {
    /// A cache rooted at `root`, typically `~/.cache/huggingface/hub`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            known: RwLock::new(HashMap::new()),
        }
    }

    /// The cache this machine's HuggingFace clients use.
    ///
    /// Honours `HF_HUB_CACHE`, then `HF_HOME`, then the default. Returns
    /// `None` when no home directory can be determined, rather than
    /// guessing a path that might belong to someone else.
    #[must_use]
    pub fn discover() -> Option<Self> {
        if let Some(cache) = std::env::var_os("HF_HUB_CACHE") {
            return Some(Self::new(PathBuf::from(cache)));
        }
        if let Some(home) = std::env::var_os("HF_HOME") {
            return Some(Self::new(PathBuf::from(home).join("hub")));
        }
        let home = std::env::var_os("HOME")?;
        Some(Self::new(
            PathBuf::from(home).join(".cache/huggingface/hub"),
        ))
    }

    /// Where this cache lives.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Hashes every blob in the cache and records what is there.
    ///
    /// Only `blobs/` directories are walked: that is the deduplicated
    /// form, so content shared between revisions is hashed once rather
    /// than once per snapshot symlink pointing at it.
    ///
    /// Cost is one read per blob, and [`crate::fastresume`] means it is
    /// one read *ever* for an unchanged file, across restarts if the
    /// record is persisted. That is what makes adopting a terabyte cache
    /// a throughput cost rather than a recurring one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] only if the cache root cannot be walked at
    /// all. Individual unreadable files are skipped: a cache we do not
    /// own will always contain something we cannot read, and refusing
    /// all of it over one file would be useless.
    pub fn adopt_into(&self, store: &ContentStore) -> Result<usize, StoreError> {
        let mut adopted = 0;
        for blobs in self.blob_directories() {
            for indexed in store.adopt(&blobs)? {
                if let Some(path) = store.locate(indexed.id)
                    && let Ok(mut known) = self.known.write()
                {
                    known.insert(indexed.id, path);
                }
                adopted += 1;
            }
        }
        Ok(adopted)
    }

    /// `models--*` / `datasets--*` directories directly under the root.
    fn repo_directories(&self) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect()
    }

    fn blob_directories(&self) -> Vec<PathBuf> {
        self.repo_directories()
            .into_iter()
            .map(|repo| repo.join("blobs"))
            .filter(|blobs| blobs.is_dir())
            .collect()
    }
}

/// The HuggingFace caches this node has adopted.
///
/// A cache root is the unit both halves of the system already speak: the
/// store walks one to hash its blobs, and the model layer resolves a
/// model's files inside one. Recording which roots were adopted is what
/// lets `hellas store adopt --cache /data/hf` make a model quotable —
/// otherwise the store learns about a cache the quote path has never
/// heard of, and the operator is told two different things by one
/// program.
///
/// It is a list of places to look, not a list of what is there. Nothing
/// here asserts a file exists or has any particular content; resolving
/// still stats, and hashing still happens when the manifest is built.
///
/// Returns an empty list when the registry is missing or unreadable: the
/// cost of forgetting a cache is a refusal an operator can fix, and the
/// registry is a hint about where to look rather than a source of truth.
#[must_use]
pub fn adopted_caches() -> Vec<PathBuf> {
    crate::state::adopted_caches_path()
        .map(|path| adopted_caches_in(&path))
        .unwrap_or_default()
}

/// [`adopted_caches`], from a named registry file.
#[must_use]
pub fn adopted_caches_in(registry: &Path) -> Vec<PathBuf> {
    let Ok(text) = std::fs::read_to_string(registry) else {
        return Vec::new();
    };
    parse_registry(&text)
}

/// Records `root` as a cache this node has adopted, so later processes
/// resolve models against it too.
///
/// Idempotent, and order-preserving so the file stays readable by the
/// person who has to debug it. Written atomically, like the fastresume
/// record: two `adopt` runs racing lose one entry rather than corrupting
/// the list.
///
/// # Errors
///
/// Returns the underlying I/O error if the registry cannot be written.
pub fn remember_adopted(registry: &Path, root: &Path) -> std::io::Result<()> {
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let mut roots = adopted_caches_in(registry);
    if roots.contains(&root) {
        return Ok(());
    }
    roots.push(root);

    let mut text = String::new();
    for root in &roots {
        // A path that is not UTF-8 cannot be written as a line and would
        // come back as a different path. Skipping it keeps the file
        // honest; the operator can still pass --cache.
        if let Some(root) = root.to_str() {
            text.push_str(root);
            text.push('\n');
        }
    }
    if let Some(parent) = registry.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = registry.with_extension("tmp");
    std::fs::write(&temporary, text.as_bytes())?;
    std::fs::rename(&temporary, registry)
}

fn parse_registry(text: &str) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let root = PathBuf::from(line);
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    roots
}

impl Substituter for HfCache {
    fn name(&self) -> &str {
        "huggingface-cache"
    }

    fn locate(&self, id: XetHash) -> Option<PathBuf> {
        self.known
            .read()
            .ok()
            .and_then(|known| known.get(&id).cloned())
            .filter(|path| path.exists())
    }
}
