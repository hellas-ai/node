//! Remembering that a file has already been hashed.
//!
//! Identifying a weight file costs a full read of it. A 14 GB shard read
//! on every quote is the difference between a manifest being cheap and
//! being a denial-of-service surface, so the result has to be
//! remembered.
//!
//! Named after libtorrent's fastresume data, which is the same idea and
//! the same hazard: after a hash-check a client records what it learned
//! about each file so a restart need not re-verify, and validates that
//! record against the file's size and mtime before trusting it. Every
//! such client also offers "force recheck", because the record can be
//! wrong.
//!
//! # Why this one has to be stricter than a torrent client's
//!
//! A stale entry in a torrent client means a corrupt download. A stale
//! entry here means the provider signs an `execution_environment`
//! committing to weights it does not have — a claim it can lose under
//! the fraud game. So the key carries more than libtorrent's
//! `(size, mtime)`:
//!
//! - `dev` + `ino` — in the HuggingFace layout a content change *is* an
//!   inode change, because the client writes a new blob and re-points
//!   the snapshot symlink. Weak to inode reuse on its own.
//! - `size` — catches truncation and extension.
//! - `mtime_ns` — catches ordinary edits. Defeated by `utimensat`
//!   backdating, and by coarse filesystem resolution within one second.
//! - `ctime_ns` — cannot be set backwards from userspace, which is what
//!   closes the two holes above.
//!
//! Any disagreement discards the entry. There is no partial trust.
//!
//! # Scope
//!
//! In-process only, and deliberately so. A persisted cache is a
//! correctness contract that survives restarts, upgrades and crashes,
//! and it should not be introduced before the content store that will
//! own it. This removes every repeat cost within a process and carries
//! no such contract.

use std::collections::HashMap;
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use hellas_rpc::ContentId;

/// What a file must still look like for its recorded hash to be reused.
///
/// Every field is a way the file could have changed underneath us. They
/// are checked together; there is no most-significant one.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

impl FileIdentity {
    fn of(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            mtime_ns: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
            ctime_ns: i128::from(metadata.ctime()) * 1_000_000_000
                + i128::from(metadata.ctime_nsec()),
        }
    }
}

fn records() -> &'static Mutex<HashMap<FileIdentity, ContentId>> {
    static RECORDS: OnceLock<Mutex<HashMap<FileIdentity, ContentId>>> = OnceLock::new();
    RECORDS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns the recorded content id for `path`, if the file still looks
/// exactly as it did when it was hashed.
///
/// Keyed on identity rather than path so the same blob reached through
/// two revisions' snapshot symlinks is hashed once.
pub(crate) fn get(metadata: &Metadata) -> Option<ContentId> {
    let identity = FileIdentity::of(metadata);
    records()
        .lock()
        .map(|records| records.get(&identity).copied())
        .unwrap_or_default()
}

/// Records that `metadata`'s file hashed to `id`.
pub(crate) fn put(metadata: &Metadata, id: ContentId) {
    let identity = FileIdentity::of(metadata);
    if let Ok(mut records) = records().lock() {
        records.insert(identity, id);
    }
}

/// True when two stats describe the same unchanged file.
///
/// Used to check that a file did not change *while it was being
/// hashed*: a read that races a rewrite produces an id for bytes that
/// were never on disk together, and recording it would poison the
/// record with a hash of nothing real.
pub(crate) fn identical(before: &Metadata, after: &Metadata) -> bool {
    FileIdentity::of(before) == FileIdentity::of(after)
}

/// Discards every record, forcing a re-hash of everything.
///
/// The "force recheck" every fastresume implementation needs, because
/// the identity check is a heuristic and heuristics are wrong
/// eventually.
pub fn force_recheck() {
    if let Ok(mut records) = records().lock() {
        records.clear();
    }
}

/// Number of files currently remembered. For tests and diagnostics.
#[must_use]
pub fn remembered() -> usize {
    records().lock().map(|records| records.len()).unwrap_or(0)
}

/// True when `path` cannot be content: HuggingFace caches carry lock
/// files, partial downloads and negative-cache markers alongside real
/// blobs, and none of them are weights.
///
/// Not used on the manifest path, where filenames come from the model
/// index — it is here for whatever indexes a cache directory wholesale,
/// so the rule lives with the rest of the cache-shaped knowledge.
#[must_use]
pub fn is_cache_debris(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    // `hf-hub` writes `<etag>.lock` INSIDE blobs/; Python writes
    // `.incomplete` files whose embedded etag is a goal, not a fact.
    name.ends_with(".lock")
        || name.ends_with(".incomplete")
        || path
            .components()
            .any(|component| component.as_os_str() == ".no_exist")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debris_is_recognised_and_real_files_are_not() {
        assert!(is_cache_debris(Path::new("/c/blobs/abc.lock")));
        assert!(is_cache_debris(Path::new("/c/download/x.abc.incomplete")));
        assert!(is_cache_debris(Path::new("/c/.no_exist/sha/config.json")));
        assert!(!is_cache_debris(Path::new("/c/blobs/abcdef")));
        assert!(!is_cache_debris(Path::new(
            "/c/snapshots/sha/model.safetensors"
        )));
    }
}
