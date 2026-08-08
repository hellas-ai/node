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
//! # Persistence
//!
//! Records survive restarts via [`load`] and [`save`], because a store
//! that re-hashes a 1.5 TB cache every boot is a store nobody will
//! adopt. The file format carries a magic and a version, and anything
//! it does not recognise is discarded rather than guessed at — a
//! misparsed record is a wrong content id, which is the one failure
//! this module exists to prevent.
//!
//! Loading is not trusting: a loaded record is still checked against the
//! live file's identity before it is used, exactly as an in-process one
//! is. The file is a cache of work, never a source of truth.

use std::collections::HashMap;
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Mutex;

use crate::Indexed;
use hellas_xet::{Chunk, XetHash};

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

/// What one store remembers about files it has hashed.
///
/// Owned rather than global. A process-wide table would mean one
/// store's `force_recheck` silently emptied another's, and two stores in
/// one process could never be reasoned about independently — which also
/// made tests interfere with each other, which is how this was noticed.
#[derive(Debug, Default)]
pub struct Records {
    entries: Mutex<HashMap<FileIdentity, Indexed>>,
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

impl Records {
    /// What indexing this file produced last time, if it still looks
    /// exactly the same.
    ///
    /// Keyed on identity rather than path, so one blob reached through
    /// two revisions' snapshot symlinks is hashed once.
    #[must_use]
    pub fn get(&self, metadata: &Metadata) -> Option<Indexed> {
        let identity = FileIdentity::of(metadata);
        self.entries
            .lock()
            .ok()
            .and_then(|entries| entries.get(&identity).cloned())
    }

    /// Records what indexing this file produced.
    ///
    /// The chunk list is stored, not just the id: re-deriving the id
    /// costs a full read, and the chunk list is what a later partial
    /// fetch needs to be verifiable.
    pub fn put(&self, metadata: &Metadata, indexed: &Indexed) {
        let identity = FileIdentity::of(metadata);
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(identity, indexed.clone());
        }
    }

    /// Discards every record, forcing a re-hash of everything.
    ///
    /// The "force recheck" every fastresume implementation needs,
    /// because the identity check is a heuristic and heuristics are
    /// wrong eventually.
    pub fn force_recheck(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }

    /// Number of files remembered.
    #[must_use]
    pub fn remembered(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0)
    }
}

/// Magic at the head of a fastresume file. Present so a truncated or
/// unrelated file is refused rather than read as records.
const MAGIC: &[u8; 8] = b"HELLASFR";
/// Bumped whenever the record layout changes. Old files are discarded,
/// never reinterpreted.
const FORMAT_VERSION: u32 = 1;

/// Writes every remembered record to `path`, atomically.
///
/// Written to a sibling temporary file and renamed, so a crash midway
/// leaves the previous file intact rather than a half-written one that
/// would parse into wrong ids.
///
/// # Errors
///
/// Returns the underlying I/O error if the file cannot be written or
/// renamed.
impl Records {
    #[allow(clippy::missing_errors_doc, reason = "documented on the item above")]
    pub fn save(&self, path: &Path) -> std::io::Result<usize> {
        let records = match self.entries.lock() {
            Ok(entries) => entries.clone(),
            Err(_) => return Ok(0),
        };

        let mut out = Vec::with_capacity(records.len() * 128);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&(records.len() as u64).to_le_bytes());
        for (identity, indexed) in &records {
            out.extend_from_slice(&identity.dev.to_le_bytes());
            out.extend_from_slice(&identity.ino.to_le_bytes());
            out.extend_from_slice(&identity.size.to_le_bytes());
            out.extend_from_slice(&identity.mtime_ns.to_le_bytes());
            out.extend_from_slice(&identity.ctime_ns.to_le_bytes());
            out.extend_from_slice(indexed.id.as_bytes());
            out.extend_from_slice(&indexed.len.to_le_bytes());
            out.extend_from_slice(&(indexed.chunks.len() as u64).to_le_bytes());
            for chunk in &indexed.chunks {
                out.extend_from_slice(chunk.hash.as_bytes());
                out.extend_from_slice(&chunk.data_len.to_le_bytes());
            }
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("fastresume.tmp");
        std::fs::write(&temporary, &out)?;
        std::fs::rename(&temporary, path)?;
        Ok(records.len())
    }
}

/// Reads records from `path` into memory, returning how many were
/// adopted.
///
/// A file that is missing, truncated, of another version, or otherwise
/// unreadable yields zero — never an error and never a partial parse.
/// The cost of ignoring a cache is a re-hash; the cost of misreading one
/// is a wrong content id.
impl Records {
    /// Reads records from `path`, returning how many were adopted.
    #[must_use]
    pub fn load(&self, path: &Path) -> usize {
        let Ok(bytes) = std::fs::read(path) else {
            return 0;
        };
        let Some(parsed) = parse(&bytes) else {
            return 0;
        };
        let count = parsed.len();
        if let Ok(mut entries) = self.entries.lock() {
            entries.extend(parsed);
        }
        count
    }
}

fn parse(bytes: &[u8]) -> Option<Vec<(FileIdentity, Indexed)>> {
    let mut at = 0;
    let mut take = |n: usize| -> Option<&[u8]> {
        let slice = bytes.get(at..at + n)?;
        at += n;
        Some(slice)
    };
    if take(8)? != MAGIC {
        return None;
    }
    if u32::from_le_bytes(take(4)?.try_into().ok()?) != FORMAT_VERSION {
        return None;
    }
    let count = usize::try_from(u64::from_le_bytes(take(8)?.try_into().ok()?)).ok()?;

    let mut parsed = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let identity = FileIdentity {
            dev: u64::from_le_bytes(take(8)?.try_into().ok()?),
            ino: u64::from_le_bytes(take(8)?.try_into().ok()?),
            size: u64::from_le_bytes(take(8)?.try_into().ok()?),
            mtime_ns: i128::from_le_bytes(take(16)?.try_into().ok()?),
            ctime_ns: i128::from_le_bytes(take(16)?.try_into().ok()?),
        };
        let id = XetHash::from_bytes(take(32)?.try_into().ok()?);
        let len = u64::from_le_bytes(take(8)?.try_into().ok()?);
        let chunk_count = usize::try_from(u64::from_le_bytes(take(8)?.try_into().ok()?)).ok()?;
        let mut chunks = Vec::with_capacity(chunk_count.min(1 << 20));
        for _ in 0..chunk_count {
            let hash = XetHash::from_bytes(take(32)?.try_into().ok()?);
            chunks.push(Chunk::new(
                hash,
                u64::from_le_bytes(take(8)?.try_into().ok()?),
            ));
        }
        parsed.push((identity, Indexed { id, chunks, len }));
    }
    // Trailing bytes mean this is not the file we think it is.
    (at == bytes.len()).then_some(parsed)
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
