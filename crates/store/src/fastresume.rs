//! Remembering that a file has already been hashed.
//!
//! Identifying a large file costs a full read of it. Repeating that work
//! on every scan makes routine indexing expensive and turns large cache
//! trees into a denial-of-service surface, so the result has to be
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
//! entry here makes the index claim that content still occupies a path
//! whose bytes have changed. So the key carries more than libtorrent's
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
use std::ffi::OsString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write as _};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Indexed, open_regular_file};
use hellas_xet::{Chunk, XetHash};

/// What a file must still look like for its recorded hash to be reused.
///
/// Every field is a way the file could have changed underneath us. They
/// are checked together; there is no most-significant one.
///
/// Public because it is the one definition of "the same file" this
/// workspace has. Anything else that remembers work done on a file must
/// ask the same question this asks; a second implementation would be a
/// second answer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

impl FileIdentity {
    /// This file's identity, as `stat` describes it.
    #[must_use]
    pub fn of(metadata: &Metadata) -> Self {
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
/// Maximum persisted cache file accepted or produced. A 1 GiB ceiling keeps
/// very large multi-terabyte content indexes practical while preventing an
/// untrusted or corrupt index from driving an unbounded allocation.
const MAX_FASTRESUME_INDEX_BYTES: usize = 1024 * 1024 * 1024;
/// A persisted index is a cache, so excess entries may be re-hashed instead of
/// allowing an attacker-controlled record count to size an unbounded table.
const MAX_FASTRESUME_RECORDS: usize = 1_000_000;
const FASTRESUME_HEADER_BYTES: usize = 8 + 4 + 8;
const FASTRESUME_RECORD_FIXED_BYTES: usize = 8 + 8 + 8 + 16 + 16 + 32 + 8 + 8;
const FASTRESUME_CHUNK_BYTES: usize = 32 + 8;
const MAX_TEMPORARY_CREATE_ATTEMPTS: usize = 128;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Writes a bounded subset of remembered records to `path`, atomically.
///
/// Written and synced through a uniquely-created sibling before an atomic
/// rename and parent-directory sync. A crash midway therefore leaves the
/// previous file intact rather than a half-written one that would parse into
/// wrong ids. Missing parent components are created owner-only and every new
/// directory edge is synced before publication. Path-based publication still
/// assumes the parent and its ancestors remain stable and trusted while this
/// operation runs.
///
/// # Errors
///
/// Returns the underlying I/O error if the file cannot be written or
/// renamed.
impl Records {
    #[allow(clippy::missing_errors_doc, reason = "documented on the item above")]
    pub fn save(&self, path: &Path) -> std::io::Result<usize> {
        let records = match self.entries.lock() {
            Ok(entries) => entries,
            Err(_) => return Ok(0),
        };

        let capacity = records
            .len()
            .min(MAX_FASTRESUME_RECORDS)
            .saturating_mul(128)
            .clamp(FASTRESUME_HEADER_BYTES, MAX_FASTRESUME_INDEX_BYTES);
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&0_u64.to_le_bytes());
        let mut saved = 0_usize;
        for (identity, indexed) in records.iter() {
            if saved == MAX_FASTRESUME_RECORDS {
                break;
            }
            let Some(record_bytes) = indexed
                .chunks
                .len()
                .checked_mul(FASTRESUME_CHUNK_BYTES)
                .and_then(|chunks| FASTRESUME_RECORD_FIXED_BYTES.checked_add(chunks))
            else {
                continue;
            };
            if out
                .len()
                .checked_add(record_bytes)
                .is_none_or(|total| total > MAX_FASTRESUME_INDEX_BYTES)
            {
                continue;
            }
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
            saved += 1;
        }
        out[12..FASTRESUME_HEADER_BYTES]
            .copy_from_slice(&u64::try_from(saved).unwrap_or(u64::MAX).to_le_bytes());
        drop(records);

        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        create_durable_parent(parent)?;
        let (temporary, mut file) = create_temporary(path, parent)?;
        let mut published = false;
        let result = (|| {
            file.write_all(&out)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temporary, path)?;
            published = true;
            sync_directory(parent)?;
            Ok(saved)
        })();
        if !published {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }
}

fn create_temporary(path: &Path, parent: &Path) -> std::io::Result<(PathBuf, File)> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} has no file name", path.display()),
        )
    })?;
    let mut last_collision = None;
    for _ in 0..MAX_TEMPORARY_CREATE_ATTEMPTS {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".{}.{sequence}.fastresume.tmp", std::process::id()));
        let temporary = parent.join(temporary_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not create a unique fastresume temporary file",
        )
    }))
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK)
            .open(path)?
            .sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Create any missing index-parent components and durably link every new
/// directory into its parent before the index itself is published.
fn create_durable_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        use std::path::Component;

        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} contains a parent-directory component", path.display()),
            ));
        }

        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut missing = Vec::new();
        let mut candidate = absolute.as_path();
        loop {
            match std::fs::metadata(candidate) {
                Ok(metadata) if metadata.is_dir() => break,
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("{} exists and is not a directory", candidate.display()),
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(candidate.to_path_buf());
                }
                Err(error) => return Err(error),
            }
            candidate = candidate.parent().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("{} has no existing directory ancestor", path.display()),
                )
            })?;
        }

        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(&absolute)?;
        for directory in &missing {
            sync_directory(directory)?;
        }
        if let Some(existing_parent) = missing.last().and_then(|directory| directory.parent()) {
            sync_directory(existing_parent)?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
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
        let Ok(file) = open_regular_file(path) else {
            return 0;
        };
        let Ok(metadata) = file.metadata() else {
            return 0;
        };
        let max_bytes = u64::try_from(MAX_FASTRESUME_INDEX_BYTES).unwrap_or(u64::MAX);
        if metadata.len() > max_bytes {
            return 0;
        }
        // The descriptor can grow after metadata inspection. Read one byte
        // beyond the limit so that race is rejected rather than truncated
        // into a different valid-looking index.
        let mut bytes = Vec::new();
        if file
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() > MAX_FASTRESUME_INDEX_BYTES
        {
            return 0;
        }
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
    if count > MAX_FASTRESUME_RECORDS {
        return None;
    }

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
/// blobs, and none of them are complete content.
///
/// An explicitly named file is still checked. This helper also keeps the
/// filtering rule in one place for callers that index a cache directory
/// wholesale.
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

    fn test_path(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("store crate lives below the workspace root")
            .join("target/fastresume-tests")
            .join(format!("{name}-{}.bin", std::process::id()))
    }

    fn one_record(marker: u8) -> Records {
        let hash = XetHash::from_bytes([marker; 32]);
        Records {
            entries: Mutex::new(HashMap::from([(
                FileIdentity {
                    dev: u64::from(marker),
                    ino: u64::from(marker) + 1,
                    size: u64::from(marker) + 2,
                    mtime_ns: i128::from(marker) + 3,
                    ctime_ns: i128::from(marker) + 4,
                },
                Indexed {
                    id: hash,
                    chunks: vec![Chunk::new(hash, u64::from(marker) + 5)],
                    len: u64::from(marker) + 5,
                },
            )])),
        }
    }

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

    #[test]
    fn oversized_persisted_index_is_rejected_without_reading_its_body() {
        let path = test_path("oversized-index");
        std::fs::create_dir_all(path.parent().expect("fixture parent"))
            .expect("create fixture parent");
        let file = std::fs::File::create(&path).expect("create sparse oversized index");
        file.set_len(
            u64::try_from(MAX_FASTRESUME_INDEX_BYTES)
                .unwrap()
                .saturating_add(1),
        )
        .expect("size sparse oversized index");

        assert_eq!(Records::default().load(&path), 0);
        std::fs::remove_file(path).expect("remove oversized fixture");
    }

    #[cfg(unix)]
    #[test]
    fn special_file_index_is_rejected_without_blocking() {
        let path = test_path("fifo-index");
        std::fs::create_dir_all(path.parent().expect("fixture parent"))
            .expect("create fixture parent");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo");
        assert!(status.success(), "the fixture needs a FIFO");

        let (sender, receiver) = std::sync::mpsc::channel();
        let thread_path = path.clone();
        std::thread::spawn(move || {
            let _ = sender.send(Records::default().load(&thread_path));
        });
        assert_eq!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("fastresume load blocked while opening a FIFO"),
            0
        );
        std::fs::remove_file(path).expect("remove FIFO fixture");
    }

    #[test]
    fn excessive_record_count_is_rejected_before_allocation() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(
            &u64::try_from(MAX_FASTRESUME_RECORDS)
                .unwrap()
                .saturating_add(1)
                .to_le_bytes(),
        );

        assert!(parse(&bytes).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn save_does_not_follow_the_legacy_fixed_temporary_symlink() {
        use std::os::unix::fs::symlink;

        let path = test_path("legacy-temporary-symlink");
        let parent = path.parent().expect("fixture parent");
        std::fs::create_dir_all(parent).expect("create fixture parent");
        let victim = parent.join(format!("fastresume-victim-{}", std::process::id()));
        let legacy_temporary = path.with_extension("fastresume.tmp");
        std::fs::write(&victim, b"operator data").expect("create victim");
        symlink(&victim, &legacy_temporary).expect("plant legacy temporary symlink");

        assert_eq!(one_record(1).save(&path).expect("save fastresume"), 1);
        assert_eq!(
            std::fs::read(&victim).expect("read victim"),
            b"operator data"
        );
        assert!(
            std::fs::symlink_metadata(&legacy_temporary)
                .expect("legacy temporary remains")
                .file_type()
                .is_symlink()
        );
        assert_eq!(Records::default().load(&path), 1);

        std::fs::remove_file(path).expect("remove index");
        std::fs::remove_file(legacy_temporary).expect("remove legacy temporary");
        std::fs::remove_file(victim).expect("remove victim");
    }

    #[test]
    fn concurrent_saves_publish_only_complete_parseable_indexes() {
        let path = test_path("concurrent-publication");
        let parent = path.parent().expect("fixture parent");
        std::fs::create_dir_all(parent).expect("create fixture parent");
        one_record(1).save(&path).expect("seed complete index");

        let publishers = 12;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(publishers + 1));
        let mut threads = Vec::new();
        for marker in 2..=u8::try_from(publishers + 1).unwrap() {
            let path = path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                one_record(marker).save(&path)
            }));
        }
        barrier.wait();
        for thread in threads {
            assert_eq!(thread.join().expect("publisher thread").expect("save"), 1);
            let bytes = std::fs::read(&path).expect("read published index");
            assert_eq!(parse(&bytes).expect("published index parses").len(), 1);
        }
        assert_eq!(Records::default().load(&path), 1);

        let final_name = path.file_name().expect("final file name").to_string_lossy();
        let temporary_prefix = format!(".{final_name}.");
        assert!(
            std::fs::read_dir(parent)
                .expect("read fixture parent")
                .filter_map(Result::ok)
                .all(|entry| {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    !name.starts_with(&temporary_prefix) || !name.ends_with(".fastresume.tmp")
                }),
            "successful publication must clean every unique temporary"
        );
        std::fs::remove_file(path).expect("remove index");
    }

    #[test]
    fn save_durably_creates_a_private_parent() {
        use std::os::unix::fs::PermissionsExt as _;

        let existing_parent = test_path("missing-parent").with_extension(format!(
            "{}-dir",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(existing_parent.parent().expect("fixture root"))
            .expect("create fixture root");
        std::fs::create_dir(&existing_parent).expect("create existing parent");
        std::fs::set_permissions(&existing_parent, std::fs::Permissions::from_mode(0o755))
            .expect("make existing parent permissive");
        let missing_parent = existing_parent.join("new").join("state");
        let path = missing_parent.join("content-index.bin");

        assert_eq!(one_record(1).save(&path).expect("save index"), 1);

        assert!(path.is_file());
        assert_eq!(
            std::fs::metadata(&missing_parent)
                .expect("leaf parent metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(existing_parent.join("new"))
                .expect("intermediate parent metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&existing_parent)
                .expect("existing parent metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        std::fs::remove_file(path).expect("remove index");
        std::fs::remove_dir(missing_parent).expect("remove parent");
        std::fs::remove_dir(existing_parent.join("new")).expect("remove intermediate parent");
        std::fs::remove_dir(existing_parent).expect("remove existing parent");
    }

    #[test]
    fn save_rejects_parent_components_before_creating_directories() {
        let existing_parent = test_path("parent-component").with_extension(format!(
            "{}-dir",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(existing_parent.parent().expect("fixture root"))
            .expect("create fixture root");
        std::fs::create_dir(&existing_parent).expect("create existing parent");
        let unrelated = existing_parent.join("must-not-be-created");
        let path = unrelated.join("..").join("content-index.bin");

        let error = one_record(1)
            .save(&path)
            .expect_err("parent components must be refused before mutation");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!unrelated.exists());
        assert!(!existing_parent.join("content-index.bin").exists());
        std::fs::remove_dir(existing_parent).expect("remove existing parent");
    }
}
