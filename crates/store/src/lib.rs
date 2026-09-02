//! A content store addressed by Xet file hash.
//!
//! # The shape
//!
//! A Nix store, or a BitTorrent client's view of its own disk: an entry
//! is named by a hash of its content, so *where it came from is not part
//! of its identity*. That single property is what makes everything else
//! work — any source producing the right bytes is as good as any other,
//! so content can be substituted from a local HuggingFace cache, a peer,
//! an HTTP seed, or a tarball without any of them being privileged.
//!
//! We reuse HuggingFace's exact hashing scheme ([`hellas_xet`]), which
//! is the trick the whole design turns on: **an existing HuggingFace
//! cache is already a populated store**. Adopting one is indexing, not
//! downloading.
//!
//! # Indexing produces two things, and the second is the valuable one
//!
//! [`ContentStore::index`] returns the content id *and* the chunk list.
//! Keeping only the id would throw away the expensive half of a pass we
//! must make anyway.
//!
//! The chunk list is the metainfo, in the BitTorrent sense. A Xet file
//! hash is a Merkle root over exactly those descriptors, so holding them
//! makes any later *partial* fetch of that file verifiable. This matters
//! because HuggingFace's reconstruction protocol returns no chunk hashes
//! at all — content arriving from an untrusted peer is otherwise
//! unverifiable until the whole file is reassembled, which is a fine way
//! to waste fourteen gigabytes on a liar.
//!
//! # Never trust an id you did not compute
//!
//! HuggingFace advertises an `x-xet-hash` per file. For Xet-native
//! uploads it is exactly the Xet hash of the content. For legacy-LFS
//! content bridged into Xet it is **not** — measured, on real files,
//! with matching sha256 confirming the bytes were the ones HF meant.
//!
//! So an advertised id is a hint that lets us skip work when it agrees,
//! and never a key. Ids in this store are ones we computed: a
//! content-addressed store cannot defend a key it did not derive from
//! the bytes.

pub mod fastresume;
pub mod hf;
pub mod hf_cache;
pub mod state;
pub mod xorb;

use std::collections::HashMap;
#[cfg(any(unix, test))]
use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use hellas_xet::{Chunk, XetFileHasher, XetHash};

/// Bytes read per `read` while hashing. Large enough that the syscall is
/// not the bottleneck, small enough to be irrelevant beside a model.
const STREAM_BUFFER: usize = 1024 * 1024;

/// Opens a local regular file without first opening a FIFO or device for I/O.
///
/// Explicit content paths may be symlinks: the target descriptor, rather than
/// the symlink name, is the authority. Linux first acquires an `O_PATH`
/// descriptor, which does not open the underlying object, checks its type, and
/// then reopens that exact inode through `/proc/self/fd`. Consequently a path
/// replacement between the type check and the readable open cannot substitute
/// a FIFO or device. The returned descriptor is read-only, seekable, and
/// close-on-exec.
///
/// Other platforms do not expose an equivalent through `std`: they preflight
/// the followed path, use nonblocking open where Unix provides it, and verify
/// the resulting descriptor. That rejects stable special files but cannot
/// close an adversarial replacement race as Linux does.
pub fn open_regular_file(path: &Path) -> io::Result<std::fs::File> {
    open_regular_file_impl(path)
}

fn not_a_regular_file(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{} is not a regular file", path.display()),
    )
}

#[cfg(target_os = "linux")]
fn open_regular_file_impl(path: &Path) -> io::Result<std::fs::File> {
    let path_handle = open_path_handle(path)?;
    reopen_regular_path_handle(path, &path_handle)
}

/// Acquires an inode reference without invoking the target's file operations.
#[cfg(target_os = "linux")]
fn open_path_handle(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC);
    options.open(path)
}

/// Converts an `O_PATH` reference to a readable descriptor for the same inode.
#[cfg(target_os = "linux")]
fn reopen_regular_path_handle(
    path: &Path,
    path_handle: &std::fs::File,
) -> io::Result<std::fs::File> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let expected = path_handle.metadata()?;
    if !expected.file_type().is_file() {
        return Err(not_a_regular_file(path));
    }

    let descriptor_path = Path::new("/proc/self/fd").join(path_handle.as_raw_fd().to_string());
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_CLOEXEC);
    let file = options.open(&descriptor_path).map_err(|source| {
        // Once the held descriptor has been fstat-ed successfully, ENOENT can
        // only mean procfs cannot provide the safe reopen. Do not report the
        // caller's existing content as a cache miss.
        let kind = if source.kind() == io::ErrorKind::NotFound {
            io::ErrorKind::Unsupported
        } else {
            source.kind()
        };
        io::Error::new(
            kind,
            format!(
                "cannot safely reopen {} through {}: {source}",
                path.display(),
                descriptor_path.display()
            ),
        )
    })?;
    let actual = file.metadata()?;
    if !actual.file_type().is_file()
        || (expected.dev(), expected.ino()) != (actual.dev(), actual.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} did not reopen the inode held by its path descriptor",
                path.display()
            ),
        ));
    }
    Ok(file)
}

/// Best available fallback where `O_PATH` plus descriptor reopen is absent.
#[cfg(all(unix, not(target_os = "linux")))]
fn open_regular_file_impl(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let expected = std::fs::metadata(path)?;
    if !expected.file_type().is_file() {
        return Err(not_a_regular_file(path));
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = options.open(path)?;
    let actual = file.metadata()?;
    if !actual.file_type().is_file()
        || (expected.dev(), expected.ino()) != (actual.dev(), actual.ino())
    {
        return Err(not_a_regular_file(path));
    }
    Ok(file)
}

/// Best available fallback for non-Unix targets.
#[cfg(not(unix))]
fn open_regular_file_impl(path: &Path) -> io::Result<std::fs::File> {
    let expected = std::fs::metadata(path)?;
    if !expected.file_type().is_file() {
        return Err(not_a_regular_file(path));
    }
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(not_a_regular_file(path));
    }
    Ok(file)
}

/// What indexing one file learned about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Indexed {
    /// The content id: a Merkle root over `chunks`.
    pub id: XetHash,
    /// Chunk descriptors, in order. The metainfo that makes a partial
    /// fetch of this content verifiable.
    pub chunks: Vec<Chunk>,
    /// Total length in bytes.
    pub len: u64,
}

/// Hashes exactly the length captured from the descriptor, then probes one
/// byte past it. `None` means the file was truncated or grew while it was
/// being read; importantly, a writer that grows forever cannot extend this
/// loop forever.
fn hash_exact_length(reader: &mut impl io::Read, expected_len: u64) -> io::Result<Option<Indexed>> {
    let mut hasher = XetFileHasher::new();
    let mut buffer = vec![0_u8; STREAM_BUFFER];
    let mut remaining = expected_len;
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(STREAM_BUFFER as u64))
            .expect("the read is bounded by STREAM_BUFFER");
        let read = reader.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Ok(None);
        }
        remaining -= read as u64;
        hasher.update(&buffer[..read]);
    }

    let mut sentinel = [0_u8; 1];
    if reader.read(&mut sentinel)? != 0 {
        return Ok(None);
    }

    let chunks = hasher.finalize_chunks();
    Ok(Some(Indexed {
        id: hellas_xet::file_hash(&chunks),
        chunks,
        len: expected_len,
    }))
}

/// A read-only handle to content whose identity and exact length the store
/// verified.
///
/// The descriptor, rather than its path, is the authority. A cache name may
/// be replaced after this value is returned without changing the inode that a
/// consumer receives. This is not an immutable-file seal: another writable
/// descriptor can still modify the same inode after verification.
#[derive(Debug)]
pub struct VerifiedFile {
    file: std::fs::File,
    id: XetHash,
    len: u64,
}

impl VerifiedFile {
    /// The Xet content id this descriptor was verified against.
    #[must_use]
    pub fn id(&self) -> XetHash {
        self.id
    }

    /// The exact verified length of the file.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the verified file is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Transfers the read-only descriptor to its consumer.
    #[must_use]
    pub fn into_file(self) -> std::fs::File {
        self.file
    }
}

/// Anything that can make content appear that is not here yet.
///
/// Separate from [`Substituter`] on purpose. A substituter answers
/// cheaply and locally; a fetcher may spend bandwidth and disk. Keeping
/// the interfaces separate lets callers choose explicitly whether an
/// operation may perform remote work.
pub trait Fetcher: Send + Sync {
    /// Name, for diagnostics.
    fn name(&self) -> &str;

    /// Writes content `id` to `dest`, verifying it.
    ///
    /// `expected` is our chunk list for this content when we have one,
    /// which lets an implementation check a partial response as it
    /// arrives instead of only once it is whole.
    fn fetch(
        &self,
        id: XetHash,
        dest: &Path,
        expected: Option<&[Chunk]>,
    ) -> core::result::Result<u64, crate::hf::FetchError>;
}

/// Anything that might already hold content we want.
///
/// Deliberately narrow: a substituter answers "do you have this, and
/// where", and nothing else. It does not fetch, because a source that
/// can fetch and a source that can answer cheaply have very different
/// costs. An availability check must not silently become network
/// activity.
pub trait Substituter: Send + Sync {
    /// Name, for diagnostics.
    fn name(&self) -> &str;

    /// Path to content with this id, if this source already holds it.
    fn locate(&self, id: XetHash) -> Option<PathBuf>;
}

/// Errors from store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("reading {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is cache debris, not content")]
    Debris { path: PathBuf },
    #[error("{path} changed while it was being read")]
    Raced { path: PathBuf },
    #[error("{path} now names a different file than the one that was read")]
    Replaced { path: PathBuf },
    #[error("{path} holds {actual}, which is not the {expected} that was asked for")]
    WrongContent {
        expected: String,
        actual: String,
        path: PathBuf,
    },
    #[error("{path} is {actual} bytes, not the {expected} bytes declared for {id}")]
    WrongLength {
        id: String,
        expected: u64,
        actual: u64,
        path: PathBuf,
    },
    #[error("{path} is {actual} bytes, over the {maximum}-byte limit for {id}")]
    TooLarge {
        id: String,
        maximum: u64,
        actual: u64,
        path: PathBuf,
    },
    #[error("materialising {id}")]
    Fetch {
        id: String,
        #[source]
        source: crate::hf::FetchError,
    },
}

type Result<T> = std::result::Result<T, StoreError>;

/// A content-addressed store over local paths.
///
/// Cheap to clone; clones share one index.
#[derive(Clone, Default)]
pub struct ContentStore {
    index: Arc<RwLock<HashMap<XetHash, Entry>>>,
    /// What this store has already hashed. Owned, so two stores never
    /// invalidate each other's work.
    records: Arc<fastresume::Records>,
    substituters: Arc<Vec<Arc<dyn Substituter>>>,
}

#[derive(Clone, Debug)]
struct Entry {
    path: PathBuf,
    /// The file this id was computed from, as `stat` described it.
    ///
    /// An entry says "these bytes are at this path", and a path is not a
    /// promise. Keeping the identity is what lets [`ContentStore::locate`]
    /// notice that the name now refers to something else, instead of
    /// answering `have` for content that was overwritten an hour ago.
    identity: fastresume::FileIdentity,
    chunks: Vec<Chunk>,
}

impl ContentStore {
    /// An empty store with no substituters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a place content may already be. Consulted in the order
    /// added, after the store's own index.
    #[must_use]
    pub fn with_substituter(mut self, substituter: Arc<dyn Substituter>) -> Self {
        let mut substituters = self.substituters.as_ref().clone();
        substituters.push(substituter);
        self.substituters = Arc::new(substituters);
        self
    }

    /// Hashes the file at `path` and records it — "give it data to hash
    /// and start seeding".
    ///
    /// Streams, so cost is one read regardless of size. An unchanged
    /// file is hashed once: [`fastresume`] remembers the result against
    /// the file's identity.
    pub fn index(&self, path: &Path) -> Result<Indexed> {
        self.index_open(path).map(|(indexed, _file)| indexed)
    }

    /// Indexes `path` while retaining the descriptor whose bytes justified
    /// the result.
    fn index_open(&self, path: &Path) -> Result<(Indexed, std::fs::File)> {
        use std::io::Seek as _;

        if fastresume::is_cache_debris(path) {
            return Err(StoreError::Debris {
                path: path.to_path_buf(),
            });
        }

        let read_err = |source| StoreError::Read {
            path: path.to_path_buf(),
            source,
        };
        let mut file = open_regular_file(path).map_err(read_err)?;
        let before = file.metadata().map_err(read_err)?;
        let identity = fastresume::FileIdentity::of(&before);

        let remembered = self.records.get(&before);
        let indexed = match remembered.clone() {
            Some(indexed) => indexed,
            None => hash_exact_length(&mut file, before.len())
                .map_err(read_err)?
                .ok_or_else(|| StoreError::Raced {
                    path: path.to_path_buf(),
                })?,
        };

        // Nothing is remembered, recorded or returned until this holds.
        // Whether the id was computed just now or looked up, it is an id
        // for the descriptor; recording it against a *name* needs that
        // name to still refer to the same file, and an id that cannot be
        // bound to what was read is an error rather than an answer.
        still_the_file_that_was_read(path, identity, &file)?;
        file.rewind().map_err(read_err)?;
        if remembered.is_none() {
            self.records.put(&before, &indexed);
        }
        self.record(path, identity, &indexed);
        Ok((indexed, file))
    }

    /// Indexes every regular file under `directory`, skipping cache
    /// debris. Returns what was indexed.
    ///
    /// This is how an existing HuggingFace cache becomes a populated
    /// store: no download, no copy, just a read of what is already
    /// there.
    pub fn adopt(&self, directory: &Path) -> Result<Vec<Indexed>> {
        let mut adopted = Vec::new();
        let mut pending = vec![directory.to_path_buf()];
        while let Some(dir) = pending.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                // A cache we do not own can have directories we cannot
                // read. Skipping one is better than refusing all of it.
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                // `file_type` is `lstat`, and only a regular file is
                // content. A symlink here would be followed to bytes
                // that are already indexed under their own name — or,
                // pointed at `/dev/zero`, read forever. A fifo under
                // `blobs/` would block adoption of the whole cache on
                // `open`. Neither is exotic in a directory we do not own.
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                if kind.is_dir() {
                    pending.push(path);
                } else if kind.is_file()
                    && !fastresume::is_cache_debris(&path)
                    && let Ok(indexed) = self.index(&path)
                {
                    adopted.push(indexed);
                }
            }
        }
        Ok(adopted)
    }

    /// True when this content is available locally, right now, without
    /// touching the network.
    ///
    /// Deliberately narrower than [`Self::materialize`]: checking
    /// availability never causes a remote fetch.
    #[must_use]
    pub fn have(&self, id: XetHash) -> bool {
        self.locate(id).is_some()
    }

    /// Where this content is, if anywhere reachable already holds it.
    #[must_use]
    pub fn locate(&self, id: XetHash) -> Option<PathBuf> {
        if let Some(entry) = self
            .index
            .read()
            .ok()
            .and_then(|index| index.get(&id).cloned())
        {
            // Existence is not the question. The question is whether the
            // name still refers to the file whose bytes produced this id:
            // an ordinary rewrite leaves the path there and the entry
            // false, and `have` must not claim bytes the store no longer
            // holds.
            if std::fs::metadata(&entry.path)
                .is_ok_and(|metadata| fastresume::FileIdentity::of(&metadata) == entry.identity)
            {
                return Some(entry.path);
            }
            if let Ok(mut index) = self.index.write() {
                index.remove(&id);
            }
        }
        self.substituters
            .iter()
            .find_map(|substituter| substituter.locate(id))
    }

    /// Opens locally available content as the exact inode the store verified.
    ///
    /// An indexed hit is opened and matched against the full file identity
    /// recorded when it was hashed, so replacing its path cannot substitute a
    /// different inode between lookup and open. This path does not rehash an
    /// unchanged indexed file. A substituter hit is less trusted: it is
    /// indexed, checked against `id`, and returned through the same descriptor
    /// that was indexed. No fetcher is consulted and no content is acquired.
    ///
    /// `expected_len` is part of the caller's content contract and must match
    /// the descriptor exactly.
    pub fn open_verified(&self, id: XetHash, expected_len: u64) -> Result<Option<VerifiedFile>> {
        self.open_verified_with(id, LengthContract::Exact(expected_len))
    }

    /// Opens locally available content whose exact length is not known by the
    /// caller, refusing it before allocation when it exceeds `maximum_len`.
    ///
    /// This is for content-addressed metadata such as an application-owned
    /// manifest root: its hash is the identity, while its decoder owns the
    /// exact shape and length. As with [`Self::open_verified`], this performs
    /// no network fetch and returns the descriptor whose identity was checked.
    pub fn open_verified_bounded(
        &self,
        id: XetHash,
        maximum_len: u64,
    ) -> Result<Option<VerifiedFile>> {
        self.open_verified_with(id, LengthContract::AtMost(maximum_len))
    }

    fn open_verified_with(
        &self,
        id: XetHash,
        length: LengthContract,
    ) -> Result<Option<VerifiedFile>> {
        if let Some(entry) = self
            .index
            .read()
            .ok()
            .and_then(|index| index.get(&id).cloned())
        {
            if let Some(verified) = open_indexed_file(id, length, &entry)? {
                return Ok(Some(verified));
            }
            self.forget_if_stale(id, &entry);
        }

        for substituter in self.substituters.iter() {
            let Some(path) = substituter.locate(id) else {
                continue;
            };
            let (indexed, file) = self.index_open(&path)?;
            if indexed.id != id {
                return Err(StoreError::WrongContent {
                    expected: id.to_string(),
                    actual: indexed.id.to_string(),
                    path,
                });
            }
            let actual = file
                .metadata()
                .map_err(|source| StoreError::Read {
                    path: path.clone(),
                    source,
                })?
                .len();
            check_length(id, actual, &path, length)?;
            return Ok(Some(VerifiedFile {
                file,
                id,
                len: actual,
            }));
        }

        Ok(None)
    }

    /// The chunk list for indexed content — the metainfo needed to
    /// verify a partial fetch of it.
    #[must_use]
    pub fn chunks(&self, id: XetHash) -> Option<Vec<Chunk>> {
        self.index
            .read()
            .ok()
            .and_then(|index| index.get(&id).map(|entry| entry.chunks.clone()))
    }

    /// Makes content `id` available locally, fetching it if it is not
    /// already here, and indexes the result.
    ///
    /// Unlike [`Self::have`], this operation may cost bandwidth and disk.
    /// The caller decides when that remote work is permitted.
    ///
    /// `fetch` is handed the chunk list when we already hold one, so a
    /// partial response can be checked chunk by chunk rather than only
    /// at the end.
    pub fn materialize(&self, id: XetHash, dest: &Path, fetch: &dyn Fetcher) -> Result<Indexed> {
        if let Some(path) = self.locate(id) {
            let indexed = self.index(&path)?;
            // A source said it held this id. Believing that without
            // looking is how `materialize(a)` comes to return content
            // `b` — a substituter is another node's answer, not ours.
            if indexed.id != id {
                return Err(StoreError::WrongContent {
                    expected: id.to_string(),
                    actual: indexed.id.to_string(),
                    path,
                });
            }
            return Ok(indexed);
        }
        // Only what we made appear is ours to clean up. A `dest` that was
        // already there belongs to whoever put it there.
        let ours = dest.symlink_metadata().is_err();
        fetch
            .fetch(id, dest, self.chunks(id).as_deref())
            .map_err(|source| StoreError::Fetch {
                id: id.to_string(),
                source,
            })?;
        let indexed = self.index(dest)?;
        // A fetcher that wrote the wrong bytes must not leave them in
        // the store under a name they do not own.
        if indexed.id != id {
            if ours {
                let _ = std::fs::remove_file(dest);
            }
            return Err(StoreError::Fetch {
                id: id.to_string(),
                source: crate::hf::FetchError::WrongContent {
                    expected: id,
                    actual: indexed.id,
                },
            });
        }
        Ok(indexed)
    }

    /// What this store remembers having hashed.
    ///
    /// Exposed so a caller can persist it across restarts — adopting a
    /// terabyte cache should cost one read per file ever, not one per
    /// boot.
    #[must_use]
    pub fn records(&self) -> &fastresume::Records {
        &self.records
    }

    /// Number of distinct contents indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.read().map(|index| index.len()).unwrap_or(0)
    }

    /// True when nothing is indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn record(&self, path: &Path, identity: fastresume::FileIdentity, indexed: &Indexed) {
        if let Ok(mut index) = self.index.write() {
            index.insert(
                indexed.id,
                Entry {
                    path: path.to_path_buf(),
                    identity,
                    chunks: indexed.chunks.clone(),
                },
            );
        }
    }

    fn forget_if_stale(&self, id: XetHash, stale: &Entry) {
        if let Ok(mut index) = self.index.write()
            && index.get(&id).is_some_and(|current| {
                current.path == stale.path && current.identity == stale.identity
            })
        {
            index.remove(&id);
        }
    }
}

#[derive(Clone, Copy)]
enum LengthContract {
    Exact(u64),
    AtMost(u64),
}

/// Opens an indexed path, then decides from the descriptor rather than from a
/// second lookup of the name. If replacement happened before `open`, the new
/// inode is refused. If it happened after `open`, the already-open verified
/// inode remains the one returned.
fn open_indexed_file(
    id: XetHash,
    length: LengthContract,
    entry: &Entry,
) -> Result<Option<VerifiedFile>> {
    let file = match open_regular_file(&entry.path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StoreError::Read {
                path: entry.path.clone(),
                source,
            });
        }
    };
    verify_opened_indexed_file(id, length, entry, file)
}

fn verify_opened_indexed_file(
    id: XetHash,
    length: LengthContract,
    entry: &Entry,
    file: std::fs::File,
) -> Result<Option<VerifiedFile>> {
    let metadata = file.metadata().map_err(|source| StoreError::Read {
        path: entry.path.clone(),
        source,
    })?;
    if fastresume::FileIdentity::of(&metadata) != entry.identity {
        return Ok(None);
    }
    let actual = metadata.len();
    check_length(id, actual, &entry.path, length)?;
    Ok(Some(VerifiedFile {
        file,
        id,
        len: actual,
    }))
}

fn check_length(id: XetHash, actual: u64, path: &Path, contract: LengthContract) -> Result<()> {
    match contract {
        LengthContract::Exact(expected) if actual != expected => Err(StoreError::WrongLength {
            id: id.to_string(),
            expected,
            actual,
            path: path.to_path_buf(),
        }),
        LengthContract::AtMost(maximum) if actual > maximum => Err(StoreError::TooLarge {
            id: id.to_string(),
            maximum,
            actual,
            path: path.to_path_buf(),
        }),
        LengthContract::Exact(_) | LengthContract::AtMost(_) => Ok(()),
    }
}

/// The file that was read is still the file this name refers to.
///
/// Two questions, and they are not the same one.
///
/// `file` is the descriptor the bytes came from. If its identity moved
/// while it was being read, the id is a Merkle root over bytes that were
/// never on disk together — a hash of nothing real. The old code noticed
/// this and declined to *remember* it, but still put it in the live index
/// and returned it, which is the half that mattered.
///
/// `path` is the name the id is about to be recorded against. A rename
/// over an open file leaves the descriptor untouched, so no amount of
/// re-`fstat`ing sees it; only stat-ing the name does. Without this the
/// index would map A's id to a path that now holds B, and `locate` would
/// hand that path to a caller who asked for A.
///
/// Either way this is an error rather than a silent skip. The caller
/// asked what the bytes at this name are, and the honest answer is that
/// nobody knows.
fn still_the_file_that_was_read(
    path: &Path,
    read: fastresume::FileIdentity,
    file: &std::fs::File,
) -> Result<()> {
    let read_err = |source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    };
    if fastresume::FileIdentity::of(&file.metadata().map_err(read_err)?) != read {
        return Err(StoreError::Raced {
            path: path.to_path_buf(),
        });
    }
    if fastresume::FileIdentity::of(&std::fs::metadata(path).map_err(read_err)?) != read {
        return Err(StoreError::Replaced {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

impl core::fmt::Debug for ContentStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ContentStore")
            .field("indexed", &self.len())
            .field(
                "substituters",
                &self
                    .substituters
                    .iter()
                    .map(|substituter| substituter.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hellas-store-binding-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn opened(path: &Path) -> (std::fs::File, fastresume::FileIdentity) {
        let file = std::fs::File::open(path).expect("open");
        let identity = fastresume::FileIdentity::of(&file.metadata().expect("fstat"));
        (file, identity)
    }

    /// The Linux primitive is the contract, not merely an implementation
    /// detail: a harmless path descriptor is acquired before type inspection,
    /// and the readable descriptor remains bound to that inode even if the
    /// name is replaced with a device.
    #[cfg(target_os = "linux")]
    #[test]
    fn regular_open_is_safe_readable_seekable_and_close_on_exec() {
        use std::io::{Read as _, Seek as _, SeekFrom};
        use std::os::fd::AsRawFd as _;

        let dir = scratch("regular-open");
        let target = dir.join("blob");
        let content = b"ordinary bytes";
        std::fs::write(&target, content).expect("write target");
        let link = dir.join("snapshot");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let mut file = open_regular_file(&link).expect("open regular symlink");
        let mut read = Vec::new();
        file.read_to_end(&mut read).expect("read");
        assert_eq!(read, content);
        file.seek(SeekFrom::Start(0)).expect("seek");
        read.clear();
        file.read_to_end(&mut read).expect("read again");
        assert_eq!(read, content);
        // SAFETY: F_GETFD only observes the live descriptor owned by `file`.
        let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        assert!(
            descriptor_flags >= 0,
            "F_GETFD: {}",
            io::Error::last_os_error()
        );
        assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);

        // Hold the ordinary inode without opening it for I/O, replace its
        // public name with a device, then finish the reopen. The bytes must
        // still come from the held inode.
        let path_handle = open_path_handle(&link).expect("path handle");
        let replacement = dir.join("replacement");
        std::os::unix::fs::symlink("/dev/null", &replacement).expect("device symlink");
        std::fs::rename(&replacement, &link).expect("replace link");
        let mut held = reopen_regular_path_handle(&link, &path_handle).expect("reopen held inode");
        read.clear();
        held.read_to_end(&mut read).expect("read held inode");
        assert_eq!(read, content);

        let fifo = dir.join("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success(), "the fixture needs a fifo");
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(open_regular_file(&fifo));
        });
        let fifo_error = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("opening the FIFO blocked before its type check")
            .expect_err("a FIFO is not regular content");
        assert_eq!(fifo_error.kind(), io::ErrorKind::InvalidInput);

        if Path::new("/dev/null").exists() {
            let device_error = open_regular_file(Path::new("/dev/null"))
                .expect_err("a character device is not regular content");
            assert_eq!(device_error.kind(), io::ErrorKind::InvalidInput);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Hashing is bounded by the descriptor length captured before the read.
    /// Mutations are injected between real file reads, so growth is found by
    /// the one-byte sentinel and truncation by an early EOF.
    #[test]
    fn mid_hash_growth_and_truncation_are_bounded_and_rejected() {
        use std::io::{Seek as _, SeekFrom, Write as _};

        enum Mutation {
            Grow,
            Truncate(u64),
        }

        struct MutatingFile {
            reader: std::fs::File,
            writer: std::fs::File,
            mutation: Option<Mutation>,
        }

        impl std::io::Read for MutatingFile {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let read = self.reader.read(buffer)?;
                if read != 0 {
                    match self.mutation.take() {
                        Some(Mutation::Grow) => {
                            self.writer.seek(SeekFrom::End(0))?;
                            self.writer.write_all(b"growth after hashing began")?;
                            self.writer.flush()?;
                        }
                        Some(Mutation::Truncate(len)) => self.writer.set_len(len)?,
                        None => {}
                    }
                }
                Ok(read)
            }
        }

        let dir = scratch("bounded-hash");
        let original = vec![0x5a; STREAM_BUFFER * 2 + 17];

        let grow_path = dir.join("grow");
        std::fs::write(&grow_path, &original).expect("write growing file");
        let grow_reader = open_regular_file(&grow_path).expect("open growing file");
        let grow_len = grow_reader.metadata().expect("metadata").len();
        let grow_writer = OpenOptions::new()
            .write(true)
            .open(&grow_path)
            .expect("open growth writer");
        let mut growing = MutatingFile {
            reader: grow_reader,
            writer: grow_writer,
            mutation: Some(Mutation::Grow),
        };
        assert!(
            hash_exact_length(&mut growing, grow_len)
                .expect("bounded growth read")
                .is_none(),
            "a byte beyond the captured length must reject growth",
        );

        let truncate_path = dir.join("truncate");
        std::fs::write(&truncate_path, &original).expect("write truncated file");
        let truncate_reader = open_regular_file(&truncate_path).expect("open truncated file");
        let truncate_len = truncate_reader.metadata().expect("metadata").len();
        let truncate_writer = OpenOptions::new()
            .write(true)
            .open(&truncate_path)
            .expect("open truncation writer");
        let mut truncating = MutatingFile {
            reader: truncate_reader,
            writer: truncate_writer,
            mutation: Some(Mutation::Truncate(STREAM_BUFFER as u64)),
        };
        assert!(
            hash_exact_length(&mut truncating, truncate_len)
                .expect("bounded truncation read")
                .is_none(),
            "EOF before the captured length must reject truncation",
        );

        let mut stable = std::io::Cursor::new(&original);
        let indexed = hash_exact_length(&mut stable, original.len() as u64)
            .expect("stable hash")
            .expect("stable length");
        assert_eq!(indexed.id, XetHash::hash(&original));
        assert_eq!(indexed.len, original.len() as u64);

        struct Endless {
            bytes_read: u64,
        }
        impl std::io::Read for Endless {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                buffer.fill(0xa5);
                self.bytes_read += buffer.len() as u64;
                Ok(buffer.len())
            }
        }
        let bounded_len = STREAM_BUFFER as u64 * 3 + 23;
        let mut endless = Endless { bytes_read: 0 };
        assert!(
            hash_exact_length(&mut endless, bounded_len)
                .expect("bounded endless read")
                .is_none(),
        );
        assert_eq!(
            endless.bytes_read,
            bounded_len + 1,
            "even a source that never reaches EOF gets one bounded prefix and one sentinel byte",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The binding, asserted where it can be made to happen rather than
    /// raced for: an id is about a descriptor, and recording it against a
    /// name requires the name to still mean that descriptor.
    #[test]
    fn what_was_read_is_bound_to_the_name_it_is_recorded_against() {
        use std::io::Write as _;

        let dir = scratch("binding");
        let path = dir.join("shard.bin");
        std::fs::write(&path, b"the bytes that were read").expect("write");

        // Nothing moved.
        let (file, identity) = opened(&path);
        still_the_file_that_was_read(&path, identity, &file).expect("an untouched file");

        // Rewritten under the descriptor: the id would cover bytes that
        // were never on disk together.
        let (file, identity) = opened(&path);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("reopen")
            .write_all(b" and some more")
            .expect("append");
        assert!(matches!(
            still_the_file_that_was_read(&path, identity, &file),
            Err(StoreError::Raced { .. }),
        ));

        // Renamed over. On Linux the descriptor does see this — the
        // rename unlinks the old name, the link count changes, and that
        // moves the replaced inode's ctime — so it is refused by the
        // first check rather than the second. Either refusal will do;
        // resolving as content is what must not happen.
        let (file, identity) = opened(&path);
        let other = dir.join("other.bin");
        std::fs::write(&other, b"different bytes entirely").expect("write");
        std::fs::rename(&other, &path).expect("rename over");
        assert!(matches!(
            still_the_file_that_was_read(&path, identity, &file),
            Err(StoreError::Raced { .. } | StoreError::Replaced { .. }),
        ));

        // The case the descriptor genuinely cannot see, and the one a
        // HuggingFace cache is made of: the name is a symlink into
        // `blobs/`, and it is repointed at another blob. Nothing happens
        // to the file that was read — no write, no link count change —
        // so only stat-ing the *name* can tell.
        let blobs = dir.join("blobs");
        std::fs::create_dir_all(&blobs).expect("blobs");
        std::fs::write(blobs.join("a"), b"blob a").expect("blob a");
        std::fs::write(blobs.join("b"), b"blob b").expect("blob b");
        let link = dir.join("snapshot-shard.bin");
        std::os::unix::fs::symlink(blobs.join("a"), &link).expect("symlink");

        let (file, identity) = opened(&link);
        let swap = dir.join("swap");
        std::os::unix::fs::symlink(blobs.join("b"), &swap).expect("symlink");
        std::fs::rename(&swap, &link).expect("repoint the symlink");
        assert_eq!(
            fastresume::FileIdentity::of(&file.metadata().expect("fstat")),
            identity,
            "the descriptor must be untouched, or this case tests the wrong thing",
        );
        assert!(matches!(
            still_the_file_that_was_read(&link, identity, &file),
            Err(StoreError::Replaced { .. }),
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The path lookup and the descriptor open are deliberately separate in
    /// `open_verified`; exercise both sides of that boundary without hoping to
    /// win a scheduler race.
    #[test]
    fn a_path_replacement_cannot_change_the_inode_being_lent() {
        use std::io::Read as _;

        let dir = scratch("verified-open-replacement");
        let blobs = dir.join("blobs");
        std::fs::create_dir_all(&blobs).expect("blobs");
        let original = b"blob a";
        std::fs::write(blobs.join("a"), original).expect("blob a");
        std::fs::write(blobs.join("b"), b"blob b").expect("blob b");
        let link = dir.join("weights.bin");
        std::os::unix::fs::symlink(blobs.join("a"), &link).expect("symlink");

        let store = ContentStore::new();
        let indexed = store.index(&link).expect("index through link");
        let entry = store
            .index
            .read()
            .expect("index lock")
            .get(&indexed.id)
            .expect("entry")
            .clone();

        // This descriptor models replacement after `open`: repointing the
        // symlink does not and cannot retarget an already-open file.
        let opened_before_replacement = std::fs::File::open(&link).expect("open original");
        let swap = dir.join("swap");
        std::os::unix::fs::symlink(blobs.join("b"), &swap).expect("replacement link");
        std::fs::rename(&swap, &link).expect("replace link");

        let verified = verify_opened_indexed_file(
            indexed.id,
            LengthContract::Exact(indexed.len),
            &entry,
            opened_before_replacement,
        )
        .expect("verify open descriptor")
        .expect("the old inode is still verified");
        let mut file = verified.into_file();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).expect("read old inode");
        assert_eq!(bytes, original);

        // This call models replacement between lookup and `open`: opening the
        // stale name reaches blob b, whose descriptor identity is refused.
        assert!(
            open_indexed_file(indexed.id, LengthContract::Exact(indexed.len), &entry)
                .expect("inspect replacement")
                .is_none(),
            "the replacement inode must not be lent under blob a's id",
        );
        assert!(
            store
                .open_verified(indexed.id, indexed.len)
                .expect("public open")
                .is_none(),
            "a stale index entry becomes a local miss",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
