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
//! and never a key. Ids in this store are ones we computed, because they
//! end up signed into an execution environment and a key we cannot
//! defend is a claim we can lose.

pub mod fastresume;
pub mod hf;
pub mod hf_cache;
pub mod state;
pub mod xorb;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use hellas_xet::{Chunk, XetFileHasher, XetHash};

/// Bytes read per `read` while hashing. Large enough that the syscall is
/// not the bottleneck, small enough to be irrelevant beside a model.
const STREAM_BUFFER: usize = 1024 * 1024;

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

/// Anything that can make content appear that is not here yet.
///
/// Separate from [`Substituter`] on purpose. A substituter answers
/// cheaply and locally; a fetcher spends bandwidth. Only one of those
/// may be reached from a quote.
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
/// costs and a quote may only ever consult the cheap question.
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
        use std::io::Read as _;

        if fastresume::is_cache_debris(path) {
            return Err(StoreError::Debris {
                path: path.to_path_buf(),
            });
        }

        let read_err = |source| StoreError::Read {
            path: path.to_path_buf(),
            source,
        };
        let mut file = std::fs::File::open(path).map_err(read_err)?;
        let before = file.metadata().map_err(read_err)?;
        let identity = fastresume::FileIdentity::of(&before);

        let remembered = self.records.get(&before);
        let indexed = match remembered.clone() {
            Some(indexed) => indexed,
            None => {
                let mut hasher = XetFileHasher::new();
                let mut buffer = vec![0_u8; STREAM_BUFFER];
                let mut len = 0_u64;
                loop {
                    let read = file.read(&mut buffer).map_err(read_err)?;
                    if read == 0 {
                        break;
                    }
                    len += read as u64;
                    hasher.update(&buffer[..read]);
                }
                let chunks = hasher.finalize_chunks();
                Indexed {
                    id: hellas_xet::file_hash(&chunks),
                    chunks,
                    len,
                }
            }
        };

        // Nothing is remembered, recorded or returned until this holds.
        // Whether the id was computed just now or looked up, it is an id
        // for the descriptor; recording it against a *name* needs that
        // name to still refer to the same file, and an id that cannot be
        // bound to what was read is an error rather than an answer.
        still_the_file_that_was_read(path, identity, &file)?;
        if remembered.is_none() {
            self.records.put(&before, &indexed);
        }
        self.record(path, identity, &indexed);
        Ok(indexed)
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
    /// The question a quote is allowed to ask. Answering a quote for
    /// content we do not hold is what turns quoting into a remote fetch
    /// primitive.
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
            // false, and a quote answered on it commits to weights this
            // node no longer holds.
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
    /// The privileged operation. [`Self::have`] is the question a quote
    /// may ask; this is the one that costs bandwidth and disk, and so
    /// belongs behind whatever admission control the caller applies.
    /// Separating them is the whole reason answering a quote can stop
    /// being a way to make a stranger's node download an arbitrary
    /// repository.
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
}
