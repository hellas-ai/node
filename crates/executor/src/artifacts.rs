//! Local artifact store for catnix `Value`s and `Term`s.
//!
//! Stores canonical DAG-CBOR bytes addressable by their BLAKE3 digest
//! and tracks a small side-table of "this `Term` was run and produced
//! this `Value`". Backed either by an in-process `HashMap` (for tests
//! and one-shot executors) or by a directory on disk (for `node serve`).
//!
//! Replaces the prior `BoundTermId`/`TextExecutionId`/`TextArtifactId`
//! API. In the new world (see `docs/AXES.md` and `PROGRESS.md`),
//! catnix has two primitives — `Value` and `Term` — and everything
//! else (`TokenIds`, `TextPolicy`, `TextState`, `TextRunOutput`) is a
//! Canonical type producing a `ValueId`. The store is just key/value
//! over canonical bytes plus a `TermId → ValueId` map.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use catnix::{
    Canonical, CanonicalDecode, DecodeError, Digest, Term, TermId, TextPolicy, TextRunOutput,
    TextState, TokenIds, ValueId,
};
use tempfile::NamedTempFile;

const BLOBS_DIR: &str = "blobs";
const TERM_OUTPUTS_DIR: &str = "term_outputs";

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("artifact decode failed: {0}")]
    Decode(String),
    #[error("blob {digest} on disk has wrong content (hash mismatch)")]
    BlobCorrupt { digest: Digest },
    #[error("term {term} already has output {existing}; refusing to overwrite with {proposed}")]
    TermOutputConflict {
        term: TermId,
        existing: ValueId,
        proposed: ValueId,
    },
}

impl From<DecodeError> for ArtifactError {
    fn from(err: DecodeError) -> Self {
        Self::Decode(err.to_string())
    }
}

/// Choose between an in-process memory store and an on-disk store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactStoreConfig {
    Memory,
    Fs(PathBuf),
}

impl ArtifactStoreConfig {
    pub fn memory() -> Self {
        Self::Memory
    }

    pub fn fs(path: impl Into<PathBuf>) -> Self {
        Self::Fs(path.into())
    }
}

/// Key-value store of canonical catnix bytes plus a `TermId → ValueId`
/// side-table.
///
/// All inserts are content-addressed: putting bytes returns the BLAKE3
/// `Digest` they hash to, and putting a `Canonical` value returns its
/// `ValueId` (or `TermId` for a `Term`). The store enforces that
/// fetched bytes hash to the expected digest, so a corrupt on-disk
/// blob is reported as `BlobCorrupt`, not silently used.
pub struct ArtifactStore {
    backend: Backend,
}

enum Backend {
    Memory(MemoryBackend),
    Fs(FsBackend),
}

#[derive(Default)]
struct MemoryBackend {
    blobs: HashMap<Digest, Vec<u8>>,
    term_outputs: HashMap<TermId, ValueId>,
}

struct FsBackend {
    blobs_dir: PathBuf,
    term_outputs_dir: PathBuf,
}

impl ArtifactStore {
    pub fn open(config: ArtifactStoreConfig) -> Result<Self, ArtifactError> {
        let backend = match config {
            ArtifactStoreConfig::Memory => Backend::Memory(MemoryBackend::default()),
            ArtifactStoreConfig::Fs(root) => Backend::Fs(FsBackend::open(root)?),
        };
        Ok(Self { backend })
    }

    pub fn memory() -> Self {
        Self::open(ArtifactStoreConfig::Memory).expect("memory backend is infallible")
    }

    pub fn fs(root: impl Into<PathBuf>) -> Result<Self, ArtifactError> {
        Self::open(ArtifactStoreConfig::Fs(root.into()))
    }

    // ---- canonical bytes ------------------------------------------------

    /// Insert canonical bytes; returns their BLAKE3 digest. Idempotent:
    /// re-inserting the same bytes is a no-op.
    pub fn put_canonical(&mut self, bytes: &[u8]) -> Result<Digest, ArtifactError> {
        let digest = Digest::from_canonical_bytes(bytes);
        match &mut self.backend {
            Backend::Memory(m) => {
                m.blobs.entry(digest).or_insert_with(|| bytes.to_vec());
            }
            Backend::Fs(b) => b.put_blob(&digest, bytes)?,
        }
        Ok(digest)
    }

    /// Fetch the canonical bytes for `digest`. Returns `None` if the
    /// blob isn't present; returns `BlobCorrupt` if the on-disk bytes
    /// don't hash to `digest` (caller may want to delete and re-fetch).
    pub fn get_canonical(&self, digest: &Digest) -> Result<Option<Vec<u8>>, ArtifactError> {
        match &self.backend {
            Backend::Memory(m) => Ok(m.blobs.get(digest).cloned()),
            Backend::Fs(b) => b.get_blob(digest),
        }
    }

    // ---- typed put helpers ---------------------------------------------

    /// Insert a Canonical `Value`-typed object; returns its `ValueId`.
    pub fn put_value<V: Canonical>(&mut self, value: &V) -> Result<ValueId, ArtifactError> {
        let bytes = value.canonical_bytes();
        let digest = self.put_canonical(&bytes)?;
        Ok(ValueId::from_digest(digest))
    }

    /// Insert a `Term`; returns its `TermId`.
    pub fn put_term(&mut self, term: &Term) -> Result<TermId, ArtifactError> {
        let bytes = term.canonical_bytes();
        let digest = self.put_canonical(&bytes)?;
        Ok(TermId::from_digest(digest))
    }

    // ---- typed get helpers (return decoded values) ----------------------

    pub fn get_token_ids(&self, id: ValueId) -> Result<Option<TokenIds>, ArtifactError> {
        self.get_decoded::<TokenIds>(id.digest())
    }

    pub fn get_text_policy(&self, id: ValueId) -> Result<Option<TextPolicy>, ArtifactError> {
        self.get_decoded::<TextPolicy>(id.digest())
    }

    pub fn get_text_state(&self, id: ValueId) -> Result<Option<TextState>, ArtifactError> {
        self.get_decoded::<TextState>(id.digest())
    }

    pub fn get_text_run_output(&self, id: ValueId) -> Result<Option<TextRunOutput>, ArtifactError> {
        self.get_decoded::<TextRunOutput>(id.digest())
    }

    pub fn get_term(&self, id: TermId) -> Result<Option<Term>, ArtifactError> {
        self.get_decoded::<Term>(id.digest())
    }

    fn get_decoded<T: CanonicalDecode>(&self, digest: Digest) -> Result<Option<T>, ArtifactError> {
        match self.get_canonical(&digest)? {
            None => Ok(None),
            Some(bytes) => Ok(Some(T::from_canonical_bytes(&bytes)?)),
        }
    }

    // ---- Term → output side-table --------------------------------------

    /// Record that running `term` produced `output`. Idempotent rewrite
    /// of the same mapping is allowed; recording a *different* output
    /// for the same `term` returns `TermOutputConflict` — a producer
    /// must not give two different outputs for the same input-addressed
    /// Term under any scheme that promises replay correctness.
    pub fn record_term_output(
        &mut self,
        term: TermId,
        output: ValueId,
    ) -> Result<(), ArtifactError> {
        if let Some(existing) = self.term_output(term)? {
            if existing != output {
                return Err(ArtifactError::TermOutputConflict {
                    term,
                    existing,
                    proposed: output,
                });
            }
            return Ok(());
        }
        match &mut self.backend {
            Backend::Memory(m) => {
                m.term_outputs.insert(term, output);
                Ok(())
            }
            Backend::Fs(b) => b.write_term_output(term, output),
        }
    }

    pub fn term_output(&self, term: TermId) -> Result<Option<ValueId>, ArtifactError> {
        match &self.backend {
            Backend::Memory(m) => Ok(m.term_outputs.get(&term).copied()),
            Backend::Fs(b) => b.read_term_output(term),
        }
    }
}

// ---- Fs backend implementation -----------------------------------------

impl FsBackend {
    fn open(root: PathBuf) -> Result<Self, ArtifactError> {
        let blobs_dir = root.join(BLOBS_DIR);
        let term_outputs_dir = root.join(TERM_OUTPUTS_DIR);
        fs::create_dir_all(&blobs_dir)?;
        fs::create_dir_all(&term_outputs_dir)?;
        Ok(Self {
            blobs_dir,
            term_outputs_dir,
        })
    }

    fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.blobs_dir.join(format!("{digest}"))
    }

    fn term_output_path(&self, term: TermId) -> PathBuf {
        self.term_outputs_dir.join(format!("{term}"))
    }

    fn put_blob(&self, digest: &Digest, bytes: &[u8]) -> Result<(), ArtifactError> {
        let path = self.blob_path(digest);
        match atomic_create_no_clobber(&path, bytes)? {
            CreateOutcome::Created => Ok(()),
            CreateOutcome::AlreadyExists => {
                // Verify the existing content matches what we expected.
                // Two honest writers racing both compute the same digest
                // and the same bytes, so they agree. A mismatch means
                // the on-disk blob was corrupted or written by a buggy
                // caller using the wrong digest path; surface as
                // BlobCorrupt rather than silently keeping bad bytes.
                let existing = fs::read(&path)?;
                if existing.as_slice() != bytes {
                    return Err(ArtifactError::BlobCorrupt { digest: *digest });
                }
                Ok(())
            }
        }
    }

    fn get_blob(&self, digest: &Digest) -> Result<Option<Vec<u8>>, ArtifactError> {
        let path = self.blob_path(digest);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path)?;
        if Digest::from_canonical_bytes(&bytes) != *digest {
            return Err(ArtifactError::BlobCorrupt { digest: *digest });
        }
        Ok(Some(bytes))
    }

    fn write_term_output(&self, term: TermId, output: ValueId) -> Result<(), ArtifactError> {
        let path = self.term_output_path(term);
        match atomic_create_no_clobber(&path, output.as_bytes())? {
            CreateOutcome::Created => Ok(()),
            CreateOutcome::AlreadyExists => {
                // Another writer (possibly another process) created the
                // file between our caller's check and our write. Read
                // and compare against `output` to decide whether this
                // is an idempotent replay or a real conflict.
                let existing = fs::read(&path)?;
                let value_bytes: [u8; 32] = existing.as_slice().try_into().map_err(|_| {
                    ArtifactError::Decode(format!(
                        "term_output file {path:?} has wrong length {} (want 32)",
                        existing.len()
                    ))
                })?;
                let existing_value = ValueId::from_bytes(value_bytes);
                if existing_value == output {
                    Ok(())
                } else {
                    Err(ArtifactError::TermOutputConflict {
                        term,
                        existing: existing_value,
                        proposed: output,
                    })
                }
            }
        }
    }

    fn read_term_output(&self, term: TermId) -> Result<Option<ValueId>, ArtifactError> {
        let path = self.term_output_path(term);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path)?;
        let value_bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            ArtifactError::Decode(format!(
                "term_output file {path:?} has wrong length {} (want 32)",
                bytes.len()
            ))
        })?;
        Ok(Some(ValueId::from_bytes(value_bytes)))
    }
}

/// Outcome of [`atomic_create_no_clobber`].
enum CreateOutcome {
    /// We wrote the file successfully — caller can assume `bytes` are
    /// now at `dest`.
    Created,
    /// `dest` already existed when we tried to persist. Caller should
    /// read the existing content to decide whether this is an
    /// idempotent replay or a real conflict.
    AlreadyExists,
}

/// Atomically create a file with `bytes` at `dest`, failing fast if
/// `dest` already exists.
///
/// Uses `tempfile::NamedTempFile` for a unique temp file (per-pid +
/// random suffix) in `dest`'s parent directory, then
/// `persist_noclobber` for an atomic `link()`-based publish that
/// returns `AlreadyExists` rather than overwriting. This makes the
/// FS backend safe under multi-writer (intra- or inter-process)
/// races: no two writers can both think they "created" the file.
///
/// Crash-durability is best-effort. We call `sync_all()` on the temp
/// file before persisting, but do NOT fsync the parent directory —
/// on a system crash mid-write the file may be missing even though
/// `persist_noclobber` returned successfully.
fn atomic_create_no_clobber(dest: &Path, bytes: &[u8]) -> Result<CreateOutcome, ArtifactError> {
    let parent = dest
        .parent()
        .ok_or_else(|| ArtifactError::Io(io::Error::other("artifact path has no parent")))?;
    fs::create_dir_all(parent)?;
    let mut tmp = NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    match tmp.persist_noclobber(dest) {
        Ok(_) => Ok(CreateOutcome::Created),
        Err(persist_err) => {
            if persist_err.error.kind() == io::ErrorKind::AlreadyExists {
                // NamedTempFile is dropped, removing the temp.
                Ok(CreateOutcome::AlreadyExists)
            } else {
                Err(ArtifactError::Io(persist_err.error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catnix::{BindingKey, TextPolicy, TokenIds};
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn sample_term() -> Term {
        let program = ValueId::from_bytes([0xaa; 32]);
        let mut bindings = BTreeMap::new();
        bindings.insert(
            BindingKey::Named("from".into()),
            ValueId::from_bytes([1; 32]),
        );
        bindings.insert(BindingKey::Arg(0), ValueId::from_bytes([2; 32]));
        Term::new(program, bindings)
    }

    fn round_trip(mut store: ArtifactStore) {
        let tokens = TokenIds::from([1, 2, 3]);
        let tokens_id = store.put_value(&tokens).unwrap();
        assert_eq!(
            store.get_token_ids(tokens_id).unwrap(),
            Some(tokens.clone())
        );

        let policy = TextPolicy::from_u32_stop_tokens(16, [1, 2]);
        let policy_id = store.put_value(&policy).unwrap();
        assert_eq!(store.get_text_policy(policy_id).unwrap(), Some(policy));

        let term = sample_term();
        let term_id = store.put_term(&term).unwrap();
        assert_eq!(store.get_term(term_id).unwrap(), Some(term.clone()));

        let output = ValueId::from_bytes([7; 32]);
        store.record_term_output(term_id, output).unwrap();
        assert_eq!(store.term_output(term_id).unwrap(), Some(output));

        // Idempotent on identical replay.
        store.record_term_output(term_id, output).unwrap();

        // Conflicting output for the same term is rejected.
        let other = ValueId::from_bytes([8; 32]);
        let err = store.record_term_output(term_id, other).unwrap_err();
        assert!(matches!(err, ArtifactError::TermOutputConflict { .. }));
    }

    #[test]
    fn memory_round_trip() {
        round_trip(ArtifactStore::memory());
    }

    #[test]
    fn fs_round_trip() {
        let tmp = TempDir::new().unwrap();
        round_trip(ArtifactStore::fs(tmp.path()).unwrap());
    }

    #[test]
    fn fs_persists_across_open() {
        let tmp = TempDir::new().unwrap();
        let term = sample_term();
        let (term_id, output_id) = {
            let mut s = ArtifactStore::fs(tmp.path()).unwrap();
            let id = s.put_term(&term).unwrap();
            let out = ValueId::from_bytes([7; 32]);
            s.record_term_output(id, out).unwrap();
            (id, out)
        };
        // Re-open from disk; data should survive.
        let s = ArtifactStore::fs(tmp.path()).unwrap();
        assert_eq!(s.get_term(term_id).unwrap(), Some(term));
        assert_eq!(s.term_output(term_id).unwrap(), Some(output_id));
    }

    #[test]
    fn fs_detects_blob_corruption() {
        let tmp = TempDir::new().unwrap();
        let mut s = ArtifactStore::fs(tmp.path()).unwrap();
        let tokens = TokenIds::from([1]);
        let id = s.put_value(&tokens).unwrap();
        let blob_path = tmp.path().join(BLOBS_DIR).join(format!("{}", id.digest()));
        fs::write(&blob_path, b"not the canonical bytes").unwrap();
        let err = s.get_token_ids(id).unwrap_err();
        assert!(matches!(err, ArtifactError::BlobCorrupt { .. }));
    }

    #[test]
    fn missing_blob_returns_none() {
        let s = ArtifactStore::memory();
        let nope = ValueId::from_bytes([0xff; 32]);
        assert_eq!(s.get_token_ids(nope).unwrap(), None);
    }
}
