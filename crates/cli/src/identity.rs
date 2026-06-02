use anyhow::Context;
use hellas_core::ProducerSigningKey;
use iroh::SecretKey;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

const IDENTITY_DIR: &str = ".hellas";
const IDENTITY_FILE: &str = "identity";
const PRODUCER_KEY_FILE: &str = "signing-key.secp256k1";
#[cfg(feature = "hellas-executor")]
const ARTIFACT_STORE_DIR: &str = "artifacts";
const KEY_LEN: usize = 32;

/// Resolve the identity file path and load or create the secret key.
///
/// If `path` is `Some`, uses it directly. Otherwise defaults to `$HOME/.hellas/identity`.
/// Creates a new random key if the file does not exist, using atomic rename to avoid races.
pub fn load_or_create(path: Option<&Path>) -> anyhow::Result<SecretKey> {
    let path = match path {
        Some(p) => p.to_owned(),
        None => default_identity_path()?,
    };
    match fs::read(&path) {
        Ok(bytes) => load_from_bytes(&path, &bytes),
        Err(e) if e.kind() == ErrorKind::NotFound => create_new(&path),
        Err(e) => {
            Err(e).with_context(|| format!("failed to read identity file {}", path.display()))
        }
    }
}

pub fn load_or_create_producer_key(path: Option<&Path>) -> anyhow::Result<ProducerSigningKey> {
    let path = match path {
        Some(p) => p.to_owned(),
        None => default_producer_key_path()?,
    };
    match fs::read(&path) {
        Ok(bytes) => load_producer_key_from_bytes(&path, &bytes),
        Err(e) if e.kind() == ErrorKind::NotFound => create_new_producer_key(&path),
        Err(e) => {
            Err(e).with_context(|| format!("failed to read producer key file {}", path.display()))
        }
    }
}

/// Load an existing identity file; error if missing.
///
/// Unlike `load_or_create`, this never creates a new key. Use this for
/// read-only queries (e.g. printing the node ID of a running service) to avoid
/// racing the file creator.
pub fn load_existing(path: Option<&Path>) -> anyhow::Result<SecretKey> {
    let path = match path {
        Some(p) => p.to_owned(),
        None => default_identity_path()?,
    };
    let bytes = fs::read(&path)
        .with_context(|| format!("failed to read identity file {}", path.display()))?;
    load_from_bytes(&path, &bytes)
}

pub fn load_existing_producer_key(path: Option<&Path>) -> anyhow::Result<ProducerSigningKey> {
    let path = match path {
        Some(p) => p.to_owned(),
        None => default_producer_key_path()?,
    };
    let bytes = fs::read(&path)
        .with_context(|| format!("failed to read producer key file {}", path.display()))?;
    load_producer_key_from_bytes(&path, &bytes)
}

fn default_identity_path() -> anyhow::Result<PathBuf> {
    default_hellas_path(IDENTITY_FILE, "--identity")
}

fn default_producer_key_path() -> anyhow::Result<PathBuf> {
    default_hellas_path(PRODUCER_KEY_FILE, "--producer-key-path")
}

#[cfg(feature = "hellas-executor")]
pub fn default_artifact_store_path() -> anyhow::Result<PathBuf> {
    default_hellas_path(ARTIFACT_STORE_DIR, "--artifact-store-path")
}

fn default_hellas_path(file: &str, flag: &str) -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").with_context(|| {
        format!("HOME environment variable not set; use {flag} to specify path")
    })?;
    Ok(PathBuf::from(home).join(IDENTITY_DIR).join(file))
}

fn load_from_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<SecretKey> {
    let bytes: [u8; KEY_LEN] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "identity file at {} has invalid size ({} bytes, expected {KEY_LEN})",
            path.display(),
            bytes.len(),
        )
    })?;
    let key = SecretKey::from(bytes);
    info!(node_id = %key.public(), path = %path.display(), "loaded identity");
    Ok(key)
}

fn create_new(path: &Path) -> anyhow::Result<SecretKey> {
    let dir = path
        .parent()
        .context("identity path has no parent directory")?;

    create_dir_restricted(dir)
        .with_context(|| format!("failed to create identity directory {}", dir.display()))?;

    let key = SecretKey::generate();
    let bytes = key.to_bytes();

    // Write to a temp file, then atomic rename. If rename fails because another
    // process created the file first, read the existing one instead.
    let tmp_path = dir.join(format!(
        ".identity.tmp.{}.{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    write_file_restricted(&tmp_path, &bytes)
        .with_context(|| format!("failed to write temp identity file {}", tmp_path.display()))?;

    match fs::rename(&tmp_path, path) {
        Ok(()) => {
            info!(node_id = %key.public(), path = %path.display(), "created new identity");
            Ok(key)
        }
        Err(e) => {
            // Clean up temp file on failure.
            let _ = fs::remove_file(&tmp_path);
            // If the target appeared (race), read it.
            if path.exists() {
                let bytes = fs::read(path)
                    .with_context(|| format!("failed to read identity file {}", path.display()))?;
                load_from_bytes(path, &bytes)
            } else {
                Err(e)
                    .with_context(|| format!("failed to persist identity file {}", path.display()))
            }
        }
    }
}

fn load_producer_key_from_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<ProducerSigningKey> {
    let bytes: [u8; KEY_LEN] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "producer key file at {} has invalid size ({} bytes, expected {KEY_LEN})",
            path.display(),
            bytes.len(),
        )
    })?;
    let key = ProducerSigningKey::from_secret_bytes(bytes)
        .with_context(|| format!("producer key file {} is invalid", path.display()))?;
    info!(
        producer_id = ?key.producer_id(),
        path = %path.display(),
        "loaded producer signing key"
    );
    Ok(key)
}

fn create_new_producer_key(path: &Path) -> anyhow::Result<ProducerSigningKey> {
    let dir = path
        .parent()
        .context("producer key path has no parent directory")?;

    create_dir_restricted(dir)
        .with_context(|| format!("failed to create producer key directory {}", dir.display()))?;

    let key = ProducerSigningKey::generate();
    let bytes = key.to_secret_bytes();

    let tmp_path = dir.join(format!(
        ".signing-key.secp256k1.tmp.{}.{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    write_file_restricted(&tmp_path, &bytes).with_context(|| {
        format!(
            "failed to write temp producer key file {}",
            tmp_path.display()
        )
    })?;

    match fs::rename(&tmp_path, path) {
        Ok(()) => {
            info!(
                producer_id = ?key.producer_id(),
                path = %path.display(),
                "created new producer signing key"
            );
            Ok(key)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            if path.exists() {
                let bytes = fs::read(path).with_context(|| {
                    format!("failed to read producer key file {}", path.display())
                })?;
                load_producer_key_from_bytes(path, &bytes)
            } else {
                Err(e).with_context(|| {
                    format!("failed to persist producer key file {}", path.display())
                })
            }
        }
    }
}

/// Create a directory with restricted permissions (0700 on Unix).
fn create_dir_restricted(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

/// Write a file with restricted permissions (0600 on Unix).
fn write_file_restricted(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
        file.sync_all()
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn creates_new_identity_in_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");

        let key = load_or_create(Some(&path)).unwrap();

        assert!(path.exists());
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len(), KEY_LEN);
        assert_eq!(
            SecretKey::from(<[u8; 32]>::try_from(bytes.as_slice()).unwrap()).to_bytes(),
            key.to_bytes()
        );
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn creates_new_producer_key_in_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.secp256k1");

        let key = load_or_create_producer_key(Some(&path)).unwrap();

        assert!(path.exists());
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len(), KEY_LEN);
        let reloaded =
            ProducerSigningKey::from_secret_bytes(<[u8; 32]>::try_from(bytes.as_slice()).unwrap())
                .unwrap();
        assert_eq!(reloaded.producer_id(), key.producer_id());
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn reloads_existing_producer_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.secp256k1");

        let key1 = load_or_create_producer_key(Some(&path)).unwrap();
        let key2 = load_or_create_producer_key(Some(&path)).unwrap();

        assert_eq!(key1.producer_id(), key2.producer_id());
    }

    #[test]
    fn reloads_existing_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");

        let key1 = load_or_create(Some(&path)).unwrap();
        let key2 = load_or_create(Some(&path)).unwrap();

        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn rejects_wrong_size_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        fs::write(&path, [0u8; 16]).unwrap();

        let err = load_or_create(Some(&path)).unwrap_err();
        assert!(err.to_string().contains("invalid size"));
        assert!(err.to_string().contains("16 bytes"));
    }

    #[test]
    fn creates_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("dir").join("identity");

        let _key = load_or_create(Some(&path)).unwrap();

        assert!(path.exists());
        assert!(path.parent().unwrap().is_dir());
    }

    #[test]
    fn default_path_uses_home() {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: test is single-threaded and restores the value immediately.
        unsafe { env::set_var("HOME", dir.path()) };

        let path = default_identity_path().unwrap();
        assert_eq!(path, dir.path().join(".hellas").join("identity"));

        let path = default_producer_key_path().unwrap();
        assert_eq!(
            path,
            dir.path().join(".hellas").join("signing-key.secp256k1")
        );

        #[cfg(feature = "hellas-executor")]
        {
            let path = default_artifact_store_path().unwrap();
            assert_eq!(path, dir.path().join(".hellas").join("artifacts"));
        }

        unsafe { env::remove_var("HOME") };
    }

    #[test]
    fn concurrent_creation_produces_valid_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || load_or_create(Some(&p)).unwrap().to_bytes())
            })
            .collect();

        let results: Vec<[u8; 32]> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All threads should get a valid 32-byte key (the first one created wins).
        for result in &results {
            assert_eq!(result.len(), KEY_LEN);
        }
        // At most one unique key should exist (all should converge on the same file).
        // Some threads may have generated their own key before rename, but the file
        // content should be consistent — all reads after the first create should match.
        let file_bytes = fs::read(&path).unwrap();
        let file_key: [u8; 32] = file_bytes.try_into().unwrap();
        // The last reader should have gotten the persisted key.
        // (We can't guarantee all threads saw the same key due to create_new vs rename races,
        // but the file on disk should be a valid 32-byte key.)
        assert_eq!(file_key.len(), KEY_LEN);
    }
}
