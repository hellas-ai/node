use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use hellas_attestation::{AssertionCounterStore, AttestationError};

/// Filesystem-backed assertion-counter high-water marks for native clients.
/// Each producer key has one locked, atomically replaced counter file.
#[derive(Clone, Debug)]
pub struct FilesystemAssertionCounterStore {
    directory: PathBuf,
}

impl FilesystemAssertionCounterStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn path(&self, public_key: &[u8; 33], suffix: &str) -> PathBuf {
        self.directory
            .join(format!("{}{suffix}", encode_hex(public_key)))
    }
}

impl AssertionCounterStore for FilesystemAssertionCounterStore {
    fn advance(&self, public_key: &[u8; 33], counter: u32) -> Result<(), AttestationError> {
        create_private_directory(&self.directory).map_err(|_| AttestationError::State)?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.path(public_key, ".lock"))
            .map_err(|_| AttestationError::State)?;
        fs::File::lock(&lock).map_err(|_| AttestationError::State)?;

        let path = self.path(public_key, ".counter");
        let previous = match fs::read(&path) {
            Ok(stored) => match stored.as_slice() {
                [a, b, c, d] => u32::from_be_bytes([*a, *b, *c, *d]),
                _ => return Err(AttestationError::State),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => 0,
            Err(_) => return Err(AttestationError::State),
        };
        if counter <= previous {
            return Err(AttestationError::Counter);
        }

        let mut temporary = tempfile::NamedTempFile::new_in(&self.directory)
            .map_err(|_| AttestationError::State)?;
        #[cfg(unix)]
        temporary
            .as_file()
            .set_permissions({
                use std::os::unix::fs::PermissionsExt;
                fs::Permissions::from_mode(0o600)
            })
            .map_err(|_| AttestationError::State)?;
        temporary
            .write_all(&counter.to_be_bytes())
            .and_then(|()| temporary.flush())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|_| AttestationError::State)?;
        temporary
            .persist(&path)
            .map_err(|_| AttestationError::State)?;
        #[cfg(unix)]
        fs::File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AttestationError::State)?;
        Ok(())
    }
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_a_strict_counter_high_water_mark() {
        let directory = tempfile::tempdir().unwrap();
        let counters = FilesystemAssertionCounterStore::new(directory.path().join("counters"));
        let key = [7_u8; 33];

        counters.advance(&key, 1).unwrap();
        assert_eq!(counters.advance(&key, 1), Err(AttestationError::Counter));
        assert_eq!(counters.advance(&key, 0), Err(AttestationError::Counter));
        counters.advance(&key, 2).unwrap();

        let reopened = FilesystemAssertionCounterStore::new(directory.path().join("counters"));
        assert_eq!(reopened.advance(&key, 2), Err(AttestationError::Counter));
        reopened.advance(&key, 3).unwrap();
    }
}
