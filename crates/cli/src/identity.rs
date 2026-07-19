use anyhow::{Context, bail};
use hellas_rpc::signature::verify_digest_signature;
#[cfg(feature = "node")]
use hellas_rpc::{AssuranceRequirement, ContentId};
use hellas_rpc::{
    Digest, PlatformCredential, ProducerSigningKey, ProviderGenesisStatement, PublicKey, RootKind,
    RootProof, Signature, SignedProviderGenesis,
};
use iroh::SecretKey;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

const IDENTITY_DIR: &str = ".hellas";
const IDENTITY_FILE: &str = "identity";
#[cfg(feature = "node")]
const ARTIFACT_STORE_DIR: &str = "artifacts";
const VERSION: u8 = 1;

pub(crate) struct LocalIdentity {
    pub(crate) transport_key: SecretKey,
    pub(crate) producer_key: ProducerSigningKey,
    #[cfg(any(feature = "node", test))]
    pub(crate) genesis: SignedProviderGenesis,
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    version: u8,
    root: StoredRoot,
    producer_key: [u8; 32],
    transport_key: [u8; 32],
    installation_nonce: [u8; 32],
    root_signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "secret")]
enum StoredRoot {
    Software([u8; 32]),
}

trait PlatformRoot {
    fn kind(&self) -> RootKind;
    fn public_key(&self) -> PublicKey;
    fn prove(&self, statement: &[u8]) -> anyhow::Result<RootProof>;
}

struct SoftwareRoot(ProducerSigningKey);

impl PlatformRoot for SoftwareRoot {
    fn kind(&self) -> RootKind {
        RootKind::Software
    }

    fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    fn prove(&self, statement: &[u8]) -> anyhow::Result<RootProof> {
        Ok(RootProof::Software(
            self.0.sign_digest(Digest::hash(statement))?,
        ))
    }
}

#[cfg(feature = "node")]
pub(crate) fn assurance(
    codec: Option<&str>,
    policy: Option<ContentId>,
) -> anyhow::Result<AssuranceRequirement> {
    AssuranceRequirement::new(
        codec.context("local provider requires --assurance-codec")?,
        policy.context("local provider requires --assurance-policy")?,
    )
    .map_err(Into::into)
}

pub(crate) fn load_or_create(
    path: Option<&Path>,
    software_root: bool,
) -> anyhow::Result<LocalIdentity> {
    let path = path
        .map(Path::to_owned)
        .map(Ok)
        .unwrap_or_else(default_path)?;
    match fs::read(&path) {
        Ok(bytes) => decode(&path, &bytes),
        Err(error) if error.kind() == ErrorKind::NotFound => create(&path, software_root),
        Err(error) => {
            Err(error).with_context(|| format!("failed to read identity file {}", path.display()))
        }
    }
}

pub(crate) fn load_existing(path: Option<&Path>) -> anyhow::Result<LocalIdentity> {
    let path = path
        .map(Path::to_owned)
        .map(Ok)
        .unwrap_or_else(default_path)?;
    let bytes = fs::read(&path)
        .with_context(|| format!("failed to read identity file {}", path.display()))?;
    decode(&path, &bytes)
}

fn default_path() -> anyhow::Result<PathBuf> {
    default_hellas_path(IDENTITY_FILE, "--identity")
}

#[cfg(feature = "node")]
pub(crate) fn default_artifact_store_path() -> anyhow::Result<PathBuf> {
    default_hellas_path(ARTIFACT_STORE_DIR, "--artifact-store-path")
}

fn default_hellas_path(file: &str, flag: &str) -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").with_context(|| {
        format!("HOME environment variable not set; use {flag} to specify path")
    })?;
    Ok(PathBuf::from(home).join(IDENTITY_DIR).join(file))
}

fn create(path: &Path, software_root: bool) -> anyhow::Result<LocalIdentity> {
    require_software_root(software_root)?;
    let root = SoftwareRoot(ProducerSigningKey::generate());
    let producer_key = ProducerSigningKey::generate();
    let transport_key = SecretKey::generate();
    let installation_nonce = rand::random();
    let statement = statement(&root, &producer_key, &transport_key, installation_nonce);
    let genesis = SignedProviderGenesis {
        root_proof: root.prove(&statement.canonical_bytes())?,
        statement,
    };
    let RootProof::Software(signature) = &genesis.root_proof else {
        unreachable!("software root returns a software proof")
    };
    let stored = StoredIdentity {
        version: VERSION,
        root: StoredRoot::Software(root.0.to_secret_bytes()),
        producer_key: producer_key.to_secret_bytes(),
        transport_key: transport_key.to_bytes(),
        installation_nonce,
        root_signature: signature.bytes().to_vec(),
    };
    let identity = LocalIdentity {
        transport_key,
        producer_key,
        #[cfg(any(feature = "node", test))]
        genesis,
    };
    if !persist(path, &stored)? {
        return load_existing(Some(path));
    }
    info!(
        node_id = %identity.transport_key.public(),
        producer_id = ?identity.producer_key.producer_id(),
        path = %path.display(),
        "created provider identity"
    );
    Ok(identity)
}

fn materialize(stored: &StoredIdentity) -> anyhow::Result<LocalIdentity> {
    if stored.version != VERSION {
        bail!("unsupported identity version {}", stored.version);
    }
    let root = match stored.root {
        StoredRoot::Software(secret) => SoftwareRoot(
            ProducerSigningKey::from_secret_bytes(secret).context("invalid software root key")?,
        ),
    };
    let producer_key = ProducerSigningKey::from_secret_bytes(stored.producer_key)
        .context("invalid producer key")?;
    let transport_key = SecretKey::from(stored.transport_key);
    let statement = statement(
        &root,
        &producer_key,
        &transport_key,
        stored.installation_nonce,
    );
    let signature = Signature::Secp256k1(
        stored
            .root_signature
            .as_slice()
            .try_into()
            .context("software root signature must be 64 bytes")?,
    );
    verify_digest_signature(
        &statement.root_public_key,
        &signature,
        Digest::hash(&statement.canonical_bytes()),
    )
    .context("invalid provider genesis root signature")?;
    Ok(LocalIdentity {
        transport_key,
        producer_key,
        #[cfg(any(feature = "node", test))]
        genesis: SignedProviderGenesis {
            statement,
            root_proof: RootProof::Software(signature),
        },
    })
}

fn statement(
    root: &impl PlatformRoot,
    producer: &ProducerSigningKey,
    transport: &SecretKey,
    installation_nonce: [u8; 32],
) -> ProviderGenesisStatement {
    ProviderGenesisStatement {
        root_kind: root.kind(),
        root_public_key: root.public_key(),
        producer_public_key: producer.public_key(),
        transport_public_key: PublicKey::Ed25519(*transport.public().as_bytes()),
        platform_credential: PlatformCredential::Absent,
        installation_nonce,
    }
}

fn decode(path: &Path, bytes: &[u8]) -> anyhow::Result<LocalIdentity> {
    let stored: StoredIdentity = serde_json::from_slice(bytes)
        .with_context(|| format!("identity file {} is not version 1", path.display()))?;
    let identity = materialize(&stored)
        .with_context(|| format!("invalid identity file {}", path.display()))?;
    info!(
        node_id = %identity.transport_key.public(),
        producer_id = ?identity.producer_key.producer_id(),
        path = %path.display(),
        "loaded provider identity"
    );
    Ok(identity)
}

fn persist(path: &Path, stored: &StoredIdentity) -> anyhow::Result<bool> {
    let dir = path
        .parent()
        .context("identity path has no parent directory")?;
    create_dir_restricted(dir)
        .with_context(|| format!("failed to create identity directory {}", dir.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("failed to create temporary identity in {}", dir.display()))?;
    #[cfg(unix)]
    temp.as_file().set_permissions({
        use std::os::unix::fs::PermissionsExt;
        fs::Permissions::from_mode(0o600)
    })?;
    serde_json::to_writer(&mut temp, stored)?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    match temp.persist_noclobber(path) {
        Ok(_) => {
            #[cfg(unix)]
            fs::File::open(dir)?.sync_all()?;
            Ok(true)
        }
        Err(_error) if path.exists() => Ok(false),
        Err(error) => Err(error.error)
            .with_context(|| format!("failed to persist identity file {}", path.display())),
    }
}

#[cfg(target_os = "linux")]
fn require_software_root(explicit: bool) -> anyhow::Result<()> {
    require_software_root_at(
        explicit,
        Path::new("/sys/class/tpm/tpm0"),
        &[Path::new("/dev/tpmrm0"), Path::new("/dev/tpm0")],
    )
}

#[cfg(target_os = "linux")]
fn require_software_root_at(explicit: bool, tpm: &Path, devices: &[&Path]) -> anyhow::Result<()> {
    if explicit || !tpm.exists() {
        return Ok(());
    }
    let device = devices
        .iter()
        .copied()
        .find(|path| path.exists())
        .context("TPM 2.0 is present but has no device node; use --software-root explicitly")?;
    if let Err(error) = fs::OpenOptions::new().read(true).write(true).open(device) {
        bail!(
            "TPM 2.0 is present but {} is inaccessible ({error}); use --software-root explicitly",
            device.display()
        );
    }
    bail!("TPM 2.0 is present; use --software-root explicitly until TPM root support graduates")
}

#[cfg(not(target_os = "linux"))]
fn require_software_root(_explicit: bool) -> anyhow::Result<()> {
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn creates_and_reloads_one_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        let first = load_or_create(Some(&path), true).unwrap();
        let second = load_or_create(Some(&path), true).unwrap();

        assert_eq!(
            first.transport_key.to_bytes(),
            second.transport_key.to_bytes()
        );
        assert_eq!(
            first.producer_key.producer_id(),
            second.producer_key.producer_id()
        );
        assert_eq!(first.genesis, second.genesis);
        assert_eq!(first.genesis.statement.root_kind, RootKind::Software);
        assert_eq!(
            first.genesis.statement.transport_public_key,
            PublicKey::Ed25519(*first.transport_key.public().as_bytes())
        );
        assert_eq!(
            first.genesis.statement.producer_public_key,
            first.producer_key.public_key()
        );
        let other = load_or_create(Some(&dir.path().join("other")), true).unwrap();
        assert_ne!(
            first.genesis.statement.installation_nonce,
            other.genesis.statement.installation_nonce
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn rejects_old_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        fs::write(&path, [0; 32]).unwrap();
        assert!(
            load_existing(Some(&path))
                .err()
                .unwrap()
                .to_string()
                .contains("not version 1")
        );
    }

    #[test]
    fn rejects_tampered_root_signature() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        load_or_create(Some(&path), true).unwrap();
        let mut stored: StoredIdentity = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        stored.root_signature[0] ^= 1;
        fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert!(load_existing(Some(&path)).is_err());
    }

    #[test]
    fn creates_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/dir/identity");
        load_or_create(Some(&path), true).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn default_path_uses_home() {
        let dir = tempfile::tempdir().unwrap();
        unsafe { env::set_var("HOME", dir.path()) };
        assert_eq!(default_path().unwrap(), dir.path().join(".hellas/identity"));
        #[cfg(feature = "node")]
        assert_eq!(
            default_artifact_store_path().unwrap(),
            dir.path().join(".hellas/artifacts")
        );
        unsafe { env::remove_var("HOME") };
    }

    #[test]
    fn concurrent_creation_converges() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    load_or_create(Some(&path), true)
                        .unwrap()
                        .transport_key
                        .to_bytes()
                })
            })
            .collect();
        let keys: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(keys.iter().all(|key| key == &keys[0]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detected_tpm_requires_explicit_software_root() {
        let dir = tempfile::tempdir().unwrap();
        let tpm = dir.path().join("tpm0");
        fs::write(&tpm, []).unwrap();
        let missing = dir.path().join("missing");
        assert!(require_software_root_at(false, &tpm, &[&missing]).is_err());
        assert!(
            require_software_root_at(false, &tpm, &[&tpm])
                .unwrap_err()
                .to_string()
                .contains("until TPM root support graduates")
        );
        assert!(require_software_root_at(true, &tpm, &[&missing]).is_ok());
    }
}
