use anyhow::{Context, bail};
#[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
use hellas_attestation::{
    AppleAppAttest, AppleCredential, apple_credential_identity, client_data_hash,
};
#[cfg(any(test, all(target_os = "macos", feature = "apple-app-attest")))]
use hellas_attestation::{ApplePolicy, RegisteredAppleCredential, verify_apple_assertion};
use hellas_attestation::{AssertionCounterStore, AttestationError};
#[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
use hellas_rpc::AppleAppAttestEnrollment;
#[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
use hellas_rpc::DagCborEncoder;
use hellas_rpc::signature::verify_digest_signature;
use hellas_rpc::{
    DagCborDecoder, Digest, PlatformCredential, ProducerSigningKey, ProviderGenesisStatement,
    PublicKey, RootKind, RootProof, SignedProviderGenesis,
};
#[cfg(feature = "node")]
use hellas_rpc::{
    OPEN_NONCE_LEN,
    open::OpenHandler,
    open_proof_binding,
    pb::execute::{OpenRequest, OpenResponse, open_response},
    run_ticket::signature_to_pb,
};
use hellas_rpc::{PlatformEnrollment, ProviderEnrollmentBundle};
#[cfg(feature = "node")]
use hellas_wire::{TransportContext, WireCode, WireStatus};
use iroh::SecretKey;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
use std::time::{SystemTime, UNIX_EPOCH};

const IDENTITY_DIR: &str = ".hellas";
const IDENTITY_FILE: &str = "identity";
const APPLE_OPEN_COUNTER_STORE_DIR: &str = "apple-app-attest-open-counters";
#[cfg(feature = "node")]
const ARTIFACT_STORE_DIR: &str = "artifacts";
const VERSION: u8 = 3;
const IDENTITY_TAG: &str = "hellas.provider.identity.persistence.v3";

/// Filesystem-backed assertion-counter high-water marks, keyed by public key.
#[derive(Clone, Debug)]
struct FilesystemAssertionCounterStore {
    directory: PathBuf,
}

impl FilesystemAssertionCounterStore {
    fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn counter_path(&self, public_key: &[u8; 33]) -> PathBuf {
        self.directory
            .join(format!("{}.counter", Self::key_name(public_key)))
    }

    fn lock_path(&self, public_key: &[u8; 33]) -> PathBuf {
        self.directory
            .join(format!("{}.counter.lock", Self::key_name(public_key)))
    }

    fn key_name(public_key: &[u8; 33]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = String::with_capacity(public_key.len() * 2);
        for byte in public_key {
            name.push(HEX[(byte >> 4) as usize] as char);
            name.push(HEX[(byte & 0xf) as usize] as char);
        }
        name
    }
}

impl AssertionCounterStore for FilesystemAssertionCounterStore {
    fn advance(&self, public_key: &[u8; 33], counter: u32) -> Result<(), AttestationError> {
        create_dir_restricted(&self.directory).map_err(|_| AttestationError::State)?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.lock_path(public_key))
            .map_err(|_| AttestationError::State)?;
        fs::File::lock(&lock).map_err(|_| AttestationError::State)?;

        let counter_path = self.counter_path(public_key);
        let previous = match fs::read(&counter_path) {
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

        let mut temp = tempfile::NamedTempFile::new_in(&self.directory)
            .map_err(|_| AttestationError::State)?;
        #[cfg(unix)]
        temp.as_file()
            .set_permissions({
                use std::os::unix::fs::PermissionsExt;
                fs::Permissions::from_mode(0o600)
            })
            .map_err(|_| AttestationError::State)?;
        temp.write_all(&counter.to_be_bytes())
            .map_err(|_| AttestationError::State)?;
        temp.flush().map_err(|_| AttestationError::State)?;
        temp.as_file()
            .sync_all()
            .map_err(|_| AttestationError::State)?;
        temp.persist(&counter_path)
            .map_err(|_| AttestationError::State)?;
        #[cfg(unix)]
        fs::File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AttestationError::State)?;
        Ok(())
    }
}

#[cfg(any(test, all(target_os = "macos", feature = "apple-app-attest")))]
/// Revalidates the fixed enrollment assertion while materializing an identity.
/// Stored assertions are historical evidence, so this path must not advance a counter.
fn materialize_apple_genesis_root(
    assertion: &[u8],
    client_data_hash: &[u8; 32],
    credential: &RegisteredAppleCredential,
    rp_id_hash: [u8; 32],
    cd_hash: [u8; 32],
) -> anyhow::Result<RootProof> {
    verify_apple_assertion(
        assertion,
        client_data_hash,
        credential,
        &ApplePolicy {
            expected_rp_id_hash: rp_id_hash,
            allowed_cd_hashes: vec![cd_hash],
        },
    )
    .context("invalid provider genesis root assertion")?;
    Ok(RootProof::AppleAppAttest(assertion.to_vec()))
}

pub(crate) struct LocalIdentity {
    pub(crate) transport_key: SecretKey,
    pub(crate) producer_key: ProducerSigningKey,
    #[cfg(any(feature = "node", test))]
    pub(crate) genesis: SignedProviderGenesis,
    #[cfg(any(feature = "node", feature = "evaluate", test))]
    pub(crate) enrollment: ProviderEnrollmentBundle,
    #[cfg(feature = "node")]
    root: Arc<PlatformRoot>,
}

#[cfg(feature = "node")]
pub(crate) struct ProviderOpenIdentity {
    root: Arc<PlatformRoot>,
    producer_key: ProducerSigningKey,
    enrollment: ProviderEnrollmentBundle,
}

struct StoredIdentity {
    version: u8,
    root: StoredRoot,
    producer_key: [u8; 32],
    transport_key: [u8; 32],
    enrollment: ProviderEnrollmentBundle,
}

enum StoredRoot {
    Software([u8; 32]),
    #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
    AppleAppAttest {
        key: String,
    },
}

enum PlatformRoot {
    Software(ProducerSigningKey),
    #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
    AppleAppAttest {
        service: AppleAppAttest,
        credential: AppleCredential,
        public_key: [u8; 33],
        rp_id_hash: [u8; 32],
        cd_hash: [u8; 32],
        validation_time: u64,
    },
}

impl PlatformRoot {
    fn prove(&self, statement: &[u8]) -> anyhow::Result<RootProof> {
        self.prove_prehashed(
            Digest::hash(statement),
            #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
            client_data_hash(statement),
        )
    }

    fn prove_prehashed(
        &self,
        software_digest: Digest,
        #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
        apple_client_data_hash: [u8; 32],
    ) -> anyhow::Result<RootProof> {
        match self {
            Self::Software(key) => Ok(RootProof::Software(key.sign_digest(software_digest)?)),
            #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
            Self::AppleAppAttest { service, .. } => Ok(RootProof::AppleAppAttest(
                service.assertion(apple_client_data_hash)?,
            )),
        }
    }

    #[cfg(feature = "node")]
    fn prove_open(&self, binding: Digest) -> anyhow::Result<RootProof> {
        self.prove_prehashed(
            binding,
            #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
            *binding.as_bytes(),
        )
    }
}

#[cfg(feature = "node")]
impl ProviderOpenIdentity {
    fn proof(&self, binding: Digest) -> anyhow::Result<RootProof> {
        match self.root.as_ref() {
            // Open is signed by the producer key recorded in genesis. The
            // separate software root key only authenticates genesis itself.
            PlatformRoot::Software(_) => {
                PlatformRoot::Software(self.producer_key.clone()).prove_open(binding)
            }
            #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
            PlatformRoot::AppleAppAttest { .. } => self.root.prove_open(binding),
        }
    }
}

#[cfg(feature = "node")]
impl OpenHandler for ProviderOpenIdentity {
    async fn open(
        &self,
        request: OpenRequest,
        context: TransportContext,
        alpn: &'static [u8],
    ) -> Result<OpenResponse, WireStatus> {
        let nonce: [u8; OPEN_NONCE_LEN] = request.nonce.try_into().map_err(|bytes: Vec<u8>| {
            WireStatus::new(
                WireCode::InvalidArgument,
                format!(
                    "confidential open nonce must be {OPEN_NONCE_LEN} bytes, got {}",
                    bytes.len()
                ),
            )
        })?;
        let exporter = context.open_exporter.ok_or_else(|| {
            WireStatus::new(
                WireCode::FailedPrecondition,
                "transport does not expose a confidential-open exporter",
            )
        })?;
        let binding = open_proof_binding(
            &exporter,
            &nonce,
            &self.enrollment.genesis.statement.producer_public_key,
            self.enrollment.content_id(),
            alpn,
        );
        let proof = match self
            .proof(binding)
            .map_err(|error| WireStatus::internal(format!("open proof failed: {error}")))?
        {
            RootProof::Software(signature) => {
                open_response::Proof::ProducerSignature(signature_to_pb(&signature))
            }
            RootProof::AppleAppAttest(assertion) => {
                open_response::Proof::AppleAppAttestAssertion(assertion)
            }
            RootProof::Tpm20(_) => {
                return Err(WireStatus::new(
                    WireCode::FailedPrecondition,
                    "TPM confidential open is not implemented",
                ));
            }
        };
        Ok(OpenResponse {
            provider_genesis: self.enrollment.canonical_bytes(),
            proof: Some(proof),
        })
    }
}

#[cfg(feature = "node")]
impl LocalIdentity {
    pub(crate) fn open_identity(&self) -> Arc<ProviderOpenIdentity> {
        Arc::new(ProviderOpenIdentity {
            root: self.root.clone(),
            producer_key: self.producer_key.clone(),
            enrollment: self.enrollment.clone(),
        })
    }
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

pub(crate) fn provider_trust(
    expected_genesis: Option<hellas_rpc::ContentId>,
    required_assurance: hellas_rpc::Assurance,
    app_id: Option<String>,
    allowed_cd_hashes: Vec<[u8; 32]>,
) -> anyhow::Result<hellas_client::ProviderTrustAnchor> {
    let expected_genesis =
        expected_genesis.context("remote execution requires --provider-genesis <content-id>")?;
    let apple_app_attest = match (app_id, allowed_cd_hashes.is_empty()) {
        (None, true) if required_assurance == hellas_rpc::Assurance::ProducerSigned => None,
        (Some(app_id), false) => Some(hellas_client::AppleAppAttestTrust::new(
            app_id,
            allowed_cd_hashes,
            Arc::new(FilesystemAssertionCounterStore::new(default_hellas_path(
                APPLE_OPEN_COUNTER_STORE_DIR,
                "--apple-app-attest-cdhashes",
            )?)),
        )),
        (None, _) => {
            bail!("Apple App Attest trust requires --apple-app-attest-app-id <team-id.bundle-id>")
        }
        (Some(_), true) => {
            bail!("Apple App Attest trust requires --apple-app-attest-cdhashes <hex>")
        }
    };
    Ok(hellas_client::ProviderTrustAnchor {
        expected_genesis,
        required_assurance,
        apple_app_attest,
    })
}

fn default_hellas_path(file: &str, flag: &str) -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").with_context(|| {
        format!("HOME environment variable not set; use {flag} to specify path")
    })?;
    Ok(PathBuf::from(home).join(IDENTITY_DIR).join(file))
}

fn create_root(explicit: bool, _installation_nonce: [u8; 32]) -> anyhow::Result<PlatformRoot> {
    require_software_root(explicit)?;
    #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
    if !explicit {
        let mut e = DagCborEncoder::new();
        e.array(2);
        e.str("hellas.apple.app-attest.enrollment.v1");
        e.bytes(&_installation_nonce);
        let (service, credential) = AppleAppAttest::create(client_data_hash(&e.into_bytes()))?;
        let identity = apple_credential_identity(&credential.attestation)?;
        let validation_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs();
        return Ok(PlatformRoot::AppleAppAttest {
            service,
            credential,
            public_key: identity.public_key,
            rp_id_hash: identity.rp_id_hash,
            cd_hash: identity.cd_hash,
            validation_time,
        });
    }
    Ok(PlatformRoot::Software(ProducerSigningKey::generate()))
}

fn create(path: &Path, software_root: bool) -> anyhow::Result<LocalIdentity> {
    let producer_key = ProducerSigningKey::generate();
    let transport_key = SecretKey::generate();
    let installation_nonce = rand::random();
    let root = Arc::new(create_root(software_root, installation_nonce)?);
    let statement = statement(&root, &producer_key, &transport_key, installation_nonce);
    let genesis = SignedProviderGenesis {
        root_proof: root.prove(&statement.canonical_bytes())?,
        statement,
    };
    let enrollment = enrollment_bundle(&root, genesis.clone());
    let stored_root = match root.as_ref() {
        PlatformRoot::Software(key) => StoredRoot::Software(key.to_secret_bytes()),
        #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
        PlatformRoot::AppleAppAttest { service, .. } => StoredRoot::AppleAppAttest {
            key: service.key().into(),
        },
    };
    let stored = StoredIdentity {
        version: VERSION,
        root: stored_root,
        producer_key: producer_key.to_secret_bytes(),
        transport_key: transport_key.to_bytes(),
        enrollment: enrollment.clone(),
    };
    let identity = LocalIdentity {
        transport_key,
        producer_key,
        #[cfg(any(feature = "node", test))]
        genesis,
        #[cfg(any(feature = "node", feature = "evaluate", test))]
        enrollment,
        #[cfg(feature = "node")]
        root,
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
    let root = Arc::new(match &stored.root {
        StoredRoot::Software(secret) => PlatformRoot::Software(
            ProducerSigningKey::from_secret_bytes(*secret).context("invalid software root key")?,
        ),
        #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
        StoredRoot::AppleAppAttest { key } => {
            let PlatformEnrollment::AppleAppAttest(enrollment) = &stored.enrollment.platform else {
                bail!("Apple App Attest root requires Apple enrollment");
            };
            let credential = AppleCredential {
                attestation: enrollment.attestation_object.clone(),
                client_data_hash: enrollment.client_data_hash,
            };
            let identity = apple_credential_identity(&enrollment.attestation_object)?;
            PlatformRoot::AppleAppAttest {
                service: AppleAppAttest::load(key.clone(), credential.content_id()),
                credential,
                public_key: identity.public_key,
                rp_id_hash: identity.rp_id_hash,
                cd_hash: identity.cd_hash,
                validation_time: enrollment.validation_time,
            }
        }
    });
    let producer_key = ProducerSigningKey::from_secret_bytes(stored.producer_key)
        .context("invalid producer key")?;
    let transport_key = SecretKey::from(stored.transport_key);
    let statement = statement(
        &root,
        &producer_key,
        &transport_key,
        stored.enrollment.genesis.statement.installation_nonce,
    );
    #[cfg_attr(not(any(feature = "node", test)), allow(unused_variables))]
    let root_proof = match (root.as_ref(), &stored.enrollment.genesis.root_proof) {
        (PlatformRoot::Software(_), RootProof::Software(signature)) => {
            verify_digest_signature(
                &statement.root_public_key,
                signature,
                Digest::hash(&statement.canonical_bytes()),
            )
            .context("invalid provider genesis root signature")?;
            RootProof::Software(*signature)
        }
        (PlatformRoot::Software(_), _) => bail!("software root requires a software root proof"),
        #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
        (
            PlatformRoot::AppleAppAttest {
                credential,
                public_key,
                rp_id_hash,
                cd_hash,
                ..
            },
            RootProof::AppleAppAttest(assertion),
        ) => materialize_apple_genesis_root(
            assertion,
            &client_data_hash(&statement.canonical_bytes()),
            &RegisteredAppleCredential {
                id: credential.content_id(),
                public_key: *public_key,
            },
            *rp_id_hash,
            *cd_hash,
        )?,
        #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
        (PlatformRoot::AppleAppAttest { .. }, _) => {
            bail!("Apple App Attest root requires an Apple App Attest proof")
        }
    };
    #[cfg_attr(
        not(any(feature = "node", feature = "evaluate", test)),
        allow(unused_variables)
    )]
    let genesis = SignedProviderGenesis {
        statement,
        root_proof,
    };
    let enrollment = enrollment_bundle(&root, genesis.clone());
    if enrollment != stored.enrollment {
        bail!("stored provider enrollment does not match the persisted keys");
    }
    Ok(LocalIdentity {
        transport_key,
        producer_key,
        #[cfg(any(feature = "node", test))]
        genesis,
        #[cfg(any(feature = "node", feature = "evaluate", test))]
        enrollment,
        #[cfg(feature = "node")]
        root,
    })
}

fn enrollment_bundle(
    root: &PlatformRoot,
    genesis: SignedProviderGenesis,
) -> ProviderEnrollmentBundle {
    let platform = match root {
        PlatformRoot::Software(_) => PlatformEnrollment::Absent,
        #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
        PlatformRoot::AppleAppAttest {
            credential,
            validation_time,
            ..
        } => PlatformEnrollment::AppleAppAttest(AppleAppAttestEnrollment {
            attestation_object: credential.attestation.clone(),
            client_data_hash: credential.client_data_hash,
            validation_time: *validation_time,
        }),
    };
    ProviderEnrollmentBundle { genesis, platform }
}

fn statement(
    root: &PlatformRoot,
    producer: &ProducerSigningKey,
    transport: &SecretKey,
    installation_nonce: [u8; 32],
) -> ProviderGenesisStatement {
    let (root_kind, root_public_key, platform_credential) = match root {
        PlatformRoot::Software(key) => (
            RootKind::Software,
            key.public_key(),
            PlatformCredential::Absent,
        ),
        #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
        PlatformRoot::AppleAppAttest {
            credential,
            public_key,
            ..
        } => (
            RootKind::SecureEnclave,
            PublicKey::P256(*public_key),
            PlatformCredential::Registered(credential.content_id()),
        ),
    };
    ProviderGenesisStatement {
        root_kind,
        root_public_key,
        producer_public_key: producer.public_key(),
        transport_public_key: PublicKey::Ed25519(*transport.public().as_bytes()),
        platform_credential,
        installation_nonce,
    }
}

impl StoredIdentity {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = hellas_rpc::DagCborEncoder::new();
        encoder.array(6);
        encoder.str(IDENTITY_TAG);
        encoder.u64(u64::from(self.version));
        match &self.root {
            StoredRoot::Software(secret) => {
                encoder.array(2);
                encoder.u64(0);
                encoder.bytes(secret);
            }
            #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
            StoredRoot::AppleAppAttest { key } => {
                encoder.array(2);
                encoder.u64(1);
                encoder.str(key);
            }
        }
        encoder.bytes(&self.producer_key);
        encoder.bytes(&self.transport_key);
        encoder.bytes(&self.enrollment.canonical_bytes());
        encoder.into_bytes()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut decoder = DagCborDecoder::new(bytes);
        decoder.array(6, "identity")?;
        decoder.tag(IDENTITY_TAG)?;
        let version = u8::try_from(decoder.u64("identity version")?)
            .context("identity version does not fit in one byte")?;
        let root_len = decoder.array_len("identity root")?;
        if root_len != 2 {
            bail!("identity root must contain 2 items, got {root_len}");
        }
        let root = match decoder.u64("identity root kind")? {
            0 => StoredRoot::Software(decoder.fixed_bytes("software root key")?),
            #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
            1 => StoredRoot::AppleAppAttest {
                key: decoder.text("Apple App Attest key")?.to_owned(),
            },
            #[cfg(not(all(target_os = "macos", feature = "apple-app-attest")))]
            1 => bail!("Apple App Attest identity is not supported on this platform"),
            value => bail!("unknown identity root kind {value}"),
        };
        let producer_key = decoder.fixed_bytes("producer key")?;
        let transport_key = decoder.fixed_bytes("transport key")?;
        let enrollment =
            ProviderEnrollmentBundle::from_canonical_bytes(decoder.bytes("provider enrollment")?)
                .context("invalid canonical provider enrollment")?;
        decoder.finish()?;
        let stored = Self {
            version,
            root,
            producer_key,
            transport_key,
            enrollment,
        };
        if stored.canonical_bytes() != bytes {
            bail!("identity is not canonical DAG-CBOR");
        }
        Ok(stored)
    }
}

fn decode(path: &Path, bytes: &[u8]) -> anyhow::Result<LocalIdentity> {
    let stored = StoredIdentity::from_canonical_bytes(bytes).with_context(|| {
        format!(
            "identity file {} has an unsupported encoding",
            path.display()
        )
    })?;
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
    temp.write_all(&stored.canonical_bytes())?;
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
    use hellas_rpc::Signature;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
    use serde::Serialize;
    use serde_bytes::ByteBuf;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;
    use std::env;

    fn apple_assertion(
        signing_key: &P256SigningKey,
        rp_id_hash: [u8; 32],
        cd_hash: [u8; 32],
        counter: u32,
        client_data_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "apple_cd_hash_hash_01".to_owned(),
            ByteBuf::from(cd_hash.to_vec()),
        );
        extensions.insert("apple_cd_hash_type_01".to_owned(), ByteBuf::from(vec![2]));
        extensions.insert(
            "apple_validation_category_01".to_owned(),
            ByteBuf::from(vec![6, 0, 0, 0]),
        );
        let mut extension_bytes = Vec::new();
        ciborium::into_writer(&extensions, &mut extension_bytes).unwrap();

        let mut authenticator_data = Vec::new();
        authenticator_data.extend_from_slice(&rp_id_hash);
        authenticator_data.push(0x40);
        authenticator_data.extend_from_slice(&counter.to_be_bytes());
        authenticator_data.extend_from_slice(&extension_bytes);
        let digest = Sha256::digest([authenticator_data.as_slice(), client_data_hash].concat());
        let signature: P256Signature = signing_key.sign(&digest);

        #[derive(Serialize)]
        struct Assertion {
            #[serde(rename = "authenticatorData")]
            authenticator_data: ByteBuf,
            signature: ByteBuf,
        }

        let mut encoded = Vec::new();
        ciborium::into_writer(
            &Assertion {
                authenticator_data: ByteBuf::from(authenticator_data),
                signature: ByteBuf::from(signature.to_der().as_bytes().to_vec()),
            },
            &mut encoded,
        )
        .unwrap();
        encoded
    }

    #[test]
    fn creates_and_reloads_one_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        let first = load_or_create(Some(&path), true).unwrap();
        let persisted = fs::read(&path).unwrap();
        let stored = StoredIdentity::from_canonical_bytes(&persisted).unwrap();
        assert_eq!(stored.version, VERSION);
        assert_eq!(stored.canonical_bytes(), persisted);
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
        assert_eq!(first.enrollment, second.enrollment);
        assert_eq!(first.enrollment.genesis, first.genesis);
        assert_eq!(first.enrollment.platform, PlatformEnrollment::Absent);
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
                .contains("unsupported encoding")
        );
    }

    #[test]
    fn rejects_v2_json_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        fs::write(&path, br#"{"version":2}"#).unwrap();
        assert!(
            load_existing(Some(&path))
                .err()
                .unwrap()
                .to_string()
                .contains("unsupported encoding")
        );
    }

    #[test]
    fn identity_canonical_decode_contract() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        load_or_create(Some(&path), true).unwrap();
        let persisted = fs::read(&path).unwrap();
        let stored = StoredIdentity::from_canonical_bytes(&persisted).unwrap();
        assert_eq!(stored.canonical_bytes(), persisted);

        let mut trailing = persisted.clone();
        trailing.push(0);
        assert!(StoredIdentity::from_canonical_bytes(&trailing).is_err());

        let mut encoded_producer_key = vec![0x58, 0x20];
        encoded_producer_key.extend_from_slice(&stored.producer_key);
        let producer_key_start = persisted
            .windows(encoded_producer_key.len())
            .position(|window| window == encoded_producer_key)
            .unwrap();
        let mut wrong_length = persisted.clone();
        wrong_length[producer_key_start + 1] = 31;
        wrong_length.remove(producer_key_start + 33);
        assert!(StoredIdentity::from_canonical_bytes(&wrong_length).is_err());

        assert_eq!(persisted[0], 0x86);
        let mut noncanonical = vec![0x98, 0x06];
        noncanonical.extend_from_slice(&persisted[1..]);
        fs::write(&path, noncanonical).unwrap();
        assert!(load_existing(Some(&path)).is_err());
    }

    #[test]
    fn rejects_tampered_root_signature() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        load_or_create(Some(&path), true).unwrap();
        let mut stored = StoredIdentity::from_canonical_bytes(&fs::read(&path).unwrap()).unwrap();
        let RootProof::Software(Signature::Secp256k1(signature)) =
            &mut stored.enrollment.genesis.root_proof
        else {
            panic!("software identity has a software root proof");
        };
        signature[0] ^= 1;
        fs::write(&path, stored.canonical_bytes()).unwrap();
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

    #[test]
    fn assertion_counter_partial_temp_write_leaves_old_value_intact() {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemAssertionCounterStore::new(dir.path());
        let public_key = [7; 33];
        store.advance(&public_key, 2).unwrap();

        let mut interrupted = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        interrupted.write_all(&[0, 0]).unwrap();
        interrupted.flush().unwrap();
        let (interrupted, _) = interrupted.keep().unwrap();
        drop(interrupted);

        assert_eq!(
            fs::read(store.counter_path(&public_key)).unwrap(),
            2_u32.to_be_bytes()
        );
        assert_eq!(
            store.advance(&public_key, 1),
            Err(AttestationError::Counter)
        );
        store.advance(&public_key, 3).unwrap();
    }

    #[test]
    fn assertion_counter_corruption_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemAssertionCounterStore::new(dir.path());
        let public_key = [8; 33];
        fs::write(store.counter_path(&public_key), [0, 1]).unwrap();

        assert_eq!(store.advance(&public_key, 3), Err(AttestationError::State));
    }

    #[test]
    fn stored_apple_genesis_materialization_is_repeatable() {
        let signing_key = P256SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let credential = RegisteredAppleCredential {
            id: hellas_rpc::ContentId::from_bytes([9; 32]),
            public_key: signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
        };
        let cd_hash = [8; 32];
        let rp_id_hash = [7; 32];
        let client_data_hash = [3; 32];
        let assertion = apple_assertion(&signing_key, rp_id_hash, cd_hash, 1, &client_data_hash);

        let first = materialize_apple_genesis_root(
            &assertion,
            &client_data_hash,
            &credential,
            rp_id_hash,
            cd_hash,
        )
        .unwrap();
        let second = materialize_apple_genesis_root(
            &assertion,
            &client_data_hash,
            &credential,
            rp_id_hash,
            cd_hash,
        )
        .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn provider_trust_requires_complete_apple_policy_and_threads_assurance() {
        let expected = Some(hellas_rpc::ContentId::from_bytes([9; 32]));
        let producer = provider_trust(
            expected,
            hellas_rpc::Assurance::ProducerSigned,
            None,
            vec![],
        )
        .unwrap();
        assert_eq!(
            producer.required_assurance,
            hellas_rpc::Assurance::ProducerSigned
        );
        assert!(producer.apple_app_attest.is_none());

        assert!(
            provider_trust(
                expected,
                hellas_rpc::Assurance::AppleAppAttest,
                None,
                vec![[1; 32]],
            )
            .unwrap_err()
            .to_string()
            .contains("--apple-app-attest-app-id")
        );
        assert!(
            provider_trust(
                expected,
                hellas_rpc::Assurance::AppleAppAttest,
                Some("TEAM.example.app".to_owned()),
                vec![],
            )
            .unwrap_err()
            .to_string()
            .contains("--apple-app-attest-cdhashes")
        );
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
