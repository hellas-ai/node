use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::bls12381::primitives::sharing::ModeVersion;
use commonware_cryptography::{Signer, ed25519};
use commonware_p2p::Address as P2pAddress;
use commonware_runtime::{BufferPooler, buffer::paged::CacheRef};
use commonware_utils::ordered::{Map, Set};
use hellas_kernel::domain::{
    Address as UserAddress, AddressError, PublicKey, ThresholdPolynomial, ThresholdShare,
};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid hex key data")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("invalid key bytes")]
    InvalidKey(#[from] commonware_codec::Error),
    #[error("unable to determine local data directory")]
    MissingDataDirectory,
    #[error("duplicate public keys in config")]
    DuplicatePublicKeys,
    #[error("invalid network address")]
    InvalidAddress(#[from] std::net::AddrParseError),
    #[error("duplicate keys in peer address map")]
    DuplicatePeerAddressKeys,
    #[error("invalid genesis address: {0}")]
    InvalidGenesisAddress(#[from] AddressError),
    #[error("duplicate addresses in genesis allocations")]
    DuplicateGenesisAddresses,
    #[error("failed to read credential {path}: {source}")]
    CredentialRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Filenames systemd `LoadCredential=` is expected to provide under `$CREDENTIALS_DIRECTORY`.
pub const CREDENTIAL_PRIVATE_KEY: &str = "private-key";
pub const CREDENTIAL_THRESHOLD_SHARE: &str = "threshold-share";
pub const CREDENTIAL_THRESHOLD_POLYNOMIAL: &str = "threshold-polynomial";

#[derive(Clone, Copy)]
pub struct Config {
    pub mailbox_size: usize,
    pub replay_buffer: usize,
    pub write_buffer: usize,
    pub page_cache_size: u16,
    pub page_cache_count: usize,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub nullify_retry: Duration,
    pub activity_timeout: u64,
    pub skip_timeout: u64,
    pub fetch_timeout: Duration,
    pub fetch_concurrent: usize,
    pub broadcast_cache_per_peer: usize,
    pub max_repair: usize,
}

impl Config {
    pub const fn mainnet() -> Self {
        Self {
            mailbox_size: 1024,
            replay_buffer: 1024 * 1024,
            write_buffer: 64 * 1024,
            page_cache_size: 4096,
            page_cache_count: 4096,
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            nullify_retry: Duration::from_millis(500),
            activity_timeout: 10,
            skip_timeout: 5,
            fetch_timeout: Duration::from_secs(5),
            fetch_concurrent: 3,
            broadcast_cache_per_peer: 128,
            max_repair: 16,
        }
    }

    pub fn page_cache(self, pooler: &impl BufferPooler) -> CacheRef {
        let page_cache_count =
            NonZeroUsize::new(self.page_cache_count).unwrap_or(NonZeroUsize::MIN);
        let page_cache_size = NonZeroU16::new(self.page_cache_size).unwrap_or(NonZeroU16::MIN);
        CacheRef::from_pooler(pooler, page_cache_size, page_cache_count)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub private_key: String,
    pub threshold_share: String,
    pub threshold_polynomial: String,
    pub listen_port: u16,
    #[serde(default)]
    pub metrics_port: Option<u16>,
    #[serde(default)]
    pub ws_bind: Option<String>,
    #[serde(default)]
    pub explorer_url: Option<String>,
    #[serde(default)]
    pub genesis_allocations: Vec<GenesisEntry>,
    pub peers: Vec<PeerEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct PeerEntry {
    pub public_key: String,
    pub address: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GenesisEntry {
    pub address: String,
    pub balance: u64,
}

impl ValidatorConfig {
    pub fn decode_private_key(&self) -> Result<ed25519::PrivateKey, ConfigError> {
        let bytes = hex::decode(&self.private_key)?;
        Ok(ed25519::PrivateKey::decode(bytes.as_slice())?)
    }

    pub fn decode_threshold_share(&self) -> Result<ThresholdShare, ConfigError> {
        let bytes = hex::decode(&self.threshold_share)?;
        Ok(ThresholdShare::decode(bytes.as_slice())?)
    }

    pub fn decode_threshold_polynomial(&self) -> Result<ThresholdPolynomial, ConfigError> {
        let bytes = hex::decode(&self.threshold_polynomial)?;
        let total = u32::try_from(self.peers.len() + 1).unwrap_or(u32::MAX);
        let max_participants = NonZeroU32::new(total).unwrap_or(NonZeroU32::MIN);
        Ok(ThresholdPolynomial::decode_cfg(
            bytes.as_slice(),
            &(max_participants, ModeVersion::v0()),
        )?)
    }

    pub fn storage_directory(&self) -> Result<PathBuf, ConfigError> {
        let base = dirs::data_local_dir().ok_or(ConfigError::MissingDataDirectory)?;
        let pk_hex = hex::encode(self.public_key()?.encode());
        Ok(base.join("hellas").join(&pk_hex[..16]))
    }

    pub fn public_key(&self) -> Result<PublicKey, ConfigError> {
        Ok(self.decode_private_key()?.public_key())
    }

    pub fn participants(&self) -> Result<Set<PublicKey>, ConfigError> {
        let me = self.public_key()?;
        let mut keys: Vec<PublicKey> = self
            .peers
            .iter()
            .map(|p| -> Result<PublicKey, ConfigError> {
                let bytes = hex::decode(&p.public_key)?;
                let key: PublicKey = PublicKey::decode(bytes.as_slice())?;
                Ok(key)
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;
        keys.push(me);
        match Set::try_from(keys) {
            Ok(set) => Ok(set),
            Err(_) => Err(ConfigError::DuplicatePublicKeys),
        }
    }

    pub fn peer_address_map(&self) -> Result<Map<PublicKey, P2pAddress>, ConfigError> {
        let me = self.public_key()?;
        let listen: SocketAddr = format!("0.0.0.0:{}", self.listen_port).parse()?;

        let mut entries: Vec<(PublicKey, P2pAddress)> = self
            .peers
            .iter()
            .map(|p| -> Result<(PublicKey, P2pAddress), ConfigError> {
                let bytes = hex::decode(&p.public_key)?;
                let key: PublicKey = PublicKey::decode(bytes.as_slice())?;
                let addr: SocketAddr = p.address.parse()?;
                Ok((key, P2pAddress::Symmetric(addr)))
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;
        entries.push((me, P2pAddress::Symmetric(listen)));
        match Map::try_from(entries) {
            Ok(map) => Ok(map),
            Err(_) => Err(ConfigError::DuplicatePeerAddressKeys),
        }
    }

    /// Overlay `private_key`, `threshold_share`, and `threshold_polynomial` from
    /// `$CREDENTIALS_DIRECTORY/{private-key,threshold-share,threshold-polynomial}`. When the
    /// env var is set, all three files are required — a partial set is a deployment misconfig.
    /// Returns `Ok(true)` when credentials were loaded, `Ok(false)` when the env var is unset.
    pub fn load_credentials(&mut self) -> Result<bool, ConfigError> {
        let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from) else {
            return Ok(false);
        };
        for (name, field) in [
            (CREDENTIAL_PRIVATE_KEY, &mut self.private_key),
            (CREDENTIAL_THRESHOLD_SHARE, &mut self.threshold_share),
            (
                CREDENTIAL_THRESHOLD_POLYNOMIAL,
                &mut self.threshold_polynomial,
            ),
        ] {
            let path = dir.join(name);
            let raw = std::fs::read_to_string(&path)
                .map_err(|source| ConfigError::CredentialRead { path, source })?;
            *field = raw.trim().to_string();
        }
        Ok(true)
    }

    pub fn genesis_allocations(&self) -> Result<Vec<(UserAddress, u64)>, ConfigError> {
        let mut allocations: Vec<(UserAddress, u64)> = self
            .genesis_allocations
            .iter()
            .map(|entry| -> Result<(UserAddress, u64), ConfigError> {
                let address: UserAddress = entry.address.parse()?;
                Ok((address, entry.balance))
            })
            .collect::<Result<Vec<_>, _>>()?;
        allocations.sort_by(|a, b| a.0.cmp(&b.0));
        if allocations.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(ConfigError::DuplicateGenesisAddresses);
        }
        Ok(allocations)
    }
}

pub fn encode_private_key(key: &ed25519::PrivateKey) -> String {
    hex::encode(key.encode())
}

pub fn encode_threshold_share(share: &ThresholdShare) -> String {
    hex::encode(share.encode())
}

pub fn encode_threshold_polynomial(polynomial: &ThresholdPolynomial) -> String {
    hex::encode(polynomial.encode())
}
