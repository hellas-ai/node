use crate::domain::{
    Address as UserAddress, PublicKey, SettlementKey as UserSettlementKey, SettlementKeyError,
    ThresholdPolynomial, ThresholdShare,
};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::bls12381::primitives::sharing::ModeVersion;
use commonware_cryptography::{Signer, ed25519};
use commonware_p2p::Address as P2pAddress;
use commonware_runtime::{BufferPooler, buffer::paged::CacheRef};
use commonware_utils::ordered::{Map, Set};
pub use hellas_genesis::{Genesis, GenesisAllocation as GenesisEntry, GenesisValidator};
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
    #[error("invalid genesis document")]
    Genesis(#[from] hellas_genesis::GenesisError),
    #[error("validator identity is not in the genesis committee")]
    MissingLocalValidator,
    #[error("configured peer identities do not match the genesis committee")]
    PeerSetMismatch,
    #[error("network `{configured}` is not supported by this binary; expected `{supported}`")]
    UnsupportedNetwork {
        configured: String,
        supported: &'static str,
    },
    #[error("invalid network address")]
    InvalidAddress(#[from] std::net::AddrParseError),
    #[error("duplicate keys in peer address map")]
    DuplicatePeerAddressKeys,
    #[error("invalid genesis settlement key `{entry}`: {source}")]
    InvalidGenesisSettlementKey {
        entry: String,
        #[source]
        source: SettlementKeyError,
    },
    #[error("genesis settlement key `{entry}` is not a valid P-256 address")]
    InvalidGenesisP256SettlementKey { entry: String },
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
    pub skip_timeout: Duration,
    pub fetch_timeout: Duration,
    pub fetch_concurrent: usize,
    pub broadcast_cache_per_peer: usize,
    pub max_repair: usize,
}

impl Default for Config {
    fn default() -> Self {
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
            skip_timeout: Duration::from_secs(5),
            fetch_timeout: Duration::from_secs(5),
            fetch_concurrent: 3,
            broadcast_cache_per_peer: 128,
            max_repair: 16,
        }
    }
}

impl Config {

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
    pub relay_urls: Vec<String>,
    pub genesis: Genesis,
    pub peers: Vec<PeerEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct PeerEntry {
    pub public_key: String,
    pub address: String,
}

impl ValidatorConfig {
    pub fn validate_genesis(&self) -> Result<(), ConfigError> {
        self.genesis.validate()?;
        if self.genesis.network_id != hellas_genesis::DEFAULT_NETWORK_ID {
            return Err(ConfigError::UnsupportedNetwork {
                configured: self.genesis.network_id.clone(),
                supported: hellas_genesis::DEFAULT_NETWORK_ID,
            });
        }
        Ok(())
    }

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
        let total = u32::try_from(self.genesis.validators.len()).unwrap_or(u32::MAX);
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
        self.validate_genesis()?;
        let me = self.public_key()?;
        let keys: Vec<PublicKey> = self
            .genesis
            .validators
            .iter()
            .map(|validator| -> Result<PublicKey, ConfigError> {
                let bytes = hex::decode(&validator.public_key)?;
                let key: PublicKey = PublicKey::decode(bytes.as_slice())?;
                Ok(key)
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;
        let set = Set::try_from(keys).map_err(|_| ConfigError::DuplicatePublicKeys)?;
        if set.position(&me).is_none() {
            return Err(ConfigError::MissingLocalValidator);
        }
        Ok(set)
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
        let configured = Set::try_from(
            entries
                .iter()
                .map(|(public_key, _)| public_key.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(|_| ConfigError::DuplicatePeerAddressKeys)?;
        if configured != self.participants()? {
            return Err(ConfigError::PeerSetMismatch);
        }
        Map::try_from(entries).map_err(|_| ConfigError::DuplicatePeerAddressKeys)
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

    pub fn genesis_allocations(&self) -> Result<Vec<(UserSettlementKey, u64)>, ConfigError> {
        self.validate_genesis()?;
        let mut allocations: Vec<(UserSettlementKey, u64)> = self
            .genesis
            .allocations
            .iter()
            .map(|entry| -> Result<(UserSettlementKey, u64), ConfigError> {
                let key = parse_genesis_settlement_key(&entry.address)?;
                Ok((key, entry.balance))
            })
            .collect::<Result<Vec<_>, _>>()?;
        allocations.sort_by_key(|entry| entry.0);
        if allocations.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(ConfigError::DuplicateGenesisAddresses);
        }
        Ok(allocations)
    }
}

pub(crate) fn parse_genesis_settlement_key(entry: &str) -> Result<UserSettlementKey, ConfigError> {
    let key = entry
        .parse()
        .map_err(|source| ConfigError::InvalidGenesisSettlementKey {
            entry: entry.to_string(),
            source,
        })?;
    UserAddress::try_from(key).map_err(|_| ConfigError::InvalidGenesisP256SettlementKey {
        entry: entry.to_string(),
    })?;
    Ok(key)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{SettlementKey, addr_from_signing_key, secp256r1_key_from_seed};

    fn config_with_genesis(address: String) -> ValidatorConfig {
        let private_key = ed25519::PrivateKey::from_seed(1);
        let public_key = hex::encode(private_key.public_key().encode());
        ValidatorConfig {
            private_key: encode_private_key(&private_key),
            threshold_share: String::new(),
            threshold_polynomial: String::new(),
            listen_port: 0,
            metrics_port: None,
            relay_urls: Vec::new(),
            genesis: Genesis {
                schema_version: hellas_genesis::GENESIS_SCHEMA_VERSION,
                network_id: hellas_genesis::DEFAULT_NETWORK_ID.to_string(),
                validators: vec![GenesisValidator {
                    public_key,
                    label: "validator-0".to_string(),
                }],
                allocations: vec![GenesisEntry {
                    address,
                    balance: 10,
                }],
            },
            peers: Vec::new(),
        }
    }

    #[test]
    fn genesis_allocations_reject_non_p256_settlement_key() {
        let entry = SettlementKey::from_bytes([0xa5; SettlementKey::LENGTH]).to_string();
        let err = config_with_genesis(entry.clone())
            .genesis_allocations()
            .expect_err("non-P-256 genesis owner");
        assert!(matches!(
            err,
            ConfigError::InvalidGenesisP256SettlementKey { entry: actual } if actual == entry
        ));
    }

    #[test]
    fn genesis_allocations_accept_p256_settlement_key() {
        let address = addr_from_signing_key(&secp256r1_key_from_seed(7));
        let key = SettlementKey::from(address);
        assert_eq!(
            config_with_genesis(key.to_string())
                .genesis_allocations()
                .expect("valid P-256 genesis owner"),
            vec![(key, 10)]
        );
    }

    #[test]
    fn genesis_committee_must_include_local_identity() {
        let address = addr_from_signing_key(&secp256r1_key_from_seed(7));
        let mut config = config_with_genesis(SettlementKey::from(address).to_string());
        let other = ed25519::PrivateKey::from_seed(2);
        config.genesis.validators[0].public_key = hex::encode(other.public_key().encode());

        assert!(matches!(
            config.participants(),
            Err(ConfigError::MissingLocalValidator)
        ));
    }

    #[test]
    fn peer_topology_must_cover_exact_genesis_committee() {
        let address = addr_from_signing_key(&secp256r1_key_from_seed(7));
        let mut config = config_with_genesis(SettlementKey::from(address).to_string());
        let other = ed25519::PrivateKey::from_seed(2);
        config.genesis.validators.push(GenesisValidator {
            public_key: hex::encode(other.public_key().encode()),
            label: "validator-1".to_string(),
        });

        assert!(matches!(
            config.peer_address_map(),
            Err(ConfigError::PeerSetMismatch)
        ));
    }

    #[test]
    fn rejects_network_id_the_transaction_domain_does_not_support() {
        let address = addr_from_signing_key(&secp256r1_key_from_seed(7));
        let mut config = config_with_genesis(SettlementKey::from(address).to_string());
        config.genesis.network_id = "hellas-testnet-1".to_string();

        assert!(matches!(
            config.validate_genesis(),
            Err(ConfigError::UnsupportedNetwork { .. })
        ));
    }
}
