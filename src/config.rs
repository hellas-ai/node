use crate::app::AppMailbox;
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{Reporter, elector::RoundRobin, minimmit, types::ViewDelta};
use commonware_cryptography::{Sha256, Signer, ed25519, sha256::Digest};
use commonware_p2p::{Address, Blocker};
use commonware_parallel::Sequential;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_utils::ordered::{Map, Set};
use hellas_types::{Activity, EPOCH, PublicKey, Scheme};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    num::{NonZeroU16, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid hex key data")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("invalid ed25519 key bytes")]
    InvalidKey(#[from] commonware_codec::Error),
    #[error("unable to determine local data directory")]
    MissingDataDirectory,
    #[error("duplicate public keys in config")]
    DuplicatePublicKeys,
    #[error("invalid network address")]
    InvalidAddress(#[from] std::net::AddrParseError),
    #[error("duplicate keys in peer address map")]
    DuplicatePeerAddressKeys,
}

#[derive(Clone, Copy)]
pub struct Config {
    pub mailbox_size: usize,
    pub replay_buffer: usize,
    pub write_buffer: usize,
    pub page_cache_size: u16,
    pub page_cache_count: usize,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub activity_timeout: u64,
    pub skip_timeout: u64,
    pub fetch_timeout: Duration,
    pub fetch_concurrent: usize,
}

impl Config {
    pub const fn mainnet() -> Self {
        Self {
            mailbox_size: 1024,
            replay_buffer: 1024 * 1024,
            write_buffer: 64 * 1024,
            page_cache_size: 4096,
            page_cache_count: 1024,
            leader_timeout: Duration::from_secs(1),
            notarization_timeout: Duration::from_secs(2),
            nullify_retry: Duration::from_millis(500),
            activity_timeout: 10,
            skip_timeout: 5,
            fetch_timeout: Duration::from_secs(5),
            fetch_concurrent: 3,
        }
    }

    pub const fn test() -> Self {
        Self {
            mailbox_size: 1024,
            replay_buffer: 1024 * 1024,
            write_buffer: 64 * 1024,
            page_cache_size: 4096,
            page_cache_count: 1024,
            leader_timeout: Duration::from_millis(100),
            notarization_timeout: Duration::from_millis(200),
            nullify_retry: Duration::from_millis(50),
            activity_timeout: 10,
            skip_timeout: 5,
            fetch_timeout: Duration::from_millis(500),
            fetch_concurrent: 3,
        }
    }

    pub fn into_minimmit<B, R>(
        self,
        scheme: Scheme,
        blocker: B,
        automaton: AppMailbox,
        relay: AppMailbox,
        reporter: R,
        partition: &PublicKey,
    ) -> minimmit::Config<
        Scheme,
        RoundRobin<Sha256>,
        B,
        Digest,
        AppMailbox,
        AppMailbox,
        R,
        Sequential,
    >
    where
        B: Blocker<PublicKey = PublicKey>,
        R: Reporter<Activity = Activity>,
    {
        let replay_buffer = NonZeroUsize::new(self.replay_buffer).unwrap_or(NonZeroUsize::MIN);
        let write_buffer = NonZeroUsize::new(self.write_buffer).unwrap_or(NonZeroUsize::MIN);
        let page_cache_count =
            NonZeroUsize::new(self.page_cache_count).unwrap_or(NonZeroUsize::MIN);
        let page_cache_size = NonZeroU16::new(self.page_cache_size).unwrap_or(NonZeroU16::MIN);

        minimmit::Config {
            scheme,
            elector: RoundRobin::<Sha256>::default(),
            blocker,
            automaton,
            relay,
            reporter,
            strategy: Sequential,
            partition: partition.to_string(),
            mailbox_size: self.mailbox_size,
            epoch: EPOCH,
            replay_buffer,
            write_buffer,
            page_cache: CacheRef::new(page_cache_size, page_cache_count),
            leader_timeout: self.leader_timeout,
            notarization_timeout: self.notarization_timeout,
            nullify_retry: self.nullify_retry,
            activity_timeout: ViewDelta::new(self.activity_timeout),
            skip_timeout: ViewDelta::new(self.skip_timeout),
            fetch_timeout: self.fetch_timeout,
            fetch_concurrent: self.fetch_concurrent,
        }
    }
}

// ---------------------------------------------------------------------------
// Node configuration (serialized to/from TOML)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct NodeConfig {
    pub private_key: String,
    pub listen_port: u16,
    #[serde(default)]
    pub metrics_port: Option<u16>,
    pub peers: Vec<PeerEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct PeerEntry {
    pub public_key: String,
    pub address: String,
}

impl NodeConfig {
    pub fn decode_private_key(&self) -> Result<ed25519::PrivateKey, ConfigError> {
        let bytes = hex::decode(&self.private_key)?;
        Ok(ed25519::PrivateKey::decode(bytes.as_slice())?)
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

    pub fn peer_address_map(&self) -> Result<Map<PublicKey, Address>, ConfigError> {
        let me = self.public_key()?;
        let listen: SocketAddr = format!("0.0.0.0:{}", self.listen_port).parse()?;

        let mut entries: Vec<(PublicKey, Address)> = self
            .peers
            .iter()
            .map(|p| -> Result<(PublicKey, Address), ConfigError> {
                let bytes = hex::decode(&p.public_key)?;
                let key: PublicKey = PublicKey::decode(bytes.as_slice())?;
                let addr: SocketAddr = p.address.parse()?;
                Ok((key, Address::Symmetric(addr)))
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;
        entries.push((me, Address::Symmetric(listen)));
        match Map::try_from(entries) {
            Ok(map) => Ok(map),
            Err(_) => Err(ConfigError::DuplicatePeerAddressKeys),
        }
    }
}

pub fn encode_private_key(key: &ed25519::PrivateKey) -> String {
    hex::encode(key.encode())
}
