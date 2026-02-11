use crate::app::Mailbox;
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{Reporter as Rp, elector::RoundRobin, minimmit, types::ViewDelta};
use commonware_cryptography::{Sha256, Signer, ed25519, sha256::Digest};
use commonware_p2p::{Address, Blocker};
use commonware_parallel::Sequential;
use commonware_runtime::buffer::PoolRef;
use commonware_utils::{
    NZU16,
    ordered::{Map, Set},
};
use hellas_types::{Activity, EPOCH, PublicKey, Scheme};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, num::NonZeroUsize, path::PathBuf, time::Duration};

#[derive(Clone, Copy)]
pub struct Config {
    pub mailbox_size: usize,
    pub replay_buffer: usize,
    pub write_buffer: usize,
    pub buffer_page_size: u16,
    pub buffer_page_count: usize,
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
            buffer_page_size: 4096,
            buffer_page_count: 1024,
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
            buffer_page_size: 4096,
            buffer_page_count: 1024,
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
        automaton: Mailbox,
        relay: Mailbox,
        reporter: R,
        partition: &PublicKey,
    ) -> minimmit::Config<Scheme, RoundRobin<Sha256>, B, Digest, Mailbox, Mailbox, R, Sequential>
    where
        B: Blocker<PublicKey = PublicKey>,
        R: Rp<Activity = Activity>,
    {
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
            replay_buffer: NonZeroUsize::new(self.replay_buffer).unwrap(),
            write_buffer: NonZeroUsize::new(self.write_buffer).unwrap(),
            buffer_pool: PoolRef::new(
                NZU16!(self.buffer_page_size),
                NonZeroUsize::new(self.buffer_page_count).unwrap(),
            ),
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
    pub peers: Vec<PeerEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct PeerEntry {
    pub public_key: String,
    pub address: String,
}

impl NodeConfig {
    pub fn decode_private_key(&self) -> ed25519::PrivateKey {
        let bytes = hex::decode(&self.private_key).expect("invalid hex in private_key");
        ed25519::PrivateKey::decode(bytes.as_slice()).expect("invalid ed25519 private key")
    }

    pub fn storage_directory(&self) -> PathBuf {
        let base = dirs::data_local_dir().expect("unable to determine data directory");
        let pk_hex = hex::encode(self.decode_private_key().public_key().encode());
        base.join("hellas").join(&pk_hex[..16])
    }

    pub fn public_key(&self) -> PublicKey {
        self.decode_private_key().public_key()
    }

    pub fn participants(&self) -> Set<PublicKey> {
        let me = self.public_key();
        let mut keys: Vec<PublicKey> = self
            .peers
            .iter()
            .map(|p| {
                let bytes = hex::decode(&p.public_key).expect("invalid hex in peer public_key");
                PublicKey::decode(bytes.as_slice()).expect("invalid ed25519 public key")
            })
            .collect();
        keys.push(me);
        Set::try_from(keys).expect("duplicate public keys in config")
    }

    pub fn peer_address_map(&self) -> Map<PublicKey, Address> {
        let me = self.public_key();
        let listen: SocketAddr = format!("0.0.0.0:{}", self.listen_port)
            .parse()
            .expect("invalid listen port");

        let mut entries: Vec<(PublicKey, Address)> = self
            .peers
            .iter()
            .map(|p| {
                let bytes = hex::decode(&p.public_key).expect("invalid hex in peer public_key");
                let key = PublicKey::decode(bytes.as_slice()).expect("invalid ed25519 public key");
                let addr: SocketAddr = p.address.parse().expect("invalid peer address");
                (key, Address::Symmetric(addr))
            })
            .collect();
        entries.push((me, Address::Symmetric(listen)));
        Map::try_from(entries).expect("duplicate keys in peer address map")
    }
}

pub fn encode_private_key(key: &ed25519::PrivateKey) -> String {
    hex::encode(key.encode())
}
