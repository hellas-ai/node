use commonware_codec::Encode;
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme, Zoda};
use commonware_consensus::types::Round;
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_utils::{Faults, N5f1};
use hellas_types::PublicKey;

pub type CodingImpl = Zoda<Sha256>;
pub type ZodaShard = <CodingImpl as CodingScheme>::Shard;
pub type ZodaReShard = <CodingImpl as CodingScheme>::ReShard;
pub type ZodaCheckedShard = <CodingImpl as CodingScheme>::CheckedShard;
pub type ZodaCheckingData = <CodingImpl as CodingScheme>::CheckingData;
pub type ZodaCommitment = <CodingImpl as CodingScheme>::Commitment;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockKey {
    pub round: Round,
    pub digest: Digest,
}

impl BlockKey {
    pub const fn new(round: Round, digest: Digest) -> Self {
        Self { round, digest }
    }
}

pub fn coding_config(validators: u16) -> CodingConfig {
    assert!(validators > 0, "validator set must not be empty");
    let faults = N5f1::max_faults(validators);
    let minimum_shards = u16::try_from(faults + 1).expect("fault count should fit into u16");
    let extra_shards = validators
        .checked_sub(minimum_shards)
        .expect("minimum shards must not exceed validator count");
    CodingConfig {
        minimum_shards,
        extra_shards,
    }
}

pub fn hash_encoded<T: Encode>(value: &T) -> Digest {
    Sha256::hash(&value.encode())
}

#[derive(Clone)]
pub enum ShardMessage {
    Initial {
        sender: PublicKey,
        key: BlockKey,
        commitment: ZodaCommitment,
        shard: ZodaShard,
        shard_index: u16,
    },
    ReShare {
        sender: PublicKey,
        key: BlockKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        reshard: ZodaReShard,
    },
}

impl ShardMessage {
    pub const fn key(&self) -> BlockKey {
        match self {
            Self::Initial { key, .. } => *key,
            Self::ReShare { key, .. } => *key,
        }
    }

    pub fn sender(&self) -> &PublicKey {
        match self {
            Self::Initial { sender, .. } => sender,
            Self::ReShare { sender, .. } => sender,
        }
    }

    pub const fn shard_index(&self) -> u16 {
        match self {
            Self::Initial { shard_index, .. } => *shard_index,
            Self::ReShare { shard_index, .. } => *shard_index,
        }
    }

    pub fn commitment(&self) -> &ZodaCommitment {
        match self {
            Self::Initial { commitment, .. } => commitment,
            Self::ReShare { commitment, .. } => commitment,
        }
    }
}
