use super::codec::WireShardMessage;
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

/// Internal shard message after transport authentication.
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

    pub fn to_wire(&self) -> WireShardMessage {
        match self {
            Self::Initial {
                key,
                commitment,
                shard,
                shard_index,
                ..
            } => WireShardMessage::Initial {
                key: *key,
                commitment: *commitment,
                shard: shard.clone(),
                shard_index: *shard_index,
            },
            Self::ReShare {
                key,
                commitment,
                shard_index,
                reshard,
                ..
            } => WireShardMessage::ReShare {
                key: *key,
                commitment: *commitment,
                shard_index: *shard_index,
                reshard: reshard.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_coding::Scheme as CodingScheme;
    use commonware_parallel::Sequential;
    use proptest::prelude::*;

    fn sample_artifacts(
        payload: &[u8],
    ) -> (commonware_coding::Config, ZodaCommitment, Vec<ZodaShard>) {
        let config = coding_config(6);
        let (commitment, shards) = CodingImpl::encode(&config, payload, &Sequential).unwrap();
        (config, commitment, shards)
    }

    proptest! {
        #[test]
        fn zoda_roundtrip_prop(
            payload in prop::collection::vec(any::<u8>(), 50..512),
            first in 0u16..6u16,
            second in 0u16..6u16,
        ) {
            prop_assume!(first != second);
            let config = coding_config(6);
            let (commitment, shards) = CodingImpl::encode(&config, payload.as_slice(), &Sequential).unwrap();

            let (checking_data, checked_first, _) =
                CodingImpl::reshard(&config, &commitment, first, shards[first as usize].clone()).unwrap();
            let (_, _, reshard_second) =
                CodingImpl::reshard(&config, &commitment, second, shards[second as usize].clone()).unwrap();
            let checked_second =
                CodingImpl::check(&config, &commitment, &checking_data, second, reshard_second).unwrap();

            let checked = vec![checked_first, checked_second];
            let decoded = CodingImpl::decode(&config, &commitment, checking_data, &checked, &Sequential).unwrap();
            prop_assert_eq!(Sha256::hash(decoded.as_slice()), Sha256::hash(payload.as_slice()));
        }

    }

    #[test]
    fn commitment_mismatch_is_rejected() {
        let (cfg_a, commitment_a, _) = sample_artifacts(b"payload-a");
        let (_, commitment_b, shards_b) = sample_artifacts(b"payload-b");
        assert_ne!(commitment_a, commitment_b);

        let result = CodingImpl::reshard(&cfg_a, &commitment_a, 0, shards_b[0].clone());
        assert!(result.is_err());
    }
}
