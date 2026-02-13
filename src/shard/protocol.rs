use super::codec::WireShardMessage;
use commonware_codec::Encode;
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme, Zoda};
use commonware_consensus::types::Round;
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_utils::{Faults, N5f1};
use hellas_types::PublicKey;

pub(crate) type CodingImpl = Zoda<Sha256>;
pub(crate) type ZodaShard = <CodingImpl as CodingScheme>::Shard;
pub(crate) type ZodaReShard = <CodingImpl as CodingScheme>::ReShard;
pub(crate) type ZodaCheckedShard = <CodingImpl as CodingScheme>::CheckedShard;
pub(crate) type ZodaCheckingData = <CodingImpl as CodingScheme>::CheckingData;
pub(crate) type ZodaCommitment = <CodingImpl as CodingScheme>::Commitment;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct BlockKey {
    pub round: Round,
    pub digest: Digest,
}

impl BlockKey {
    pub(crate) const fn new(round: Round, digest: Digest) -> Self {
        Self { round, digest }
    }
}

pub(crate) fn coding_config(validators: u16) -> CodingConfig {
    if validators == 0 {
        warn!(
            "validator set was empty; defaulting coding config to minimum_shards=1 extra_shards=0"
        );
        return CodingConfig {
            minimum_shards: 1,
            extra_shards: 0,
        };
    }
    // N5f1 means the configuration expects n >= 5f + 1.
    // `max_faults` returns the largest f for the current validator count.
    let faults = N5f1::max_faults(validators);
    let minimum_shards = match u16::try_from(faults.saturating_add(1)) {
        Ok(value) => value.clamp(1, validators),
        Err(_) => {
            warn!(
                faults,
                validators,
                "fault count overflowed u16; clamping minimum shards to validator count"
            );
            validators
        }
    };
    let extra_shards = validators.saturating_sub(minimum_shards);
    CodingConfig {
        minimum_shards,
        extra_shards,
    }
}

pub(crate) fn hash_encoded<T: Encode>(value: &T) -> Digest {
    Sha256::hash(&value.encode())
}

/// Internal shard message after transport authentication.
#[derive(Clone)]
pub(crate) struct ShardMessage {
    pub(crate) sender: PublicKey,
    pub(crate) body: WireShardMessage,
}

impl ShardMessage {
    pub(crate) fn initial(
        sender: &PublicKey,
        key: BlockKey,
        commitment: ZodaCommitment,
        shard: ZodaShard,
        shard_index: u16,
    ) -> Self {
        Self {
            sender: sender.clone(),
            body: WireShardMessage::Initial {
                key,
                commitment,
                shard,
                shard_index,
            },
        }
    }

    pub(crate) fn reshare(
        sender: &PublicKey,
        key: BlockKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        reshard: ZodaReShard,
    ) -> Self {
        Self {
            sender: sender.clone(),
            body: WireShardMessage::ReShare {
                key,
                commitment,
                shard_index,
                reshard,
            },
        }
    }

    pub(crate) const fn key(&self) -> BlockKey {
        match &self.body {
            WireShardMessage::Initial { key, .. } => *key,
            WireShardMessage::ReShare { key, .. } => *key,
        }
    }

    pub(crate) fn sender(&self) -> &PublicKey {
        &self.sender
    }

    pub(crate) fn to_wire(&self) -> WireShardMessage {
        self.body.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_coding::Scheme as CodingScheme;
    use commonware_parallel::Sequential;

    fn sample_artifacts(
        payload: &[u8],
    ) -> (commonware_coding::Config, ZodaCommitment, Vec<ZodaShard>) {
        let config = coding_config(6);
        let (commitment, shards) = CodingImpl::encode(&config, payload, &Sequential).unwrap();
        (config, commitment, shards)
    }

    #[test_log::test]
    fn commitment_mismatch_is_rejected() {
        let (cfg_a, commitment_a, _) = sample_artifacts(b"payload-a");
        let (_, commitment_b, shards_b) = sample_artifacts(b"payload-b");
        assert_ne!(commitment_a, commitment_b);

        let result = CodingImpl::reshard(&cfg_a, &commitment_a, 0, shards_b[0].clone());
        assert!(result.is_err());
    }

    #[test_log::test]
    fn coding_config_boundary_values() {
        let zero = coding_config(0);
        assert_eq!(zero.minimum_shards, 1);
        assert_eq!(zero.extra_shards, 0);

        let one = coding_config(1);
        assert_eq!(one.minimum_shards, 1);
        assert_eq!(one.extra_shards, 0);

        let six = coding_config(6);
        assert_eq!(six.minimum_shards, 2);
        assert_eq!(six.extra_shards, 4);

        for validators in 1u16..=20u16 {
            let cfg = coding_config(validators);
            assert_eq!(
                cfg.minimum_shards.saturating_add(cfg.extra_shards),
                validators
            );
            assert!(cfg.minimum_shards >= 1);
        }
    }
}
