use super::types::{ZodaCheckedShard, ZodaCheckingData, ZodaCommitment, ZodaReShard};
use commonware_cryptography::sha256::Digest;
use hellas_types::PublicKey;
use std::collections::{HashMap, VecDeque};

#[derive(Clone)]
pub struct BufferedReShare {
    pub sender: PublicKey,
    pub shard_index: u16,
    pub reshard: ZodaReShard,
    pub shard_hash: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuplicateStatus {
    New,
    Duplicate,
    Equivocation,
}

pub struct ReconstructionState {
    pub leader: PublicKey,
    pub commitment: ZodaCommitment,
    pub checking_data: Option<ZodaCheckingData>,
    pub checked_shards: Vec<ZodaCheckedShard>,
    pub buffered_reshards: VecDeque<BufferedReShare>,
    seen_shard_data: HashMap<u16, Digest>,
}

impl ReconstructionState {
    pub fn new(commitment: ZodaCommitment, leader: PublicKey) -> Self {
        Self {
            leader,
            commitment,
            checking_data: None,
            checked_shards: Vec::new(),
            buffered_reshards: VecDeque::new(),
            seen_shard_data: HashMap::new(),
        }
    }

    pub fn shard_status(&self, shard_index: u16, shard_hash: Digest) -> DuplicateStatus {
        match self.seen_shard_data.get(&shard_index) {
            None => DuplicateStatus::New,
            Some(existing) if *existing == shard_hash => DuplicateStatus::Duplicate,
            Some(_) => DuplicateStatus::Equivocation,
        }
    }

    pub fn record_shard(&mut self, shard_index: u16, shard_hash: Digest) {
        self.seen_shard_data.insert(shard_index, shard_hash);
    }

    pub fn buffer_reshare(&mut self, msg: BufferedReShare, max_buffered: usize) {
        if self.buffered_reshards.len() >= max_buffered {
            self.buffered_reshards.pop_front();
        }
        self.buffered_reshards.push_back(msg);
    }

    pub fn take_buffered_reshards(&mut self) -> Vec<BufferedReShare> {
        self.buffered_reshards.drain(..).collect()
    }

    pub fn has_minimum_shards(&self, minimum_shards: u16) -> bool {
        self.checked_shards.len() >= usize::from(minimum_shards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::{CodingImpl, coding_config, hash_encoded};
    use commonware_coding::Scheme as CodingScheme;
    use commonware_cryptography::{Hasher, Sha256, Signer, ed25519};
    use commonware_parallel::Sequential;
    use proptest::prelude::*;

    fn sample_commitment() -> ZodaCommitment {
        let config = coding_config(6);
        let payload = b"state-test-payload".as_slice();
        let (commitment, _) =
            CodingImpl::encode(&config, payload, &Sequential).expect("encode should succeed");
        commitment
    }

    fn sample_buffered_reshare(seed: u64, shard_index: u16) -> BufferedReShare {
        let config = coding_config(6);
        let payload = vec![u8::try_from(seed % 255).unwrap_or(0); 128];
        let (commitment, shards) =
            CodingImpl::encode(&config, payload.as_slice(), &Sequential).expect("encode");
        let (_, _, reshard) = CodingImpl::reshard(
            &config,
            &commitment,
            shard_index,
            shards[usize::from(shard_index)].clone(),
        )
        .expect("reshard");
        BufferedReShare {
            sender: ed25519::PrivateKey::from_seed(seed).public_key(),
            shard_index,
            shard_hash: hash_encoded(&reshard),
            reshard,
        }
    }

    proptest! {
        #[test]
        fn shard_status_detects_equivocation_prop(
            idx in any::<u16>(),
            first in prop::collection::vec(any::<u8>(), 1..64),
            second in prop::collection::vec(any::<u8>(), 1..64),
        ) {
            prop_assume!(first != second);
            let leader = ed25519::PrivateKey::from_seed(7).public_key();
            let mut state = ReconstructionState::new(sample_commitment(), leader);
            let first_hash = Sha256::hash(first.as_slice());
            let second_hash = Sha256::hash(second.as_slice());

            prop_assert_eq!(state.shard_status(idx, first_hash), DuplicateStatus::New);
            state.record_shard(idx, first_hash);
            prop_assert_eq!(state.shard_status(idx, first_hash), DuplicateStatus::Duplicate);
            prop_assert_eq!(state.shard_status(idx, second_hash), DuplicateStatus::Equivocation);
        }
    }

    #[test]
    fn buffer_reshare_drops_oldest_when_capacity_is_hit() {
        let leader = ed25519::PrivateKey::from_seed(11).public_key();
        let mut state = ReconstructionState::new(sample_commitment(), leader);

        state.buffer_reshare(sample_buffered_reshare(1, 0), 2);
        state.buffer_reshare(sample_buffered_reshare(2, 1), 2);
        state.buffer_reshare(sample_buffered_reshare(3, 2), 2);

        let buffered = state.take_buffered_reshards();
        assert_eq!(buffered.len(), 2);
        assert_eq!(buffered[0].shard_index, 1);
        assert_eq!(buffered[1].shard_index, 2);
    }
}
