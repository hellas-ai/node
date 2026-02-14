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
    pub commitment: ZodaCommitment,
    pub checking_data: Option<ZodaCheckingData>,
    pub checked_shards: Vec<ZodaCheckedShard>,
    pub buffered_reshards: VecDeque<BufferedReShare>,
    seen_shard_data: HashMap<u16, Digest>,
}

impl ReconstructionState {
    pub fn new(commitment: ZodaCommitment) -> Self {
        Self {
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
