use super::protocol::{
    BlockKey, ShardMessage, ZodaCheckedShard, ZodaCheckingData, ZodaCommitment, ZodaReShard,
};
use crate::gauged::GaugedIndexMap;
use commonware_cryptography::sha256::Digest;
use hellas_types::PublicKey;
use prometheus_client::metrics::gauge::Gauge;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::AtomicI64;

#[derive(Clone)]
struct BufferedReShare {
    sender: PublicKey,
    shard_index: u16,
    reshard: ZodaReShard,
    shard_hash: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DuplicateStatus {
    New,
    Duplicate,
    Equivocation,
}

pub(super) struct RecoveryState {
    leader: PublicKey,
    commitment: ZodaCommitment,
    checking_data: Option<ZodaCheckingData>,
    checked_shards: Vec<ZodaCheckedShard>,
    buffered_reshards: VecDeque<BufferedReShare>,
    seen_shard_data: HashMap<u16, Digest>,
}

impl RecoveryState {
    fn new(commitment: ZodaCommitment, leader: PublicKey) -> Self {
        Self {
            leader,
            commitment,
            checking_data: None,
            checked_shards: Vec::new(),
            buffered_reshards: VecDeque::new(),
            seen_shard_data: HashMap::new(),
        }
    }

    fn shard_status(&self, shard_index: u16, shard_hash: Digest) -> DuplicateStatus {
        match self.seen_shard_data.get(&shard_index) {
            None => DuplicateStatus::New,
            Some(existing) if *existing == shard_hash => DuplicateStatus::Duplicate,
            Some(_) => DuplicateStatus::Equivocation,
        }
    }

    fn record_shard(&mut self, shard_index: u16, shard_hash: Digest) {
        self.seen_shard_data.insert(shard_index, shard_hash);
    }

    fn buffer_reshare(&mut self, msg: BufferedReShare, max_buffered: usize) {
        if self.buffered_reshards.len() >= max_buffered {
            self.buffered_reshards.pop_front();
        }
        self.buffered_reshards.push_back(msg);
    }

    fn take_buffered_reshards(&mut self) -> Vec<BufferedReShare> {
        self.buffered_reshards.drain(..).collect()
    }

    fn has_minimum_shards(&self, minimum_shards: u16) -> bool {
        self.checked_shards.len() >= usize::from(minimum_shards)
    }
}

#[cfg(test)]
impl RecoveryState {
    pub(super) fn buffered_reshards_len(&self) -> usize {
        self.buffered_reshards.len()
    }

    pub(super) fn commitment(&self) -> ZodaCommitment {
        self.commitment
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

pub(super) struct ReadyToCheckTask {
    pub(super) key: BlockKey,
    pub(super) commitment: ZodaCommitment,
    pub(super) checking_data: ZodaCheckingData,
    pub(super) shard_index: u16,
    pub(super) shard_hash: Digest,
    pub(super) reshard: ZodaReShard,
}

pub(super) struct DecodeCandidate {
    pub(super) commitment: ZodaCommitment,
    pub(super) checking_data: ZodaCheckingData,
    pub(super) checked_shards: Vec<ZodaCheckedShard>,
}

/// Per-tier capacity limits. Each tier evicts independently so one tier
/// cannot starve another under adversarial or high-latency conditions.
#[derive(Clone, Copy)]
pub(super) struct RecoveryLimits {
    pub(super) max_buffered_keys: usize,
    pub(super) max_announced_keys: usize,
    pub(super) max_recovering: usize,
    pub(super) max_buffered_reshards: usize,
    pub(super) max_buffered_messages: usize,
}

pub(super) enum RecoveryInput {
    AnnounceLeader {
        key: BlockKey,
        leader: PublicKey,
    },
    IngressMessage {
        message: Box<ShardMessage>,
    },
    ObserveInitial {
        key: BlockKey,
        sender: PublicKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        shard_hash: Digest,
        leader: PublicKey,
    },
    ApplyInitialValidated {
        key: BlockKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        shard_hash: Digest,
        checking_data: ZodaCheckingData,
        checked_shard: ZodaCheckedShard,
    },
    ObserveReShare {
        key: BlockKey,
        sender: PublicKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        shard_hash: Digest,
        reshard: ZodaReShard,
        leader: PublicKey,
    },
    ApplyCheckedReShare {
        key: BlockKey,
        shard_index: u16,
        shard_hash: Digest,
        checked_shard: ZodaCheckedShard,
    },
    TryTakeDecode {
        key: BlockKey,
        minimum_shards: u16,
    },
}

pub(super) enum RecoveryOutput {
    IngressReady {
        message: Box<ShardMessage>,
        expected_leader: PublicKey,
    },
    Buffered,
    Drained(Vec<ShardMessage>),
    Evicted {
        key: BlockKey,
    },
    InitialAccepted,
    ReShareBuffered,
    ReadyToCheck(ReadyToCheckTask),
    ReadyToDecode(DecodeCandidate),
    CommitmentMismatch {
        key: BlockKey,
        shard_index: u16,
        sender: PublicKey,
        source: &'static str,
    },
    DuplicateShard,
    Equivocation {
        key: BlockKey,
        shard_index: u16,
        sender: PublicKey,
        source: &'static str,
    },
}

// ---------------------------------------------------------------------------
// RecoveryMachine — three maps, one key per map, independent eviction
// ---------------------------------------------------------------------------

pub(super) struct RecoveryMachine {
    /// Shard messages that arrived before the leader was announced.
    buffered: GaugedIndexMap<BlockKey, VecDeque<ShardMessage>>,
    /// Leader announced by consensus; no shard processing started.
    announced: GaugedIndexMap<BlockKey, PublicKey>,
    /// Active shard reconstruction.
    recovering: GaugedIndexMap<BlockKey, RecoveryState>,
    limits: RecoveryLimits,
}

impl RecoveryMachine {
    pub(super) fn new(
        limits: RecoveryLimits,
        buffered_gauge: Gauge<i64, AtomicI64>,
        announced_gauge: Gauge<i64, AtomicI64>,
        recovering_gauge: Gauge<i64, AtomicI64>,
    ) -> Self {
        Self {
            buffered: GaugedIndexMap::new(buffered_gauge),
            announced: GaugedIndexMap::new(announced_gauge),
            recovering: GaugedIndexMap::new(recovering_gauge),
            limits,
        }
    }

    pub(super) fn step(&mut self, input: RecoveryInput) -> Vec<RecoveryOutput> {
        match input {
            RecoveryInput::AnnounceLeader { key, leader } => {
                let mut outputs = Vec::new();

                if self.recovering.contains_key(&key) {
                    return outputs;
                }

                if let Some(messages) = self.buffered.shift_remove(&key) {
                    self.announced.insert(key, leader);
                    outputs.push(RecoveryOutput::Drained(messages.into_iter().collect()));
                } else if !self.announced.contains_key(&key) {
                    self.announced.insert(key, leader);
                }

                for (oldest, _) in self.announced.enforce_capacity(self.limits.max_announced_keys) {
                    outputs.push(RecoveryOutput::Evicted { key: oldest });
                }

                outputs
            }
            RecoveryInput::IngressMessage { message } => {
                let message = *message;
                let Some(key) = message.key() else {
                    return Vec::new();
                };

                // Check announced and recovering for expected leader.
                if let Some(leader) = self.announced.get(&key).cloned() {
                    return vec![RecoveryOutput::IngressReady {
                        message: Box::new(message),
                        expected_leader: leader,
                    }];
                }
                if let Some(recovery) = self.recovering.get(&key) {
                    return vec![RecoveryOutput::IngressReady {
                        message: Box::new(message),
                        expected_leader: recovery.leader.clone(),
                    }];
                }

                // No leader known — buffer.
                let queue = self.buffered.entry(key).or_default();
                if queue.len() >= self.limits.max_buffered_messages {
                    queue.pop_front();
                }
                queue.push_back(message);

                self.buffered.enforce_capacity(self.limits.max_buffered_keys);

                vec![RecoveryOutput::Buffered]
            }
            RecoveryInput::ObserveInitial {
                key,
                sender,
                commitment,
                shard_index,
                shard_hash,
                leader,
            } => {
                let mut outputs = self.ensure_recovering(key, commitment, leader);
                let Some(recovery) = self.recovering.get_mut(&key) else {
                    return outputs;
                };

                if recovery.commitment != commitment {
                    if recovery.checking_data.is_none() && recovery.checked_shards.is_empty() {
                        recovery.commitment = commitment;
                    } else {
                        outputs.push(RecoveryOutput::CommitmentMismatch {
                            key,
                            shard_index,
                            sender,
                            source: "initial",
                        });
                        return outputs;
                    }
                }

                match recovery.shard_status(shard_index, shard_hash) {
                    DuplicateStatus::New => outputs.push(RecoveryOutput::InitialAccepted),
                    DuplicateStatus::Duplicate => outputs.push(RecoveryOutput::DuplicateShard),
                    DuplicateStatus::Equivocation => outputs.push(RecoveryOutput::Equivocation {
                        key,
                        shard_index,
                        sender,
                        source: "initial",
                    }),
                }

                outputs
            }
            RecoveryInput::ApplyInitialValidated {
                key,
                commitment,
                shard_index,
                shard_hash,
                checking_data,
                checked_shard,
            } => {
                let Some(recovery) = self.recovering.get_mut(&key) else {
                    return Vec::new();
                };

                let leader = recovery.leader.clone();
                if recovery.commitment != commitment {
                    return vec![RecoveryOutput::CommitmentMismatch {
                        key,
                        shard_index,
                        sender: leader,
                        source: "initial",
                    }];
                }

                recovery.record_shard(shard_index, shard_hash);
                recovery.checking_data = Some(checking_data.clone());
                recovery.checked_shards.push(checked_shard);

                let commitment = recovery.commitment;
                let buffered = recovery.take_buffered_reshards();
                let mut outputs = Vec::new();
                for buffered in buffered {
                    match recovery.shard_status(buffered.shard_index, buffered.shard_hash) {
                        DuplicateStatus::New => {
                            outputs.push(RecoveryOutput::ReadyToCheck(ReadyToCheckTask {
                                key,
                                commitment,
                                checking_data: checking_data.clone(),
                                shard_index: buffered.shard_index,
                                shard_hash: buffered.shard_hash,
                                reshard: buffered.reshard,
                            }))
                        }
                        DuplicateStatus::Duplicate => outputs.push(RecoveryOutput::DuplicateShard),
                        DuplicateStatus::Equivocation => {
                            outputs.push(RecoveryOutput::Equivocation {
                                key,
                                shard_index: buffered.shard_index,
                                sender: buffered.sender,
                                source: "buffered_reshare",
                            })
                        }
                    }
                }
                outputs
            }
            RecoveryInput::ObserveReShare {
                key,
                sender,
                commitment,
                shard_index,
                shard_hash,
                reshard,
                leader,
            } => {
                let mut outputs = self.ensure_recovering(key, commitment, leader);
                let Some(recovery) = self.recovering.get_mut(&key) else {
                    return outputs;
                };

                if recovery.commitment != commitment {
                    outputs.push(RecoveryOutput::CommitmentMismatch {
                        key,
                        shard_index,
                        sender,
                        source: "reshare",
                    });
                    return outputs;
                }

                match recovery.shard_status(shard_index, shard_hash) {
                    DuplicateStatus::Duplicate => outputs.push(RecoveryOutput::DuplicateShard),
                    DuplicateStatus::Equivocation => {
                        outputs.push(RecoveryOutput::Equivocation {
                            key,
                            shard_index,
                            sender,
                            source: "reshare",
                        });
                    }
                    DuplicateStatus::New => {
                        if let Some(checking_data) = recovery.checking_data.clone() {
                            outputs.push(RecoveryOutput::ReadyToCheck(ReadyToCheckTask {
                                key,
                                commitment,
                                checking_data,
                                shard_index,
                                shard_hash,
                                reshard,
                            }));
                        } else {
                            recovery.buffer_reshare(
                                BufferedReShare {
                                    sender,
                                    shard_index,
                                    reshard,
                                    shard_hash,
                                },
                                self.limits.max_buffered_reshards,
                            );
                            outputs.push(RecoveryOutput::ReShareBuffered);
                        }
                    }
                }

                outputs
            }
            RecoveryInput::ApplyCheckedReShare {
                key,
                shard_index,
                shard_hash,
                checked_shard,
            } => {
                let Some(recovery) = self.recovering.get_mut(&key) else {
                    return Vec::new();
                };
                if matches!(
                    recovery.shard_status(shard_index, shard_hash),
                    DuplicateStatus::New
                ) {
                    recovery.record_shard(shard_index, shard_hash);
                    recovery.checked_shards.push(checked_shard);
                }
                Vec::new()
            }
            RecoveryInput::TryTakeDecode {
                key,
                minimum_shards,
            } => {
                let decode_ready = self.recovering.get(&key).is_some_and(|recovery| {
                    recovery.has_minimum_shards(minimum_shards) && recovery.checking_data.is_some()
                });
                if !decode_ready {
                    return Vec::new();
                }

                let Some(mut recovery) = self.recovering.shift_remove(&key) else {
                    return Vec::new();
                };
                let Some(checking_data) = recovery.checking_data.take() else {
                    self.recovering.insert(key, recovery);
                    return Vec::new();
                };

                vec![RecoveryOutput::ReadyToDecode(DecodeCandidate {
                    commitment: recovery.commitment,
                    checking_data,
                    checked_shards: recovery.checked_shards,
                })]
            }
        }
    }

    // ---- Helpers ----

    /// Ensure a `recovering` entry exists for `key`. Promotes from
    /// `announced` if present. Evicts oldest recovering entry if at
    /// capacity.
    fn ensure_recovering(
        &mut self,
        key: BlockKey,
        commitment: ZodaCommitment,
        leader: PublicKey,
    ) -> Vec<RecoveryOutput> {
        if self.recovering.contains_key(&key) {
            return Vec::new();
        }

        // Promote: remove from announced or buffered (key lives in one map).
        self.announced.shift_remove(&key);
        self.buffered.shift_remove(&key);

        // Insert then evict so the new entry survives (it's at the tail).
        self.recovering
            .insert(key, RecoveryState::new(commitment, leader));
        let mut outputs = Vec::new();
        for (oldest, _) in self.recovering.enforce_capacity(self.limits.max_recovering) {
            outputs.push(RecoveryOutput::Evicted { key: oldest });
        }
        outputs
    }
}

// ---- Test support ----

#[cfg(test)]
impl RecoveryMachine {
    pub(super) fn with_limits(limits: RecoveryLimits) -> Self {
        Self::new(limits, Default::default(), Default::default(), Default::default())
    }

    pub(super) fn inspect<R>(
        &self,
        f: impl FnOnce(
            &indexmap::IndexMap<BlockKey, RecoveryState>,
            &indexmap::IndexMap<BlockKey, PublicKey>,
            &indexmap::IndexMap<BlockKey, VecDeque<ShardMessage>>,
        ) -> R,
    ) -> R {
        f(&*self.recovering, &*self.announced, &*self.buffered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::protocol::{CodingImpl, coding_config, hash_encoded};
    use commonware_coding::Scheme as CodingScheme;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::{Hasher, Sha256, Signer, ed25519};
    use commonware_parallel::Sequential;
    use proptest::prelude::*;

    fn sample_commitment() -> ZodaCommitment {
        let config = coding_config(6);
        let payload = b"recovery-test-payload".as_slice();
        let (commitment, _) =
            CodingImpl::encode(&config, payload, &Sequential).expect("encode should succeed");
        commitment
    }

    fn sample_reshare(
        seed: u64,
        shard_index: u16,
    ) -> (ZodaCommitment, ZodaReShard, Digest, PublicKey) {
        let config = coding_config(6);
        let payload = vec![u8::try_from(seed % 251).unwrap_or(0); 96];
        let (commitment, shards) =
            CodingImpl::encode(&config, payload.as_slice(), &Sequential).expect("encode");
        let (_, _, reshard) = CodingImpl::reshard(
            &config,
            &commitment,
            shard_index,
            shards[usize::from(shard_index)].clone(),
        )
        .expect("reshard");
        let shard_hash = hash_encoded(&reshard);
        let sender = ed25519::PrivateKey::from_seed(seed.saturating_add(1000)).public_key();
        (commitment, reshard, shard_hash, sender)
    }

    fn key_for_view(view: u16) -> BlockKey {
        BlockKey::new(
            Round::new(Epoch::new(1), View::new(u64::from(view))),
            Sha256::hash(&view.to_le_bytes()),
        )
    }

    proptest! {
        #[test]
        fn recovery_machine_step_preserves_bounds(
            events in prop::collection::vec((0u8..3u8, any::<u16>(), any::<u64>(), 0u16..6u16), 1..120)
        ) {
            const MAX_BUFFERED_MESSAGES: usize = 4;
            const MAX_BUFFERED_KEYS: usize = 6;
            const MAX_ANNOUNCED_KEYS: usize = 8;
            const MAX_RECOVERING: usize = 5;
            const MAX_BUFFERED_RESHARDS: usize = 3;

            let mut machine = RecoveryMachine::with_limits(RecoveryLimits {
                    max_buffered_keys: MAX_BUFFERED_KEYS,
                    max_announced_keys: MAX_ANNOUNCED_KEYS,
                    max_recovering: MAX_RECOVERING,
                    max_buffered_reshards: MAX_BUFFERED_RESHARDS,
                    max_buffered_messages: MAX_BUFFERED_MESSAGES,
            });
            let leader = ed25519::PrivateKey::from_seed(42).public_key();

            for (kind, view, seed, shard_index_raw) in events {
                let key = key_for_view(view);
                let shard_index = shard_index_raw % 6;
                let (commitment, reshard, shard_hash, sender) = sample_reshare(seed, shard_index);

                match kind % 3 {
                    0 => {
                        let message = ShardMessage::reshare(
                            &sender,
                            key,
                            commitment,
                            shard_index,
                            reshard,
                        );
                        let _ = machine.step(RecoveryInput::IngressMessage {
                            message: Box::new(message),
                        });
                    }
                    1 => {
                        let _ = machine.step(RecoveryInput::AnnounceLeader {
                            key,
                            leader: leader.clone(),
                        });
                    }
                    _ => {
                        let _ = machine.step(RecoveryInput::ObserveReShare {
                            key,
                            sender,
                            commitment,
                            shard_index,
                            shard_hash,
                            reshard,
                            leader: leader.clone(),
                        });
                    }
                }

                let (
                    buffered_key_len,
                    buffered_max_messages,
                    recovering_len,
                    max_reshards,
                    announced_len,
                ) = machine.inspect(|recovering, announced, buffered| {
                    (
                        buffered.len(),
                        buffered
                            .values()
                            .map(VecDeque::len)
                            .max()
                            .unwrap_or(0),
                        recovering.len(),
                        recovering
                            .values()
                            .map(|r| r.buffered_reshards.len())
                            .max()
                            .unwrap_or(0),
                        announced.len(),
                    )
                });

                prop_assert!(buffered_key_len <= MAX_BUFFERED_KEYS);
                prop_assert!(buffered_max_messages <= MAX_BUFFERED_MESSAGES);
                prop_assert!(recovering_len <= MAX_RECOVERING);
                prop_assert!(announced_len <= MAX_ANNOUNCED_KEYS);
                prop_assert!(max_reshards <= MAX_BUFFERED_RESHARDS);
            }
        }

        #[test]
        fn buffer_reshare_keeps_latest_entries(
            max_buffered in 1usize..6usize,
            entries in prop::collection::vec((any::<u64>(), 0u16..6u16), 1..40),
        ) {
            let leader = ed25519::PrivateKey::from_seed(11).public_key();
            let mut recovery = RecoveryState::new(sample_commitment(), leader);
            let (_template_commitment, template_reshard, _template_hash, _template_sender) =
                sample_reshare(7, 0);
            let mut expected = VecDeque::new();

            for (seed, shard_index) in entries {
                let shard_hash = Sha256::hash(&seed.to_le_bytes());
                recovery.buffer_reshare(
                    BufferedReShare {
                        sender: ed25519::PrivateKey::from_seed(seed).public_key(),
                        shard_index,
                        reshard: template_reshard.clone(),
                        shard_hash,
                    },
                    max_buffered,
                );

                if expected.len() >= max_buffered {
                    expected.pop_front();
                }
                expected.push_back((shard_index, shard_hash));
            }

            let buffered = recovery.take_buffered_reshards();
            prop_assert_eq!(buffered.len(), expected.len());
            for (actual, (expected_index, expected_hash)) in buffered.iter().zip(expected.iter()) {
                prop_assert_eq!(actual.shard_index, *expected_index);
                prop_assert_eq!(actual.shard_hash, *expected_hash);
            }
        }
    }

    #[test_log::test]
    fn duplicate_checked_reshare_does_not_count_toward_decode_threshold() {
        let validators = 11u16;
        let config = coding_config(validators);
        assert_eq!(config.minimum_shards, 3);

        let payload = b"duplicate-checked-reshare-regression";
        let (commitment, shards) = CodingImpl::encode(&config, payload.as_slice(), &Sequential)
            .expect("encode should succeed");
        let key = BlockKey::new(
            Round::new(Epoch::new(7), View::new(1)),
            Sha256::hash(payload),
        );

        let leader = ed25519::PrivateKey::from_seed(1).public_key();
        let helper = ed25519::PrivateKey::from_seed(2).public_key();
        let my_index = 1u16;
        let helper_index = 2u16;

        let mut machine = RecoveryMachine::with_limits(RecoveryLimits {
            max_buffered_keys: 256,
            max_announced_keys: 1024,
            max_recovering: 64,
            max_buffered_reshards: 32,
            max_buffered_messages: 64,
        });
        let initial_hash = hash_encoded(&shards[usize::from(my_index)]);
        let outputs = machine.step(RecoveryInput::ObserveInitial {
            key,
            sender: leader.clone(),
            commitment,
            shard_index: my_index,
            shard_hash: initial_hash,
            leader: leader.clone(),
        });
        assert!(
            outputs
                .iter()
                .any(|output| matches!(output, RecoveryOutput::InitialAccepted))
        );

        let (checking_data, checked_shard, _reshard) = CodingImpl::reshard(
            &config,
            &commitment,
            my_index,
            shards[usize::from(my_index)].clone(),
        )
        .expect("reshard for initial");
        let _ = machine.step(RecoveryInput::ApplyInitialValidated {
            key,
            commitment,
            shard_index: my_index,
            shard_hash: initial_hash,
            checking_data: checking_data.clone(),
            checked_shard,
        });

        let (_, _, helper_reshard) = CodingImpl::reshard(
            &config,
            &commitment,
            helper_index,
            shards[usize::from(helper_index)].clone(),
        )
        .expect("reshard for helper");
        let helper_hash = hash_encoded(&helper_reshard);
        for _ in 0..2 {
            let outputs = machine.step(RecoveryInput::ObserveReShare {
                key,
                sender: helper.clone(),
                commitment,
                shard_index: helper_index,
                shard_hash: helper_hash,
                reshard: helper_reshard.clone(),
                leader: leader.clone(),
            });
            assert!(
                outputs
                    .iter()
                    .any(|output| matches!(output, RecoveryOutput::ReadyToCheck(_)))
            );
        }

        for _ in 0..2 {
            let helper_checked = CodingImpl::check(
                &config,
                &commitment,
                &checking_data,
                helper_index,
                helper_reshard.clone(),
            )
            .expect("helper check should succeed");
            let _ = machine.step(RecoveryInput::ApplyCheckedReShare {
                key,
                shard_index: helper_index,
                shard_hash: helper_hash,
                checked_shard: helper_checked,
            });
        }

        let outputs = machine.step(RecoveryInput::TryTakeDecode {
            key,
            minimum_shards: config.minimum_shards,
        });
        assert!(
            !outputs
                .iter()
                .any(|output| matches!(output, RecoveryOutput::ReadyToDecode(_))),
            "duplicate checked reshare must not satisfy decode threshold",
        );
    }
}
