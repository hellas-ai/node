use super::protocol::{
    BlockKey, ShardMessage, ZodaCheckedShard, ZodaCheckingData, ZodaCommitment, ZodaReShard,
};
use commonware_cryptography::sha256::Digest;
use hellas_types::PublicKey;
use indexmap::IndexMap;
use std::collections::{HashMap, VecDeque};

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

#[derive(Clone, Copy)]
pub(super) struct RecoveryLimits {
    pub(super) max_known_keys: usize,
    pub(super) max_recovery_entries: usize,
    pub(super) max_buffered_reshards: usize,
    pub(super) max_pre_leader_messages: usize,
    pub(super) max_pre_leader_keys: usize,
}

pub(super) enum RecoveryInput {
    NoteKnownKey {
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
    BufferedPreLeader,
    DrainedPreLeader(Vec<ShardMessage>),
    Evicted {
        key: BlockKey,
    },
    KnownKeyEvicted {
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

pub(super) struct RecoveryMachine {
    recovery: IndexMap<BlockKey, RecoveryState>,
    known_leaders: IndexMap<BlockKey, PublicKey>,
    pre_leader_buffer: IndexMap<BlockKey, VecDeque<ShardMessage>>,
    limits: RecoveryLimits,
}

impl RecoveryMachine {
    pub(super) fn new(limits: RecoveryLimits) -> Self {
        Self {
            recovery: IndexMap::new(),
            known_leaders: IndexMap::new(),
            pre_leader_buffer: IndexMap::new(),
            limits,
        }
    }

    pub(super) fn step(&mut self, input: RecoveryInput) -> Vec<RecoveryOutput> {
        match input {
            RecoveryInput::NoteKnownKey { key, leader } => {
                self.known_leaders.insert(key, leader);
                let mut outputs = Vec::new();
                if let Some(drained) = self.pre_leader_buffer.shift_remove(&key) {
                    outputs.push(RecoveryOutput::DrainedPreLeader(
                        drained.into_iter().collect(),
                    ));
                }
                outputs.extend(self.evict_known_keys());
                outputs
            }
            RecoveryInput::IngressMessage { message } => {
                let message = *message;
                let Some(key) = message.key() else {
                    return Vec::new();
                };
                if !self.has_known_or_recovery(&key) {
                    self.buffer_pre_leader_message(key, message);
                    return vec![RecoveryOutput::BufferedPreLeader];
                }

                let Some(expected_leader) = self.expected_leader(key) else {
                    self.buffer_pre_leader_message(key, message);
                    return vec![RecoveryOutput::BufferedPreLeader];
                };

                vec![RecoveryOutput::IngressReady {
                    message: Box::new(message),
                    expected_leader,
                }]
            }
            RecoveryInput::ObserveInitial {
                key,
                sender,
                commitment,
                shard_index,
                shard_hash,
                leader,
            } => {
                let mut outputs = self.ensure_recovery_state(key, commitment, leader);
                let Some(recovery) = self.recovery.get_mut(&key) else {
                    return outputs;
                };

                if recovery.commitment != commitment {
                    // Initial shard may arrive after a re-share path seeded this entry with a
                    // commitment but before any checking data exists. Allow replacing that
                    // provisional commitment until validation has materially progressed.
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
                let Some(recovery) = self.recovery.get_mut(&key) else {
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
                let mut outputs = self.ensure_recovery_state(key, commitment, leader);
                let Some(recovery) = self.recovery.get_mut(&key) else {
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
                let Some(recovery) = self.recovery.get_mut(&key) else {
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
                let decode_ready = self.recovery.get(&key).is_some_and(|recovery| {
                    recovery.has_minimum_shards(minimum_shards) && recovery.checking_data.is_some()
                });
                if !decode_ready {
                    return Vec::new();
                }

                let Some(mut recovery) = self.recovery.shift_remove(&key) else {
                    return Vec::new();
                };
                let Some(checking_data) = recovery.checking_data.take() else {
                    self.recovery.insert(key, recovery);
                    return Vec::new();
                };

                self.pre_leader_buffer.shift_remove(&key);
                self.known_leaders.shift_remove(&key);
                vec![RecoveryOutput::ReadyToDecode(DecodeCandidate {
                    commitment: recovery.commitment,
                    checking_data,
                    checked_shards: recovery.checked_shards,
                })]
            }
        }
    }

    fn has_known_or_recovery(&self, key: &BlockKey) -> bool {
        self.known_leaders.contains_key(key) || self.recovery.contains_key(key)
    }

    fn expected_leader(&self, key: BlockKey) -> Option<PublicKey> {
        self.known_leaders.get(&key).cloned().or_else(|| {
            self.recovery
                .get(&key)
                .map(|recovery| recovery.leader.clone())
        })
    }

    fn ensure_recovery_state(
        &mut self,
        key: BlockKey,
        commitment: ZodaCommitment,
        leader: PublicKey,
    ) -> Vec<RecoveryOutput> {
        if self.recovery.contains_key(&key) {
            return Vec::new();
        }

        let mut outputs = Vec::new();

        // Capacity-based FIFO eviction. The effective staleness window
        // self-tunes: it equals max_recovery_entries / view_rate.
        while self.recovery.len() >= self.limits.max_recovery_entries {
            let Some((oldest, _state)) = self.recovery.shift_remove_index(0) else {
                break;
            };
            self.pre_leader_buffer.shift_remove(&oldest);
            self.known_leaders.shift_remove(&oldest);
            outputs.push(RecoveryOutput::Evicted { key: oldest });
        }

        self.recovery
            .insert(key, RecoveryState::new(commitment, leader));
        outputs
    }

    fn buffer_pre_leader_message(&mut self, key: BlockKey, message: ShardMessage) {
        let queue = self.pre_leader_buffer.entry(key).or_default();
        if queue.len() >= self.limits.max_pre_leader_messages {
            queue.pop_front();
        }
        queue.push_back(message);

        while self.pre_leader_buffer.len() > self.limits.max_pre_leader_keys {
            let Some((_oldest, _queue)) = self.pre_leader_buffer.shift_remove_index(0) else {
                break;
            };
        }
    }

    fn evict_known_keys(&mut self) -> Vec<RecoveryOutput> {
        let mut outputs = Vec::new();
        while self.known_leaders.len() > self.limits.max_known_keys {
            let Some((oldest, _leader)) = self.known_leaders.shift_remove_index(0) else {
                break;
            };
            self.pre_leader_buffer.shift_remove(&oldest);
            if self.recovery.shift_remove(&oldest).is_some() {
                outputs.push(RecoveryOutput::KnownKeyEvicted { key: oldest });
            }
        }
        outputs
    }
}

impl RecoveryMachine {
    pub(crate) fn active_count(&self) -> usize {
        self.recovery.len()
    }

    pub(crate) fn known_keys_count(&self) -> usize {
        self.known_leaders.len()
    }

    pub(crate) fn pre_leader_keys_count(&self) -> usize {
        self.pre_leader_buffer.len()
    }
}

#[cfg(test)]
impl RecoveryMachine {
    pub(super) fn inspect<R>(
        &self,
        f: impl FnOnce(
            &IndexMap<BlockKey, RecoveryState>,
            &IndexMap<BlockKey, PublicKey>,
            &IndexMap<BlockKey, VecDeque<ShardMessage>>,
        ) -> R,
    ) -> R {
        f(&self.recovery, &self.known_leaders, &self.pre_leader_buffer)
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
            const MAX_PRE_LEADER_MESSAGES: usize = 4;
            const MAX_PRE_LEADER_KEYS: usize = 6;
            const MAX_KNOWN_KEYS: usize = 8;
            const MAX_RECOVERY_ENTRIES: usize = 5;
            const MAX_BUFFERED_RESHARDS: usize = 3;

            let mut machine = RecoveryMachine::new(RecoveryLimits {
                max_known_keys: MAX_KNOWN_KEYS,
                max_recovery_entries: MAX_RECOVERY_ENTRIES,
                max_buffered_reshards: MAX_BUFFERED_RESHARDS,
                max_pre_leader_messages: MAX_PRE_LEADER_MESSAGES,
                max_pre_leader_keys: MAX_PRE_LEADER_KEYS,
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
                        let _ = machine.step(RecoveryInput::NoteKnownKey {
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
                    pre_leader_key_len,
                    pre_leader_max_messages,
                    recovery_len,
                    max_buffered_reshards,
                    known_len,
                    known_non_recovery_count,
                ) = machine.inspect(|recovery, known_leaders, pre_leader_buffer| {
                    (
                        pre_leader_buffer.len(),
                        pre_leader_buffer
                            .values()
                            .map(VecDeque::len)
                            .max()
                            .unwrap_or(0),
                        recovery.len(),
                        recovery
                            .values()
                            .map(|recovery| recovery.buffered_reshards.len())
                            .max()
                            .unwrap_or(0),
                        known_leaders.len(),
                        known_leaders
                            .iter()
                            .filter(|(key, _)| !recovery.contains_key(*key))
                            .count(),
                    )
                });

                prop_assert!(pre_leader_key_len <= MAX_PRE_LEADER_KEYS);
                prop_assert!(pre_leader_max_messages <= MAX_PRE_LEADER_MESSAGES);
                prop_assert!(recovery_len <= MAX_RECOVERY_ENTRIES);
                prop_assert!(max_buffered_reshards <= MAX_BUFFERED_RESHARDS);
                if known_len > MAX_KNOWN_KEYS {
                    prop_assert_eq!(known_non_recovery_count, 0);
                }
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

        let mut machine = RecoveryMachine::new(RecoveryLimits {
            max_known_keys: 1024,
            max_recovery_entries: 64,
            max_buffered_reshards: 32,
            max_pre_leader_messages: 64,
            max_pre_leader_keys: 256,
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
