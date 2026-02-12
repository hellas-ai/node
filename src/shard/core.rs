use super::codec::WireShardMessage;
use super::protocol::{BlockKey, CodingImpl, ShardMessage, ZodaCommitment, hash_encoded};
use super::recovery::{
    ReadyToCheckTask, RecoveryInput, RecoveryLimits, RecoveryMachine, RecoveryOutput,
};
use bytes::Bytes;
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_parallel::Rayon;
use hellas_types::PublicKey;
use std::collections::{HashMap, VecDeque};

#[derive(Clone)]
pub(crate) enum ShardEffect {
    Broadcast(Box<ShardMessage>),
    Recovered { key: BlockKey, contents: Bytes },
    Failed { key: BlockKey },
}

struct IncomingReShare {
    key: BlockKey,
    commitment: ZodaCommitment,
    shard_index: u16,
    reshard: <CodingImpl as CodingScheme>::ReShard,
}

pub(crate) struct ShardRecoverer {
    me: PublicKey,
    my_index: u16,
    coding_config: CodingConfig,
    strategy: Rayon,
    machine: RecoveryMachine,
}

impl ShardRecoverer {
    const MAX_RECOVERY_ENTRIES: usize = 64;
    const MAX_BUFFERED_RESHARDS: usize = 32;
    const MAX_PRE_LEADER_MESSAGES: usize = 64;
    const MAX_PRE_LEADER_KEYS: usize = 256;
    const MAX_KNOWN_KEYS: usize = 1024;

    pub(crate) fn new(
        me: &PublicKey,
        my_index: u16,
        coding_config: CodingConfig,
        strategy: Rayon,
    ) -> Self {
        Self {
            me: me.clone(),
            my_index,
            coding_config,
            strategy,
            machine: RecoveryMachine::new(RecoveryLimits {
                max_known_keys: Self::MAX_KNOWN_KEYS,
                max_recovery_entries: Self::MAX_RECOVERY_ENTRIES,
                max_buffered_reshards: Self::MAX_BUFFERED_RESHARDS,
                max_pre_leader_messages: Self::MAX_PRE_LEADER_MESSAGES,
                max_pre_leader_keys: Self::MAX_PRE_LEADER_KEYS,
            }),
        }
    }

    pub(crate) const fn me(&self) -> &PublicKey {
        &self.me
    }

    pub(crate) const fn coding_config(&self) -> &CodingConfig {
        &self.coding_config
    }

    pub(crate) fn note_known_key(
        &mut self,
        key: BlockKey,
        leader: &PublicKey,
    ) -> Vec<ShardMessage> {
        let mut drained = Vec::new();
        for output in self.machine.step(RecoveryInput::NoteKnownKey {
            key,
            leader: leader.clone(),
        }) {
            match output {
                RecoveryOutput::DrainedPreLeader(messages) => drained.extend(messages),
                RecoveryOutput::KnownKeysOverflow {
                    known_keys,
                    max_known_keys,
                } => {
                    warn!(
                        known_keys,
                        max_known_keys,
                        "unable to evict known keys because all candidates are active recoveries"
                    );
                }
                _ => {}
            }
        }
        drained
    }

    pub(crate) fn handle_message<F>(
        &mut self,
        message: ShardMessage,
        seen: &HashMap<Digest, Bytes>,
        validator_index: F,
    ) -> VecDeque<ShardEffect>
    where
        F: Fn(&PublicKey) -> Option<u16>,
    {
        let key = message.key();
        if seen.contains_key(&key.digest) {
            return VecDeque::new();
        }

        let mut effects = VecDeque::new();
        let outputs = self.machine.step(RecoveryInput::IngressMessage {
            message: Box::new(message),
        });

        for output in outputs {
            match output {
                RecoveryOutput::IngressReady {
                    message,
                    expected_leader,
                } => {
                    let ShardMessage { sender, body } = *message;
                    match body {
                        WireShardMessage::Initial {
                            key,
                            commitment,
                            shard,
                            shard_index,
                        } => effects.extend(self.handle_initial(
                            key,
                            sender,
                            expected_leader,
                            commitment,
                            shard,
                            shard_index,
                        )),
                        WireShardMessage::ReShare {
                            key,
                            commitment,
                            shard_index,
                            reshard,
                        } => effects.extend(self.handle_reshare(
                            sender,
                            expected_leader,
                            IncomingReShare {
                                key,
                                commitment,
                                shard_index,
                                reshard,
                            },
                            &validator_index,
                        )),
                    }
                }
                RecoveryOutput::BufferedPreLeader => {}
                other => self.push_machine_effect(other, key, &mut effects),
            }
        }
        effects
    }

    fn handle_initial(
        &mut self,
        key: BlockKey,
        sender: PublicKey,
        expected_leader: PublicKey,
        commitment: ZodaCommitment,
        shard: <CodingImpl as CodingScheme>::Shard,
        shard_index: u16,
    ) -> VecDeque<ShardEffect> {
        if sender != expected_leader || shard_index != self.my_index {
            return VecDeque::new();
        }

        let shard_hash = hash_encoded(&shard);
        let mut effects = VecDeque::new();
        let mut accepted = false;
        for output in self.machine.step(RecoveryInput::ObserveInitial {
            key,
            sender: sender.clone(),
            commitment,
            shard_index,
            shard_hash,
            leader: expected_leader,
        }) {
            match output {
                RecoveryOutput::InitialAccepted => accepted = true,
                other => self.push_machine_effect(other, key, &mut effects),
            }
        }
        if !accepted {
            return effects;
        }

        let (checking_data, checked_shard, reshard) =
            match CodingImpl::reshard(&self.coding_config, &commitment, shard_index, shard) {
                Ok(tuple) => tuple,
                Err(_) => return effects,
            };

        let mut pending_checks: Vec<ReadyToCheckTask> = Vec::new();
        for output in self.machine.step(RecoveryInput::ApplyInitialValidated {
            key,
            commitment,
            shard_index,
            shard_hash,
            checking_data,
            checked_shard,
        }) {
            match output {
                RecoveryOutput::ReadyToCheck(task) => pending_checks.push(task),
                other => self.push_machine_effect(other, key, &mut effects),
            }
        }

        for task in pending_checks {
            let _checked = self.process_ready_to_check(task, &mut effects);
        }

        effects.push_back(ShardEffect::Broadcast(Box::new(ShardMessage::reshare(
            &self.me,
            key,
            commitment,
            self.my_index,
            reshard,
        ))));
        if let Some(effect) = self.try_recover(key) {
            effects.push_back(effect);
        }
        effects
    }

    fn handle_reshare<F>(
        &mut self,
        sender: PublicKey,
        expected_leader: PublicKey,
        incoming: IncomingReShare,
        validator_index: &F,
    ) -> VecDeque<ShardEffect>
    where
        F: Fn(&PublicKey) -> Option<u16>,
    {
        let IncomingReShare {
            key,
            commitment,
            shard_index,
            reshard,
        } = incoming;

        let Some(expected_index) = validator_index(&sender) else {
            return VecDeque::new();
        };
        if expected_index != shard_index {
            return VecDeque::new();
        }

        let shard_hash = hash_encoded(&reshard);
        let mut effects = VecDeque::new();
        let mut pending_checks: Vec<ReadyToCheckTask> = Vec::new();
        for output in self.machine.step(RecoveryInput::ObserveReShare {
            key,
            sender: sender.clone(),
            commitment,
            shard_index,
            shard_hash,
            reshard,
            leader: expected_leader,
        }) {
            match output {
                RecoveryOutput::ReadyToCheck(task) => pending_checks.push(task),
                RecoveryOutput::ReShareBuffered => {}
                other => self.push_machine_effect(other, key, &mut effects),
            }
        }

        let mut recorded_checked = false;
        for task in pending_checks {
            recorded_checked |= self.process_ready_to_check(task, &mut effects);
        }
        if recorded_checked && let Some(effect) = self.try_recover(key) {
            effects.push_back(effect);
        }
        effects
    }

    fn process_ready_to_check(
        &mut self,
        task: ReadyToCheckTask,
        effects: &mut VecDeque<ShardEffect>,
    ) -> bool {
        let checked = match CodingImpl::check(
            &self.coding_config,
            &task.commitment,
            &task.checking_data,
            task.shard_index,
            task.reshard,
        ) {
            Ok(checked) => checked,
            Err(_) => return false,
        };

        for output in self.machine.step(RecoveryInput::ApplyCheckedReShare {
            key: task.key,
            shard_index: task.shard_index,
            shard_hash: task.shard_hash,
            checked_shard: checked,
        }) {
            self.push_machine_effect(output, task.key, effects);
        }
        true
    }

    fn try_recover(&mut self, key: BlockKey) -> Option<ShardEffect> {
        let mut decode_candidate = None;
        for output in self.machine.step(RecoveryInput::TryTakeDecode {
            key,
            minimum_shards: self.coding_config.minimum_shards,
        }) {
            match output {
                RecoveryOutput::ReadyToDecode(candidate) => decode_candidate = Some(candidate),
                other => {
                    if let Some(effect) = self.machine_output_to_effect(other, key) {
                        return Some(effect);
                    }
                }
            }
        }
        let decode_candidate = decode_candidate?;

        let reconstructed = match CodingImpl::decode(
            &self.coding_config,
            &decode_candidate.commitment,
            decode_candidate.checking_data,
            decode_candidate.checked_shards.as_slice(),
            &self.strategy,
        ) {
            Ok(decoded) => decoded,
            Err(_) => return Some(ShardEffect::Failed { key }),
        };

        if Sha256::hash(reconstructed.as_slice()) != key.digest {
            return Some(ShardEffect::Failed { key });
        }

        Some(ShardEffect::Recovered {
            key,
            contents: Bytes::from(reconstructed),
        })
    }

    fn push_machine_effect(
        &self,
        output: RecoveryOutput,
        incoming: BlockKey,
        effects: &mut VecDeque<ShardEffect>,
    ) {
        if let Some(effect) = self.machine_output_to_effect(output, incoming) {
            effects.push_back(effect);
        }
    }

    fn machine_output_to_effect(
        &self,
        output: RecoveryOutput,
        incoming: BlockKey,
    ) -> Option<ShardEffect> {
        match output {
            RecoveryOutput::Evicted { key } => {
                warn!(
                    evicted = ?key,
                    incoming = ?incoming,
                    max_recovery_entries = Self::MAX_RECOVERY_ENTRIES,
                    "evicting oldest recovery entry to admit new recovery"
                );
                Some(ShardEffect::Failed { key })
            }
            RecoveryOutput::KnownKeysOverflow {
                known_keys,
                max_known_keys,
            } => {
                warn!(
                    known_keys,
                    max_known_keys,
                    "unable to evict known keys because all candidates are active recoveries"
                );
                None
            }
            RecoveryOutput::CommitmentMismatch {
                key,
                shard_index,
                sender,
                source,
            } => {
                if source == "reshare" {
                    warn!(
                        digest = ?key.digest,
                        shard_index,
                        ?sender,
                        "commitment mismatch for reshard"
                    );
                } else {
                    warn!(digest = ?key.digest, "commitment mismatch for initial shard");
                }
                None
            }
            RecoveryOutput::Equivocation {
                key,
                shard_index,
                sender,
                source,
            } => {
                warn!(
                    digest = ?key.digest,
                    shard_index,
                    ?sender,
                    source,
                    "equivocation detected for shard"
                );
                None
            }
            RecoveryOutput::DuplicateShard
            | RecoveryOutput::BufferedPreLeader
            | RecoveryOutput::DrainedPreLeader(_)
            | RecoveryOutput::IngressReady { .. }
            | RecoveryOutput::InitialAccepted
            | RecoveryOutput::ReShareBuffered
            | RecoveryOutput::ReadyToCheck(_)
            | RecoveryOutput::ReadyToDecode(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::protocol::coding_config;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::{Signer, ed25519};
    use commonware_parallel::Sequential;

    struct BlockArtifacts {
        key: BlockKey,
        commitment: ZodaCommitment,
        shards: Vec<<CodingImpl as CodingScheme>::Shard>,
        reshares: Vec<<CodingImpl as CodingScheme>::ReShard>,
    }

    struct Fixture {
        validators: Vec<PublicKey>,
        index_by_validator: HashMap<PublicKey, u16>,
        leader: PublicKey,
        my_index: u16,
        recoverer: ShardRecoverer,
    }

    impl Fixture {
        fn new() -> Self {
            let mut validators: Vec<_> = (0u64..6u64)
                .map(|seed| ed25519::PrivateKey::from_seed(seed).public_key())
                .collect();
            validators.sort();
            let my_index = 1u16;
            let me = validators[usize::from(my_index)].clone();
            let leader = validators[0].clone();
            let strategy = crate::coding_strategy();
            let recoverer = ShardRecoverer::new(&me, my_index, coding_config(6), strategy);
            let mut index_by_validator = HashMap::new();
            for (idx, validator) in validators.iter().enumerate() {
                let validator_index = u16::try_from(idx).expect("index should fit into u16");
                index_by_validator.insert(validator.clone(), validator_index);
            }
            Self {
                validators,
                index_by_validator,
                leader,
                my_index,
                recoverer,
            }
        }

        fn handle_message(
            &mut self,
            message: ShardMessage,
            seen: &HashMap<Digest, Bytes>,
        ) -> VecDeque<ShardEffect> {
            let index_by_validator = &self.index_by_validator;
            self.recoverer
                .handle_message(message, seen, |pk| index_by_validator.get(pk).copied())
        }

        fn note_known_key(&mut self, key: BlockKey) -> Vec<ShardMessage> {
            self.recoverer.note_known_key(key, &self.leader)
        }

        fn make_artifacts(&self, view: u64, payload: &[u8]) -> BlockArtifacts {
            let key = BlockKey::new(
                Round::new(Epoch::new(1), View::new(view)),
                Sha256::hash(payload),
            );
            let (commitment, shards) =
                CodingImpl::encode(self.recoverer.coding_config(), payload, &Sequential)
                    .expect("encode should succeed");
            let mut reshares = Vec::with_capacity(shards.len());
            for (idx, shard) in shards.iter().cloned().enumerate() {
                let shard_index = u16::try_from(idx).expect("index should fit into u16");
                let (_, _, reshard) = CodingImpl::reshard(
                    self.recoverer.coding_config(),
                    &commitment,
                    shard_index,
                    shard,
                )
                .expect("reshard should succeed");
                reshares.push(reshard);
            }
            BlockArtifacts {
                key,
                commitment,
                shards,
                reshares,
            }
        }
    }

    #[test]
    fn pre_leader_reshare_is_drained_after_note_known_key() {
        let mut fixture = Fixture::new();
        let artifacts = fixture.make_artifacts(1, b"buffer-then-recover");
        let sender = fixture.validators[2].clone();
        let shard_index = 2u16;
        let reshare = artifacts.reshares[usize::from(shard_index)].clone();

        let seen = HashMap::<Digest, Bytes>::new();
        let buffered = fixture.handle_message(
            ShardMessage::reshare(
                &sender,
                artifacts.key,
                artifacts.commitment,
                shard_index,
                reshare,
            ),
            &seen,
        );
        assert!(buffered.is_empty());
        assert!(fixture.recoverer.machine.inspect(
            |_recovery, _known_leaders, pre_leader_buffer| {
                pre_leader_buffer.contains_key(&artifacts.key)
            }
        ));

        let drained = fixture.note_known_key(artifacts.key);
        assert_eq!(drained.len(), 1);

        for msg in drained {
            let effects = fixture.handle_message(msg, &seen);
            assert!(effects.is_empty());
        }
        assert!(!fixture.recoverer.machine.inspect(
            |_recovery, _known_leaders, pre_leader_buffer| {
                pre_leader_buffer.contains_key(&artifacts.key)
            }
        ));
        let buffered_reshards_len =
            fixture
                .recoverer
                .machine
                .inspect(|recovery, _known_leaders, _pre_leader_buffer| {
                    recovery
                        .get(&artifacts.key)
                        .map(|recovery| recovery.buffered_reshards_len())
                });
        assert_eq!(
            buffered_reshards_len,
            Some(1),
            "drained reshare should start recovery state"
        );
    }

    #[test]
    fn wrong_sender_initial_does_not_poison_commitment() {
        let mut fixture = Fixture::new();
        let good = fixture.make_artifacts(2, b"good-payload");
        let bad = fixture.make_artifacts(2, b"bad-payload");
        let attacker = fixture.validators[3].clone();

        let _ = fixture.note_known_key(good.key);
        let seen = HashMap::<Digest, Bytes>::new();

        let malicious = fixture.handle_message(
            ShardMessage::initial(
                &attacker,
                good.key,
                bad.commitment,
                bad.shards[usize::from(fixture.my_index)].clone(),
                fixture.my_index,
            ),
            &seen,
        );
        assert!(malicious.is_empty());
        assert!(!fixture.recoverer.machine.inspect(
            |recovery, _known_leaders, _pre_leader_buffer| { recovery.contains_key(&good.key) }
        ));

        let _ = fixture.handle_message(
            ShardMessage::initial(
                &fixture.leader,
                good.key,
                good.commitment,
                good.shards[usize::from(fixture.my_index)].clone(),
                fixture.my_index,
            ),
            &seen,
        );
        let commitment =
            fixture
                .recoverer
                .machine
                .inspect(|recovery, _known_leaders, _pre_leader_buffer| {
                    recovery
                        .get(&good.key)
                        .map(|recovery| recovery.commitment())
                });
        let Some(commitment) = commitment else {
            panic!("leader initial should create recovery state");
        };
        assert_eq!(commitment, good.commitment);
        assert_ne!(commitment, bad.commitment);
    }
}
