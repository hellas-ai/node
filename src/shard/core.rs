use super::{
    BlockKey, BufferedReShare, CodingImpl, DuplicateStatus, RecoveryState, ShardMessage,
    WireShardMessage, ZodaCommitment,
};
use crate::effects::Effects;
use bytes::Bytes;
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use hellas_types::PublicKey;
use std::collections::{HashMap, VecDeque};

#[derive(Clone)]
pub(crate) enum ShardEffect {
    Broadcast(Box<ShardMessage>),
    Recovered { key: BlockKey, contents: Bytes },
    Failed { key: BlockKey },
}

pub(crate) struct ShardRecoverer {
    me: PublicKey,
    my_index: u16,
    coding_config: CodingConfig,

    recovery: HashMap<BlockKey, RecoveryState>,
    recovery_order: VecDeque<BlockKey>,
    known_keys: HashMap<BlockKey, PublicKey>,
    known_key_order: VecDeque<BlockKey>,
    pre_leader_buffer: HashMap<BlockKey, VecDeque<ShardMessage>>,
    pre_leader_order: VecDeque<BlockKey>,
}

impl ShardRecoverer {
    const MAX_RECOVERY_ENTRIES: usize = 64;
    const MAX_BUFFERED_RESHARDS: usize = 32;
    const MAX_PRE_LEADER_MESSAGES: usize = 64;
    const MAX_PRE_LEADER_KEYS: usize = 256;
    const MAX_KNOWN_KEYS: usize = 1024;

    pub(crate) fn new(me: &PublicKey, my_index: u16, coding_config: CodingConfig) -> Self {
        Self {
            me: me.clone(),
            my_index,
            coding_config,
            recovery: HashMap::new(),
            recovery_order: VecDeque::new(),
            known_keys: HashMap::new(),
            known_key_order: VecDeque::new(),
            pre_leader_buffer: HashMap::new(),
            pre_leader_order: VecDeque::new(),
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
        if !self.known_keys.contains_key(&key) {
            self.known_key_order.push_back(key);
        }
        self.known_keys.insert(key, leader.clone());
        self.evict_known_keys();
        self.remove_buffered_pre_leader_key(key)
            .map(|queue| queue.into_iter().collect())
            .unwrap_or_default()
    }

    pub(crate) fn handle_message<F>(
        &mut self,
        message: ShardMessage,
        seen: &HashMap<Digest, Bytes>,
        validator_index: F,
    ) -> Effects<ShardEffect>
    where
        F: Fn(&PublicKey) -> Option<u16>,
    {
        let key = message.key();
        if seen.contains_key(&key.digest) {
            return Effects::new();
        }

        if !self.known_keys.contains_key(&key) && !self.recovery.contains_key(&key) {
            self.buffer_pre_leader_message(key, message);
            return Effects::new();
        }

        let ShardMessage { sender, body } = message;
        match body {
            WireShardMessage::Initial {
                commitment,
                shard,
                shard_index,
                ..
            } => self.handle_initial(key, sender, commitment, shard, shard_index),
            WireShardMessage::ReShare {
                commitment,
                shard_index,
                reshard,
                ..
            } => self.handle_reshare(
                key,
                sender,
                commitment,
                shard_index,
                reshard,
                validator_index,
            ),
        }
    }

    fn handle_initial(
        &mut self,
        key: BlockKey,
        sender: PublicKey,
        commitment: ZodaCommitment,
        shard: <CodingImpl as CodingScheme>::Shard,
        shard_index: u16,
    ) -> Effects<ShardEffect> {
        let expected_leader = self.known_keys.get(&key).cloned().or_else(|| {
            self.recovery
                .get(&key)
                .map(|recovery| recovery.leader.clone())
        });
        let Some(expected_leader) = expected_leader else {
            return Effects::new();
        };

        if sender != expected_leader || shard_index != self.my_index {
            return Effects::new();
        }

        let mut effects = self.ensure_recovery_state(key, commitment, expected_leader);
        if !self.check_or_adopt_initial_commitment(key, commitment) {
            return effects;
        }

        let shard_hash = super::hash_encoded(&shard);
        let Some(status) = self
            .recovery
            .get(&key)
            .map(|recovery| recovery.shard_status(shard_index, shard_hash))
        else {
            warn!(digest = ?key.digest, "missing recovery state while processing initial shard");
            return effects;
        };
        if !self.accept_new_shard_status(status, key, shard_index, &sender, "initial") {
            return effects;
        }

        let (checking_data, checked_shard, reshard) =
            match CodingImpl::reshard(&self.coding_config, &commitment, shard_index, shard) {
                Ok(tuple) => tuple,
                Err(_) => return effects,
            };

        if let Some(recovery) = self.recovery.get_mut(&key) {
            recovery.record_shard(shard_index, shard_hash);
            recovery.checking_data = Some(checking_data);
            recovery.checked_shards.push(checked_shard);
        }
        self.process_buffered_reshards(key);
        effects.push(ShardEffect::Broadcast(Box::new(ShardMessage::reshare(
            &self.me,
            key,
            commitment,
            self.my_index,
            reshard,
        ))));
        if let Some(effect) = self.try_recover(key) {
            effects.push(effect);
        }
        effects
    }

    fn handle_reshare<F>(
        &mut self,
        key: BlockKey,
        sender: PublicKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        reshard: <CodingImpl as CodingScheme>::ReShard,
        validator_index: F,
    ) -> Effects<ShardEffect>
    where
        F: Fn(&PublicKey) -> Option<u16>,
    {
        let leader = self.known_keys.get(&key).cloned().or_else(|| {
            self.recovery
                .get(&key)
                .map(|recovery| recovery.leader.clone())
        });
        let Some(leader) = leader else {
            warn!(digest = ?key.digest, "reshare key was neither known nor recovering");
            return Effects::new();
        };

        let Some(expected_index) = validator_index(&sender) else {
            return Effects::new();
        };
        if expected_index != shard_index {
            return Effects::new();
        }

        let mut effects = self.ensure_recovery_state(key, commitment, leader);
        if !self.commitment_matches_recovery(key, commitment) {
            warn!(
                digest = ?key.digest,
                shard_index,
                ?sender,
                "commitment mismatch for reshard"
            );
            return effects;
        }

        let shard_hash = super::hash_encoded(&reshard);
        let Some(status) = self
            .recovery
            .get(&key)
            .map(|recovery| recovery.shard_status(shard_index, shard_hash))
        else {
            warn!(digest = ?key.digest, "missing recovery state while processing reshard");
            return effects;
        };
        if !self.accept_new_shard_status(status, key, shard_index, &sender, "reshare") {
            return effects;
        }

        let checking_data = self
            .recovery
            .get(&key)
            .and_then(|recovery| recovery.checking_data.clone());
        let Some(checking_data) = checking_data else {
            if let Some(recovery) = self.recovery.get_mut(&key) {
                recovery.buffer_reshare(
                    BufferedReShare {
                        sender,
                        shard_index,
                        reshard,
                        shard_hash,
                    },
                    Self::MAX_BUFFERED_RESHARDS,
                );
            }
            return effects;
        };

        let checked = match CodingImpl::check(
            &self.coding_config,
            &commitment,
            &checking_data,
            shard_index,
            reshard,
        ) {
            Ok(checked) => checked,
            Err(_) => return effects,
        };

        if let Some(recovery) = self.recovery.get_mut(&key) {
            recovery.record_shard(shard_index, shard_hash);
            recovery.checked_shards.push(checked);
        }
        if let Some(effect) = self.try_recover(key) {
            effects.push(effect);
        }
        effects
    }

    fn ensure_recovery_state(
        &mut self,
        key: BlockKey,
        commitment: ZodaCommitment,
        leader: PublicKey,
    ) -> Effects<ShardEffect> {
        if self.recovery.contains_key(&key) {
            return Effects::new();
        }

        let mut effects = Effects::new();
        while self.recovery.len() >= Self::MAX_RECOVERY_ENTRIES {
            let Some(oldest) = self.recovery_order.pop_front() else {
                break;
            };
            self.recovery.remove(&oldest);
            self.remove_buffered_pre_leader_key(oldest);
            self.remove_known_key(oldest);
            effects.push(ShardEffect::Failed { key: oldest });
        }

        self.recovery
            .insert(key, RecoveryState::new(commitment, leader));
        self.recovery_order.push_back(key);
        effects
    }

    fn process_buffered_reshards(&mut self, key: BlockKey) {
        let Some((commitment, checking_data, buffered)) =
            self.recovery.get_mut(&key).and_then(|recovery| {
                let checking_data = recovery.checking_data.clone()?;
                Some((
                    recovery.commitment,
                    checking_data,
                    recovery.take_buffered_reshards(),
                ))
            })
        else {
            return;
        };

        for buffered in buffered {
            let Some(status) = self
                .recovery
                .get(&key)
                .map(|recovery| recovery.shard_status(buffered.shard_index, buffered.shard_hash))
            else {
                warn!(
                    digest = ?key.digest,
                    "missing recovery state while draining buffered reshards"
                );
                return;
            };
            if !self.accept_new_shard_status(
                status,
                key,
                buffered.shard_index,
                &buffered.sender,
                "buffered_reshare",
            ) {
                continue;
            }
            let checked = match CodingImpl::check(
                &self.coding_config,
                &commitment,
                &checking_data,
                buffered.shard_index,
                buffered.reshard,
            ) {
                Ok(checked) => checked,
                Err(_) => continue,
            };
            if let Some(recovery) = self.recovery.get_mut(&key) {
                recovery.record_shard(buffered.shard_index, buffered.shard_hash);
                recovery.checked_shards.push(checked);
            }
        }
    }

    fn try_recover(&mut self, key: BlockKey) -> Option<ShardEffect> {
        let reconstructed = {
            let recovery = self.recovery.get(&key)?;
            if !recovery.has_minimum_shards(self.coding_config.minimum_shards) {
                return None;
            }
            let checking_data = recovery.checking_data.clone()?;
            match CodingImpl::decode(
                &self.coding_config,
                &recovery.commitment,
                checking_data,
                recovery.checked_shards.as_slice(),
                &Sequential,
            ) {
                Ok(decoded) => decoded,
                Err(_) => {
                    self.cleanup_recovery_key(key);
                    return Some(ShardEffect::Failed { key });
                }
            }
        };

        if Sha256::hash(reconstructed.as_slice()) != key.digest {
            self.cleanup_recovery_key(key);
            return Some(ShardEffect::Failed { key });
        }

        self.cleanup_recovery_key(key);
        Some(ShardEffect::Recovered {
            key,
            contents: Bytes::from(reconstructed),
        })
    }

    fn cleanup_recovery_key(&mut self, key: BlockKey) {
        self.recovery.remove(&key);
        if let Some(pos) = self.recovery_order.iter().position(|item| *item == key) {
            self.recovery_order.remove(pos);
        }
        self.remove_buffered_pre_leader_key(key);
        self.remove_known_key(key);
    }

    fn check_or_adopt_initial_commitment(
        &mut self,
        key: BlockKey,
        commitment: ZodaCommitment,
    ) -> bool {
        let Some(recovery) = self.recovery.get_mut(&key) else {
            return false;
        };
        if recovery.commitment == commitment {
            return true;
        }
        // Safe adoption window: we can switch commitment only before validating any shard.
        if recovery.checking_data.is_none() && recovery.checked_shards.is_empty() {
            recovery.commitment = commitment;
            return true;
        }
        warn!(digest = ?key.digest, "commitment mismatch for initial shard");
        false
    }

    fn commitment_matches_recovery(&self, key: BlockKey, commitment: ZodaCommitment) -> bool {
        self.recovery
            .get(&key)
            .is_some_and(|recovery| recovery.commitment == commitment)
    }

    fn buffer_pre_leader_message(&mut self, key: BlockKey, message: ShardMessage) {
        if !self.pre_leader_buffer.contains_key(&key) {
            self.pre_leader_order.push_back(key);
        }
        let queue = self.pre_leader_buffer.entry(key).or_default();
        if queue.len() >= Self::MAX_PRE_LEADER_MESSAGES {
            queue.pop_front();
        }
        queue.push_back(message);

        while self.pre_leader_buffer.len() > Self::MAX_PRE_LEADER_KEYS {
            let Some(oldest) = self.pre_leader_order.pop_front() else {
                break;
            };
            self.pre_leader_buffer.remove(&oldest);
        }
    }

    fn remove_buffered_pre_leader_key(&mut self, key: BlockKey) -> Option<VecDeque<ShardMessage>> {
        if let Some(pos) = self.pre_leader_order.iter().position(|item| *item == key) {
            self.pre_leader_order.remove(pos);
        }
        self.pre_leader_buffer.remove(&key)
    }

    fn evict_known_keys(&mut self) {
        let mut attempts_left = self.known_key_order.len();
        while self.known_keys.len() > Self::MAX_KNOWN_KEYS && attempts_left > 0 {
            let Some(oldest) = self.known_key_order.pop_front() else {
                break;
            };
            if self.recovery.contains_key(&oldest) {
                self.known_key_order.push_back(oldest);
                attempts_left -= 1;
                continue;
            }
            self.known_keys.remove(&oldest);
            self.remove_buffered_pre_leader_key(oldest);
            // Reset attempts after a successful eviction so we can keep scanning.
            attempts_left = self.known_key_order.len();
        }

        if self.known_keys.len() > Self::MAX_KNOWN_KEYS {
            warn!(
                known_keys = self.known_keys.len(),
                max_known_keys = Self::MAX_KNOWN_KEYS,
                "unable to evict known keys because all candidates are active recoveries"
            );
        }
    }

    fn remove_known_key(&mut self, key: BlockKey) {
        if let Some(pos) = self.known_key_order.iter().position(|item| *item == key) {
            self.known_key_order.remove(pos);
        }
        self.known_keys.remove(&key);
    }

    fn accept_new_shard_status(
        &self,
        status: DuplicateStatus,
        key: BlockKey,
        shard_index: u16,
        sender: &PublicKey,
        source: &'static str,
    ) -> bool {
        match status {
            DuplicateStatus::New => true,
            DuplicateStatus::Duplicate => false,
            DuplicateStatus::Equivocation => {
                warn!(
                    digest = ?key.digest,
                    shard_index,
                    ?sender,
                    source,
                    "equivocation detected for shard"
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::coding_config;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::{Signer, ed25519};
    use proptest::prelude::*;

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
            let recoverer = ShardRecoverer::new(&me, my_index, coding_config(6));
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

        fn validator_index(&self, sender: &PublicKey) -> Option<u16> {
            self.index_by_validator.get(sender).copied()
        }

        fn handle_message(
            &mut self,
            message: ShardMessage,
            seen: &HashMap<Digest, Bytes>,
        ) -> Effects<ShardEffect> {
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

    fn has_recovered<'a, I>(effects: I, key: BlockKey) -> bool
    where
        I: IntoIterator<Item = &'a ShardEffect>,
    {
        effects
            .into_iter()
            .any(|effect| matches!(effect, ShardEffect::Recovered { key: reconstructed, .. } if *reconstructed == key))
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
        assert!(
            fixture
                .recoverer
                .pre_leader_buffer
                .contains_key(&artifacts.key)
        );

        let drained = fixture.note_known_key(artifacts.key);
        assert_eq!(drained.len(), 1);

        for msg in drained {
            let _ = fixture.handle_message(msg, &seen);
        }

        let effects = fixture.handle_message(
            ShardMessage::initial(
                &fixture.leader,
                artifacts.key,
                artifacts.commitment,
                artifacts.shards[usize::from(fixture.my_index)].clone(),
                fixture.my_index,
            ),
            &seen,
        );
        assert!(has_recovered(effects.iter(), artifacts.key));
    }

    #[test]
    fn wrong_sender_initial_does_not_poison_commitment() {
        let mut fixture = Fixture::new();
        let good = fixture.make_artifacts(2, b"good-payload");
        let bad = fixture.make_artifacts(2, b"bad-payload");
        let attacker = fixture.validators[3].clone();
        let helper = fixture.validators[2].clone();

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

        let helper_index = fixture.validator_index(&helper).expect("known validator");
        let effects = fixture.handle_message(
            ShardMessage::reshare(
                &helper,
                good.key,
                good.commitment,
                helper_index,
                good.reshares[usize::from(helper_index)].clone(),
            ),
            &seen,
        );
        assert!(has_recovered(effects.iter(), good.key));
    }

    #[test]
    fn known_keys_stay_bounded_with_active_oldest_recovery() {
        let mut fixture = Fixture::new();
        let active = fixture.make_artifacts(3, b"active-recovery");
        let helper = fixture.validators[2].clone();
        let helper_index = fixture.validator_index(&helper).expect("known validator");

        let _ = fixture.note_known_key(active.key);
        let seen = HashMap::<Digest, Bytes>::new();
        let _ = fixture.handle_message(
            ShardMessage::reshare(
                &helper,
                active.key,
                active.commitment,
                helper_index,
                active.reshares[usize::from(helper_index)].clone(),
            ),
            &seen,
        );
        assert!(fixture.recoverer.recovery.contains_key(&active.key));

        for view in 10u64..(10u64 + ShardRecoverer::MAX_KNOWN_KEYS as u64 + 64u64) {
            let key = BlockKey::new(
                Round::new(Epoch::new(2), View::new(view)),
                Sha256::hash(&view.to_le_bytes()),
            );
            let _ = fixture.note_known_key(key);
        }

        assert!(fixture.recoverer.known_keys.len() <= ShardRecoverer::MAX_KNOWN_KEYS);
        assert!(fixture.recoverer.recovery.contains_key(&active.key));
    }

    proptest! {
        #[test]
        fn recovers_with_one_valid_reshare_prop(
            payload in prop::collection::vec(any::<u8>(), 50..256),
            peer_index in 0u16..6u16,
            reshare_first in any::<bool>(),
        ) {
            prop_assume!(peer_index != 1);
            let mut fixture = Fixture::new();
            let artifacts = fixture.make_artifacts(4, payload.as_slice());
            let _ = fixture.note_known_key(artifacts.key);
            let seen = HashMap::<Digest, Bytes>::new();
            let peer = fixture.validators[usize::from(peer_index)].clone();

            let initial = ShardMessage::initial(
                &fixture.leader,
                artifacts.key,
                artifacts.commitment,
                artifacts.shards[usize::from(fixture.my_index)].clone(),
                fixture.my_index,
            );
            let reshare = ShardMessage::reshare(
                &peer,
                artifacts.key,
                artifacts.commitment,
                peer_index,
                artifacts.reshares[usize::from(peer_index)].clone(),
            );

            let mut effects = Vec::new();
            if reshare_first {
                effects.extend(fixture.handle_message(reshare, &seen));
                effects.extend(fixture.handle_message(initial, &seen));
            } else {
                effects.extend(fixture.handle_message(initial, &seen));
                effects.extend(fixture.handle_message(reshare, &seen));
            }

            prop_assert!(has_recovered(effects.iter(), artifacts.key));
        }
    }
}
