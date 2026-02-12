use super::codec::WireShardMessage;
use super::protocol::{BlockKey, CodingImpl, ShardMessage, ZodaCommitment, hash_encoded};
use super::recovery::{BufferedReShare, DuplicateStatus, RecoveryState};
use bytes::Bytes;
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_parallel::Rayon;
use hellas_types::PublicKey;
use indexmap::IndexMap;
use std::collections::{HashMap, VecDeque};

#[derive(Clone)]
pub(crate) enum ShardEffect {
    Broadcast(Box<ShardMessage>),
    Recovered { key: BlockKey, contents: Bytes },
    Failed { key: BlockKey },
}

struct KeyBook {
    recovery: IndexMap<BlockKey, RecoveryState>,
    known_leaders: IndexMap<BlockKey, PublicKey>,
    pre_leader_buffer: IndexMap<BlockKey, VecDeque<ShardMessage>>,
}

impl KeyBook {
    fn new() -> Self {
        Self {
            recovery: IndexMap::new(),
            known_leaders: IndexMap::new(),
            pre_leader_buffer: IndexMap::new(),
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

    fn note_known_key(&mut self, key: BlockKey, leader: PublicKey) -> Vec<ShardMessage> {
        self.known_leaders.insert(key, leader);
        self.take_buffered_pre_leader(key)
            .map(|queue| queue.into_iter().collect())
            .unwrap_or_default()
    }

    fn take_buffered_pre_leader(&mut self, key: BlockKey) -> Option<VecDeque<ShardMessage>> {
        self.pre_leader_buffer.shift_remove(&key)
    }

    fn cleanup_key(&mut self, key: BlockKey) {
        self.recovery.shift_remove(&key);
        self.pre_leader_buffer.shift_remove(&key);
        self.known_leaders.shift_remove(&key);
    }

    fn recovery_contains(&self, key: &BlockKey) -> bool {
        self.recovery.contains_key(key)
    }

    fn recovery_get(&self, key: &BlockKey) -> Option<&RecoveryState> {
        self.recovery.get(key)
    }

    fn recovery_get_mut(&mut self, key: &BlockKey) -> Option<&mut RecoveryState> {
        self.recovery.get_mut(key)
    }

    fn insert_recovery(&mut self, key: BlockKey, state: RecoveryState) {
        self.recovery.insert(key, state);
    }

    fn recovery_len(&self) -> usize {
        self.recovery.len()
    }

    fn evict_oldest_recovery(&mut self) -> Option<BlockKey> {
        let (oldest, _state) = self.recovery.shift_remove_index(0)?;
        self.pre_leader_buffer.shift_remove(&oldest);
        self.known_leaders.shift_remove(&oldest);
        Some(oldest)
    }

    fn buffer_pre_leader_message(
        &mut self,
        key: BlockKey,
        message: ShardMessage,
        max_per_key: usize,
    ) {
        let queue = self.pre_leader_buffer.entry(key).or_default();
        if queue.len() >= max_per_key {
            queue.pop_front();
        }
        queue.push_back(message);
    }

    fn evict_oldest_pre_leader_keys(&mut self, max_keys: usize) {
        while self.pre_leader_buffer.len() > max_keys {
            let Some((_oldest, _queue)) = self.pre_leader_buffer.shift_remove_index(0) else {
                break;
            };
        }
    }

    fn evict_known_keys(&mut self, max_known_keys: usize) {
        while self.known_leaders.len() > max_known_keys {
            let eviction_index = self
                .known_leaders
                .iter()
                .position(|(candidate, _)| !self.recovery.contains_key(candidate));
            let Some(eviction_index) = eviction_index else {
                break;
            };
            let Some((oldest, _leader)) = self.known_leaders.shift_remove_index(eviction_index)
            else {
                break;
            };
            self.pre_leader_buffer.shift_remove(&oldest);
        }
    }

    fn known_len(&self) -> usize {
        self.known_leaders.len()
    }
}

pub(crate) struct ShardRecoverer {
    me: PublicKey,
    my_index: u16,
    coding_config: CodingConfig,
    strategy: Rayon,
    keys: KeyBook,
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
            keys: KeyBook::new(),
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
        let drained = self.keys.note_known_key(key, leader.clone());
        self.evict_known_keys();
        drained
    }

    fn expected_leader(&self, key: BlockKey) -> Option<PublicKey> {
        self.keys.expected_leader(key)
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

        if !self.keys.has_known_or_recovery(&key) {
            self.buffer_pre_leader_message(key, message);
            return VecDeque::new();
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
    ) -> VecDeque<ShardEffect> {
        let expected_leader = self.expected_leader(key);
        let Some(expected_leader) = expected_leader else {
            return VecDeque::new();
        };

        if sender != expected_leader || shard_index != self.my_index {
            return VecDeque::new();
        }

        let mut effects = self.ensure_recovery_state(key, commitment, expected_leader);
        if !self.check_or_adopt_initial_commitment(key, commitment) {
            return effects;
        }

        let shard_hash = hash_encoded(&shard);
        let status = self
            .keys
            .recovery_get(&key)
            .expect("recovery must exist after ensure_recovery_state")
            .shard_status(shard_index, shard_hash);
        if !self.accept_new_shard_status(status, key, shard_index, &sender, "initial") {
            return effects;
        }

        let (checking_data, checked_shard, reshard) =
            match CodingImpl::reshard(&self.coding_config, &commitment, shard_index, shard) {
                Ok(tuple) => tuple,
                Err(_) => return effects,
            };

        let recovery = self
            .keys
            .recovery_get_mut(&key)
            .expect("recovery must exist while handling initial shard");
        recovery.record_shard(shard_index, shard_hash);
        recovery.checking_data = Some(checking_data);
        recovery.checked_shards.push(checked_shard);
        self.process_buffered_reshards(key);
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
        key: BlockKey,
        sender: PublicKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        reshard: <CodingImpl as CodingScheme>::ReShard,
        validator_index: F,
    ) -> VecDeque<ShardEffect>
    where
        F: Fn(&PublicKey) -> Option<u16>,
    {
        let leader = self.expected_leader(key);
        let Some(leader) = leader else {
            warn!(digest = ?key.digest, "reshare key was neither known nor recovering");
            return VecDeque::new();
        };

        let Some(expected_index) = validator_index(&sender) else {
            return VecDeque::new();
        };
        if expected_index != shard_index {
            return VecDeque::new();
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

        let shard_hash = hash_encoded(&reshard);
        let status = self
            .keys
            .recovery_get(&key)
            .expect("recovery must exist after ensure_recovery_state")
            .shard_status(shard_index, shard_hash);
        if !self.accept_new_shard_status(status, key, shard_index, &sender, "reshare") {
            return effects;
        }

        let checking_data = self
            .keys
            .recovery_get(&key)
            .expect("recovery must exist while handling reshard")
            .checking_data
            .clone();
        let Some(checking_data) = checking_data else {
            self.keys
                .recovery_get_mut(&key)
                .expect("recovery must exist while buffering reshard")
                .buffer_reshare(
                    BufferedReShare {
                        sender,
                        shard_index,
                        reshard,
                        shard_hash,
                    },
                    Self::MAX_BUFFERED_RESHARDS,
                );
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

        let recovery = self
            .keys
            .recovery_get_mut(&key)
            .expect("recovery must exist while recording checked reshard");
        recovery.record_shard(shard_index, shard_hash);
        recovery.checked_shards.push(checked);
        if let Some(effect) = self.try_recover(key) {
            effects.push_back(effect);
        }
        effects
    }

    fn ensure_recovery_state(
        &mut self,
        key: BlockKey,
        commitment: ZodaCommitment,
        leader: PublicKey,
    ) -> VecDeque<ShardEffect> {
        if self.keys.recovery_contains(&key) {
            return VecDeque::new();
        }

        let mut effects = VecDeque::new();
        while self.keys.recovery_len() >= Self::MAX_RECOVERY_ENTRIES {
            let Some(oldest) = self.keys.evict_oldest_recovery() else {
                break;
            };
            warn!(
                evicted = ?oldest,
                incoming = ?key,
                max_recovery_entries = Self::MAX_RECOVERY_ENTRIES,
                "evicting oldest recovery entry to admit new recovery"
            );
            effects.push_back(ShardEffect::Failed { key: oldest });
        }

        self.keys
            .insert_recovery(key, RecoveryState::new(commitment, leader));
        effects
    }

    fn process_buffered_reshards(&mut self, key: BlockKey) {
        let Some((commitment, checking_data, buffered)) =
            self.keys.recovery_get_mut(&key).and_then(|recovery| {
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
            let status = self
                .keys
                .recovery_get(&key)
                .expect("recovery must exist while draining buffered reshards")
                .shard_status(buffered.shard_index, buffered.shard_hash);
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
            let recovery = self
                .keys
                .recovery_get_mut(&key)
                .expect("recovery must exist while recording drained reshard");
            recovery.record_shard(buffered.shard_index, buffered.shard_hash);
            recovery.checked_shards.push(checked);
        }
    }

    fn try_recover(&mut self, key: BlockKey) -> Option<ShardEffect> {
        let reconstructed = {
            let recovery = self.keys.recovery_get(&key)?;
            if !recovery.has_minimum_shards(self.coding_config.minimum_shards) {
                return None;
            }
            let checking_data = recovery.checking_data.clone()?;
            match CodingImpl::decode(
                &self.coding_config,
                &recovery.commitment,
                checking_data,
                recovery.checked_shards.as_slice(),
                &self.strategy,
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
        self.keys.cleanup_key(key);
    }

    fn check_or_adopt_initial_commitment(
        &mut self,
        key: BlockKey,
        commitment: ZodaCommitment,
    ) -> bool {
        let Some(recovery) = self.keys.recovery_get_mut(&key) else {
            return false;
        };
        if recovery.commitment == commitment {
            return true;
        }
        // Safe adoption window: we can switch commitment only before validating any shard.
        // This path is only reachable for the expected leader (validated in handle_initial),
        // so this resolves leader self-equivalence before shard validation begins.
        if recovery.checking_data.is_none() && recovery.checked_shards.is_empty() {
            recovery.commitment = commitment;
            return true;
        }
        warn!(digest = ?key.digest, "commitment mismatch for initial shard");
        false
    }

    fn commitment_matches_recovery(&self, key: BlockKey, commitment: ZodaCommitment) -> bool {
        self.keys
            .recovery_get(&key)
            .is_some_and(|recovery| recovery.commitment == commitment)
    }

    fn buffer_pre_leader_message(&mut self, key: BlockKey, message: ShardMessage) {
        self.keys
            .buffer_pre_leader_message(key, message, Self::MAX_PRE_LEADER_MESSAGES);
        self.keys
            .evict_oldest_pre_leader_keys(Self::MAX_PRE_LEADER_KEYS);
    }

    fn evict_known_keys(&mut self) {
        self.keys.evict_known_keys(Self::MAX_KNOWN_KEYS);
        if self.keys.known_len() > Self::MAX_KNOWN_KEYS {
            warn!(
                known_keys = self.keys.known_len(),
                max_known_keys = Self::MAX_KNOWN_KEYS,
                "unable to evict known keys because all candidates are active recoveries"
            );
        }
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

        fn validator_index(&self, sender: &PublicKey) -> Option<u16> {
            self.index_by_validator.get(sender).copied()
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
        assert!(
            fixture
                .recoverer
                .keys
                .pre_leader_buffer
                .contains_key(&artifacts.key)
        );

        let drained = fixture.note_known_key(artifacts.key);
        assert_eq!(drained.len(), 1);

        for msg in drained {
            let effects = fixture.handle_message(msg, &seen);
            assert!(effects.is_empty());
        }
        assert!(
            !fixture
                .recoverer
                .keys
                .pre_leader_buffer
                .contains_key(&artifacts.key)
        );
        let recovery = fixture
            .recoverer
            .keys
            .recovery
            .get(&artifacts.key)
            .expect("drained reshare should start recovery state");
        assert_eq!(recovery.buffered_reshards.len(), 1);
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
        assert!(!fixture.recoverer.keys.recovery.contains_key(&good.key));

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
        let recovery = fixture
            .recoverer
            .keys
            .recovery
            .get(&good.key)
            .expect("leader initial should create recovery state");
        assert_eq!(recovery.commitment, good.commitment);
        assert_ne!(recovery.commitment, bad.commitment);
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
        assert!(fixture.recoverer.keys.recovery.contains_key(&active.key));

        for view in 10u64..(10u64 + ShardRecoverer::MAX_KNOWN_KEYS as u64 + 64u64) {
            let key = BlockKey::new(
                Round::new(Epoch::new(2), View::new(view)),
                Sha256::hash(&view.to_le_bytes()),
            );
            let _ = fixture.note_known_key(key);
        }

        assert!(fixture.recoverer.keys.known_leaders.len() <= ShardRecoverer::MAX_KNOWN_KEYS);
        assert!(fixture.recoverer.keys.recovery.contains_key(&active.key));
    }
}
