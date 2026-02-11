use super::{
    BlockKey, BufferedReShare, CodingImpl, DuplicateStatus, ReconstructionState, ShardMessage,
    ZodaCommitment,
};
use bytes::Bytes;
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use hellas_types::PublicKey;
use std::collections::{HashMap, VecDeque};

#[derive(Clone)]
pub enum ShardEffect {
    Broadcast(Box<ShardMessage>),
    Reconstructed { key: BlockKey, contents: Bytes },
    Failed { key: BlockKey },
}

pub struct ShardReconstructor {
    me: PublicKey,
    my_index: u16,
    coding_config: CodingConfig,

    reconstruction: HashMap<BlockKey, ReconstructionState>,
    reconstruction_order: VecDeque<BlockKey>,
    known_keys: HashMap<BlockKey, PublicKey>,
    known_key_order: VecDeque<BlockKey>,
    pre_leader_buffer: HashMap<BlockKey, VecDeque<ShardMessage>>,
    pre_leader_order: VecDeque<BlockKey>,
}

impl ShardReconstructor {
    const MAX_RECONSTRUCTION_ENTRIES: usize = 64;
    const MAX_BUFFERED_RESHARDS: usize = 32;
    const MAX_PRE_LEADER_MESSAGES: usize = 64;
    const MAX_PRE_LEADER_KEYS: usize = 256;
    const MAX_KNOWN_KEYS: usize = 1024;

    pub fn new(me: PublicKey, my_index: u16, coding_config: CodingConfig) -> Self {
        Self {
            me,
            my_index,
            coding_config,
            reconstruction: HashMap::new(),
            reconstruction_order: VecDeque::new(),
            known_keys: HashMap::new(),
            known_key_order: VecDeque::new(),
            pre_leader_buffer: HashMap::new(),
            pre_leader_order: VecDeque::new(),
        }
    }

    pub const fn me(&self) -> &PublicKey {
        &self.me
    }

    pub const fn coding_config(&self) -> &CodingConfig {
        &self.coding_config
    }

    pub fn note_known_key(&mut self, key: BlockKey, leader: PublicKey) -> Vec<ShardMessage> {
        if !self.known_keys.contains_key(&key) {
            self.known_key_order.push_back(key);
        }
        self.known_keys.insert(key, leader);
        self.evict_known_keys();
        self.remove_buffered_pre_leader_key(key)
            .map(|queue| queue.into_iter().collect())
            .unwrap_or_default()
    }

    pub fn handle_message<F>(
        &mut self,
        message: ShardMessage,
        seen: &HashMap<Digest, Bytes>,
        validator_index: F,
    ) -> Vec<ShardEffect>
    where
        F: Fn(&PublicKey) -> Option<u16>,
    {
        let key = message.key();
        if seen.contains_key(&key.digest) {
            return Vec::new();
        }

        if !self.known_keys.contains_key(&key) && !self.reconstruction.contains_key(&key) {
            self.buffer_pre_leader_message(key, message);
            return Vec::new();
        }

        match message {
            ShardMessage::Initial {
                sender,
                commitment,
                shard,
                shard_index,
                ..
            } => self.handle_initial(key, sender, commitment, shard, shard_index),
            ShardMessage::ReShare {
                sender,
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
    ) -> Vec<ShardEffect> {
        let expected_leader = self.known_keys.get(&key).cloned().or_else(|| {
            self.reconstruction
                .get(&key)
                .map(|state| state.leader.clone())
        });
        let Some(expected_leader) = expected_leader else {
            return Vec::new();
        };

        if sender != expected_leader || shard_index != self.my_index {
            return Vec::new();
        }

        let mut effects = self.ensure_reconstruction_state(key, commitment, expected_leader);
        if !self.check_or_adopt_initial_commitment(key, commitment) {
            return effects;
        }

        let shard_hash = super::hash_encoded(&shard);
        let status = self
            .reconstruction
            .get(&key)
            .expect("reconstruction state should exist")
            .shard_status(shard_index, shard_hash);
        match status {
            DuplicateStatus::New => {}
            DuplicateStatus::Duplicate => return effects,
            DuplicateStatus::Equivocation => {
                warn!(
                    digest = ?key.digest,
                    shard_index,
                    ?sender,
                    "equivocation detected for initial shard"
                );
                return effects;
            }
        }

        let (checking_data, checked_shard, reshard) =
            match CodingImpl::reshard(&self.coding_config, &commitment, shard_index, shard) {
                Ok(tuple) => tuple,
                Err(_) => return effects,
            };

        if let Some(state) = self.reconstruction.get_mut(&key) {
            state.record_shard(shard_index, shard_hash);
            state.checking_data = Some(checking_data);
            state.checked_shards.push(checked_shard);
        }
        self.process_buffered_reshards(key);
        effects.push(ShardEffect::Broadcast(Box::new(ShardMessage::ReShare {
            sender: self.me.clone(),
            key,
            commitment,
            shard_index: self.my_index,
            reshard,
        })));
        if let Some(effect) = self.try_reconstruct(key) {
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
    ) -> Vec<ShardEffect>
    where
        F: Fn(&PublicKey) -> Option<u16>,
    {
        let leader = self.known_keys.get(&key).cloned().or_else(|| {
            self.reconstruction
                .get(&key)
                .map(|state| state.leader.clone())
        });
        let leader = leader.expect(
            "reshare key should be known or reconstructing due to handle_message pre-leader guard",
        );

        let Some(expected_index) = validator_index(&sender) else {
            return Vec::new();
        };
        if expected_index != shard_index {
            return Vec::new();
        }

        let mut effects = self.ensure_reconstruction_state(key, commitment, leader);
        if !self.commitment_matches_state(key, commitment) {
            warn!(
                digest = ?key.digest,
                shard_index,
                ?sender,
                "commitment mismatch for reshard"
            );
            return effects;
        }

        let shard_hash = super::hash_encoded(&reshard);
        let status = self
            .reconstruction
            .get(&key)
            .expect("reconstruction state should exist")
            .shard_status(shard_index, shard_hash);
        match status {
            DuplicateStatus::New => {}
            DuplicateStatus::Duplicate => return effects,
            DuplicateStatus::Equivocation => {
                warn!(
                    digest = ?key.digest,
                    shard_index,
                    ?sender,
                    "equivocation detected for reshard"
                );
                return effects;
            }
        }

        let checking_data = self
            .reconstruction
            .get(&key)
            .and_then(|state| state.checking_data.clone());
        let Some(checking_data) = checking_data else {
            if let Some(state) = self.reconstruction.get_mut(&key) {
                state.buffer_reshare(
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

        if let Some(state) = self.reconstruction.get_mut(&key) {
            state.record_shard(shard_index, shard_hash);
            state.checked_shards.push(checked);
        }
        if let Some(effect) = self.try_reconstruct(key) {
            effects.push(effect);
        }
        effects
    }

    fn ensure_reconstruction_state(
        &mut self,
        key: BlockKey,
        commitment: ZodaCommitment,
        leader: PublicKey,
    ) -> Vec<ShardEffect> {
        if self.reconstruction.contains_key(&key) {
            return Vec::new();
        }

        let mut effects = Vec::new();
        while self.reconstruction.len() >= Self::MAX_RECONSTRUCTION_ENTRIES {
            let Some(oldest) = self.reconstruction_order.pop_front() else {
                break;
            };
            self.reconstruction.remove(&oldest);
            self.remove_buffered_pre_leader_key(oldest);
            self.remove_known_key(oldest);
            effects.push(ShardEffect::Failed { key: oldest });
        }

        self.reconstruction
            .insert(key, ReconstructionState::new(commitment, leader));
        self.reconstruction_order.push_back(key);
        effects
    }

    fn process_buffered_reshards(&mut self, key: BlockKey) {
        let Some((commitment, checking_data, buffered)) =
            self.reconstruction.get_mut(&key).and_then(|state| {
                let checking_data = state.checking_data.clone()?;
                Some((
                    state.commitment,
                    checking_data,
                    state.take_buffered_reshards(),
                ))
            })
        else {
            return;
        };

        for buffered in buffered {
            let status = self
                .reconstruction
                .get(&key)
                .expect("reconstruction state should exist")
                .shard_status(buffered.shard_index, buffered.shard_hash);
            match status {
                DuplicateStatus::New => {}
                DuplicateStatus::Duplicate => continue,
                DuplicateStatus::Equivocation => {
                    warn!(
                        digest = ?key.digest,
                        shard_index = buffered.shard_index,
                        sender = ?buffered.sender,
                        "equivocation detected for buffered reshard"
                    );
                    continue;
                }
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
            if let Some(state) = self.reconstruction.get_mut(&key) {
                state.record_shard(buffered.shard_index, buffered.shard_hash);
                state.checked_shards.push(checked);
            }
        }
    }

    fn try_reconstruct(&mut self, key: BlockKey) -> Option<ShardEffect> {
        let reconstructed = {
            let state = self.reconstruction.get(&key)?;
            if !state.has_minimum_shards(self.coding_config.minimum_shards) {
                return None;
            }
            let checking_data = state.checking_data.clone()?;
            match CodingImpl::decode(
                &self.coding_config,
                &state.commitment,
                checking_data,
                state.checked_shards.as_slice(),
                &Sequential,
            ) {
                Ok(decoded) => decoded,
                Err(_) => {
                    self.cleanup_reconstruction_key(key);
                    return Some(ShardEffect::Failed { key });
                }
            }
        };

        if Sha256::hash(reconstructed.as_slice()) != key.digest {
            self.cleanup_reconstruction_key(key);
            return Some(ShardEffect::Failed { key });
        }

        self.cleanup_reconstruction_key(key);
        Some(ShardEffect::Reconstructed {
            key,
            contents: Bytes::from(reconstructed),
        })
    }

    fn cleanup_reconstruction_key(&mut self, key: BlockKey) {
        self.reconstruction.remove(&key);
        if let Some(pos) = self
            .reconstruction_order
            .iter()
            .position(|item| *item == key)
        {
            self.reconstruction_order.remove(pos);
        }
        self.remove_buffered_pre_leader_key(key);
        self.remove_known_key(key);
    }

    fn check_or_adopt_initial_commitment(
        &mut self,
        key: BlockKey,
        commitment: ZodaCommitment,
    ) -> bool {
        let Some(state) = self.reconstruction.get_mut(&key) else {
            return false;
        };
        if state.commitment == commitment {
            return true;
        }
        if state.checking_data.is_none() && state.checked_shards.is_empty() {
            state.commitment = commitment;
            return true;
        }
        warn!(digest = ?key.digest, "commitment mismatch for initial shard");
        false
    }

    fn commitment_matches_state(&self, key: BlockKey, commitment: ZodaCommitment) -> bool {
        self.reconstruction
            .get(&key)
            .is_some_and(|state| state.commitment == commitment)
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
            if self.reconstruction.contains_key(&oldest) {
                self.known_key_order.push_back(oldest);
                attempts_left -= 1;
                continue;
            }
            self.known_keys.remove(&oldest);
            self.remove_buffered_pre_leader_key(oldest);
            attempts_left = self.known_key_order.len();
        }

        if self.known_keys.len() > Self::MAX_KNOWN_KEYS {
            warn!(
                known_keys = self.known_keys.len(),
                max_known_keys = Self::MAX_KNOWN_KEYS,
                "unable to evict known keys because all candidates are active reconstructions"
            );
        }
    }

    fn remove_known_key(&mut self, key: BlockKey) {
        if let Some(pos) = self.known_key_order.iter().position(|item| *item == key) {
            self.known_key_order.remove(pos);
        }
        self.known_keys.remove(&key);
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
        leader: PublicKey,
        my_index: u16,
        reconstructor: ShardReconstructor,
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
            let reconstructor = ShardReconstructor::new(me, my_index, coding_config(6));
            Self {
                validators,
                leader,
                my_index,
                reconstructor,
            }
        }

        fn validator_index(&self, sender: &PublicKey) -> Option<u16> {
            self.validators
                .iter()
                .position(|pk| pk == sender)
                .and_then(|idx| u16::try_from(idx).ok())
        }

        fn make_artifacts(&self, view: u64, payload: &[u8]) -> BlockArtifacts {
            let key = BlockKey::new(
                Round::new(Epoch::new(1), View::new(view)),
                Sha256::hash(payload),
            );
            let (commitment, shards) =
                CodingImpl::encode(self.reconstructor.coding_config(), payload, &Sequential)
                    .expect("encode should succeed");
            let mut reshares = Vec::with_capacity(shards.len());
            for (idx, shard) in shards.iter().cloned().enumerate() {
                let shard_index = u16::try_from(idx).expect("index should fit into u16");
                let (_, _, reshard) = CodingImpl::reshard(
                    self.reconstructor.coding_config(),
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

    fn has_reconstructed(effects: &[ShardEffect], key: BlockKey) -> bool {
        effects
            .iter()
            .any(|effect| matches!(effect, ShardEffect::Reconstructed { key: reconstructed, .. } if *reconstructed == key))
    }

    #[test]
    fn pre_leader_reshare_is_drained_after_note_known_key() {
        let mut fixture = Fixture::new();
        let artifacts = fixture.make_artifacts(1, b"buffer-then-reconstruct");
        let sender = fixture.validators[2].clone();
        let shard_index = 2u16;
        let reshare = artifacts.reshares[usize::from(shard_index)].clone();

        let seen = HashMap::<Digest, Bytes>::new();
        let validators = fixture.validators.clone();
        let buffered = fixture.reconstructor.handle_message(
            ShardMessage::ReShare {
                sender: sender.clone(),
                key: artifacts.key,
                commitment: artifacts.commitment,
                shard_index,
                reshard: reshare,
            },
            &seen,
            |pk| {
                validators
                    .iter()
                    .position(|validator| validator == pk)
                    .and_then(|idx| u16::try_from(idx).ok())
            },
        );
        assert!(buffered.is_empty());
        assert!(
            fixture
                .reconstructor
                .pre_leader_buffer
                .contains_key(&artifacts.key)
        );

        let drained = fixture
            .reconstructor
            .note_known_key(artifacts.key, fixture.leader.clone());
        assert_eq!(drained.len(), 1);

        let validators = fixture.validators.clone();
        for msg in drained {
            let _ = fixture.reconstructor.handle_message(msg, &seen, |pk| {
                validators
                    .iter()
                    .position(|validator| validator == pk)
                    .and_then(|idx| u16::try_from(idx).ok())
            });
        }

        let validators = fixture.validators.clone();
        let effects = fixture.reconstructor.handle_message(
            ShardMessage::Initial {
                sender: fixture.leader.clone(),
                key: artifacts.key,
                commitment: artifacts.commitment,
                shard: artifacts.shards[usize::from(fixture.my_index)].clone(),
                shard_index: fixture.my_index,
            },
            &seen,
            |pk| {
                validators
                    .iter()
                    .position(|validator| validator == pk)
                    .and_then(|idx| u16::try_from(idx).ok())
            },
        );
        assert!(has_reconstructed(&effects, artifacts.key));
    }

    #[test]
    fn wrong_sender_initial_does_not_poison_commitment() {
        let mut fixture = Fixture::new();
        let good = fixture.make_artifacts(2, b"good-payload");
        let bad = fixture.make_artifacts(2, b"bad-payload");
        let attacker = fixture.validators[3].clone();
        let helper = fixture.validators[2].clone();

        let _ = fixture
            .reconstructor
            .note_known_key(good.key, fixture.leader.clone());
        let seen = HashMap::<Digest, Bytes>::new();

        let validators = fixture.validators.clone();
        let malicious = fixture.reconstructor.handle_message(
            ShardMessage::Initial {
                sender: attacker,
                key: good.key,
                commitment: bad.commitment,
                shard: bad.shards[usize::from(fixture.my_index)].clone(),
                shard_index: fixture.my_index,
            },
            &seen,
            |pk| {
                validators
                    .iter()
                    .position(|validator| validator == pk)
                    .and_then(|idx| u16::try_from(idx).ok())
            },
        );
        assert!(malicious.is_empty());

        let validators = fixture.validators.clone();
        let _ = fixture.reconstructor.handle_message(
            ShardMessage::Initial {
                sender: fixture.leader.clone(),
                key: good.key,
                commitment: good.commitment,
                shard: good.shards[usize::from(fixture.my_index)].clone(),
                shard_index: fixture.my_index,
            },
            &seen,
            |pk| {
                validators
                    .iter()
                    .position(|validator| validator == pk)
                    .and_then(|idx| u16::try_from(idx).ok())
            },
        );

        let helper_index = fixture.validator_index(&helper).expect("known validator");
        let validators = fixture.validators.clone();
        let effects = fixture.reconstructor.handle_message(
            ShardMessage::ReShare {
                sender: helper,
                key: good.key,
                commitment: good.commitment,
                shard_index: helper_index,
                reshard: good.reshares[usize::from(helper_index)].clone(),
            },
            &seen,
            |pk| {
                validators
                    .iter()
                    .position(|validator| validator == pk)
                    .and_then(|idx| u16::try_from(idx).ok())
            },
        );
        assert!(has_reconstructed(&effects, good.key));
    }

    #[test]
    fn known_keys_stay_bounded_with_active_oldest_reconstruction() {
        let mut fixture = Fixture::new();
        let active = fixture.make_artifacts(3, b"active-reconstruction");
        let helper = fixture.validators[2].clone();
        let helper_index = fixture.validator_index(&helper).expect("known validator");

        let _ = fixture
            .reconstructor
            .note_known_key(active.key, fixture.leader.clone());
        let seen = HashMap::<Digest, Bytes>::new();
        let validators = fixture.validators.clone();
        let _ = fixture.reconstructor.handle_message(
            ShardMessage::ReShare {
                sender: helper,
                key: active.key,
                commitment: active.commitment,
                shard_index: helper_index,
                reshard: active.reshares[usize::from(helper_index)].clone(),
            },
            &seen,
            |pk| {
                validators
                    .iter()
                    .position(|validator| validator == pk)
                    .and_then(|idx| u16::try_from(idx).ok())
            },
        );
        assert!(
            fixture
                .reconstructor
                .reconstruction
                .contains_key(&active.key)
        );

        for view in 10u64..(10u64 + ShardReconstructor::MAX_KNOWN_KEYS as u64 + 64u64) {
            let key = BlockKey::new(
                Round::new(Epoch::new(2), View::new(view)),
                Sha256::hash(&view.to_le_bytes()),
            );
            let _ = fixture
                .reconstructor
                .note_known_key(key, fixture.leader.clone());
        }

        assert!(fixture.reconstructor.known_keys.len() <= ShardReconstructor::MAX_KNOWN_KEYS);
        assert!(
            fixture
                .reconstructor
                .reconstruction
                .contains_key(&active.key)
        );
    }

    proptest! {
        #[test]
        fn reconstructs_with_one_valid_reshare_prop(
            payload in prop::collection::vec(any::<u8>(), 50..256),
            peer_index in 0u16..6u16,
            reshare_first in any::<bool>(),
        ) {
            prop_assume!(peer_index != 1);
            let mut fixture = Fixture::new();
            let artifacts = fixture.make_artifacts(4, payload.as_slice());
            let _ = fixture.reconstructor.note_known_key(artifacts.key, fixture.leader.clone());
            let seen = HashMap::<Digest, Bytes>::new();
            let peer = fixture.validators[usize::from(peer_index)].clone();

            let initial = ShardMessage::Initial {
                sender: fixture.leader.clone(),
                key: artifacts.key,
                commitment: artifacts.commitment,
                shard: artifacts.shards[usize::from(fixture.my_index)].clone(),
                shard_index: fixture.my_index,
            };
            let reshare = ShardMessage::ReShare {
                sender: peer,
                key: artifacts.key,
                commitment: artifacts.commitment,
                shard_index: peer_index,
                reshard: artifacts.reshares[usize::from(peer_index)].clone(),
            };

            let mut effects = Vec::new();
            let validators = fixture.validators.clone();
            if reshare_first {
                effects.extend(fixture.reconstructor.handle_message(reshare, &seen, |pk| {
                    validators
                        .iter()
                        .position(|validator| validator == pk)
                        .and_then(|idx| u16::try_from(idx).ok())
                }));
                let validators = fixture.validators.clone();
                effects.extend(fixture.reconstructor.handle_message(initial, &seen, |pk| {
                    validators
                        .iter()
                        .position(|validator| validator == pk)
                        .and_then(|idx| u16::try_from(idx).ok())
                }));
            } else {
                effects.extend(fixture.reconstructor.handle_message(initial, &seen, |pk| {
                    validators
                        .iter()
                        .position(|validator| validator == pk)
                        .and_then(|idx| u16::try_from(idx).ok())
                }));
                let validators = fixture.validators.clone();
                effects.extend(fixture.reconstructor.handle_message(reshare, &seen, |pk| {
                    validators
                        .iter()
                        .position(|validator| validator == pk)
                        .and_then(|idx| u16::try_from(idx).ok())
                }));
            }

            prop_assert!(has_reconstructed(&effects, artifacts.key));
        }
    }
}
