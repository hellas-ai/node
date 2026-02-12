use super::codec::WireShardMessage;
use super::core::{ShardEffect, ShardRecoverer};
use super::protocol::{
    BlockKey, CodingImpl, ShardMessage, ZodaCommitment, ZodaShard, coding_config,
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_coding::Scheme as CodingScheme;
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::{Hasher, Sha256, Signer, ed25519, sha256::Digest};
use commonware_parallel::Sequential;
use hellas_types::PublicKey;
use std::collections::HashMap;

struct EncodedArtifacts {
    key: BlockKey,
    commitment: ZodaCommitment,
    shards: Vec<ZodaShard>,
}

fn validator_keys(count: usize) -> Vec<PublicKey> {
    let mut validators: Vec<_> = (0..count)
        .map(|seed| {
            ed25519::PrivateKey::from_seed(u64::try_from(seed).expect("seed should fit u64"))
                .public_key()
        })
        .collect();
    validators.sort();
    validators
}

fn encode_artifacts(validators: u16, view: u64, payload: &[u8]) -> EncodedArtifacts {
    let config = coding_config(validators);
    let (commitment, shards) =
        CodingImpl::encode(&config, payload, &Sequential).expect("encode should succeed");
    let key = BlockKey::new(
        Round::new(Epoch::new(1), View::new(view)),
        Sha256::hash(payload),
    );
    EncodedArtifacts {
        key,
        commitment,
        shards,
    }
}

fn is_recovered_for_key(effect: &ShardEffect, key: BlockKey) -> bool {
    matches!(effect, ShardEffect::Recovered { key: recovered, .. } if *recovered == key)
}

pub fn encode_shards_once(validators: u16, payload: &[u8]) -> usize {
    let config = coding_config(validators);
    let (_commitment, shards) =
        CodingImpl::encode(&config, payload, &Sequential).expect("encode should succeed");
    shards.len()
}

pub fn wire_roundtrip_once(validators: u16, payload: &[u8]) -> bool {
    assert!(
        validators >= 3,
        "wire_roundtrip_once requires at least 3 validators"
    );
    let artifacts = encode_artifacts(validators, 1, payload);
    let helper_index = 2u16;
    let (_, _, helper_reshare) = CodingImpl::reshard(
        &coding_config(validators),
        &artifacts.commitment,
        helper_index,
        artifacts.shards[usize::from(helper_index)].clone(),
    )
    .expect("reshard should succeed");

    let initial = WireShardMessage::Initial {
        key: artifacts.key,
        commitment: artifacts.commitment,
        shard: artifacts.shards[0].clone(),
        shard_index: 0,
    };
    let initial_encoded = initial.encode();
    let Some(initial_decoded) = WireShardMessage::decode(initial_encoded.clone()) else {
        return false;
    };
    if initial_decoded.encode() != initial_encoded {
        return false;
    }

    let reshare = WireShardMessage::ReShare {
        key: artifacts.key,
        commitment: artifacts.commitment,
        shard_index: helper_index,
        reshard: helper_reshare,
    };
    let reshare_encoded = reshare.encode();
    let Some(reshare_decoded) = WireShardMessage::decode(reshare_encoded.clone()) else {
        return false;
    };
    reshare_decoded.encode() == reshare_encoded
}

pub fn recover_with_one_helper_once(validators: u16, payload: &[u8]) -> bool {
    assert!(
        validators >= 3,
        "recover_with_one_helper_once requires at least 3 validators"
    );
    let validator_count = usize::from(validators);
    let validator_list = validator_keys(validator_count);
    let index_by_validator: HashMap<_, _> = validator_list
        .iter()
        .enumerate()
        .map(|(idx, key)| {
            (
                key.clone(),
                u16::try_from(idx).expect("validator index should fit u16"),
            )
        })
        .collect();

    let leader = validator_list[0].clone();
    let my_index = 1u16;
    let me = validator_list[usize::from(my_index)].clone();
    let helper = validator_list[2].clone();
    let helper_index = *index_by_validator
        .get(&helper)
        .expect("helper index should exist");

    let artifacts = encode_artifacts(validators, 2, payload);
    let (_, _, helper_reshare) = CodingImpl::reshard(
        &coding_config(validators),
        &artifacts.commitment,
        helper_index,
        artifacts.shards[usize::from(helper_index)].clone(),
    )
    .expect("reshard should succeed");

    let mut recoverer = ShardRecoverer::new(
        &me,
        my_index,
        coding_config(validators),
        crate::coding_strategy(),
    );
    let _drained = recoverer.note_known_key(artifacts.key, &leader);
    let seen = HashMap::<Digest, Bytes>::new();

    let initial = ShardMessage::initial(
        &leader,
        artifacts.key,
        artifacts.commitment,
        artifacts.shards[usize::from(my_index)].clone(),
        my_index,
    );
    let effects =
        recoverer.handle_message(initial, &seen, |key| index_by_validator.get(key).copied());
    if effects
        .into_iter()
        .any(|effect| is_recovered_for_key(&effect, artifacts.key))
    {
        return true;
    }

    let reshare = ShardMessage::reshare(
        &helper,
        artifacts.key,
        artifacts.commitment,
        helper_index,
        helper_reshare,
    );
    let effects =
        recoverer.handle_message(reshare, &seen, |key| index_by_validator.get(key).copied());
    effects
        .into_iter()
        .any(|effect| is_recovered_for_key(&effect, artifacts.key))
}
