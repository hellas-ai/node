use super::protocol::{CodingImpl, WireShardMessage, coding_config};
use commonware_codec::Encode;
use commonware_coding::Scheme as CodingScheme;
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::Sequential;

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
    let config = coding_config(validators);
    let (commitment, shards) =
        CodingImpl::encode(&config, payload, &Sequential).expect("encode should succeed");
    let key = super::protocol::BlockKey::new(
        Round::new(Epoch::new(1), View::new(1)),
        Sha256::hash(payload),
    );
    let helper_index = 2u16;
    let (_, _, helper_reshare) = CodingImpl::reshard(
        &config,
        &commitment,
        helper_index,
        shards[usize::from(helper_index)].clone(),
    )
    .expect("reshard should succeed");

    let initial = WireShardMessage::Initial {
        key,
        commitment,
        shard: shards[0].clone(),
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
        key,
        commitment,
        shard_index: helper_index,
        reshard: helper_reshare,
    };
    let reshare_encoded = reshare.encode();
    let Some(reshare_decoded) = WireShardMessage::decode(reshare_encoded.clone()) else {
        return false;
    };
    reshare_decoded.encode() == reshare_encoded
}

/// Exercises a single-block recovery with one helper using direct crypto calls.
///
/// Steps: encode → reshard (self) → reshard (helper) → check (helper's reshare) → decode.
pub fn recover_with_one_helper_once(validators: u16, payload: &[u8]) -> bool {
    assert!(
        validators >= 3,
        "recover_with_one_helper_once requires at least 3 validators"
    );
    let config = coding_config(validators);
    let (commitment, shards) =
        CodingImpl::encode(&config, payload, &Sequential).expect("encode should succeed");

    let my_index = 1u16;
    let helper_index = 2u16;

    // Reshard our own shard (as if received from the leader).
    let (checking_data, my_checked, _my_reshard) = CodingImpl::reshard(
        &config,
        &commitment,
        my_index,
        shards[usize::from(my_index)].clone(),
    )
    .expect("reshard should succeed");

    // Helper reshards their shard and sends us their reshard.
    let (_, _, helper_reshard) = CodingImpl::reshard(
        &config,
        &commitment,
        helper_index,
        shards[usize::from(helper_index)].clone(),
    )
    .expect("helper reshard should succeed");

    // We check the helper's reshard.
    let helper_checked = CodingImpl::check(
        &config,
        &commitment,
        &checking_data,
        helper_index,
        helper_reshard,
    )
    .expect("check should succeed");

    // Decode with our checked shard + helper's checked shard.
    let reconstructed = CodingImpl::decode(
        &config,
        &commitment,
        checking_data,
        &[my_checked, helper_checked],
        &Sequential,
    )
    .expect("decode should succeed");

    Sha256::hash(&reconstructed) == Sha256::hash(payload)
}
