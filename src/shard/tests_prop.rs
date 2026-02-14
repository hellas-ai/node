use super::{CodingImpl, DuplicateStatus, ReconstructionState, coding_config};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::Sequential;
use proptest::prelude::*;

fn sample_artifacts(
    payload: &[u8],
) -> (
    commonware_coding::Config,
    super::ZodaCommitment,
    Vec<super::ZodaShard>,
    super::ZodaReShard,
    super::ZodaReShard,
) {
    let config = coding_config(6);
    let (commitment, shards) = CodingImpl::encode(&config, payload, &Sequential).unwrap();
    let (_, _, reshard_0) =
        CodingImpl::reshard(&config, &commitment, 0, shards[0].clone()).unwrap();
    let (_, _, reshard_1) =
        CodingImpl::reshard(&config, &commitment, 1, shards[1].clone()).unwrap();
    (config, commitment, shards, reshard_0, reshard_1)
}

proptest! {
    #[test]
    fn zoda_roundtrip_prop(
        payload in prop::collection::vec(any::<u8>(), 50..512),
        first in 0u16..6u16,
        second in 0u16..6u16,
    ) {
        prop_assume!(first != second);
        let config = coding_config(6);
        let (commitment, shards) = CodingImpl::encode(&config, payload.as_slice(), &Sequential).unwrap();

        let (checking_data, checked_first, _) =
            CodingImpl::reshard(&config, &commitment, first, shards[first as usize].clone()).unwrap();
        let (_, _, reshard_second) =
            CodingImpl::reshard(&config, &commitment, second, shards[second as usize].clone()).unwrap();
        let checked_second =
            CodingImpl::check(&config, &commitment, &checking_data, second, reshard_second).unwrap();

        let checked = vec![checked_first, checked_second];
        let decoded = CodingImpl::decode(&config, &commitment, checking_data, &checked, &Sequential).unwrap();
        prop_assert_eq!(Sha256::hash(decoded.as_slice()), Sha256::hash(payload.as_slice()));
    }

    #[test]
    fn shard_status_detects_equivocation_prop(
        idx in any::<u16>(),
        first in prop::collection::vec(any::<u8>(), 1..64),
        second in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(first != second);
        let (_, commitment, _, _, _) = sample_artifacts(b"sample payload");
        let mut state = ReconstructionState::new(commitment);
        let first_hash = Sha256::hash(first.as_slice());
        let second_hash = Sha256::hash(second.as_slice());

        prop_assert_eq!(state.shard_status(idx, first_hash), DuplicateStatus::New);
        state.record_shard(idx, first_hash);
        prop_assert_eq!(state.shard_status(idx, first_hash), DuplicateStatus::Duplicate);
        prop_assert_eq!(state.shard_status(idx, second_hash), DuplicateStatus::Equivocation);
    }
}

#[test]
fn commitment_mismatch_is_rejected() {
    let (cfg_a, commitment_a, _, _, _) = sample_artifacts(b"payload-a");
    let (_, commitment_b, shards_b, _, _) = sample_artifacts(b"payload-b");
    assert_ne!(commitment_a, commitment_b);

    let result = CodingImpl::reshard(&cfg_a, &commitment_a, 0, shards_b[0].clone());
    assert!(result.is_err());
}
