use hellas_types::PublicKey;
use std::sync::{Mutex, MutexGuard};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum DistributionError {
    #[error("shard count mismatch: shards={shards} validators={validators}")]
    CountMismatch { shards: usize, validators: usize },
    #[error("validator index too large: {index}")]
    IndexTooLarge { index: usize },
    #[error("validator set not finalized")]
    NotFinalized,
}

enum ValidatorPhase {
    Collecting(Vec<PublicKey>),
    Finalized(Vec<PublicKey>),
}

impl ValidatorPhase {
    fn validators(&self) -> &Vec<PublicKey> {
        match self {
            Self::Collecting(validators) | Self::Finalized(validators) => validators,
        }
    }

    fn finalized(&self) -> Option<&Vec<PublicKey>> {
        match self {
            Self::Finalized(validators) => Some(validators),
            Self::Collecting(_) => None,
        }
    }
}

pub(crate) struct ValidatorSet {
    phase: Mutex<ValidatorPhase>,
}

impl ValidatorSet {
    pub(crate) fn new() -> Self {
        Self {
            phase: Mutex::new(ValidatorPhase::Collecting(Vec::new())),
        }
    }

    pub(crate) fn declare(&self, public_key: &PublicKey) {
        let mut phase = self.lock_phase();
        match &mut *phase {
            ValidatorPhase::Collecting(validators) => {
                if !validators.contains(public_key) {
                    validators.push(public_key.clone());
                }
            }
            ValidatorPhase::Finalized(_) => {
                warn!("attempted to declare validator after finalization; ignoring");
            }
        }
    }

    pub(crate) fn finalize(&self) {
        let mut phase = self.lock_phase();
        let ValidatorPhase::Collecting(validators) = &mut *phase else {
            return;
        };
        validators.sort();
        validators.dedup();
        let finalized = std::mem::take(validators);
        *phase = ValidatorPhase::Finalized(finalized);
    }

    pub(crate) fn count(&self) -> u16 {
        let phase = self.lock_phase();
        match u16::try_from(phase.validators().len()) {
            Ok(count) => count,
            Err(_) => {
                warn!(
                    validator_count = phase.validators().len(),
                    "validator count overflowed u16; saturating to u16::MAX"
                );
                u16::MAX
            }
        }
    }

    pub(crate) fn index(&self, public_key: &PublicKey) -> Option<u16> {
        let phase = self.lock_phase();
        let validators = phase.finalized()?;
        validators
            .binary_search(public_key)
            .ok()
            .and_then(|idx| u16::try_from(idx).ok())
    }

    pub(crate) fn others(&self, excluded: &PublicKey) -> Vec<PublicKey> {
        let phase = self.lock_phase();
        let Some(validators) = phase.finalized() else {
            warn!("attempted to list peers before validator finalization");
            return Vec::new();
        };
        validators
            .iter()
            .filter(|pk| *pk != excluded)
            .cloned()
            .collect()
    }

    pub(crate) fn assign_shards<T>(
        &self,
        proposer: &PublicKey,
        shards: Vec<T>,
    ) -> Result<Vec<(PublicKey, u16, T)>, DistributionError> {
        let validators = {
            let phase = self.lock_phase();
            match &*phase {
                ValidatorPhase::Finalized(validators) => validators.clone(),
                ValidatorPhase::Collecting(_) => return Err(DistributionError::NotFinalized),
            }
        };
        if shards.len() != validators.len() {
            return Err(DistributionError::CountMismatch {
                shards: shards.len(),
                validators: validators.len(),
            });
        }

        let mut assignments = Vec::with_capacity(shards.len().saturating_sub(1));
        for (idx, (target, shard)) in validators.into_iter().zip(shards).enumerate() {
            if &target == proposer {
                continue;
            }
            let shard_index = match u16::try_from(idx) {
                Ok(value) => value,
                Err(_) => return Err(DistributionError::IndexTooLarge { index: idx }),
            };
            assignments.push((target, shard_index, shard));
        }
        Ok(assignments)
    }

    fn lock_phase(&self) -> MutexGuard<'_, ValidatorPhase> {
        match self.phase.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("validator set lock poisoned; continuing with inner state");
                poisoned.into_inner()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer, ed25519};

    #[test_log::test]
    fn declare_after_finalize_is_ignored() {
        let set = ValidatorSet::new();
        let a = ed25519::PrivateKey::from_seed(1).public_key();
        let b = ed25519::PrivateKey::from_seed(2).public_key();

        set.declare(&a);
        set.finalize();
        set.declare(&b);

        assert_eq!(set.count(), 1);
        assert!(set.index(&a).is_some());
        assert!(set.index(&b).is_none());
    }

    #[test_log::test]
    fn assign_shards_skips_proposer() {
        let set = ValidatorSet::new();
        let validators: Vec<_> = [9u64, 2u64, 7u64, 4u64]
            .into_iter()
            .map(|seed| ed25519::PrivateKey::from_seed(seed).public_key())
            .collect();
        for validator in validators.iter() {
            set.declare(validator);
        }
        set.finalize();

        let proposer = validators[1].clone();
        let shards = vec![10u8, 11u8, 12u8, 13u8];
        let assignments = set
            .assign_shards(&proposer, shards)
            .expect("assignment should succeed");

        assert_eq!(assignments.len(), validators.len().saturating_sub(1));
        assert!(assignments.iter().all(|(target, _, _)| target != &proposer));
    }

    #[test_log::test]
    fn assign_shards_count_mismatch() {
        let set = ValidatorSet::new();
        let validators: Vec<_> = [1u64, 2u64, 3u64, 4u64]
            .into_iter()
            .map(|seed| ed25519::PrivateKey::from_seed(seed).public_key())
            .collect();
        for validator in validators.iter() {
            set.declare(validator);
        }
        set.finalize();

        let proposer = validators[0].clone();
        let err = set
            .assign_shards(&proposer, vec![1u8, 2u8, 3u8])
            .expect_err("count mismatch should fail");
        assert!(matches!(
            err,
            DistributionError::CountMismatch {
                shards: 3,
                validators: 4
            }
        ));
    }

    #[test_log::test]
    fn assign_shards_requires_finalized_validators() {
        let set = ValidatorSet::new();
        let proposer = ed25519::PrivateKey::from_seed(1).public_key();
        set.declare(&proposer);

        let err = set
            .assign_shards(&proposer, vec![1u8])
            .expect_err("assignment should fail before finalize");
        assert!(matches!(err, DistributionError::NotFinalized));
    }
}

#[cfg(all(test, feature = "loom-tests"))]
mod loom_tests {
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    enum LoomValidatorPhase {
        Collecting(Vec<u8>),
        Finalized(Vec<u8>),
    }

    struct LoomValidatorSet {
        phase: Mutex<LoomValidatorPhase>,
    }

    impl LoomValidatorSet {
        fn new() -> Self {
            Self {
                phase: Mutex::new(LoomValidatorPhase::Collecting(Vec::new())),
            }
        }

        fn declare(&self, public_key: &u8) {
            let mut phase = self.phase.lock().expect("lock should succeed");
            match &mut *phase {
                LoomValidatorPhase::Collecting(validators) => {
                    if !validators.contains(public_key) {
                        validators.push(*public_key);
                    }
                }
                LoomValidatorPhase::Finalized(_) => {}
            }
        }

        fn finalize(&self) {
            let mut phase = self.phase.lock().expect("lock should succeed");
            let LoomValidatorPhase::Collecting(validators) = &mut *phase else {
                return;
            };
            validators.sort();
            validators.dedup();
            let finalized = std::mem::take(validators);
            *phase = LoomValidatorPhase::Finalized(finalized);
        }

        fn count(&self) -> usize {
            let phase = self.phase.lock().expect("lock should succeed");
            match &*phase {
                LoomValidatorPhase::Collecting(validators)
                | LoomValidatorPhase::Finalized(validators) => validators.len(),
            }
        }

        fn index(&self, public_key: &u8) -> Option<usize> {
            let phase = self.phase.lock().expect("lock should succeed");
            let LoomValidatorPhase::Finalized(validators) = &*phase else {
                return None;
            };
            validators.binary_search(public_key).ok()
        }
    }

    fn run_model<F>(f: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        let mut builder = loom::model::Builder::new();
        builder.max_threads = 4;
        builder.max_branches = 64;
        builder.max_permutations = Some(2_000);
        builder.preemption_bound = Some(2);
        builder.check(f);
    }

    #[test_log::test]
    fn declare_finalize_race_keeps_ordered_unique_membership() {
        run_model(|| {
            let set = Arc::new(LoomValidatorSet::new());
            let a = 1u8;
            let b = 2u8;
            let c = 3u8;

            set.declare(&a);

            let set_b = set.clone();
            let b_cloned = b.clone();
            let join_b = thread::spawn(move || {
                set_b.declare(&b_cloned);
            });

            let set_finalize = set.clone();
            let join_finalize = thread::spawn(move || {
                set_finalize.finalize();
            });

            let set_c = set.clone();
            let c_cloned = c.clone();
            let join_c = thread::spawn(move || {
                set_c.declare(&c_cloned);
            });

            join_b.join().expect("declare b should join");
            join_finalize.join().expect("finalize should join");
            join_c.join().expect("declare c should join");

            // Ensure we end in finalized phase for index() checks.
            set.finalize();

            let count = set.count();
            assert!((1..=3).contains(&count));

            let mut indexes = Vec::new();
            for candidate in [&a, &b, &c] {
                if let Some(idx) = set.index(candidate) {
                    indexes.push(idx);
                }
            }
            assert!(indexes.windows(2).all(|window| window[0] < window[1]));
        });
    }

    #[test_log::test]
    fn duplicate_declare_race_deduplicates() {
        run_model(|| {
            let set = Arc::new(LoomValidatorSet::new());
            let a = 7u8;
            set.declare(&a);

            let set_1 = set.clone();
            let a_1 = a.clone();
            let join_1 = thread::spawn(move || {
                set_1.declare(&a_1);
            });

            let set_2 = set.clone();
            let a_2 = a.clone();
            let join_2 = thread::spawn(move || {
                set_2.declare(&a_2);
            });

            let set_finalize = set.clone();
            let join_finalize = thread::spawn(move || {
                set_finalize.finalize();
            });

            join_1.join().expect("declare #1 should join");
            join_2.join().expect("declare #2 should join");
            join_finalize.join().expect("finalize should join");

            set.finalize();
            assert_eq!(set.count(), 1);
            assert_eq!(set.index(&a), Some(0));
        });
    }
}
