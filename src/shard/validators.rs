use hellas_types::PublicKey;
use std::sync::{
    Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum DistributionError {
    #[error("shard count mismatch: shards={shards} validators={validators}")]
    CountMismatch { shards: usize, validators: usize },
    #[error("validator index too large: {index}")]
    IndexTooLarge { index: usize },
}

pub(crate) struct ValidatorSet {
    validators: Mutex<Vec<PublicKey>>,
    finalized: AtomicBool,
}

impl ValidatorSet {
    pub(crate) fn new() -> Self {
        Self {
            validators: Mutex::new(Vec::new()),
            finalized: AtomicBool::new(false),
        }
    }

    pub(crate) fn declare(&self, public_key: &PublicKey) {
        // Check finalization after taking the lock to avoid a declare/finalize
        // race that could append unsorted entries after finalization.
        let mut validators = self.lock_validators();
        if self.finalized.load(Ordering::Acquire) {
            warn!("attempted to declare validator after finalization; ignoring");
            return;
        }
        if !validators.contains(public_key) {
            validators.push(public_key.clone());
        }
    }

    pub(crate) fn finalize(&self) {
        let mut validators = self.lock_validators();
        validators.sort();
        validators.dedup();
        self.finalized.store(true, Ordering::Release);
    }

    pub(crate) fn count(&self) -> u16 {
        let validators = self.lock_validators();
        match u16::try_from(validators.len()) {
            Ok(count) => count,
            Err(_) => {
                warn!(
                    validator_count = validators.len(),
                    "validator count overflowed u16; saturating to u16::MAX"
                );
                u16::MAX
            }
        }
    }

    pub(crate) fn index(&self, public_key: &PublicKey) -> Option<u16> {
        if !self.finalized.load(Ordering::Acquire) {
            return None;
        }
        let validators = self.lock_validators();
        validators
            .binary_search(public_key)
            .ok()
            .and_then(|idx| u16::try_from(idx).ok())
    }

    pub(crate) fn others(&self, excluded: &PublicKey) -> Vec<PublicKey> {
        let validators = self.lock_validators();
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
        let validators = self.lock_validators().clone();
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

    fn lock_validators(&self) -> MutexGuard<'_, Vec<PublicKey>> {
        match self.validators.lock() {
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

    #[test]
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

    #[test]
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

    #[test]
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
}
