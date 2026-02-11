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

    pub(crate) fn declare(&self, public_key: PublicKey) {
        if self.finalized.load(Ordering::Relaxed) {
            warn!("attempted to declare validator after finalization; ignoring");
            return;
        }
        let mut validators = self.lock_validators();
        if !validators.contains(&public_key) {
            validators.push(public_key);
        }
    }

    pub(crate) fn finalize(&self) {
        let mut validators = self.lock_validators();
        validators.sort();
        validators.dedup();
        self.finalized.store(true, Ordering::Relaxed);
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
        if !self.finalized.load(Ordering::Relaxed) {
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
