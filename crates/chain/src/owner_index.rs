use crate::HellasBlock;
use crate::domain::{
    Address, Coin, ObjectId, SettlementKey, Transaction, genesis_object_id, output_object_id,
};
use commonware_codec::Encode;
use commonware_consensus::{Block as _, Heightable};
use commonware_cryptography::{Digestible, Hasher, Sha256, sha256::Digest};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerCursor {
    pub height: u64,
    pub payload: Digest,
    pub state_root: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OwnerIndexError {
    #[error("finalized block height gap: current={current} next={next}")]
    HeightGap { current: u64, next: u64 },
    #[error("conflicting block at height {height}")]
    ConflictingHeight { height: u64 },
    #[error("finalized block parent mismatch at height {height}")]
    ParentMismatch { height: u64 },
    #[error("object not found: {id:?}")]
    ObjectNotFound { id: ObjectId },
    #[error("invalid signature")]
    InvalidSignature,
    #[error("insufficient balance: available={available} requested={requested}")]
    InsufficientBalance { available: u64, requested: u64 },
    #[error("transfer amount must be > 0")]
    ZeroAmount,
    #[error("duplicate merge input: {id:?}")]
    DuplicateInput { id: ObjectId },
    #[error("merge requires at least 2 inputs")]
    TooFewMergeInputs,
    #[error("merge inputs must be strictly increasing")]
    NonCanonicalMergeInputs,
    #[error("merge inputs must have the same owner")]
    MergeOwnerMismatch,
    #[error("merge overflowed u64 total")]
    MergeOverflow,
    #[error("output object collision: {id:?}")]
    OutputCollision { id: ObjectId },
    #[error("kernel transactions cannot reach the owner index before M4")]
    KernelTransactionUnsupported,
}

#[derive(Clone)]
pub struct OwnerIndex {
    inner: Arc<RwLock<State>>,
}

impl OwnerIndex {
    pub fn new(genesis: &HellasBlock, genesis_allocations: Vec<(SettlementKey, u64)>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(State::new(genesis, genesis_allocations))),
        }
    }

    pub fn apply_finalized(&self, block: &HellasBlock) -> Result<ApplyOutcome, OwnerIndexError> {
        self.inner
            .write()
            .expect("owner index lock poisoned")
            .apply_finalized(block)
    }

    pub fn cursor(&self) -> OwnerCursor {
        self.inner.read().expect("owner index lock poisoned").cursor
    }

    pub fn get_coin(&self, object_id: &ObjectId) -> Option<Coin> {
        self.inner
            .read()
            .expect("owner index lock poisoned")
            .coins
            .get(object_id)
            .cloned()
    }

    pub fn get_coin_snapshot(&self, object_id: &ObjectId) -> (OwnerCursor, Option<Coin>) {
        let state = self.inner.read().expect("owner index lock poisoned");
        (state.cursor, state.coins.get(object_id).cloned())
    }

    pub fn get_coins_by_owner(&self, owner: &SettlementKey) -> Vec<(ObjectId, u64)> {
        self.inner
            .read()
            .expect("owner index lock poisoned")
            .by_owner
            .get(owner)
            .map(|coins| coins.iter().map(|(id, value)| (*id, *value)).collect())
            .unwrap_or_default()
    }

    pub fn get_coins_by_owner_snapshot(
        &self,
        owner: &SettlementKey,
    ) -> (OwnerCursor, Vec<(ObjectId, u64)>) {
        let state = self.inner.read().expect("owner index lock poisoned");
        let coins = state
            .by_owner
            .get(owner)
            .map(|coins| coins.iter().map(|(id, value)| (*id, *value)).collect())
            .unwrap_or_default();
        (state.cursor, coins)
    }
}

#[derive(Clone)]
struct State {
    cursor: OwnerCursor,
    genesis_allocations: Vec<(SettlementKey, u64)>,
    coins: BTreeMap<ObjectId, Coin>,
    by_owner: BTreeMap<SettlementKey, BTreeMap<ObjectId, u64>>,
}

impl State {
    fn new(genesis: &HellasBlock, genesis_allocations: Vec<(SettlementKey, u64)>) -> Self {
        Self {
            cursor: OwnerCursor {
                height: genesis.height().get(),
                payload: genesis.digest(),
                state_root: genesis.state_root(),
            },
            genesis_allocations,
            coins: BTreeMap::new(),
            by_owner: BTreeMap::new(),
        }
    }

    fn apply_finalized(&mut self, block: &HellasBlock) -> Result<ApplyOutcome, OwnerIndexError> {
        let height = block.height().get();
        let payload = block.digest();
        if height == self.cursor.height {
            if payload == self.cursor.payload {
                return Ok(ApplyOutcome::Duplicate);
            }
            return Err(OwnerIndexError::ConflictingHeight { height });
        }
        let next_height = self.cursor.height.saturating_add(1);
        if height != next_height {
            return Err(OwnerIndexError::HeightGap {
                current: self.cursor.height,
                next: height,
            });
        }
        if block.parent() != self.cursor.payload {
            return Err(OwnerIndexError::ParentMismatch { height });
        }

        let mut next = self.clone();
        if next.cursor.height == 0 {
            next.seed_genesis()?;
        }
        for tx in block.txs() {
            next.apply_transaction(tx)?;
        }
        next.cursor = OwnerCursor {
            height,
            payload,
            state_root: block.state_root(),
        };
        *self = next;
        Ok(ApplyOutcome::Applied)
    }

    fn seed_genesis(&mut self) -> Result<(), OwnerIndexError> {
        for (idx, (owner, value)) in self.genesis_allocations.clone().into_iter().enumerate() {
            let Ok(validator_index) = u16::try_from(idx) else {
                break;
            };
            self.insert_coin(genesis_object_id(validator_index), Coin { owner, value })?;
        }
        Ok(())
    }

    fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), OwnerIndexError> {
        match tx {
            Transaction::Transfer {
                input,
                recipient,
                amount,
                ..
            } => self.apply_transfer(tx, *input, recipient, *amount),
            Transaction::MergeCoin { inputs, .. } => self.apply_merge(tx, inputs.as_slice()),
            Transaction::Kernel(_) => Err(OwnerIndexError::KernelTransactionUnsupported),
        }
    }

    fn apply_transfer(
        &mut self,
        tx: &Transaction,
        input: ObjectId,
        recipient: &Address,
        amount: u64,
    ) -> Result<(), OwnerIndexError> {
        let coin = self
            .coins
            .get(&input)
            .cloned()
            .ok_or(OwnerIndexError::ObjectNotFound { id: input })?;
        let owner = Address::try_from(coin.owner).map_err(|_| OwnerIndexError::InvalidSignature)?;
        if !tx.verify_signature(&owner) {
            return Err(OwnerIndexError::InvalidSignature);
        }
        if amount == 0 {
            return Err(OwnerIndexError::ZeroAmount);
        }
        if amount > coin.value {
            return Err(OwnerIndexError::InsufficientBalance {
                available: coin.value,
                requested: amount,
            });
        }

        let tx_digest = Sha256::hash(&tx.encode());
        let recipient_id = output_object_id(&tx_digest, 0);
        if self.coins.contains_key(&recipient_id) {
            return Err(OwnerIndexError::OutputCollision { id: recipient_id });
        }

        let change_value = coin.value - amount;
        let change_id = if change_value > 0 {
            let id = output_object_id(&tx_digest, 1);
            if self.coins.contains_key(&id) || id == recipient_id {
                return Err(OwnerIndexError::OutputCollision { id });
            }
            Some(id)
        } else {
            None
        };

        self.remove_coin(&input)?;
        self.insert_coin(
            recipient_id,
            Coin {
                owner: SettlementKey::from(recipient),
                value: amount,
            },
        )?;
        if let Some(change_id) = change_id {
            self.insert_coin(
                change_id,
                Coin {
                    owner: coin.owner,
                    value: change_value,
                },
            )?;
        }
        Ok(())
    }

    fn apply_merge(
        &mut self,
        tx: &Transaction,
        inputs: &[ObjectId],
    ) -> Result<(), OwnerIndexError> {
        if inputs.len() < 2 {
            return Err(OwnerIndexError::TooFewMergeInputs);
        }
        for pair in inputs.windows(2) {
            if pair[0] == pair[1] {
                return Err(OwnerIndexError::DuplicateInput { id: pair[0] });
            }
            if pair[0] > pair[1] {
                return Err(OwnerIndexError::NonCanonicalMergeInputs);
            }
        }

        let mut owner = None;
        let mut total = 0u64;
        for input in inputs {
            let coin = self
                .coins
                .get(input)
                .ok_or(OwnerIndexError::ObjectNotFound { id: *input })?;
            if let Some(expected) = owner.as_ref() {
                if &coin.owner != expected {
                    return Err(OwnerIndexError::MergeOwnerMismatch);
                }
            } else {
                owner = Some(coin.owner);
            }
            total = total
                .checked_add(coin.value)
                .ok_or(OwnerIndexError::MergeOverflow)?;
        }
        let Some(owner) = owner else {
            return Err(OwnerIndexError::MergeOwnerMismatch);
        };
        let address = Address::try_from(owner).map_err(|_| OwnerIndexError::InvalidSignature)?;
        if !tx.verify_signature(&address) {
            return Err(OwnerIndexError::InvalidSignature);
        }

        let tx_digest = Sha256::hash(&tx.encode());
        let output_id = output_object_id(&tx_digest, 0);
        if self.coins.contains_key(&output_id) {
            return Err(OwnerIndexError::OutputCollision { id: output_id });
        }

        for input in inputs {
            self.remove_coin(input)?;
        }
        self.insert_coin(
            output_id,
            Coin {
                owner,
                value: total,
            },
        )?;
        Ok(())
    }

    fn insert_coin(&mut self, id: ObjectId, coin: Coin) -> Result<(), OwnerIndexError> {
        if self.coins.contains_key(&id) {
            return Err(OwnerIndexError::OutputCollision { id });
        }
        self.by_owner
            .entry(coin.owner)
            .or_default()
            .insert(id, coin.value);
        self.coins.insert(id, coin);
        Ok(())
    }

    fn remove_coin(&mut self, id: &ObjectId) -> Result<Coin, OwnerIndexError> {
        let coin = self
            .coins
            .remove(id)
            .ok_or(OwnerIndexError::ObjectNotFound { id: *id })?;
        let remove_owner = {
            let owned = self
                .by_owner
                .get_mut(&coin.owner)
                .expect("owner index missing active coin owner");
            owned.remove(id);
            owned.is_empty()
        };
        if remove_owner {
            self.by_owner.remove(&coin.owner);
        }
        Ok(coin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{PrivateKey, genesis_object_id};
    use commonware_consensus::{
        CertifiableBlock,
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::{Digest as _, Signer as _, ed25519};
    use commonware_storage::{merkle::Location, mmr};
    use commonware_utils::non_empty_range;
    use hellas_kernel::test_support::valid_open_tx;

    fn key(seed: u64) -> PrivateKey {
        ed25519::PrivateKey::from_seed(seed)
    }

    fn address(seed: u64) -> Address {
        Address::from(key(seed).public_key())
    }

    fn settlement(seed: u64) -> SettlementKey {
        SettlementKey::from(address(seed))
    }

    fn block(parent: &HellasBlock, txs: Vec<Transaction>) -> HellasBlock {
        let height = parent.height().get() + 1;
        let sync_target = crate::execution::store::UtxoSyncTarget::new(
            Sha256::hash(format!("root-{height}").as_bytes()),
            non_empty_range!(
                Location::<mmr::Family>::new(0),
                Location::<mmr::Family>::new(1)
            ),
        );
        HellasBlock::new(
            commonware_consensus::simplex::types::Context {
                round: Round::new(Epoch::zero(), View::new(height)),
                leader: key(0).public_key(),
                parent: (parent.context().round.view(), parent.digest()),
            },
            parent.digest(),
            Height::new(height),
            height,
            Sha256::hash(format!("state-{height}").as_bytes()),
            sync_target,
            txs,
        )
    }

    fn genesis() -> HellasBlock {
        let sync_target = crate::execution::store::UtxoSyncTarget::new(
            Digest::EMPTY,
            non_empty_range!(
                Location::<mmr::Family>::new(0),
                Location::<mmr::Family>::new(1)
            ),
        );
        HellasBlock::genesis(key(0).public_key(), Digest::EMPTY, sync_target)
    }

    #[test]
    fn indexes_finalized_owner_transitions() {
        let genesis = genesis();
        let indexer = OwnerIndex::new(&genesis, vec![(settlement(1), 100)]);
        let input = genesis_object_id(0);
        let tx = Transaction::transfer(&key(1), input, address(2), 40).unwrap();
        let recipient_id = output_object_id(&Sha256::hash(&tx.encode()), 0);
        let change_id = output_object_id(&Sha256::hash(&tx.encode()), 1);
        let block = block(&genesis, vec![tx]);

        assert_eq!(indexer.apply_finalized(&block), Ok(ApplyOutcome::Applied));
        assert_eq!(
            indexer.get_coins_by_owner(&settlement(2)),
            vec![(recipient_id, 40)]
        );
        assert_eq!(
            indexer.get_coins_by_owner(&settlement(1)),
            vec![(change_id, 60)]
        );
        assert_eq!(indexer.get_coin(&input), None);
    }

    #[test]
    fn duplicate_finalized_block_is_idempotent() {
        let genesis = genesis();
        let indexer = OwnerIndex::new(&genesis, vec![(settlement(1), 100)]);
        let tx = Transaction::transfer(&key(1), genesis_object_id(0), address(2), 40).unwrap();
        let block = block(&genesis, vec![tx]);

        assert_eq!(indexer.apply_finalized(&block), Ok(ApplyOutcome::Applied));
        let before = indexer.get_coins_by_owner(&settlement(1));

        assert_eq!(indexer.apply_finalized(&block), Ok(ApplyOutcome::Duplicate));
        assert_eq!(indexer.get_coins_by_owner(&settlement(1)), before);
    }

    #[test]
    fn rejected_block_does_not_mutate_index() {
        let genesis = genesis();
        let indexer = OwnerIndex::new(&genesis, vec![(settlement(1), 100)]);
        let bad_tx = Transaction::transfer(&key(1), genesis_object_id(0), address(2), 0).unwrap();
        let bad_block = block(&genesis, vec![bad_tx]);

        assert_eq!(
            indexer.apply_finalized(&bad_block),
            Err(OwnerIndexError::ZeroAmount)
        );
        assert_eq!(indexer.cursor().height, 0);
        assert_eq!(indexer.get_coin(&genesis_object_id(0)), None);

        let good_tx = Transaction::transfer(&key(1), genesis_object_id(0), address(2), 40).unwrap();
        let recipient_id = output_object_id(&Sha256::hash(&good_tx.encode()), 0);
        let good_block = block(&genesis, vec![good_tx]);

        assert_eq!(
            indexer.apply_finalized(&good_block),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            indexer.get_coins_by_owner(&settlement(2)),
            vec![(recipient_id, 40)]
        );
    }

    #[test]
    fn legacy_transfer_cannot_spend_non_p256_settlement_key() {
        let genesis = genesis();
        let invalid_owner = SettlementKey::from_bytes([0xa5; SettlementKey::LENGTH]);
        let indexer = OwnerIndex::new(&genesis, vec![(invalid_owner, 100)]);
        let tx = Transaction::transfer(&key(1), genesis_object_id(0), address(2), 40).unwrap();
        let block = block(&genesis, vec![tx]);

        assert_eq!(
            indexer.apply_finalized(&block),
            Err(OwnerIndexError::InvalidSignature)
        );
        assert_eq!(indexer.cursor().height, 0);
        assert_eq!(indexer.get_coin(&genesis_object_id(0)), None);
    }

    #[test]
    fn finalized_kernel_transaction_is_typed_pre_m4_error() {
        let genesis = genesis();
        let indexer = OwnerIndex::new(&genesis, Vec::new());
        let tx = Transaction::Kernel(valid_open_tx().expect("valid kernel open fixture"));
        let block = block(&genesis, vec![tx]);

        assert_eq!(
            indexer.apply_finalized(&block),
            Err(OwnerIndexError::KernelTransactionUnsupported)
        );
        assert_eq!(indexer.cursor().height, 0);
    }

    #[test]
    fn replay_matches_incremental_indexing() {
        let genesis = genesis();
        let tx1 = Transaction::transfer(&key(1), genesis_object_id(0), address(2), 40).unwrap();
        let change_id = output_object_id(&Sha256::hash(&tx1.encode()), 1);
        let block1 = block(&genesis, vec![tx1]);
        let tx2 = Transaction::transfer(&key(1), change_id, address(3), 25).unwrap();
        let block2 = block(&block1, vec![tx2]);

        let incremental = OwnerIndex::new(&genesis, vec![(settlement(1), 100)]);
        incremental.apply_finalized(&block1).unwrap();
        incremental.apply_finalized(&block2).unwrap();

        let replayed = OwnerIndex::new(&genesis, vec![(settlement(1), 100)]);
        for block in [&block1, &block2] {
            replayed.apply_finalized(block).unwrap();
        }

        assert_eq!(replayed.cursor(), incremental.cursor());
        assert_eq!(
            replayed.get_coins_by_owner(&settlement(1)),
            incremental.get_coins_by_owner(&settlement(1))
        );
        assert_eq!(
            replayed.get_coins_by_owner(&settlement(2)),
            incremental.get_coins_by_owner(&settlement(2))
        );
        assert_eq!(
            replayed.get_coins_by_owner(&settlement(3)),
            incremental.get_coins_by_owner(&settlement(3))
        );
    }

    #[test]
    fn rejects_parent_mismatch() {
        let genesis = genesis();
        let indexer = OwnerIndex::new(&genesis, vec![(settlement(1), 100)]);
        let bad_parent = Sha256::hash(b"bad-parent");
        let sync_target = crate::execution::store::UtxoSyncTarget::new(
            Sha256::hash(b"root-1"),
            non_empty_range!(
                Location::<mmr::Family>::new(0),
                Location::<mmr::Family>::new(1)
            ),
        );
        let block = HellasBlock::new(
            commonware_consensus::simplex::types::Context {
                round: Round::new(Epoch::zero(), View::new(1)),
                leader: key(0).public_key(),
                parent: (View::zero(), bad_parent),
            },
            bad_parent,
            Height::new(1),
            1,
            Sha256::hash(b"state-1"),
            sync_target,
            Vec::new(),
        );

        assert_eq!(
            indexer.apply_finalized(&block),
            Err(OwnerIndexError::ParentMismatch { height: 1 })
        );
    }
}
