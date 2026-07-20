use crate::HellasBlock;
use crate::domain::{
    Address, Coin, ObjectId, ObjectKind, SettlementKey, Transaction, coin_object_id,
    edge_object_id, genesis_object_id, output_object_id,
};
use commonware_codec::Encode;
use commonware_consensus::{Block as _, Heightable};
use commonware_cryptography::{Digestible, Hasher, Sha256, sha256::Digest};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedEdge {
    pub maker: SettlementKey,
    pub taker: SettlementKey,
}

impl From<hellas_kernel::Parties> for IndexedEdge {
    fn from(parties: hellas_kernel::Parties) -> Self {
        Self {
            maker: SettlementKey::from(parties.maker()),
            taker: SettlementKey::from(parties.taker()),
        }
    }
}

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
    #[error("wrong object kind for {id:?}: expected {expected}, found {actual}")]
    WrongObjectKind {
        id: ObjectId,
        expected: ObjectKind,
        actual: ObjectKind,
    },
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

    pub fn get_coin(&self, object_id: &ObjectId) -> Result<Option<Coin>, OwnerIndexError> {
        self.inner
            .read()
            .expect("owner index lock poisoned")
            .get_coin(object_id)
    }

    pub fn get_coin_snapshot(
        &self,
        object_id: &ObjectId,
    ) -> (OwnerCursor, Result<Option<Coin>, OwnerIndexError>) {
        let state = self.inner.read().expect("owner index lock poisoned");
        (state.cursor, state.get_coin(object_id))
    }

    #[cfg(test)]
    pub(crate) fn get_edges_by_owner(&self, owner: &SettlementKey) -> Vec<(ObjectId, IndexedEdge)> {
        self.get_edges_by_owner_snapshot(owner).1
    }

    pub fn get_edges_by_owner_snapshot(
        &self,
        owner: &SettlementKey,
    ) -> (OwnerCursor, Vec<(ObjectId, IndexedEdge)>) {
        let state = self.inner.read().expect("owner index lock poisoned");
        let edges = state
            .edges_by_owner
            .get(owner)
            .into_iter()
            .flatten()
            .filter_map(|id| state.edges.get(id).map(|edge| (*id, *edge)))
            .collect();
        (state.cursor, edges)
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

    #[cfg(test)]
    pub(crate) fn all_coins_for_test(&self) -> BTreeMap<ObjectId, Coin> {
        self.inner
            .read()
            .expect("owner index lock poisoned")
            .coins
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn all_edges_for_test(&self) -> BTreeMap<ObjectId, IndexedEdge> {
        self.inner
            .read()
            .expect("owner index lock poisoned")
            .edges
            .clone()
    }
}

#[derive(Clone)]
struct State {
    cursor: OwnerCursor,
    genesis_allocations: Vec<(SettlementKey, u64)>,
    coins: BTreeMap<ObjectId, Coin>,
    by_owner: BTreeMap<SettlementKey, BTreeMap<ObjectId, u64>>,
    edges: BTreeMap<ObjectId, IndexedEdge>,
    edges_by_owner: BTreeMap<SettlementKey, BTreeSet<ObjectId>>,
    kinds: BTreeMap<ObjectId, ObjectKind>,
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
            edges: BTreeMap::new(),
            edges_by_owner: BTreeMap::new(),
            kinds: BTreeMap::new(),
        }
    }

    fn get_coin(&self, id: &ObjectId) -> Result<Option<Coin>, OwnerIndexError> {
        if let Some(coin) = self.coins.get(id) {
            return Ok(Some(*coin));
        }
        match self.kinds.get(id).copied() {
            Some(actual @ ObjectKind::Edge) => Err(OwnerIndexError::WrongObjectKind {
                id: *id,
                expected: ObjectKind::Coin,
                actual,
            }),
            Some(ObjectKind::Coin) | None => Ok(None),
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
            Transaction::Kernel(tx) => self.apply_kernel(tx),
        }
    }

    fn apply_kernel(&mut self, tx: &hellas_kernel::Tx) -> Result<(), OwnerIndexError> {
        match tx {
            hellas_kernel::Tx::Open { funding, terms, .. } => {
                let edge_id = edge_object_id(hellas_kernel::Tx::edge_id_of(funding, terms));
                if self.kinds.contains_key(&edge_id) {
                    return Err(OwnerIndexError::OutputCollision { id: edge_id });
                }
                for id in funding.maker().iter().chain(funding.taker()) {
                    self.remove_coin(&coin_object_id(*id))?;
                }
                self.insert_edge(edge_id, terms.parties().into())
            }
            hellas_kernel::Tx::Close { input, outputs, .. } => {
                let edge_id = edge_object_id(*input);
                self.remove_edge(&edge_id)?;
                for (id, payout) in hellas_kernel::Tx::close_output_ids(*input, outputs)
                    .iter()
                    .zip(outputs)
                {
                    self.insert_coin(
                        coin_object_id(*id),
                        Coin {
                            owner: SettlementKey::from(payout.owner()),
                            value: payout.value(),
                        },
                    )?;
                }
                Ok(())
            }
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
        if self.kinds.contains_key(&recipient_id) {
            return Err(OwnerIndexError::OutputCollision { id: recipient_id });
        }

        let change_value = coin.value - amount;
        let change_id = if change_value > 0 {
            let id = output_object_id(&tx_digest, 1);
            if self.kinds.contains_key(&id) || id == recipient_id {
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
        if self.kinds.contains_key(&output_id) {
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
        if self.kinds.contains_key(&id) {
            return Err(OwnerIndexError::OutputCollision { id });
        }
        self.by_owner
            .entry(coin.owner)
            .or_default()
            .insert(id, coin.value);
        self.coins.insert(id, coin);
        self.kinds.insert(id, ObjectKind::Coin);
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
        self.kinds.remove(id);
        Ok(coin)
    }

    fn insert_edge(&mut self, id: ObjectId, edge: IndexedEdge) -> Result<(), OwnerIndexError> {
        if self.kinds.contains_key(&id) {
            return Err(OwnerIndexError::OutputCollision { id });
        }
        self.edges_by_owner
            .entry(edge.maker)
            .or_default()
            .insert(id);
        self.edges_by_owner
            .entry(edge.taker)
            .or_default()
            .insert(id);
        self.edges.insert(id, edge);
        self.kinds.insert(id, ObjectKind::Edge);
        Ok(())
    }

    fn remove_edge(&mut self, id: &ObjectId) -> Result<IndexedEdge, OwnerIndexError> {
        let edge = match self.edges.remove(id) {
            Some(edge) => edge,
            None => {
                return match self.kinds.get(id).copied() {
                    Some(actual @ ObjectKind::Coin) => Err(OwnerIndexError::WrongObjectKind {
                        id: *id,
                        expected: ObjectKind::Edge,
                        actual,
                    }),
                    Some(ObjectKind::Edge) | None => {
                        Err(OwnerIndexError::ObjectNotFound { id: *id })
                    }
                };
            }
        };
        for owner in [edge.maker, edge.taker]
            .into_iter()
            .take(if edge.maker == edge.taker { 1 } else { 2 })
        {
            let remove_owner = {
                let owned = self
                    .edges_by_owner
                    .get_mut(&owner)
                    .expect("owner index missing active edge owner");
                assert!(
                    owned.remove(id),
                    "owner index active edge missing from owner set"
                );
                owned.is_empty()
            };
            if remove_owner {
                self.edges_by_owner.remove(&owner);
            }
        }
        self.kinds.remove(id);
        Ok(edge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::genesis_object_id;
    use crate::execution::test_support::{
        index_block, index_genesis as genesis, kernel_fixture, legacy_address as address,
        validator_key as key,
    };
    use commonware_consensus::types::{Epoch, Height, Round, View};
    use commonware_cryptography::{Digest as _, Signer as _};
    use commonware_storage::{merkle::Location, mmr};
    use commonware_utils::non_empty_range;
    use hellas_kernel::SoftPasskey;
    use hellas_kernel::{
        Auth, CloseKind, List, MAX_EDGE_OUTPUTS, Parties, Payout, Proof, Terms, Tx,
    };

    fn block(parent: &HellasBlock, txs: Vec<Transaction>) -> HellasBlock {
        index_block(parent, commonware_cryptography::sha256::Digest::EMPTY, txs)
    }

    fn settlement(seed: u64) -> SettlementKey {
        SettlementKey::from(address(seed))
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
        assert_eq!(indexer.get_coin(&input), Ok(None));
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
        assert_eq!(indexer.get_coin(&genesis_object_id(0)), Ok(None));

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
        assert_eq!(indexer.get_coin(&genesis_object_id(0)), Ok(None));
    }

    #[test]
    fn indexes_kernel_edge_parties_and_coin_transitions() {
        let genesis = genesis();
        let fixture = kernel_fixture(10).expect("kernel fixture");
        let indexer = OwnerIndex::new(&genesis, fixture.allocations.clone());
        let open_block = block(&genesis, vec![Transaction::Kernel(fixture.open.clone())]);
        let edge_id = edge_object_id(fixture.edge);
        let indexed_edge = IndexedEdge::from(fixture.terms.parties());
        assert_eq!(
            indexer.apply_finalized(&open_block),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            indexer.all_edges_for_test().get(&edge_id).copied(),
            Some(indexed_edge)
        );
        assert_eq!(
            indexer.get_edges_by_owner(&indexed_edge.maker),
            vec![(edge_id, indexed_edge)]
        );
        assert_eq!(
            indexer.get_edges_by_owner(&indexed_edge.taker),
            vec![(edge_id, indexed_edge)]
        );
        assert_eq!(indexer.get_coin(&genesis_object_id(0)), Ok(None));
        assert_eq!(indexer.get_coin(&genesis_object_id(1)), Ok(None));
        assert_eq!(
            indexer.get_coin(&edge_id),
            Err(OwnerIndexError::WrongObjectKind {
                id: edge_id,
                expected: ObjectKind::Coin,
                actual: ObjectKind::Edge,
            })
        );

        let close_block = block(
            &open_block,
            vec![Transaction::Kernel(fixture.mutual_close.clone())],
        );
        assert_eq!(
            indexer.apply_finalized(&close_block),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(indexer.all_edges_for_test().get(&edge_id).copied(), None);
        assert!(indexer.get_edges_by_owner(&indexed_edge.maker).is_empty());
        assert!(indexer.get_edges_by_owner(&indexed_edge.taker).is_empty());
        for (id, payout) in fixture.payout_ids().iter().zip(&fixture.outputs) {
            let id = coin_object_id(*id);
            assert_eq!(
                indexer.get_coin(&id),
                Ok(Some(Coin {
                    owner: SettlementKey::from(payout.owner()),
                    value: payout.value(),
                }))
            );
        }
    }

    #[test]
    fn same_party_edge_has_one_owner_membership_and_closes_cleanly() {
        let genesis = genesis();
        let template = kernel_fixture(10).expect("kernel fixture");
        let passkey = SoftPasskey::from_secret_scalar([11; 32]).expect("same-party passkey");
        let party = passkey.party_key();
        let owner = SettlementKey::from(party);
        let mut payout_values = [Payout::default(); MAX_EDGE_OUTPUTS];
        *payout_values.first_mut().expect("first payout slot") = Payout::new(party, 40);
        *payout_values.get_mut(1).expect("second payout slot") = Payout::new(party, 60);
        let outputs = List::take(payout_values, 2);
        let terms = Terms::basic(
            template.terms.protocol(),
            Parties::new(party, party),
            template.terms.timeout(),
            outputs.clone(),
        );
        let funding = template.funding;
        let edge = Tx::edge_id_of(&funding, &terms);
        let open_hash = Tx::open_hash(&funding, &terms);
        let open = Tx::open(
            funding,
            terms.clone(),
            Auth::webauthn(passkey.sign(open_hash).expect("maker assertion")),
            Auth::webauthn(passkey.sign(open_hash).expect("taker assertion")),
        );
        let close_hash = Tx::payload_hash(edge, CloseKind::Mutual, terms.hash(), &outputs);
        let close = Tx::close(
            edge,
            Proof::mutual(
                Auth::webauthn(passkey.sign(close_hash).expect("maker close assertion")),
                Auth::webauthn(passkey.sign(close_hash).expect("taker close assertion")),
            ),
            outputs,
        );
        let indexer = OwnerIndex::new(&genesis, vec![(owner, 40), (owner, 60)]);
        let open_block = block(&genesis, vec![Transaction::Kernel(open)]);
        let edge_id = edge_object_id(edge);
        let indexed = IndexedEdge::from(terms.parties());

        assert_eq!(
            indexer.apply_finalized(&open_block),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(indexer.get_edges_by_owner(&owner), vec![(edge_id, indexed)]);

        let close_block = block(&open_block, vec![Transaction::Kernel(close)]);
        assert_eq!(
            indexer.apply_finalized(&close_block),
            Ok(ApplyOutcome::Applied)
        );
        assert!(indexer.get_edges_by_owner(&owner).is_empty());
        assert_eq!(indexer.all_edges_for_test().get(&edge_id).copied(), None);
    }

    #[test]
    fn duplicate_kernel_open_is_atomic_output_collision() {
        let genesis = genesis();
        let fixture = kernel_fixture(10).expect("kernel fixture");
        let indexer = OwnerIndex::new(&genesis, fixture.allocations.clone());
        let open_block = block(&genesis, vec![Transaction::Kernel(fixture.open.clone())]);
        assert_eq!(
            indexer.apply_finalized(&open_block),
            Ok(ApplyOutcome::Applied)
        );
        let cursor = indexer.cursor();
        let edge_id = edge_object_id(fixture.edge);
        let edge = indexer.all_edges_for_test().get(&edge_id).copied();
        let maker_edges = indexer.get_edges_by_owner(&fixture.maker);

        let duplicate = block(&open_block, vec![Transaction::Kernel(fixture.open)]);
        assert_eq!(
            indexer.apply_finalized(&duplicate),
            Err(OwnerIndexError::OutputCollision { id: edge_id })
        );
        assert_eq!(indexer.cursor(), cursor);
        assert_eq!(indexer.all_edges_for_test().get(&edge_id).copied(), edge);
        assert_eq!(indexer.get_edges_by_owner(&fixture.maker), maker_edges);
    }

    #[test]
    fn close_of_unknown_edge_is_typed_and_does_not_mutate() {
        let genesis = genesis();
        let fixture = kernel_fixture(10).expect("kernel fixture");
        let indexer = OwnerIndex::new(&genesis, fixture.allocations.clone());
        let edge_id = edge_object_id(fixture.edge);
        let close_block = block(&genesis, vec![Transaction::Kernel(fixture.mutual_close)]);

        assert_eq!(
            indexer.apply_finalized(&close_block),
            Err(OwnerIndexError::ObjectNotFound { id: edge_id })
        );
        assert_eq!(indexer.cursor().height, 0);
        assert_eq!(indexer.all_edges_for_test().get(&edge_id).copied(), None);
        assert!(indexer.get_edges_by_owner(&fixture.maker).is_empty());
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
