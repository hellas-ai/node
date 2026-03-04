mod finalized;
mod speculative;
pub mod store;
mod transition;

use hellas_types::{Address, Coin, ObjectId};
use std::collections::{BTreeSet, HashMap};

/// The created/deleted diffs produced by executing a block.
///
/// Always present for finalized payloads; vectors may be empty for
/// blocks that carry no transactions.
#[derive(Clone, Debug)]
pub(crate) struct FinalizationDiffs {
    pub created: Vec<(ObjectId, Coin)>,
    pub deleted: Vec<ObjectId>,
}

/// In-memory reverse index: Address → UTXOs.
///
/// Untrusted convenience layer (not Merkle-backed). Updated from
/// `FinalizationDiffs` as blocks are finalized.
pub(crate) struct CoinIndex {
    by_owner: HashMap<Address, BTreeSet<ObjectId>>,
    coins: HashMap<ObjectId, (Address, u64)>,
}

impl CoinIndex {
    pub fn new() -> Self {
        Self {
            by_owner: HashMap::new(),
            coins: HashMap::new(),
        }
    }

    /// Apply finalization diffs: deletes first, then inserts.
    ///
    /// Delete-before-insert order matters because a transfer can delete
    /// an input and create change output in the same block.
    pub fn apply_diffs(&mut self, diffs: &FinalizationDiffs) {
        for object_id in &diffs.deleted {
            if let Some((owner, _value)) = self.coins.remove(object_id) {
                if let Some(set) = self.by_owner.get_mut(&owner) {
                    set.remove(object_id);
                    if set.is_empty() {
                        self.by_owner.remove(&owner);
                    }
                }
            }
        }
        for (object_id, coin) in &diffs.created {
            let owner = coin.owner.clone();
            let value = coin.value;
            self.coins.insert(*object_id, (owner.clone(), value));
            self.by_owner.entry(owner).or_default().insert(*object_id);
        }
    }

    /// Look up all coins owned by `owner`.
    pub fn coins_by_owner(&self, owner: &Address) -> Vec<(ObjectId, u64)> {
        match self.by_owner.get(owner) {
            Some(ids) => ids
                .iter()
                .filter_map(|id| self.coins.get(id).map(|(_owner, value)| (*id, *value)))
                .collect(),
            None => Vec::new(),
        }
    }
}

pub(crate) use finalized::FinalizationTracker;
pub(crate) use speculative::SpeculativeExecutionStore;
pub(crate) use transition::ObjectState;
pub(crate) use transition::execute_transaction;
pub use transition::{ExecutionError, execute_block, genesis_state};
