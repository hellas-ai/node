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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Digest;
    use hellas_types::addr_from_signing_key;
    use p256::ecdsa::SigningKey;

    fn test_addr(seed: u8) -> Address {
        let key = SigningKey::from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = seed;
            b.into()
        })
        .unwrap();
        addr_from_signing_key(&key)
    }

    fn oid(n: u8) -> ObjectId {
        let mut d = [0u8; 32];
        d[0] = n;
        Digest::from(d)
    }

    #[test]
    fn genesis_coins_are_indexed() {
        let mut idx = CoinIndex::new();
        let alice = test_addr(1);
        let diffs = FinalizationDiffs {
            created: vec![
                (oid(1), Coin { owner: alice.clone(), value: 100 }),
                (oid(2), Coin { owner: alice.clone(), value: 200 }),
            ],
            deleted: vec![],
        };
        idx.apply_diffs(&diffs);

        let coins = idx.coins_by_owner(&alice);
        assert_eq!(coins.len(), 2);
        let total: u64 = coins.iter().map(|(_, v)| v).sum();
        assert_eq!(total, 300);
    }

    #[test]
    fn transfer_updates_both_parties() {
        let mut idx = CoinIndex::new();
        let alice = test_addr(1);
        let bob = test_addr(2);

        // Genesis: Alice has one coin
        idx.apply_diffs(&FinalizationDiffs {
            created: vec![(oid(1), Coin { owner: alice.clone(), value: 1000 })],
            deleted: vec![],
        });

        // Transfer: Alice sends 300 to Bob (input consumed, 2 outputs)
        idx.apply_diffs(&FinalizationDiffs {
            deleted: vec![oid(1)],
            created: vec![
                (oid(2), Coin { owner: bob.clone(), value: 300 }),
                (oid(3), Coin { owner: alice.clone(), value: 700 }),
            ],
        });

        let alice_coins = idx.coins_by_owner(&alice);
        assert_eq!(alice_coins.len(), 1);
        assert_eq!(alice_coins[0].1, 700);

        let bob_coins = idx.coins_by_owner(&bob);
        assert_eq!(bob_coins.len(), 1);
        assert_eq!(bob_coins[0].1, 300);
    }

    #[test]
    fn merge_coins() {
        let mut idx = CoinIndex::new();
        let alice = test_addr(1);

        // Genesis: Alice has 3 coins
        idx.apply_diffs(&FinalizationDiffs {
            created: vec![
                (oid(1), Coin { owner: alice.clone(), value: 100 }),
                (oid(2), Coin { owner: alice.clone(), value: 200 }),
                (oid(3), Coin { owner: alice.clone(), value: 300 }),
            ],
            deleted: vec![],
        });
        assert_eq!(idx.coins_by_owner(&alice).len(), 3);

        // Merge: 3 inputs → 1 output
        idx.apply_diffs(&FinalizationDiffs {
            deleted: vec![oid(1), oid(2), oid(3)],
            created: vec![(oid(4), Coin { owner: alice.clone(), value: 600 })],
        });

        let coins = idx.coins_by_owner(&alice);
        assert_eq!(coins.len(), 1);
        assert_eq!(coins[0].1, 600);
    }

    #[test]
    fn empty_owner_returns_empty() {
        let idx = CoinIndex::new();
        let nobody = test_addr(99);
        assert!(idx.coins_by_owner(&nobody).is_empty());
    }

    #[test]
    fn delete_all_removes_owner_entry() {
        let mut idx = CoinIndex::new();
        let alice = test_addr(1);

        idx.apply_diffs(&FinalizationDiffs {
            created: vec![(oid(1), Coin { owner: alice.clone(), value: 100 })],
            deleted: vec![],
        });
        assert_eq!(idx.coins_by_owner(&alice).len(), 1);

        idx.apply_diffs(&FinalizationDiffs {
            deleted: vec![oid(1)],
            created: vec![],
        });
        assert!(idx.coins_by_owner(&alice).is_empty());
        assert!(!idx.by_owner.contains_key(&alice));
    }
}
