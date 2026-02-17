use super::FinalizationDiffs;
use super::transition::{ObjectState, execute_block};
use hellas_types::Transaction;
use commonware_cryptography::sha256::Digest;
use std::collections::{HashMap, HashSet, VecDeque};

/// Materialized speculative execution state keyed by payload digest.
pub(crate) struct SpeculativeExecutionStore {
    executions: HashMap<Digest, ObjectState>,
    diffs: HashMap<Digest, FinalizationDiffs>,
    parent_by_digest: HashMap<Digest, Digest>,
}

impl SpeculativeExecutionStore {
    pub(crate) fn new() -> Self {
        Self {
            executions: HashMap::new(),
            diffs: HashMap::new(),
            parent_by_digest: HashMap::new(),
        }
    }

    pub(crate) fn contains_execution(&self, digest: Digest) -> bool {
        self.executions.contains_key(&digest)
    }

    pub(crate) fn execution(&self, digest: Digest) -> Option<&ObjectState> {
        self.executions.get(&digest)
    }

    pub(crate) fn take_diffs(&mut self, digest: Digest) -> Option<FinalizationDiffs> {
        self.diffs.remove(&digest)
    }

    pub(crate) fn insert_state_with_diffs(
        &mut self,
        digest: Digest,
        parent: Digest,
        state: ObjectState,
        diffs: FinalizationDiffs,
    ) {
        self.executions.insert(digest, state);
        self.parent_by_digest.insert(digest, parent);
        self.diffs.insert(digest, diffs);
    }

    pub(crate) fn note_parent(&mut self, digest: Digest, parent: Digest) {
        self.parent_by_digest.insert(digest, parent);
    }

    pub(crate) fn note_parent_if_absent(&mut self, digest: Digest, parent: Digest) {
        self.parent_by_digest.entry(digest).or_insert(parent);
    }

    pub(crate) fn ensure_execution_for_payload<F>(
        &mut self,
        payload: Digest,
        decode_payload: &F,
    ) -> bool
    where
        F: Fn(Digest) -> Option<(Digest, Vec<Transaction>)>,
    {
        if self.executions.contains_key(&payload) {
            return true;
        }

        // Walk backward iteratively to collect the chain of payloads that need
        // execution, stopping when we reach one that is already materialized.
        // This avoids the unbounded recursion that previously caused stack
        // overflows on long chains (e.g. after a restart).
        let mut chain: Vec<(Digest, Digest, Vec<Transaction>)> = Vec::new();
        let mut visited = HashSet::new();
        let mut cursor = payload;

        loop {
            if self.executions.contains_key(&cursor) {
                break;
            }
            if !visited.insert(cursor) {
                return false; // cycle detected
            }
            let Some((parent_payload, txs)) = decode_payload(cursor) else {
                return false;
            };
            chain.push((cursor, parent_payload, txs));
            cursor = parent_payload;
        }

        // Execute forward (the last element in `chain` is closest to the
        // already-materialized ancestor).
        for (digest, parent_payload, txs) in chain.into_iter().rev() {
            let Some(parent_state) = self.executions.get(&parent_payload).cloned() else {
                return false;
            };
            let Ok(exec) = execute_block(&parent_state, &txs) else {
                return false;
            };
            let diffs = FinalizationDiffs {
                created: exec.created,
                deleted: exec.deleted,
            };
            self.executions.insert(digest, exec.state);
            self.parent_by_digest.insert(digest, parent_payload);
            self.diffs.insert(digest, diffs);
        }

        true
    }

    pub(crate) fn prune_non_descendants<F>(
        &mut self,
        ancestor: Digest,
        keep: F,
    ) -> (Vec<Digest>, HashSet<Digest>)
    where
        F: Fn(Digest) -> bool,
    {
        let mut children_by_parent: HashMap<Digest, Vec<Digest>> = HashMap::new();
        for (digest, parent) in &self.parent_by_digest {
            children_by_parent.entry(*parent).or_default().push(*digest);
        }

        let mut reachable = HashSet::new();
        let mut queue = VecDeque::new();
        reachable.insert(ancestor);
        queue.push_back(ancestor);
        while let Some(current) = queue.pop_front() {
            if let Some(children) = children_by_parent.get(&current) {
                for child in children {
                    if reachable.insert(*child) {
                        queue.push_back(*child);
                    }
                }
            }
        }

        let pruned: Vec<_> = self
            .executions
            .keys()
            .copied()
            .filter(|digest| !reachable.contains(digest) && !keep(*digest))
            .collect();
        for digest in &pruned {
            self.executions.remove(digest);
            self.parent_by_digest.remove(digest);
            self.diffs.remove(digest);
        }
        (pruned, reachable)
    }
}

#[cfg(test)]
mod tests {
    use super::super::transition::ObjectState;
    use super::*;
    use hellas_types::{Coin, GENESIS_BALANCE};
    use commonware_cryptography::Signer;
    use commonware_cryptography::sha256::Digest;
    use hellas_types::PrivateKey;

    fn sample_state() -> ObjectState {
        let owner = hellas_types::Address::from(PrivateKey::from_seed(1).public_key());
        let id = Digest::from([7; 32]);
        let mut state = ObjectState::new();
        state.insert(
            id,
            Coin {
                owner,
                value: GENESIS_BALANCE,
            },
        );
        state
    }

    #[test_log::test]
    fn materializes_execution_chain() {
        let mut store = SpeculativeExecutionStore::new();
        let genesis_state = sample_state();
        let genesis = Digest::from([1; 32]);
        let block_a = Digest::from([2; 32]);
        let block_b = Digest::from([3; 32]);

        store.executions.insert(genesis, genesis_state);
        store
            .parent_by_digest
            .insert(genesis, Digest::from([0; 32]));
        let decode = |digest: Digest| -> Option<(Digest, Vec<Transaction>)> {
            if digest == block_a {
                Some((genesis, vec![]))
            } else if digest == block_b {
                Some((block_a, vec![]))
            } else {
                None
            }
        };

        assert!(store.ensure_execution_for_payload(block_b, &decode));
        assert!(store.contains_execution(block_a));
        assert!(store.contains_execution(block_b));
    }

    #[test_log::test]
    fn prune_can_keep_named_non_descendants() {
        let mut store = SpeculativeExecutionStore::new();
        let genesis_state = sample_state();
        let genesis = Digest::from([1; 32]);
        let canonical = Digest::from([2; 32]);
        let fork = Digest::from([9; 32]);

        store.executions.insert(genesis, genesis_state);
        store
            .parent_by_digest
            .insert(genesis, Digest::from([0; 32]));
        let decode = |digest: Digest| -> Option<(Digest, Vec<Transaction>)> {
            if digest == canonical || digest == fork {
                Some((genesis, vec![]))
            } else {
                None
            }
        };

        assert!(store.ensure_execution_for_payload(canonical, &decode));
        assert!(store.ensure_execution_for_payload(fork, &decode));

        let (pruned, reachable) =
            store.prune_non_descendants(canonical, |digest| digest == fork);
        assert!(pruned.contains(&genesis));
        assert!(!pruned.contains(&fork));
        assert!(reachable.contains(&canonical));
        assert!(!reachable.contains(&fork));
        assert!(!store.contains_execution(genesis));
        assert!(store.contains_execution(canonical));
        assert!(store.contains_execution(fork));
    }

    #[test_log::test]
    fn materializes_deep_chain_without_stack_overflow() {
        let mut store = SpeculativeExecutionStore::new();
        let genesis = Digest::from([0; 32]);
        store.executions.insert(genesis, sample_state());
        store
            .parent_by_digest
            .insert(genesis, Digest::from([255; 32]));

        // Build a chain of 10_000 empty blocks -- deep enough that a naive
        // recursive implementation would overflow the default thread stack.
        const DEPTH: usize = 10_000;
        let digests: Vec<Digest> = (1..=DEPTH)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
                Digest::from(bytes)
            })
            .collect();

        let chain: HashMap<Digest, Digest> = digests
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let parent = if i == 0 { genesis } else { digests[i - 1] };
                (*d, parent)
            })
            .collect();

        let decode = |digest: Digest| -> Option<(Digest, Vec<Transaction>)> {
            chain.get(&digest).map(|parent| (*parent, vec![]))
        };

        let tip = *digests.last().unwrap();
        assert!(store.ensure_execution_for_payload(tip, &decode));
        for d in &digests {
            assert!(store.contains_execution(*d));
        }
    }
}
