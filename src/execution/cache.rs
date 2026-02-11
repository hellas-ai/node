use super::transition::{ObjectState, execute_block};
use crate::object::Transaction;
use commonware_cryptography::sha256::Digest;
use std::collections::{HashMap, HashSet, VecDeque};

pub struct ExecutionCache {
    executions: HashMap<Digest, ObjectState>,
    parent_by_digest: HashMap<Digest, Digest>,
    finalized_execution_digests: HashSet<Digest>,
    finalized_execution_order: VecDeque<Digest>,
    latest_finalized: Option<Digest>,
    max_finalized_executions: usize,
}

impl ExecutionCache {
    pub fn new(max_finalized_executions: usize) -> Self {
        Self {
            executions: HashMap::new(),
            parent_by_digest: HashMap::new(),
            finalized_execution_digests: HashSet::new(),
            finalized_execution_order: VecDeque::new(),
            latest_finalized: None,
            max_finalized_executions,
        }
    }

    #[cfg(test)]
    pub fn latest_finalized(&self) -> Option<Digest> {
        self.latest_finalized
    }

    pub fn contains_execution(&self, digest: Digest) -> bool {
        self.executions.contains_key(&digest)
    }

    pub fn execution(&self, digest: Digest) -> Option<&ObjectState> {
        self.executions.get(&digest)
    }

    pub fn insert_state(&mut self, digest: Digest, parent: Digest, state: ObjectState) {
        self.executions.insert(digest, state);
        self.parent_by_digest.insert(digest, parent);
    }

    pub fn note_parent(&mut self, digest: Digest, parent: Digest) {
        self.parent_by_digest.insert(digest, parent);
    }

    pub fn ensure_execution_for_payload<F>(&mut self, payload: Digest, decode_payload: &F) -> bool
    where
        F: Fn(Digest) -> Option<(Digest, Vec<Transaction>)>,
    {
        self.ensure_execution_for_payload_inner(payload, decode_payload, &mut HashSet::new())
    }

    fn ensure_execution_for_payload_inner<F>(
        &mut self,
        payload: Digest,
        decode_payload: &F,
        stack: &mut HashSet<Digest>,
    ) -> bool
    where
        F: Fn(Digest) -> Option<(Digest, Vec<Transaction>)>,
    {
        if self.executions.contains_key(&payload) {
            return true;
        }
        if !stack.insert(payload) {
            return false;
        }

        let Some((parent_payload, txs)) = decode_payload(payload) else {
            stack.remove(&payload);
            return false;
        };
        if !self.ensure_execution_for_payload_inner(parent_payload, decode_payload, stack) {
            stack.remove(&payload);
            return false;
        }

        let Some(parent_state) = self.executions.get(&parent_payload).cloned() else {
            stack.remove(&payload);
            return false;
        };
        let Ok(exec) = execute_block(&parent_state, &txs) else {
            stack.remove(&payload);
            return false;
        };

        self.executions.insert(payload, exec.state);
        self.parent_by_digest.insert(payload, parent_payload);
        stack.remove(&payload);
        true
    }

    pub fn handle_finalized<F>(
        &mut self,
        payload: Digest,
        parent_payload: Digest,
        decode_payload: &F,
    ) -> Option<Vec<Digest>>
    where
        F: Fn(Digest) -> Option<(Digest, Vec<Transaction>)>,
    {
        self.parent_by_digest
            .entry(payload)
            .or_insert(parent_payload);

        if !self.ensure_execution_for_payload(payload, decode_payload) {
            return None;
        }
        self.latest_finalized = Some(payload);

        if self.finalized_execution_digests.insert(payload) {
            self.finalized_execution_order.push_back(payload);
        }
        while self.finalized_execution_order.len() > self.max_finalized_executions {
            let Some(oldest) = self.finalized_execution_order.pop_front() else {
                break;
            };
            self.finalized_execution_digests.remove(&oldest);
        }

        let pruned: Vec<_> = self
            .executions
            .keys()
            .copied()
            .filter(|digest| {
                !self.descends_from(*digest, payload)
                    && !self.finalized_execution_digests.contains(digest)
            })
            .collect();
        for digest in &pruned {
            self.executions.remove(digest);
            self.parent_by_digest.remove(digest);
        }

        Some(pruned)
    }

    fn descends_from(&self, mut digest: Digest, ancestor: Digest) -> bool {
        if digest == ancestor {
            return true;
        }
        for _ in 0..=self.parent_by_digest.len() {
            let Some(parent) = self.parent_by_digest.get(&digest).copied() else {
                return false;
            };
            if parent == ancestor {
                return true;
            }
            if parent == digest {
                return false;
            }
            digest = parent;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::super::transition::ObjectState;
    use super::*;
    use crate::object::{Coin, GENESIS_BALANCE, ObjectId, output_object_id};
    use commonware_codec::Encode;
    use commonware_cryptography::{Hasher, Sha256, Signer};
    use hellas_types::PrivateKey;

    fn sample_state() -> (ObjectId, ObjectState) {
        let owner = PrivateKey::from_seed(1).public_key();
        let id = Digest::from([7; 32]);
        let mut state = ObjectState::new();
        state.insert(
            id,
            Coin {
                owner,
                value: GENESIS_BALANCE,
            },
        );
        (id, state)
    }

    #[test]
    fn materializes_execution_chain() {
        let mut cache = ExecutionCache::new(16);
        let (_, genesis_state) = sample_state();
        let genesis = Digest::from([1; 32]);
        let block_a = Digest::from([2; 32]);
        let block_b = Digest::from([3; 32]);

        cache.insert_state(genesis, Digest::from([0; 32]), genesis_state);
        let decode = |digest: Digest| -> Option<(Digest, Vec<Transaction>)> {
            if digest == block_a {
                Some((genesis, vec![]))
            } else if digest == block_b {
                Some((block_a, vec![]))
            } else {
                None
            }
        };

        assert!(cache.ensure_execution_for_payload(block_b, &decode));
        assert!(cache.contains_execution(block_a));
        assert!(cache.contains_execution(block_b));
    }

    #[test]
    fn finalization_prunes_non_descendants() {
        let mut cache = ExecutionCache::new(16);
        let (genesis_object, genesis_state) = sample_state();
        let genesis = Digest::from([1; 32]);
        let canonical = Digest::from([2; 32]);
        let fork = Digest::from([9; 32]);

        cache.insert_state(genesis, Digest::from([0; 32]), genesis_state.clone());

        let owner = genesis_state
            .get(&genesis_object)
            .expect("genesis object should exist")
            .owner
            .clone();
        let recipient = PrivateKey::from_seed(2).public_key();
        let transfer =
            Transaction::transfer(&PrivateKey::from_seed(1), genesis_object, recipient, 1);
        let transfer_digest = Sha256::hash(&transfer.encode());
        let canonical_out = output_object_id(&transfer_digest, 0);

        let decode = |digest: Digest| -> Option<(Digest, Vec<Transaction>)> {
            if digest == canonical {
                Some((genesis, vec![transfer.clone()]))
            } else if digest == fork {
                let tx = Transaction::transfer(
                    &PrivateKey::from_seed(1),
                    genesis_object,
                    owner.clone(),
                    2,
                );
                Some((genesis, vec![tx]))
            } else {
                None
            }
        };

        assert!(cache.ensure_execution_for_payload(canonical, &decode));
        assert!(cache.ensure_execution_for_payload(fork, &decode));
        assert!(cache.contains_execution(canonical));
        assert!(cache.contains_execution(fork));

        let pruned = cache
            .handle_finalized(canonical, genesis, &decode)
            .expect("finalization should materialize");
        assert_eq!(cache.latest_finalized(), Some(canonical));
        assert!(pruned.contains(&fork));
        assert!(cache.contains_execution(canonical));
        assert!(!cache.contains_execution(fork));
        assert!(
            cache
                .execution(canonical)
                .expect("canonical state should exist")
                .contains_key(&canonical_out)
        );
    }
}
