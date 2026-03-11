use super::kernel::{BlockExecution, ObjectState, StateDiff, apply_diff, execute_block};
use commonware_cryptography::sha256::Digest;
use hellas_types::{Address, Coin, ObjectId, Transaction};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ExecutionQueryError {
    #[error("payload state is not retained locally: {payload:?}")]
    UnavailablePayload { payload: Digest },
}

#[derive(Clone)]
struct Overlay {
    parent: Digest,
    diff: StateDiff,
}

struct CoinIndex {
    by_owner: HashMap<Address, BTreeSet<ObjectId>>,
    coins: HashMap<ObjectId, (Address, u64)>,
}

impl CoinIndex {
    fn new() -> Self {
        Self {
            by_owner: HashMap::new(),
            coins: HashMap::new(),
        }
    }

    fn apply_diff(&mut self, diff: &StateDiff) {
        for object_id in &diff.deleted {
            if let Some((owner, _value)) = self.coins.remove(object_id) {
                if let Some(set) = self.by_owner.get_mut(&owner) {
                    set.remove(object_id);
                    if set.is_empty() {
                        self.by_owner.remove(&owner);
                    }
                }
            }
        }
        for (object_id, coin) in &diff.created {
            let owner = coin.owner.clone();
            let value = coin.value;
            self.coins.insert(*object_id, (owner.clone(), value));
            self.by_owner.entry(owner).or_default().insert(*object_id);
        }
    }

    fn coins_by_owner(&self, owner: &Address) -> Vec<(ObjectId, u64)> {
        match self.by_owner.get(owner) {
            Some(ids) => ids
                .iter()
                .filter_map(|id| self.coins.get(id).map(|(_owner, value)| (*id, *value)))
                .collect(),
            None => Vec::new(),
        }
    }
}

pub(crate) struct ExecutionEngine {
    snapshot_payload: Digest,
    snapshot_state: ObjectState,
    overlays: HashMap<Digest, Overlay>,
    materialized: HashMap<Digest, ObjectState>,
    finalized_window: VecDeque<Digest>,
    coin_index: CoinIndex,
    max_finalized_window: usize,
}

impl ExecutionEngine {
    pub(crate) fn from_genesis(
        payload: Digest,
        execution: BlockExecution,
        max_finalized_window: usize,
    ) -> Self {
        let mut coin_index = CoinIndex::new();
        let diff = execution.diff();
        coin_index.apply_diff(&diff);
        Self {
            snapshot_payload: payload,
            snapshot_state: execution.state,
            overlays: HashMap::new(),
            materialized: HashMap::new(),
            finalized_window: VecDeque::from([payload]),
            coin_index,
            max_finalized_window: max_finalized_window.max(1),
        }
    }

    pub(crate) fn contains_payload(&self, payload: Digest) -> bool {
        payload == self.snapshot_payload || self.overlays.contains_key(&payload)
    }

    pub(crate) fn coins_by_owner(&self, owner: &Address) -> Vec<(ObjectId, u64)> {
        self.coin_index.coins_by_owner(owner)
    }

    pub(crate) fn diff(&self, payload: Digest) -> Option<&StateDiff> {
        self.overlays.get(&payload).map(|overlay| &overlay.diff)
    }

    pub(crate) fn get_coin(
        &mut self,
        payload: Digest,
        object: ObjectId,
    ) -> Result<Option<Coin>, ExecutionQueryError> {
        let state = self
            .state_clone(payload)
            .ok_or(ExecutionQueryError::UnavailablePayload { payload })?;
        Ok(state.get(&object).cloned())
    }

    pub(crate) fn state_clone(&mut self, payload: Digest) -> Option<ObjectState> {
        if payload == self.snapshot_payload {
            return Some(self.snapshot_state.clone());
        }
        if let Some(state) = self.materialized.get(&payload) {
            return Some(state.clone());
        }
        self.materialize_known(payload)?;
        self.materialized.get(&payload).cloned()
    }

    pub(crate) fn insert_executed(
        &mut self,
        payload: Digest,
        parent: Digest,
        execution: BlockExecution,
    ) {
        let diff = execution.diff();
        if let Some(existing) = self.overlays.get(&payload) {
            if existing.parent != parent || existing.diff != diff {
                error!(?payload, "execution overlay collision detected; aborting");
                std::process::abort();
            }
        } else {
            self.overlays.insert(payload, Overlay { parent, diff });
        }

        if let Some(existing) = self.materialized.get(&payload) {
            if existing != &execution.state {
                error!(
                    ?payload,
                    "materialized execution collision detected; aborting"
                );
                std::process::abort();
            }
        } else {
            self.materialized.insert(payload, execution.state);
        }
    }

    pub(crate) fn ensure_executed<F>(&mut self, payload: Digest, decode_payload: &F) -> bool
    where
        F: Fn(Digest) -> Option<(Digest, Vec<Transaction>)>,
    {
        if self.contains_payload(payload) {
            return true;
        }

        let mut chain: Vec<(Digest, Digest, Vec<Transaction>)> = Vec::new();
        let mut visited = HashSet::new();
        let mut cursor = payload;

        while !self.contains_payload(cursor) {
            if !visited.insert(cursor) {
                return false;
            }
            let Some((parent_payload, txs)) = decode_payload(cursor) else {
                return false;
            };
            chain.push((cursor, parent_payload, txs));
            cursor = parent_payload;
        }

        let Some(mut state) = self.state_clone(cursor) else {
            return false;
        };
        for (digest, parent_payload, txs) in chain.into_iter().rev() {
            let Ok(exec) = execute_block(&state, &txs) else {
                return false;
            };
            state = exec.state.clone();
            self.insert_executed(digest, parent_payload, exec);
        }
        true
    }

    pub(crate) fn finalize(&mut self, payload: Digest) -> Vec<Digest> {
        let latest = *self
            .finalized_window
            .back()
            .expect("execution engine must always retain at least one finalized payload");
        if payload == latest {
            return Vec::new();
        }

        let overlay = self.overlays.get(&payload).unwrap_or_else(|| {
            error!(
                ?payload,
                "attempted to finalize missing execution overlay; aborting"
            );
            std::process::abort();
        });
        if overlay.parent != latest {
            error!(
                latest = ?latest,
                parent = ?overlay.parent,
                ?payload,
                "attempted to finalize a non-linear payload; aborting"
            );
            std::process::abort();
        }

        self.coin_index.apply_diff(&overlay.diff);
        self.finalized_window.push_back(payload);

        let mut pruned = Vec::new();
        while self.finalized_window.len() > self.max_finalized_window {
            pruned.push(self.advance_snapshot());
        }

        let latest = *self
            .finalized_window
            .back()
            .expect("execution engine must retain a latest finalized payload");
        let keep = self.keep_payloads(latest);
        pruned.extend(self.prune_except(&keep));
        pruned
    }

    fn materialize_known(&mut self, payload: Digest) -> Option<()> {
        let mut chain = Vec::new();
        let mut cursor = payload;
        while cursor != self.snapshot_payload && !self.materialized.contains_key(&cursor) {
            let overlay = self.overlays.get(&cursor)?;
            chain.push(cursor);
            cursor = overlay.parent;
        }

        let mut state = if cursor == self.snapshot_payload {
            self.snapshot_state.clone()
        } else {
            self.materialized.get(&cursor)?.clone()
        };

        for digest in chain.into_iter().rev() {
            let overlay = self.overlays.get(&digest)?;
            apply_diff(&mut state, &overlay.diff);
            self.materialized.insert(digest, state.clone());
        }
        Some(())
    }

    fn advance_snapshot(&mut self) -> Digest {
        let old_snapshot = self
            .finalized_window
            .pop_front()
            .expect("finalized window should never be empty");
        let new_snapshot = *self
            .finalized_window
            .front()
            .expect("advancing snapshot requires a successor finalized payload");
        let overlay = self.overlays.remove(&new_snapshot).unwrap_or_else(|| {
            error!(
                ?new_snapshot,
                "missing overlay for new execution snapshot; aborting"
            );
            std::process::abort();
        });
        if overlay.parent != old_snapshot {
            error!(
                old_snapshot = ?old_snapshot,
                new_snapshot = ?new_snapshot,
                parent = ?overlay.parent,
                "execution snapshot successor does not chain from previous snapshot; aborting"
            );
            std::process::abort();
        }

        let mut advanced = self.snapshot_state.clone();
        apply_diff(&mut advanced, &overlay.diff);
        if let Some(materialized) = self.materialized.remove(&new_snapshot) {
            if materialized != advanced {
                error!(
                    ?new_snapshot,
                    "snapshot rebase produced inconsistent state; aborting"
                );
                std::process::abort();
            }
            self.snapshot_state = materialized;
        } else {
            self.snapshot_state = advanced;
        }
        self.snapshot_payload = new_snapshot;
        self.materialized.remove(&old_snapshot);
        old_snapshot
    }

    fn keep_payloads(&self, latest: Digest) -> HashSet<Digest> {
        let mut keep: HashSet<Digest> = self.finalized_window.iter().copied().collect();
        let mut children_by_parent: HashMap<Digest, Vec<Digest>> = HashMap::new();
        for (digest, overlay) in &self.overlays {
            children_by_parent
                .entry(overlay.parent)
                .or_default()
                .push(*digest);
        }

        let mut queue = VecDeque::from([latest]);
        while let Some(current) = queue.pop_front() {
            if let Some(children) = children_by_parent.get(&current) {
                for child in children {
                    if keep.insert(*child) {
                        queue.push_back(*child);
                    }
                }
            }
        }
        keep.insert(self.snapshot_payload);
        keep
    }

    fn prune_except(&mut self, keep: &HashSet<Digest>) -> Vec<Digest> {
        let mut pruned: Vec<Digest> = self
            .overlays
            .keys()
            .copied()
            .filter(|digest| !keep.contains(digest))
            .collect();
        for digest in &pruned {
            self.overlays.remove(digest);
            self.materialized.remove(digest);
        }

        let stale_states: Vec<Digest> = self
            .materialized
            .keys()
            .copied()
            .filter(|digest| !keep.contains(digest))
            .collect();
        for digest in &stale_states {
            self.materialized.remove(digest);
        }
        pruned.extend(stale_states);
        pruned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Signer;
    use hellas_types::PrivateKey;
    use hellas_types::{Coin, GENESIS_BALANCE};

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

    fn empty_execution(state: ObjectState) -> BlockExecution {
        BlockExecution {
            state,
            created: Vec::new(),
            deleted: Vec::new(),
        }
    }

    #[test]
    fn materializes_execution_chain() {
        let genesis = Digest::from([1; 32]);
        let block_a = Digest::from([2; 32]);
        let block_b = Digest::from([3; 32]);
        let genesis_state = sample_state();
        let mut engine =
            ExecutionEngine::from_genesis(genesis, empty_execution(genesis_state.clone()), 8);

        let decode = |digest: Digest| -> Option<(Digest, Vec<Transaction>)> {
            if digest == block_a {
                Some((genesis, vec![]))
            } else if digest == block_b {
                Some((block_a, vec![]))
            } else {
                None
            }
        };

        assert!(engine.ensure_executed(block_b, &decode));
        assert!(engine.contains_payload(block_a));
        assert!(engine.contains_payload(block_b));
        assert_eq!(engine.state_clone(block_b), Some(genesis_state));
    }

    #[test]
    fn finalization_window_advances_snapshot() {
        let genesis = Digest::from([1; 32]);
        let a = Digest::from([2; 32]);
        let b = Digest::from([3; 32]);
        let state = sample_state();
        let mut engine = ExecutionEngine::from_genesis(genesis, empty_execution(state.clone()), 2);

        engine.insert_executed(a, genesis, empty_execution(state.clone()));
        assert!(engine.finalize(a).is_empty());

        engine.insert_executed(b, a, empty_execution(state.clone()));
        let pruned = engine.finalize(b);
        assert!(pruned.contains(&genesis));
        assert!(!engine.contains_payload(genesis));
        assert_eq!(engine.state_clone(a), Some(state.clone()));
        assert_eq!(engine.state_clone(b), Some(state));
    }

    #[test]
    fn finalization_prunes_non_descendant_forks() {
        let genesis = Digest::from([1; 32]);
        let a = Digest::from([2; 32]);
        let b = Digest::from([3; 32]);
        let fork = Digest::from([9; 32]);
        let state = sample_state();
        let mut engine = ExecutionEngine::from_genesis(genesis, empty_execution(state.clone()), 4);

        engine.insert_executed(a, genesis, empty_execution(state.clone()));
        engine.finalize(a);

        engine.insert_executed(fork, a, empty_execution(state.clone()));
        engine.insert_executed(b, a, empty_execution(state));
        let pruned = engine.finalize(b);
        assert!(pruned.contains(&fork));
        assert!(!engine.contains_payload(fork));
    }

    #[test]
    fn unavailable_payload_returns_error() {
        let genesis = Digest::from([1; 32]);
        let object = Digest::from([7; 32]);
        let mut engine = ExecutionEngine::from_genesis(genesis, empty_execution(sample_state()), 1);
        let missing = Digest::from([99; 32]);
        assert!(matches!(
            engine.get_coin(missing, object),
            Err(ExecutionQueryError::UnavailablePayload { payload }) if payload == missing
        ));
    }
}
