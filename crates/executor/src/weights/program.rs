use crate::backend::ExecBackend;
use crate::state::Invocation;
use catgrad_llm::{BoundProgram, Snapshot};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const DEFAULT_EXECUTION_CACHE_MAX_BYTES: usize = 1 << 30;

#[derive(Clone)]
pub(crate) struct ExecutionContext {
    bound_program: Arc<BoundProgram<ExecBackend>>,
    empty_snapshot: Arc<Snapshot<ExecBackend>>,
    execution_cache: Arc<Mutex<ExecutionCache>>,
}

#[derive(Clone)]
pub(crate) struct ExecutionStart {
    pub snapshot: Arc<Snapshot<ExecBackend>>,
    pub transcript: TranscriptState,
    pub next_token: Option<u32>,
    pub cached_output_tokens: Option<Arc<[u32]>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TranscriptHash([u8; 32]);

#[derive(Clone, Copy, Debug)]
pub(crate) struct TranscriptState {
    len: usize,
    hash: TranscriptHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ContinuationKey {
    max_new_tokens: u32,
    stop_token_ids: Vec<i32>,
}

#[derive(Clone)]
struct CheckpointEntry {
    snapshot: Arc<Snapshot<ExecBackend>>,
    next_token: u32,
    bytes: usize,
    last_touch: u64,
}

#[derive(Clone)]
struct ContinuationEntry {
    output_tokens: Arc<[u32]>,
    bytes: usize,
    last_touch: u64,
}

#[derive(Default)]
struct TranscriptNode {
    checkpoint: Option<CheckpointEntry>,
    continuations: HashMap<ContinuationKey, ContinuationEntry>,
}

struct ExecutionCache {
    nodes: HashMap<(usize, TranscriptHash), TranscriptNode>,
    max_bytes: usize,
    total_bytes: usize,
    touch_clock: u64,
}

enum CacheItemKey {
    Checkpoint {
        transcript_len: usize,
        transcript_hash: TranscriptHash,
    },
    Continuation {
        transcript_len: usize,
        transcript_hash: TranscriptHash,
        continuation: ContinuationKey,
    },
}

impl ExecutionContext {
    pub(crate) fn new(bound_program: Arc<BoundProgram<ExecBackend>>) -> Self {
        debug!(
            program_id = %bound_program.id(),
            state_tensors = bound_program.program().empty_state_type.len(),
            max_bytes = DEFAULT_EXECUTION_CACHE_MAX_BYTES,
            "initialized execution cache"
        );
        Self {
            empty_snapshot: Arc::new(bound_program.empty_snapshot()),
            execution_cache: Arc::new(Mutex::new(ExecutionCache::new(
                DEFAULT_EXECUTION_CACHE_MAX_BYTES,
            ))),
            bound_program,
        }
    }

    pub(crate) fn bound_program(&self) -> &BoundProgram<ExecBackend> {
        self.bound_program.as_ref()
    }

    pub(crate) fn execution_start(&self, invocation: &Invocation) -> ExecutionStart {
        let mut cache = self
            .execution_cache
            .lock()
            .expect("execution cache mutex poisoned");
        let checkpoint = cache.lookup_checkpoint(invocation);
        let prompt_key = cache.prompt_key(&invocation.input_ids);
        let continuation =
            cache.lookup_continuation(prompt_key, ContinuationKey::from_invocation(invocation));
        let (snapshot, transcript, next_token) = match checkpoint {
            Some((transcript, next_token, snapshot)) => (snapshot, transcript, Some(next_token)),
            None => (self.empty_snapshot.clone(), TranscriptState::seed(), None),
        };
        debug!(
            program_id = %self.bound_program.id(),
            prompt_tokens = invocation.input_ids.len(),
            matched_prefix_tokens = transcript.len(),
            cached_output_tokens = continuation.as_ref().map_or(0, |entry| entry.len()),
            cache_nodes = cache.node_count(),
            cache_bytes = cache.total_bytes(),
            "execution cache lookup"
        );
        ExecutionStart {
            snapshot,
            transcript,
            next_token,
            cached_output_tokens: continuation,
        }
    }

    pub(crate) fn cache_checkpoint(
        &self,
        transcript_len: usize,
        transcript_hash: TranscriptHash,
        next_token: u32,
        snapshot: Snapshot<ExecBackend>,
    ) {
        let snapshot_bytes = snapshot.logical_bytes();
        self.execution_cache
            .lock()
            .expect("execution cache mutex poisoned")
            .insert_checkpoint(
                self.bound_program.id(),
                transcript_len,
                transcript_hash,
                next_token,
                snapshot_bytes,
                Arc::new(snapshot),
            );
    }

    pub(crate) fn cache_continuation(
        &self,
        prompt_len: usize,
        prompt_hash: TranscriptHash,
        invocation: &Invocation,
        output_tokens: Vec<u32>,
    ) {
        self.execution_cache
            .lock()
            .expect("execution cache mutex poisoned")
            .insert_continuation(
                self.bound_program.id(),
                prompt_len,
                prompt_hash,
                ContinuationKey::from_invocation(invocation),
                Arc::<[u32]>::from(output_tokens),
            );
    }
}

impl TranscriptHash {
    pub(crate) const fn seed() -> Self {
        Self([0; 32])
    }

    pub(crate) fn extend(self, token: u32) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.0);
        hasher.update(&token.to_le_bytes());
        Self(*hasher.finalize().as_bytes())
    }
}

impl TranscriptState {
    pub(crate) const fn seed() -> Self {
        Self {
            len: 0,
            hash: TranscriptHash::seed(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_tokens(tokens: &[u32]) -> Self {
        let mut state = Self::seed();
        state.extend_tokens(tokens);
        state
    }

    pub(crate) fn extend(&mut self, token: u32) {
        self.hash = self.hash.extend(token);
        self.len += 1;
    }

    pub(crate) fn extend_tokens(&mut self, tokens: &[u32]) {
        for &token in tokens {
            self.extend(token);
        }
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) const fn hash(&self) -> TranscriptHash {
        self.hash
    }
}

impl ContinuationKey {
    fn from_invocation(invocation: &Invocation) -> Self {
        Self {
            max_new_tokens: invocation.max_new_tokens,
            stop_token_ids: invocation.stop_token_ids.clone(),
        }
    }
}

impl ExecutionCache {
    fn new(max_bytes: usize) -> Self {
        Self {
            nodes: HashMap::new(),
            max_bytes,
            total_bytes: 0,
            touch_clock: 0,
        }
    }

    fn prompt_key(&self, prompt_tokens: &[u32]) -> (usize, TranscriptHash) {
        let mut state = TranscriptState::seed();
        state.extend_tokens(prompt_tokens);
        (state.len(), state.hash())
    }

    fn lookup_checkpoint(
        &mut self,
        invocation: &Invocation,
    ) -> Option<(TranscriptState, u32, Arc<Snapshot<ExecBackend>>)> {
        let mut state = TranscriptState::seed();
        let mut best_checkpoint = None;

        for &token in &invocation.input_ids {
            state.extend(token);
            let key = (state.len(), state.hash());
            let touch = self.next_touch();
            if let Some(node) = self.nodes.get_mut(&key) {
                if let Some(checkpoint) = node.checkpoint.as_mut() {
                    checkpoint.last_touch = touch;
                    best_checkpoint =
                        Some((state, checkpoint.next_token, checkpoint.snapshot.clone()));
                }
            }
        }

        best_checkpoint
    }

    fn lookup_continuation(
        &mut self,
        prompt_key: (usize, TranscriptHash),
        continuation_key: ContinuationKey,
    ) -> Option<Arc<[u32]>> {
        let touch = self.next_touch();
        self.nodes
            .get_mut(&prompt_key)
            .and_then(|node| node.continuations.get_mut(&continuation_key))
            .map(|entry| {
                entry.last_touch = touch;
                entry.output_tokens.clone()
            })
    }

    fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    fn insert_checkpoint(
        &mut self,
        program_id: &str,
        transcript_len: usize,
        transcript_hash: TranscriptHash,
        next_token: u32,
        snapshot_bytes: usize,
        snapshot: Arc<Snapshot<ExecBackend>>,
    ) {
        if transcript_len == 0 || snapshot_bytes == 0 || snapshot_bytes > self.max_bytes {
            debug!(
                %program_id,
                transcript_len,
                snapshot_bytes,
                max_bytes = self.max_bytes,
                skip_zero_len = transcript_len == 0,
                skip_zero_size = snapshot_bytes == 0,
                skip_oversize = snapshot_bytes > self.max_bytes,
                "skipping execution checkpoint insert"
            );
            return;
        }

        let key = (transcript_len, transcript_hash);
        let existing_bytes = self
            .nodes
            .get(&key)
            .and_then(|node| node.checkpoint.as_ref())
            .map_or(0, |entry| entry.bytes);
        self.evict_until_fits(snapshot_bytes.saturating_sub(existing_bytes));
        let touch = self.next_touch();
        let node = self.nodes.entry(key).or_default();

        if let Some(entry) = node.checkpoint.as_mut() {
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
            entry.snapshot = snapshot;
            entry.next_token = next_token;
            entry.bytes = snapshot_bytes;
            entry.last_touch = touch;
            self.total_bytes = self.total_bytes.saturating_add(snapshot_bytes);
            debug!(
                %program_id,
                transcript_len,
                cache_nodes = self.nodes.len(),
                cache_bytes = self.total_bytes,
                snapshot_bytes,
                "updated execution checkpoint"
            );
            return;
        }

        node.checkpoint = Some(CheckpointEntry {
            snapshot,
            next_token,
            bytes: snapshot_bytes,
            last_touch: touch,
        });
        self.total_bytes = self.total_bytes.saturating_add(snapshot_bytes);
        debug!(
            %program_id,
            transcript_len,
            cache_nodes = self.nodes.len(),
            cache_bytes = self.total_bytes,
            snapshot_bytes,
            "inserted execution checkpoint"
        );
    }

    fn insert_continuation(
        &mut self,
        program_id: &str,
        prompt_len: usize,
        prompt_hash: TranscriptHash,
        continuation_key: ContinuationKey,
        output_tokens: Arc<[u32]>,
    ) {
        let continuation_bytes = output_tokens
            .len()
            .saturating_mul(std::mem::size_of::<u32>());
        if continuation_bytes > self.max_bytes {
            debug!(
                %program_id,
                prompt_len,
                continuation_bytes,
                max_bytes = self.max_bytes,
                "skipping execution continuation insert"
            );
            return;
        }

        let key = (prompt_len, prompt_hash);
        let existing_bytes = self
            .nodes
            .get(&key)
            .and_then(|node| node.continuations.get(&continuation_key))
            .map_or(0, |entry| entry.bytes);
        self.evict_until_fits(continuation_bytes.saturating_sub(existing_bytes));
        let touch = self.next_touch();
        let node = self.nodes.entry(key).or_default();
        if let Some(entry) = node.continuations.get_mut(&continuation_key) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
            entry.output_tokens = output_tokens;
            entry.bytes = continuation_bytes;
            entry.last_touch = touch;
            self.total_bytes = self.total_bytes.saturating_add(continuation_bytes);
            debug!(
                %program_id,
                prompt_len,
                output_tokens = entry.output_tokens.len(),
                cache_nodes = self.nodes.len(),
                cache_bytes = self.total_bytes,
                continuation_bytes,
                "updated execution continuation"
            );
            return;
        }

        node.continuations.insert(
            continuation_key,
            ContinuationEntry {
                output_tokens,
                bytes: continuation_bytes,
                last_touch: touch,
            },
        );
        self.total_bytes = self.total_bytes.saturating_add(continuation_bytes);
        debug!(
            %program_id,
            prompt_len,
            cache_nodes = self.nodes.len(),
            cache_bytes = self.total_bytes,
            continuation_bytes,
            "inserted execution continuation"
        );
    }

    fn evict_until_fits(&mut self, additional_bytes: usize) {
        while self.total_bytes.saturating_add(additional_bytes) > self.max_bytes {
            let Some(lru_key) = self.least_recently_used_item() else {
                break;
            };
            self.remove_item(lru_key);
        }
    }

    fn least_recently_used_item(&self) -> Option<CacheItemKey> {
        let mut best: Option<(u64, CacheItemKey)> = None;

        for (&(transcript_len, transcript_hash), node) in &self.nodes {
            if let Some(checkpoint) = &node.checkpoint {
                let key = CacheItemKey::Checkpoint {
                    transcript_len,
                    transcript_hash,
                };
                match &best {
                    Some((best_touch, _)) if checkpoint.last_touch >= *best_touch => {}
                    _ => best = Some((checkpoint.last_touch, key)),
                }
            }

            for (continuation, entry) in &node.continuations {
                let key = CacheItemKey::Continuation {
                    transcript_len,
                    transcript_hash,
                    continuation: continuation.clone(),
                };
                match &best {
                    Some((best_touch, _)) if entry.last_touch >= *best_touch => {}
                    _ => best = Some((entry.last_touch, key)),
                }
            }
        }

        best.map(|(_, key)| key)
    }

    fn remove_item(&mut self, key: CacheItemKey) {
        match key {
            CacheItemKey::Checkpoint {
                transcript_len,
                transcript_hash,
            } => {
                if let Some(node) = self.nodes.get_mut(&(transcript_len, transcript_hash)) {
                    if let Some(removed) = node.checkpoint.take() {
                        self.total_bytes = self.total_bytes.saturating_sub(removed.bytes);
                    }
                    if node.checkpoint.is_none() && node.continuations.is_empty() {
                        self.nodes.remove(&(transcript_len, transcript_hash));
                    }
                }
            }
            CacheItemKey::Continuation {
                transcript_len,
                transcript_hash,
                continuation,
            } => {
                if let Some(node) = self.nodes.get_mut(&(transcript_len, transcript_hash)) {
                    if let Some(removed) = node.continuations.remove(&continuation) {
                        self.total_bytes = self.total_bytes.saturating_sub(removed.bytes);
                    }
                    if node.checkpoint.is_none() && node.continuations.is_empty() {
                        self.nodes.remove(&(transcript_len, transcript_hash));
                    }
                }
            }
        }
    }

    fn next_touch(&mut self) -> u64 {
        let touch = self.touch_clock;
        self.touch_clock = self.touch_clock.wrapping_add(1);
        touch
    }
}

#[cfg(test)]
mod tests {
    use super::{ContinuationKey, ExecutionCache, TranscriptState};
    use crate::state::Invocation;
    use std::sync::Arc;

    #[test]
    fn transcript_state_matches_incremental_hashing() {
        let tokens = [1, 2, 3, 4];
        let batch = TranscriptState::from_tokens(&tokens);
        let mut incremental = TranscriptState::seed();
        incremental.extend_tokens(&tokens);
        assert_eq!(batch.len(), incremental.len());
        assert_eq!(batch.hash(), incremental.hash());
    }

    #[test]
    fn exact_continuation_lookup_hits_without_checkpoint() {
        let mut cache = ExecutionCache::new(1024);
        let prompt = [10_u32, 20, 30];
        let prompt_state = TranscriptState::from_tokens(&prompt);
        let invocation = Invocation {
            input_ids: prompt.to_vec(),
            max_new_tokens: 16,
            stop_token_ids: vec![0, 1],
        };
        let expected = Arc::<[u32]>::from(vec![4_u32, 5, 6]);

        cache.insert_continuation(
            "program",
            prompt_state.len(),
            prompt_state.hash(),
            ContinuationKey::from_invocation(&invocation),
            expected.clone(),
        );

        let continuation = cache
            .lookup_continuation(
                cache.prompt_key(&invocation.input_ids),
                ContinuationKey::from_invocation(&invocation),
            )
            .expect("continuation should exist");
        assert_eq!(continuation, expected);
    }
}
