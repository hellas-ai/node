use crate::backend::ExecBackend;
use crate::state::Invocation;
use catgrad::cid::Cid;
use catgrad::runtime::{BoundProgram, Program};
use catgrad_llm::runtime::{BoundProgramText, TextExecution, TextSnapshot};
use hellas_rpc::ExecutorError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const DEFAULT_EXECUTION_CACHE_MAX_BYTES: usize = 8 << 30;

/// Maximum number of suffix tokens to teacher-force via `advance_one` when
/// resuming from a cached prefix snapshot. If the suffix is longer than this,
/// we discard the prefix and run a parallel `prefill_from_empty` instead.
///
/// Conservative initial value per `docs/PREFIX.md` §4.2; should become a
/// measured backend/model policy once we have decode/prefill cost data.
const CATCH_UP_THRESHOLD: usize = 64;

#[derive(Clone)]
pub(crate) struct ExecutionContext {
    bound_program: Arc<BoundProgram<ExecBackend>>,
    empty_snapshot: Arc<TextSnapshot<ExecBackend>>,
    execution_cache: Arc<Mutex<ExecutionCache>>,
}

#[derive(Clone)]
pub(crate) struct ExecutionStart {
    pub snapshot: Arc<TextSnapshot<ExecBackend>>,
    pub transcript: TranscriptState,
    pub next_token: Option<u32>,
    pub cached_output_tokens: Option<Arc<[u32]>>,
    /// Commitment for the request being quoted. Threaded into the worker so
    /// `cache_continuation` can key the exact-output replay cache by the
    /// canonical `Cid<TextExecution>` instead of bespoke per-cache identity.
    pub commitment_id: Cid<TextExecution>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TranscriptHash([u8; 32]);

#[derive(Clone, Copy, Debug)]
pub(crate) struct TranscriptState {
    len: usize,
    hash: TranscriptHash,
}

#[derive(Clone)]
struct CheckpointEntry {
    snapshot: Arc<TextSnapshot<ExecBackend>>,
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

/// Two flat maps, no co-location: prefix snapshots are keyed by transcript
/// position (because lookup is a prefix scan over the prompt), exact-replay
/// continuations are keyed by `Cid<TextExecution>` (point lookup of the full
/// request commitment). LRU eviction runs across both maps via a shared
/// `touch_clock`.
struct ExecutionCache {
    checkpoints: HashMap<(usize, TranscriptHash), CheckpointEntry>,
    continuations: HashMap<Cid<TextExecution>, ContinuationEntry>,
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
        commitment: Cid<TextExecution>,
    },
}

impl ExecutionContext {
    pub(crate) fn new(
        bound_program: Arc<BoundProgram<ExecBackend>>,
    ) -> Result<Self, ExecutorError> {
        debug!(
            program_id = %bound_program.id(),
            state_tensors = bound_program.program().empty_state_type.len(),
            max_bytes = DEFAULT_EXECUTION_CACHE_MAX_BYTES,
            "initialized execution cache"
        );
        Ok(Self {
            empty_snapshot: Arc::new(bound_program.empty_text_snapshot()),
            execution_cache: Arc::new(Mutex::new(ExecutionCache::new(
                DEFAULT_EXECUTION_CACHE_MAX_BYTES,
            ))),
            bound_program,
        })
    }

    pub(crate) fn bound_program(&self) -> &Arc<BoundProgram<ExecBackend>> {
        &self.bound_program
    }

    pub(crate) fn execution_start(
        &self,
        invocation: &Invocation,
        commitment_id: Cid<TextExecution>,
    ) -> ExecutionStart {
        let mut cache = self
            .execution_cache
            .lock()
            .expect("execution cache mutex poisoned");
        let checkpoint = cache.lookup_checkpoint(invocation);
        let continuation = cache.lookup_continuation(commitment_id);
        let prompt_tokens = invocation.input_ids.len();
        let (snapshot, transcript, next_token) = match checkpoint {
            Some((transcript, next_token, snapshot))
                if prompt_tokens.saturating_sub(transcript.len()) <= CATCH_UP_THRESHOLD =>
            {
                (snapshot, transcript, Some(next_token))
            }
            _ => (self.empty_snapshot.clone(), TranscriptState::seed(), None),
        };
        debug!(
            program_id = %self.bound_program.id(),
            commitment_id = %commitment_id,
            prompt_tokens = invocation.input_ids.len(),
            matched_prefix_tokens = transcript.len(),
            cached_output_tokens = continuation.as_ref().map_or(0, |entry| entry.len()),
            cache_checkpoints = cache.checkpoints.len(),
            cache_continuations = cache.continuations.len(),
            cache_bytes = cache.total_bytes(),
            "execution cache lookup"
        );
        ExecutionStart {
            snapshot,
            transcript,
            next_token,
            cached_output_tokens: continuation,
            commitment_id,
        }
    }

    pub(crate) fn cache_checkpoint(
        &self,
        transcript_len: usize,
        transcript_hash: TranscriptHash,
        next_token: u32,
        snapshot: TextSnapshot<ExecBackend>,
    ) {
        let snapshot_bytes = snapshot.allocated();
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
        commitment_id: Cid<TextExecution>,
        output_tokens: Vec<u32>,
    ) {
        self.execution_cache
            .lock()
            .expect("execution cache mutex poisoned")
            .insert_continuation(
                self.bound_program.id(),
                commitment_id,
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

impl ExecutionCache {
    fn new(max_bytes: usize) -> Self {
        Self {
            checkpoints: HashMap::new(),
            continuations: HashMap::new(),
            max_bytes,
            total_bytes: 0,
            touch_clock: 0,
        }
    }

    fn lookup_checkpoint(
        &mut self,
        invocation: &Invocation,
    ) -> Option<(TranscriptState, u32, Arc<TextSnapshot<ExecBackend>>)> {
        let mut state = TranscriptState::seed();
        let mut best_checkpoint = None;

        for &token in &invocation.input_ids {
            state.extend(token);
            let key = (state.len(), state.hash());
            let touch = self.next_touch();
            if let Some(checkpoint) = self.checkpoints.get_mut(&key) {
                checkpoint.last_touch = touch;
                best_checkpoint = Some((state, checkpoint.next_token, checkpoint.snapshot.clone()));
            }
        }

        best_checkpoint
    }

    fn lookup_continuation(&mut self, commitment_id: Cid<TextExecution>) -> Option<Arc<[u32]>> {
        let touch = self.next_touch();
        self.continuations.get_mut(&commitment_id).map(|entry| {
            entry.last_touch = touch;
            entry.output_tokens.clone()
        })
    }

    fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    fn insert_checkpoint(
        &mut self,
        program_id: Cid<Program>,
        transcript_len: usize,
        transcript_hash: TranscriptHash,
        next_token: u32,
        snapshot_bytes: usize,
        snapshot: Arc<TextSnapshot<ExecBackend>>,
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
        let existing_bytes = self.checkpoints.get(&key).map_or(0, |entry| entry.bytes);
        self.evict_until_fits(snapshot_bytes.saturating_sub(existing_bytes));
        let touch = self.next_touch();

        if let Some(entry) = self.checkpoints.get_mut(&key) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
            entry.snapshot = snapshot;
            entry.next_token = next_token;
            entry.bytes = snapshot_bytes;
            entry.last_touch = touch;
            self.total_bytes = self.total_bytes.saturating_add(snapshot_bytes);
            debug!(
                %program_id,
                transcript_len,
                cache_checkpoints = self.checkpoints.len(),
                cache_bytes = self.total_bytes,
                snapshot_bytes,
                "updated execution checkpoint"
            );
            return;
        }

        self.checkpoints.insert(
            key,
            CheckpointEntry {
                snapshot,
                next_token,
                bytes: snapshot_bytes,
                last_touch: touch,
            },
        );
        self.total_bytes = self.total_bytes.saturating_add(snapshot_bytes);
        debug!(
            %program_id,
            transcript_len,
            cache_checkpoints = self.checkpoints.len(),
            cache_bytes = self.total_bytes,
            snapshot_bytes,
            "inserted execution checkpoint"
        );
    }

    fn insert_continuation(
        &mut self,
        program_id: Cid<Program>,
        commitment_id: Cid<TextExecution>,
        output_tokens: Arc<[u32]>,
    ) {
        let continuation_bytes = output_tokens
            .len()
            .saturating_mul(std::mem::size_of::<u32>());
        if continuation_bytes > self.max_bytes {
            debug!(
                %program_id,
                %commitment_id,
                continuation_bytes,
                max_bytes = self.max_bytes,
                "skipping execution continuation insert"
            );
            return;
        }

        let existing_bytes = self
            .continuations
            .get(&commitment_id)
            .map_or(0, |entry| entry.bytes);
        self.evict_until_fits(continuation_bytes.saturating_sub(existing_bytes));
        let touch = self.next_touch();
        if let Some(entry) = self.continuations.get_mut(&commitment_id) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
            entry.output_tokens = output_tokens;
            entry.bytes = continuation_bytes;
            entry.last_touch = touch;
            self.total_bytes = self.total_bytes.saturating_add(continuation_bytes);
            debug!(
                %program_id,
                %commitment_id,
                output_tokens = entry.output_tokens.len(),
                cache_continuations = self.continuations.len(),
                cache_bytes = self.total_bytes,
                continuation_bytes,
                "updated execution continuation"
            );
            return;
        }

        self.continuations.insert(
            commitment_id,
            ContinuationEntry {
                output_tokens,
                bytes: continuation_bytes,
                last_touch: touch,
            },
        );
        self.total_bytes = self.total_bytes.saturating_add(continuation_bytes);
        debug!(
            %program_id,
            %commitment_id,
            cache_continuations = self.continuations.len(),
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

        for (&(transcript_len, transcript_hash), checkpoint) in &self.checkpoints {
            let key = CacheItemKey::Checkpoint {
                transcript_len,
                transcript_hash,
            };
            match &best {
                Some((best_touch, _)) if checkpoint.last_touch >= *best_touch => {}
                _ => best = Some((checkpoint.last_touch, key)),
            }
        }

        for (&commitment, entry) in &self.continuations {
            let key = CacheItemKey::Continuation { commitment };
            match &best {
                Some((best_touch, _)) if entry.last_touch >= *best_touch => {}
                _ => best = Some((entry.last_touch, key)),
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
                if let Some(removed) = self.checkpoints.remove(&(transcript_len, transcript_hash)) {
                    self.total_bytes = self.total_bytes.saturating_sub(removed.bytes);
                }
            }
            CacheItemKey::Continuation { commitment } => {
                if let Some(removed) = self.continuations.remove(&commitment) {
                    self.total_bytes = self.total_bytes.saturating_sub(removed.bytes);
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
    use super::{Cid, ExecutionCache, Program, TextExecution, TranscriptState};
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
    fn exact_continuation_lookup_hits_by_commitment_id() {
        let mut cache = ExecutionCache::new(1024);
        let commitment_id = Cid::<TextExecution>::from_bytes([7; 32]);
        let expected = Arc::<[u32]>::from(vec![4_u32, 5, 6]);

        cache.insert_continuation(
            Cid::<Program>::from_bytes([0; 32]),
            commitment_id,
            expected.clone(),
        );

        let continuation = cache
            .lookup_continuation(commitment_id)
            .expect("continuation should exist");
        assert_eq!(continuation, expected);
    }

    #[test]
    fn continuation_lookup_misses_on_different_commitment() {
        let mut cache = ExecutionCache::new(1024);
        cache.insert_continuation(
            Cid::<Program>::from_bytes([0; 32]),
            Cid::<TextExecution>::from_bytes([1; 32]),
            Arc::<[u32]>::from(vec![1_u32, 2, 3]),
        );
        assert!(
            cache
                .lookup_continuation(Cid::<TextExecution>::from_bytes([2; 32]))
                .is_none()
        );
    }
}
