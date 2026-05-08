use crate::backend::ExecBackend;
use crate::state::Invocation;
use catgrad::category::core::Shape;
use catgrad::cid::Cid;
use catgrad::interpreter;
use catgrad::runtime::{BoundProgram, Program};
use catgrad_llm::runtime::{BoundProgramText, TextExecution, TextPolicy, TextReceipt, TextState};
use hellas_rpc::ExecutorError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const DEFAULT_EXECUTION_CACHE_MAX_BYTES: usize = 8 << 30;

/// A bound program plus its run-time caches: continuation (exact-replay)
/// and receipts (anchored starting states).
///
/// One [`ExecutionContext`] exists per `(WeightsLocator, Cid<Program>)`
/// — see [`crate::programs::Cache`]. The context is cheap to clone (`Arc`
/// inside) and lives for the lifetime of the bound program.
///
/// ## Continuation cache
///
/// Keyed by [`Cid<TextExecution>`] — the request commitment. Two requests
/// with the same commitment are byte-identical asks; the cache returns
/// the previously-emitted output tokens without touching the model.
///
/// ## Receipt store
///
/// Keyed by [`Cid<TextReceipt>`] — the content commitment of a particular
/// `(execution, final state, output tokens, position)` tuple. Populated
/// at bind time with the program's *genesis receipt* (the cold-start
/// anchor) and at end of every real execution with that execution's final
/// receipt. Anchored requests look up the receipt store by their incoming
/// `initial_receipt_id` to find the live state to start from.
#[derive(Clone)]
pub(crate) struct ExecutionContext {
    bound_program: Arc<BoundProgram<ExecBackend>>,
    genesis_receipt_id: Cid<TextReceipt>,
    execution_cache: Arc<Mutex<ExecutionCache>>,
}

/// Cached output of a previous identical request — produced once by a
/// real decode, reused on exact-replay hits. Carries everything needed
/// to reconstruct the original execution's terminal outcome without
/// re-running the model.
#[derive(Clone)]
pub(crate) struct CachedContinuation {
    pub output_tokens: Arc<[u32]>,
    /// Receipt CID the original real-decode produced. Replays advertise
    /// the same receipt: it identifies the same outputs and the same
    /// post-state by content.
    pub receipt_id: Cid<TextReceipt>,
}

/// Pre-computed cache lookup result for a single quote, threaded into
/// the worker via [`crate::state::QuoteRecord`].
#[derive(Clone)]
pub(crate) struct ExecutionStart {
    /// Cached output for an exact-replay hit. When `Some`, the runner
    /// streams the cached tokens and skips the model entirely.
    pub cached: Option<CachedContinuation>,
    /// Commitment for this request: a [`Cid<TextExecution>`] over
    /// `(program binding, previous execution, input_tokens, policy)`.
    /// Threaded into the worker so `cache_continuation` keys the
    /// exact-output replay cache by this canonical commitment hash.
    /// Same 32 bytes are logged at quote / accept-execution / worker-start
    /// for end-to-end audit.
    pub commitment_id: Cid<TextExecution>,
    /// Resolved starting state for this request. For cold-start runs
    /// this is the genesis state for the bound program.
    pub initial_state: Arc<TextState<ExecBackend>>,
}

#[derive(Clone)]
struct ContinuationEntry {
    output_tokens: Arc<[u32]>,
    receipt_id: Cid<TextReceipt>,
    bytes: usize,
    last_touch: u64,
}

struct ExecutionCache {
    /// Exact-replay cache, keyed by request commitment.
    continuations: HashMap<Cid<TextExecution>, ContinuationEntry>,
    /// Receipt store, keyed by content hash of the receipt. Populated at
    /// bind time with the genesis receipt; populated at end of every real
    /// execution with the resulting [`TextState`].
    receipts: HashMap<Cid<TextReceipt>, Arc<TextState<ExecBackend>>>,
    /// Live states keyed by their input-addressed execution commitment.
    /// This is the protocol-facing anchor for direct CID-only symbolic
    /// requests; receipt CIDs remain a courtesy API handle.
    states_by_execution: HashMap<Cid<TextExecution>, Arc<TextState<ExecBackend>>>,
    max_bytes: usize,
    total_bytes: usize,
    touch_clock: u64,
}

impl ExecutionContext {
    pub(crate) fn new(
        bound_program: Arc<BoundProgram<ExecBackend>>,
    ) -> Result<Self, ExecutorError> {
        let genesis = bound_program.genesis_text_state();
        let genesis_receipt_id = genesis.receipt_id();
        debug!(
            program_id = %bound_program.program().id(),
            state_tensors = bound_program.program().empty_state_type().len(),
            %genesis_receipt_id,
            max_bytes = DEFAULT_EXECUTION_CACHE_MAX_BYTES,
            "initialized execution cache"
        );
        let mut cache = ExecutionCache::new(DEFAULT_EXECUTION_CACHE_MAX_BYTES);
        cache.insert_genesis(Arc::new(genesis));
        Ok(Self {
            bound_program,
            genesis_receipt_id,
            execution_cache: Arc::new(Mutex::new(cache)),
        })
    }

    pub(crate) fn bound_program(&self) -> &Arc<BoundProgram<ExecBackend>> {
        &self.bound_program
    }

    /// CID of this bind's genesis receipt — the cold-start anchor.
    /// Cold-start requests should reference this CID as their
    /// `initial_receipt_id`.
    pub(crate) fn genesis_receipt_id(&self) -> Cid<TextReceipt> {
        self.genesis_receipt_id
    }

    /// Build the request `TextExecution` commitment from this bound program
    /// + invocation. Used at quote time to compute `commitment_id` before
    /// the runner sees the request.
    pub(crate) fn build_text_execution(
        &self,
        initial_state_receipt_id: Cid<TextReceipt>,
        invocation: &Invocation,
        policy: &TextPolicy,
    ) -> Result<TextExecution, ExecutorError> {
        let bound = &self.bound_program;
        let input_tensor = interpreter::tensor(
            &bound.interpreter().backend,
            Shape(vec![1, invocation.input_ids.len()]),
            invocation.input_ids.clone(),
        )
        .map_err(|error| {
            ExecutorError::WeightsError(format!("failed to build input tensor: {error:?}"))
        })?;
        let previous = self
            .state_for_receipt(initial_state_receipt_id)?
            .execution_id();
        Ok(TextExecution::new(bound, previous, &input_tensor, policy)?)
    }

    /// Build the [`ExecutionStart`] for a request: resolve the starting
    /// state from the receipt store and look up the continuation cache.
    /// Returns `Err` if `initial_receipt_id` names a receipt the executor
    /// doesn't have.
    pub(crate) fn execution_start(
        &self,
        commitment_id: Cid<TextExecution>,
        initial_receipt_id: Cid<TextReceipt>,
    ) -> Result<ExecutionStart, ExecutorError> {
        let mut cache = self
            .execution_cache
            .lock()
            .expect("execution cache mutex poisoned");
        let initial_state = cache
            .receipts
            .get(&initial_receipt_id)
            .cloned()
            .ok_or_else(|| {
                ExecutorError::WeightsError(format!(
                    "initial receipt not found: {initial_receipt_id}"
                ))
            })?;
        let cached = cache.lookup_continuation(commitment_id);
        debug!(
            program_id = %self.bound_program.program().id(),
            %commitment_id,
            %initial_receipt_id,
            cached_output_tokens = cached.as_ref().map_or(0, |c| c.output_tokens.len()),
            cache_continuations = cache.continuations.len(),
            cache_receipts = cache.receipts.len(),
            cache_bytes = cache.total_bytes(),
            "execution cache lookup"
        );
        Ok(ExecutionStart {
            cached,
            commitment_id,
            initial_state,
        })
    }

    /// Build an [`ExecutionStart`] from the protocol-level previous
    /// execution commitment. Direct CID-only symbolic requests use this
    /// path; they do not name a receipt.
    pub(crate) fn execution_start_after(
        &self,
        commitment_id: Cid<TextExecution>,
        previous_execution_id: Cid<TextExecution>,
    ) -> Result<ExecutionStart, ExecutorError> {
        let mut cache = self
            .execution_cache
            .lock()
            .expect("execution cache mutex poisoned");
        let initial_state = cache
            .states_by_execution
            .get(&previous_execution_id)
            .cloned()
            .ok_or_else(|| {
                ExecutorError::WeightsError(format!(
                    "previous execution state not found: {previous_execution_id}"
                ))
            })?;
        let cached = cache.lookup_continuation(commitment_id);
        debug!(
            program_id = %self.bound_program.program().id(),
            %commitment_id,
            %previous_execution_id,
            cached_output_tokens = cached.as_ref().map_or(0, |c| c.output_tokens.len()),
            cache_continuations = cache.continuations.len(),
            cache_receipts = cache.receipts.len(),
            cache_bytes = cache.total_bytes(),
            "execution cache lookup by previous execution"
        );
        Ok(ExecutionStart {
            cached,
            commitment_id,
            initial_state,
        })
    }

    fn state_for_receipt(
        &self,
        receipt_id: Cid<TextReceipt>,
    ) -> Result<Arc<TextState<ExecBackend>>, ExecutorError> {
        self.execution_cache
            .lock()
            .expect("execution cache mutex poisoned")
            .receipts
            .get(&receipt_id)
            .cloned()
            .ok_or_else(|| {
                ExecutorError::WeightsError(format!("initial receipt not found: {receipt_id}"))
            })
    }

    pub(crate) fn cache_continuation(
        &self,
        commitment_id: Cid<TextExecution>,
        output_tokens: Vec<u32>,
        receipt_id: Cid<TextReceipt>,
    ) {
        self.execution_cache
            .lock()
            .expect("execution cache mutex poisoned")
            .insert_continuation(
                self.bound_program.program().id(),
                commitment_id,
                Arc::<[u32]>::from(output_tokens),
                receipt_id,
            );
    }

    /// Store the final [`TextState`] of an execution under its receipt
    /// CID. Future anchored requests can name this receipt to resume from
    /// this state.
    pub(crate) fn cache_receipt(&self, state: Arc<TextState<ExecBackend>>) {
        let receipt_id = state.receipt_id();
        let bytes = state.allocated();
        self.execution_cache
            .lock()
            .expect("execution cache mutex poisoned")
            .insert_receipt(self.bound_program.program().id(), receipt_id, bytes, state);
    }
}

impl ExecutionCache {
    fn new(max_bytes: usize) -> Self {
        Self {
            continuations: HashMap::new(),
            receipts: HashMap::new(),
            states_by_execution: HashMap::new(),
            max_bytes,
            total_bytes: 0,
            touch_clock: 0,
        }
    }

    fn insert_genesis(&mut self, state: Arc<TextState<ExecBackend>>) {
        self.receipts.insert(state.receipt_id(), Arc::clone(&state));
        self.states_by_execution.insert(state.execution_id(), state);
    }

    fn lookup_continuation(
        &mut self,
        commitment_id: Cid<TextExecution>,
    ) -> Option<CachedContinuation> {
        let touch = self.next_touch();
        self.continuations.get_mut(&commitment_id).map(|entry| {
            entry.last_touch = touch;
            CachedContinuation {
                output_tokens: entry.output_tokens.clone(),
                receipt_id: entry.receipt_id,
            }
        })
    }

    fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    fn insert_continuation(
        &mut self,
        program_id: Cid<Program>,
        commitment_id: Cid<TextExecution>,
        output_tokens: Arc<[u32]>,
        receipt_id: Cid<TextReceipt>,
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
        self.evict_continuations_until_fits(continuation_bytes.saturating_sub(existing_bytes));
        let touch = self.next_touch();
        if let Some(entry) = self.continuations.get_mut(&commitment_id) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
            entry.output_tokens = output_tokens;
            entry.receipt_id = receipt_id;
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
                receipt_id,
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

    fn insert_receipt(
        &mut self,
        program_id: Cid<Program>,
        receipt_id: Cid<TextReceipt>,
        bytes: usize,
        state: Arc<TextState<ExecBackend>>,
    ) {
        self.states_by_execution
            .entry(state.execution_id())
            .or_insert_with(|| Arc::clone(&state));
        if self.receipts.contains_key(&receipt_id) {
            // Same content, already present; refresh nothing here (no LRU
            // eviction policy on receipts yet — TODO follow-up).
            return;
        }
        self.receipts.insert(receipt_id, state);
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        debug!(
            %program_id,
            %receipt_id,
            cache_receipts = self.receipts.len(),
            cache_bytes = self.total_bytes,
            receipt_bytes = bytes,
            "inserted receipt"
        );
    }

    fn evict_continuations_until_fits(&mut self, additional_bytes: usize) {
        while self.total_bytes.saturating_add(additional_bytes) > self.max_bytes {
            let Some(lru_commitment) = self.least_recently_used_continuation() else {
                break;
            };
            if let Some(removed) = self.continuations.remove(&lru_commitment) {
                self.total_bytes = self.total_bytes.saturating_sub(removed.bytes);
            }
        }
    }

    fn least_recently_used_continuation(&self) -> Option<Cid<TextExecution>> {
        let mut best: Option<(u64, Cid<TextExecution>)> = None;
        for (&commitment, entry) in &self.continuations {
            match &best {
                Some((best_touch, _)) if entry.last_touch >= *best_touch => {}
                _ => best = Some((entry.last_touch, commitment)),
            }
        }
        best.map(|(_, commitment)| commitment)
    }

    fn next_touch(&mut self) -> u64 {
        let touch = self.touch_clock;
        self.touch_clock = self.touch_clock.wrapping_add(1);
        touch
    }
}

#[cfg(test)]
mod tests {
    use super::{Cid, ExecutionCache, Program, TextExecution, TextReceipt};
    use std::sync::Arc;

    #[test]
    fn exact_continuation_lookup_hits_by_commitment_id() {
        let mut cache = ExecutionCache::new(1024);
        let commitment_id = Cid::<TextExecution>::from_bytes([7; 32]);
        let receipt_id = Cid::<TextReceipt>::from_bytes([9; 32]);
        let expected = Arc::<[u32]>::from(vec![4_u32, 5, 6]);

        cache.insert_continuation(
            Cid::<Program>::from_bytes([0; 32]),
            commitment_id,
            expected.clone(),
            receipt_id,
        );

        let continuation = cache
            .lookup_continuation(commitment_id)
            .expect("continuation should exist");
        assert_eq!(continuation.output_tokens, expected);
        assert_eq!(continuation.receipt_id, receipt_id);
    }

    #[test]
    fn continuation_lookup_misses_on_different_commitment() {
        let mut cache = ExecutionCache::new(1024);
        cache.insert_continuation(
            Cid::<Program>::from_bytes([0; 32]),
            Cid::<TextExecution>::from_bytes([1; 32]),
            Arc::<[u32]>::from(vec![1_u32, 2, 3]),
            Cid::<TextReceipt>::from_bytes([2; 32]),
        );
        assert!(
            cache
                .lookup_continuation(Cid::<TextExecution>::from_bytes([2; 32]))
                .is_none()
        );
    }
}
