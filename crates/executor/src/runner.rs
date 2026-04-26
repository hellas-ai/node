//! Causal-LM decode driver for the executor.
//!
//! # Overview
//!
//! The runner drives a single text-generation request to completion, emitting
//! generated tokens to a streaming callback and caching reusable artifacts
//! for future requests. It's the only place in the executor that calls into
//! catgrad's LLM execution surface; everything else (cache, scheduling,
//! quoting) is plain data.
//!
//! # Two layers
//!
//! [`run_cached_program_streaming`] is the public entry point. It is small
//! and concrete: it starts a [`TextSession`](catgrad_llm::TextSession) from
//! the cached or empty snapshot, runs the algorithm, and writes the
//! resulting outputs/snapshots back to the [`ExecutionContext`] cache.
//!
//! [`decode`] is the algorithm itself. It is generic over any
//! [`CausalStepper`] implementation, takes plain-data inputs ([`DecodePlan`]),
//! and returns plain-data outputs ([`DecodeOutcome`]). It does not touch the
//! cache, does not touch catgrad concrete types, and has no I/O beyond two
//! callbacks (first-token-ready notification and per-batch progress).
//!
//! This split exists for testability: with a deterministic in-memory
//! [`CausalStepper`] implementation, the algorithm runs in microseconds
//! against synthetic inputs and can be exhaustively property-tested without
//! a GPU or model weights. The narrow seam at [`CausalStepper`] is the only
//! abstraction the algorithm needs; cache layer, scheduling layer, gateway
//! layer all stay concrete.
//!
//! # Algorithm
//!
//! The algorithm matches `docs/PREFIX.md` §4.2:
//!
//! 1. **Exact-output replay** (handled in the wrapper, before [`decode`]).
//!    If the cache contains generated output for this exact prompt and
//!    generation settings, stream it without touching the model.
//!
//! 2. **Drive to prompt-end position.** Three sub-paths picked by the cache
//!    state passed in via [`DecodePlan`]:
//!    - **Full prefix hit** — `cached_prefix_len == input_ids.len()`. The
//!      cache shipped a `cached_next_token`; no model call needed.
//!    - **Empty session** — `cached_prefix_len == 0`. Run a single
//!      `prefill_from_empty(input_ids)` call. This is the only multi-token
//!      input call the safe causal contract permits.
//!    - **Partial prefix** — `0 < cached_prefix_len < input_ids.len()`.
//!      Teacher-force the suffix one token at a time via `advance_one`. The
//!      caller (typically [`ExecutionContext::execution_start`]) is
//!      responsible for keeping suffix length below a catch-up threshold so
//!      this chain doesn't outweigh a fresh prefill.
//!
//! 3. **Decode loop.** Emit tokens via the progress callback in batches
//!    of `batch_size`, with stop-token checking. Each step is a single
//!    `advance_one` call.
//!
//! 4. **Final snapshot.** If generation ran to the length cap (no stop
//!    token), feed the last emitted token through one more `advance_one` to
//!    align session position with transcript length, then yield the snapshot
//!    via `into_snapshot`. The wrapper writes it to the cache. If a stop
//!    token was emitted, no snapshot is captured (the session is one step
//!    behind the transcript and we don't store snapshots for stopped
//!    generations).
//!
//! # Determinism contract
//!
//! Together with [`CausalStepper`]'s split-stability contract, this
//! algorithm guarantees that committed model output is independent of cache
//! state: a request reaches the same generated tokens whether it ran from
//! an empty session, a partial-prefix snapshot, or a full-prefix snapshot.
//! The split-stability proptest in this module's test suite encodes that
//! property as an executable invariant.

use crate::backend::ExecBackend;
use crate::state::Invocation;
use crate::programs::{ExecutionContext, ExecutionStart};
use catgrad_llm::runtime::{BoundProgramText, CausalStepper, TextSession};
use hellas_rpc::ExecutorError;
use hellas_rpc::encode_token_ids;
use std::time::Instant;

#[derive(Default)]
struct FirstTokenLog {
    prompt_tokens: usize,
    cached_prompt_tokens: usize,
    cached_output_tokens: usize,
    prefill_input_tokens: usize,
    first_token_total_ms: u128,
    exact_prefix_hit: bool,
    exact_replay_hit: bool,
    session_start_ms: u128,
}

fn log_first_token(m: FirstTokenLog) {
    info!(
        prompt_tokens = m.prompt_tokens,
        cached_prompt_tokens = m.cached_prompt_tokens,
        cached_output_tokens = m.cached_output_tokens,
        prefill_input_tokens = m.prefill_input_tokens,
        first_token_total_ms = m.first_token_total_ms,
        "first token ready"
    );
    debug!(
        prompt_tokens = m.prompt_tokens,
        cached_prompt_tokens = m.cached_prompt_tokens,
        cached_output_tokens = m.cached_output_tokens,
        exact_prefix_hit = m.exact_prefix_hit,
        exact_replay_hit = m.exact_replay_hit,
        session_start_ms = m.session_start_ms,
        prefill_input_tokens = m.prefill_input_tokens,
        first_token_total_ms = m.first_token_total_ms,
        "execute first-token phases"
    );
}

/// Pure-data inputs to [`decode`]. All cache-policy decisions (whether to
/// reuse a snapshot, catch-up threshold, etc.) must be made by the caller
/// and reflected in `cached_prefix_len` / `cached_next_token`.
pub(crate) struct DecodePlan<'a> {
    /// Full prompt token sequence. Must be non-empty.
    pub input_ids: &'a [u32],
    /// Number of tokens already folded into the stepper's state. Must
    /// equal `stepper.position()` at call time. `0` for a fresh session.
    pub cached_prefix_len: usize,
    /// Pre-computed predicted next-token if the cache hit covers the full
    /// prompt. `Some` exactly when `cached_prefix_len == input_ids.len()`.
    pub cached_next_token: Option<u32>,
    /// Maximum number of tokens to generate.
    pub max_new_tokens: u32,
    /// Stop tokens; emitting any of these halts decoding before the cap.
    pub stop_token_ids: &'a [i32],
    /// Number of generated tokens to buffer before invoking the progress
    /// callback. `1` for un-batched delivery.
    pub batch_size: usize,
}

/// Pure-data outputs from [`decode`]. The caller is responsible for any
/// cache writes, observability, etc.
pub(crate) struct DecodeOutcome<S> {
    /// Tokens emitted to the progress callback, in order, excluding any
    /// stop token that ended generation.
    pub output_tokens: Vec<u32>,
    /// Final session snapshot at position
    /// `cached_prefix_len + (suffix tokens consumed) + output_tokens.len()`,
    /// paired with the predicted next token at that position. `Some` exactly
    /// when generation reached `max_new_tokens` without hitting a stop
    /// token AND at least one token was emitted; `None` otherwise (in which
    /// case the session position would be one step behind the transcript
    /// and the snapshot would not be reusable).
    pub final_snapshot: Option<(S, u32)>,
}

/// Runs the safe causal-LM decode algorithm against any [`CausalStepper`].
///
/// The stepper must already be at position `plan.cached_prefix_len`. The
/// function is otherwise pure: side effects are limited to the two
/// callbacks. See module-level documentation for the full algorithm.
pub(crate) fn decode<S: CausalStepper>(
    mut stepper: S,
    plan: DecodePlan<'_>,
    on_first_token: impl FnOnce(),
    mut on_progress: impl FnMut(u64, &[u8]),
) -> Result<DecodeOutcome<S::Snapshot>, ExecutorError> {
    debug_assert_eq!(stepper.position(), plan.cached_prefix_len);
    let prompt_tokens = plan.input_ids.len();

    let next_token = if plan.cached_prefix_len == prompt_tokens {
        plan.cached_next_token.ok_or(ExecutorError::NoOutput)?
    } else if plan.cached_prefix_len == 0 {
        stepper.prefill_from_empty(plan.input_ids)?.next_token()
    } else {
        let suffix = &plan.input_ids[plan.cached_prefix_len..];
        let mut predicted = None;
        for &token in suffix {
            predicted = Some(stepper.advance_one(token)?.next_token());
        }
        predicted.expect("partial prefix hit implies non-empty suffix")
    };

    on_first_token();

    let mut current_token = next_token;
    let mut output_tokens = Vec::new();
    let mut pending_batch = Vec::with_capacity(plan.batch_size);
    let mut generated_tokens = 0u64;
    let mut last_emitted_token = None;
    let mut hit_stop = false;

    for step_idx in 0..plan.max_new_tokens {
        if i32::try_from(current_token)
            .ok()
            .is_some_and(|token| plan.stop_token_ids.contains(&token))
        {
            hit_stop = true;
            break;
        }

        generated_tokens += 1;
        output_tokens.push(current_token);
        pending_batch.push(current_token);
        last_emitted_token = Some(current_token);

        if pending_batch.len() >= plan.batch_size {
            let chunk = encode_token_ids(&pending_batch);
            on_progress(generated_tokens, &chunk);
            pending_batch.clear();
        }

        if step_idx + 1 < plan.max_new_tokens {
            current_token = stepper.advance_one(current_token)?.next_token();
        }
    }

    if !pending_batch.is_empty() {
        let chunk = encode_token_ids(&pending_batch);
        on_progress(generated_tokens, &chunk);
    }

    let final_snapshot = if !hit_stop
        && let Some(last) = last_emitted_token
    {
        let predicted = stepper.advance_one(last)?.next_token();
        Some((stepper.into_snapshot(), predicted))
    } else {
        None
    };

    Ok(DecodeOutcome {
        output_tokens,
        final_snapshot,
    })
}

/// Public entry point. Wires the catgrad text session, runs [`decode`], and
/// writes results back to the [`ExecutionContext`] cache.
pub fn run_cached_program_streaming(
    program: &ExecutionContext,
    start: &ExecutionStart,
    invocation: &Invocation,
    stream_batch_size: u32,
    mut on_progress: impl FnMut(u64, &[u8]),
) -> Result<(), ExecutorError> {
    let started_at = Instant::now();
    let batch_size = usize::try_from(stream_batch_size.max(1)).unwrap_or(usize::MAX);
    let prompt_tokens = invocation.input_ids.len();

    if let Some(cached_output_tokens) = start.cached_output_tokens.as_deref() {
        log_first_token(FirstTokenLog {
            prompt_tokens,
            cached_prompt_tokens: start.transcript.len(),
            cached_output_tokens: cached_output_tokens.len(),
            exact_prefix_hit: start.transcript.len() == prompt_tokens,
            exact_replay_hit: true,
            first_token_total_ms: started_at.elapsed().as_millis(),
            ..Default::default()
        });
        stream_cached_output(cached_output_tokens, batch_size, on_progress);
        return Ok(());
    }

    let session_start = Instant::now();
    let stepper: TextSession<ExecBackend> = program
        .bound_program()
        .clone()
        .start_text(start.snapshot.as_ref().clone())?;
    let session_start_ms = session_start.elapsed().as_millis();

    let plan = DecodePlan {
        input_ids: &invocation.input_ids,
        cached_prefix_len: start.transcript.len(),
        cached_next_token: start.next_token,
        max_new_tokens: invocation.max_new_tokens,
        stop_token_ids: &invocation.stop_token_ids,
        batch_size,
    };

    let cached_prompt_tokens = start.transcript.len();
    let on_first_token = || {
        log_first_token(FirstTokenLog {
            prompt_tokens,
            cached_prompt_tokens,
            prefill_input_tokens: prompt_tokens.saturating_sub(cached_prompt_tokens),
            exact_prefix_hit: cached_prompt_tokens == prompt_tokens,
            first_token_total_ms: started_at.elapsed().as_millis(),
            session_start_ms,
            ..Default::default()
        });
    };

    let outcome = decode(stepper, plan, on_first_token, &mut on_progress)?;

    let mut prompt_state = start.transcript;
    if cached_prompt_tokens < prompt_tokens {
        prompt_state.extend_tokens(&invocation.input_ids[cached_prompt_tokens..]);
    }
    let DecodeOutcome {
        output_tokens,
        final_snapshot,
    } = outcome;

    if let Some((snapshot, predicted_next_token)) = final_snapshot {
        let mut transcript_state = prompt_state;
        transcript_state.extend_tokens(&output_tokens);
        program.cache_continuation(start.commitment_id, output_tokens);
        program.cache_checkpoint(
            transcript_state.len(),
            transcript_state.hash(),
            predicted_next_token,
            snapshot,
        );
    } else {
        program.cache_continuation(start.commitment_id, output_tokens);
    }

    Ok(())
}

fn stream_cached_output(
    cached_output_tokens: &[u32],
    batch_size: usize,
    mut on_progress: impl FnMut(u64, &[u8]),
) {
    let batch_size = batch_size.max(1);
    let mut emitted = 0u64;
    for chunk in cached_output_tokens.chunks(batch_size) {
        emitted = emitted.saturating_add(chunk.len() as u64);
        let encoded = encode_token_ids(chunk);
        on_progress(emitted, &encoded);
    }
}

#[cfg(test)]
mod tests;

