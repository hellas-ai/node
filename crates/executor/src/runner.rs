//! Causal-LM decode driver for the executor.
//!
//! # Overview
//!
//! The runner drives a single text-generation request to completion,
//! emitting generated tokens to a streaming callback. It's the only
//! place in the executor that calls into catgrad's LLM execution
//! surface; everything else (cache, scheduling, quoting) is plain data.
//!
//! # Algorithm
//!
//! 1. **Exact-output replay.** If the request commitment matches a
//!    previously-served request, the cached output tokens are streamed
//!    back without touching the model.
//!
//! 2. **Prefill.** A single batched call against the bound program's
//!    [`prefill`](catgrad_llm::runtime::BoundProgramText::prefill) on
//!    top of the resolved starting state (cold-start: program's genesis
//!    state; anchored: a previously-stored receipt). Returns a
//!    [`TextDecoder`] positioned to commit the first predicted token.
//!
//! 3. **Decode loop.** Peek the predicted token, check stop tokens,
//!    [`commit_next`] to emit-and-advance, repeat to `max_new_tokens`.
//!    Each iteration leaves the decoder fully receipt-aligned.
//!
//! On completion the runner consumes the decoder into a
//! [`TextState`](catgrad_llm::runtime::TextState), inserts that state
//! into the receipt store (so future anchored requests can reference
//! it), and stores the emitted token sequence in the exact-replay
//! cache.
//!
//! # Why no generic-over-stepper trait
//!
//! Earlier versions abstracted the decode loop over a `CausalStepper`
//! trait so a fake in-memory implementation could substitute for the
//! catgrad session in tests. The trait was load-bearing for the
//! split-stability test approach we no longer pursue (see PREFIX.md
//! history). Without that, the runner is concrete on
//! `TextDecoder<ExecBackend>` and tested via end-to-end smoke runs.

use crate::backend::ExecBackend;
use crate::programs::{ExecutionContext, ExecutionStart};
use crate::state::Invocation;
use catgrad::category::core::Shape;
use catgrad::interpreter;
use catgrad_llm::runtime::{BoundProgramText, TextDecoder, TextExecution, TextPolicy};
use hellas_rpc::ExecutorError;
use hellas_rpc::encode_token_ids;
use std::sync::Arc;
use std::time::Instant;

#[derive(Default)]
struct FirstTokenLog {
    prompt_tokens: usize,
    cached_output_tokens: usize,
    first_token_total_ms: u128,
    exact_replay_hit: bool,
    session_start_ms: u128,
}

fn log_first_token(m: FirstTokenLog) {
    info!(
        prompt_tokens = m.prompt_tokens,
        cached_output_tokens = m.cached_output_tokens,
        first_token_total_ms = m.first_token_total_ms,
        "first token ready"
    );
    debug!(
        prompt_tokens = m.prompt_tokens,
        cached_output_tokens = m.cached_output_tokens,
        exact_replay_hit = m.exact_replay_hit,
        session_start_ms = m.session_start_ms,
        first_token_total_ms = m.first_token_total_ms,
        "execute first-token phases"
    );
}

/// Public entry point. Wires the catgrad text decoder, runs the decode
/// loop, and writes the result back to the [`ExecutionContext`] caches.
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
            cached_output_tokens: cached_output_tokens.len(),
            exact_replay_hit: true,
            first_token_total_ms: started_at.elapsed().as_millis(),
            ..Default::default()
        });
        stream_cached_output(cached_output_tokens, batch_size, on_progress);
        return Ok(());
    }

    let session_start = Instant::now();
    let bound = program.bound_program();
    let input_tensor =
        interpreter::tensor(&bound.interpreter().backend, Shape(vec![1, prompt_tokens]), invocation.input_ids.clone())
            .map_err(|error| {
                ExecutorError::WeightsError(format!("failed to build input tensor: {error:?}"))
            })?;
    let mut decoder: TextDecoder<ExecBackend> =
        Arc::clone(bound).prefill(&start.initial_state, &input_tensor)?;
    let session_start_ms = session_start.elapsed().as_millis();

    log_first_token(FirstTokenLog {
        prompt_tokens,
        first_token_total_ms: started_at.elapsed().as_millis(),
        session_start_ms,
        ..Default::default()
    });

    let DecodeOutcome { output_tokens } = run_decode_loop(
        &mut decoder,
        invocation.max_new_tokens,
        &invocation.stop_token_ids,
        batch_size,
        &mut on_progress,
    )?;

    let final_state = decoder.into_text_state(start.commitment_id, &output_tokens)?;
    program.cache_receipt(Arc::new(final_state));
    program.cache_continuation(start.commitment_id, output_tokens);

    Ok(())
}

struct DecodeOutcome {
    output_tokens: Vec<u32>,
}

/// Decode loop: peek-stop-or-commit, batched progress callback emission.
/// After each `commit_next` the decoder is fully receipt-aligned, so
/// breaking out (stop token or cap reached) leaves a consistent state
/// for the trailing `into_text_state`.
fn run_decode_loop(
    decoder: &mut TextDecoder<ExecBackend>,
    max_new_tokens: u32,
    stop_token_ids: &[i32],
    batch_size: usize,
    on_progress: &mut impl FnMut(u64, &[u8]),
) -> Result<DecodeOutcome, ExecutorError> {
    let mut output_tokens = Vec::new();
    let mut pending_batch = Vec::with_capacity(batch_size);
    let mut generated = 0u64;

    for _ in 0..max_new_tokens {
        let predicted = decoder.next_token();
        if i32::try_from(predicted)
            .ok()
            .is_some_and(|token| stop_token_ids.contains(&token))
        {
            break;
        }
        let emitted = decoder.commit_next()?;
        debug_assert_eq!(emitted, predicted);
        generated += 1;
        output_tokens.push(emitted);
        pending_batch.push(emitted);
        if pending_batch.len() >= batch_size {
            let chunk = encode_token_ids(&pending_batch);
            on_progress(generated, &chunk);
            pending_batch.clear();
        }
    }

    if !pending_batch.is_empty() {
        let chunk = encode_token_ids(&pending_batch);
        on_progress(generated, &chunk);
    }

    Ok(DecodeOutcome { output_tokens })
}

/// Build the request [`TextExecution`] commitment from a bound program
/// + invocation. Used at quote time to compute `commitment_id` before
/// the runner sees the request.
pub(crate) fn build_text_execution(
    program: &ExecutionContext,
    initial_state_receipt_id: catgrad::cid::Cid<catgrad_llm::runtime::TextReceipt>,
    invocation: &Invocation,
    policy: &TextPolicy,
) -> Result<TextExecution, ExecutorError> {
    let bound = program.bound_program();
    let input_tensor = interpreter::tensor(
        &bound.interpreter().backend,
        Shape(vec![1, invocation.input_ids.len()]),
        invocation.input_ids.clone(),
    )
    .map_err(|error| {
        ExecutorError::WeightsError(format!("failed to build input tensor: {error:?}"))
    })?;
    // The initial_state TextState is fetched at execution_start; here we
    // only have its receipt id, which is all `TextExecution::new` needs.
    Ok(TextExecution::new(
        bound,
        initial_state_receipt_id,
        &input_tensor,
        policy,
    )?)
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
