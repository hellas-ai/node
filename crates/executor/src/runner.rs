use crate::ExecutorError;
use crate::backend::ExecBackend;
use crate::state::Invocation;
use crate::weights::{ExecutionContext, ExecutionStart};
use catgrad::interpreter::{self, Backend};
use catgrad::prelude::Shape;
use catgrad_llm::Session;
use hellas_rpc::encode_token_ids;
use std::time::Instant;

const CHECKPOINT_STRIDE: usize = 64;

fn step_tokens(
    session: &mut Session<ExecBackend>,
    backend: &ExecBackend,
    tokens: &[u32],
    max_sequence_length: usize,
    extra_nat_chunk_size: Option<usize>,
) -> Result<u32, ExecutorError> {
    let input = interpreter::tensor(backend, Shape(vec![1, tokens.len()]), tokens.to_vec())
        .map_err(ExecutorError::Backend)?;
    let mut inputs = vec![input];
    inputs.extend(session.state().iter().cloned());
    inputs.push(interpreter::Value::Nat(max_sequence_length));
    if let Some(chunk_size) = extra_nat_chunk_size {
        inputs.push(interpreter::Value::Nat(tokens.len().div_ceil(chunk_size)));
    }
    let mut outputs = session.run(inputs)?;
    if outputs.len() != 1 {
        return Err(ExecutorError::UnexpectedOutput);
    }
    match outputs.remove(0) {
        interpreter::Value::Tensor(arr) => match backend.to_vec(arr) {
            interpreter::TaggedVec::U32(v) => {
                v.last().copied().ok_or(ExecutorError::NoOutput)
            }
            _ => Err(ExecutorError::UnexpectedOutput),
        },
        _ => Err(ExecutorError::UnexpectedOutput),
    }
}

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
    let p = program.bound_program().program();
    let max_sequence_length = p.max_sequence_length;
    let state_arity = p.empty_state_type.len();
    let total_inputs = p.typed_term.source_type.len();
    // Non-state inputs beyond [token_tensor, state..., max_positions] are extra nats (e.g. num_chunks)
    let extra_nat_chunk_size = if total_inputs > state_arity + 2 {
        Some(catgrad_llm::helpers::GATED_DELTA_CHUNK_SIZE)
    } else {
        None
    };

    if let Some(cached_output_tokens) = start.cached_output_tokens.as_deref() {
        info!(
            prompt_tokens,
            cached_prompt_tokens = start.transcript.len(),
            cached_output_tokens = cached_output_tokens.len(),
            prefill_input_tokens = 0,
            first_token_step_ms = 0,
            first_token_total_ms = started_at.elapsed().as_millis(),
            "first token ready"
        );
        debug!(
            prompt_tokens,
            cached_prompt_tokens = start.transcript.len(),
            cached_output_tokens = cached_output_tokens.len(),
            exact_prefix_hit = start.transcript.len() == prompt_tokens,
            exact_replay_hit = true,
            session_start_ms = 0,
            prefill_chunks = 0,
            prefill_input_tokens = 0,
            first_token_total_ms = started_at.elapsed().as_millis(),
            "execute first-token phases"
        );
        stream_cached_output(cached_output_tokens, batch_size, on_progress);
        return Ok(());
    }

    let session_start = Instant::now();
    let bound = program.bound_program();
    let backend = bound.backend();
    let mut session = bound.start(start.snapshot.as_ref().clone())?;
    let session_start_ms = session_start.elapsed().as_millis();
    let mut generated_tokens = 0u64;
    let mut pending_batch = Vec::with_capacity(batch_size);
    let mut output_tokens = Vec::new();
    let mut prefill_chunks = 0usize;
    let mut prompt_state = start.transcript;
    let mut next_token = if prompt_tokens == 0 {
        Some(step_tokens(&mut session, backend, &[], max_sequence_length, extra_nat_chunk_size)?)
    } else if start.transcript.len() == prompt_tokens {
        start.next_token
    } else {
        None
    };

    if next_token.is_none() {
        let mut cursor = start.transcript.len();
        while cursor < prompt_tokens {
            let next_boundary = next_checkpoint_boundary(cursor, prompt_tokens);
            let chunk = &invocation.input_ids[cursor..next_boundary];
            let step_start = Instant::now();
            let predicted = step_tokens(&mut session, backend, chunk, max_sequence_length, extra_nat_chunk_size)?;
            prefill_chunks += 1;
            prompt_state.extend_tokens(chunk);
            cursor = next_boundary;
            program.cache_checkpoint(cursor, prompt_state.hash(), predicted, session.snapshot());

            if cursor == prompt_tokens {
                info!(
                    prompt_tokens,
                    cached_prompt_tokens = start.transcript.len(),
                    prefill_input_tokens = prompt_tokens.saturating_sub(start.transcript.len()),
                    first_token_step_ms = step_start.elapsed().as_millis(),
                    first_token_total_ms = started_at.elapsed().as_millis(),
                    "first token ready"
                );
                debug!(
                    prompt_tokens,
                    cached_prompt_tokens = start.transcript.len(),
                    cached_output_tokens = 0,
                    exact_prefix_hit = false,
                    exact_replay_hit = false,
                    session_start_ms,
                    prefill_chunks,
                    prefill_input_tokens = prompt_tokens.saturating_sub(start.transcript.len()),
                    first_token_total_ms = started_at.elapsed().as_millis(),
                    "execute first-token phases"
                );
                next_token = Some(predicted);
            }
        }
    } else {
        info!(
            prompt_tokens,
            cached_prompt_tokens = start.transcript.len(),
            cached_output_tokens = 0,
            prefill_input_tokens = prompt_tokens.saturating_sub(start.transcript.len()),
            first_token_step_ms = 0,
            first_token_total_ms = started_at.elapsed().as_millis(),
            "first token ready"
        );
        debug!(
            prompt_tokens,
            cached_prompt_tokens = start.transcript.len(),
            cached_output_tokens = 0,
            exact_prefix_hit = start.transcript.len() == prompt_tokens,
            exact_replay_hit = false,
            session_start_ms,
            prefill_chunks,
            prefill_input_tokens = prompt_tokens.saturating_sub(start.transcript.len()),
            first_token_total_ms = started_at.elapsed().as_millis(),
            "execute first-token phases"
        );
    }

    let Some(mut current_token) = next_token else {
        return Err(ExecutorError::NoOutput);
    };

    let mut transcript_state = prompt_state;
    let mut last_emitted_token = None;
    let mut next_token_after_full_transcript = None;

    for step_idx in 0..invocation.max_new_tokens {
        if i32::try_from(current_token)
            .ok()
            .is_some_and(|token| invocation.stop_token_ids.contains(&token))
        {
            next_token_after_full_transcript = Some(current_token);
            break;
        }

        generated_tokens += 1;
        output_tokens.push(current_token);
        pending_batch.push(current_token);
        transcript_state.extend(current_token);
        last_emitted_token = Some(current_token);

        if pending_batch.len() >= batch_size {
            let chunk = encode_token_ids(&pending_batch);
            on_progress(generated_tokens, &chunk);
            pending_batch.clear();
        }

        if step_idx + 1 < invocation.max_new_tokens {
            current_token = step_tokens(&mut session, backend, &[current_token], max_sequence_length, extra_nat_chunk_size)?;
        }
    }

    if !pending_batch.is_empty() {
        let chunk = encode_token_ids(&pending_batch);
        on_progress(generated_tokens, &chunk);
    }

    program.cache_continuation(
        prompt_state.len(),
        prompt_state.hash(),
        invocation,
        output_tokens,
    );

    let final_next_token = match next_token_after_full_transcript {
        Some(token) => Some(token),
        None => {
            if let Some(last_token) = last_emitted_token {
                Some(step_tokens(&mut session, backend, &[last_token], max_sequence_length, extra_nat_chunk_size)?)
            } else {
                None
            }
        }
    };

    if let Some(final_next_token) = final_next_token {
        program.cache_checkpoint(
            transcript_state.len(),
            transcript_state.hash(),
            final_next_token,
            session.snapshot(),
        );
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

fn next_checkpoint_boundary(cursor: usize, prompt_tokens: usize) -> usize {
    let next_stride = ((cursor / CHECKPOINT_STRIDE) + 1) * CHECKPOINT_STRIDE;
    next_stride.min(prompt_tokens).max(cursor + 1)
}
