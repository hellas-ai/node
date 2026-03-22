use crate::state::ExecutionPlan;
use crate::backend::ExecBackend;
use crate::weights::{CachedProgram, PrefixHash, PrefixState};
use crate::ExecutorError;
use catgrad_llm::Snapshot;
use hellas_rpc::encode_token_ids;
use std::time::Instant;

const PREFIX_CACHE_STRIDE: usize = 64;

pub fn run_cached_program_streaming(
    program: &CachedProgram,
    start_snapshot: &Snapshot<ExecBackend>,
    start_prefix_len: usize,
    start_prefix_hash: PrefixHash,
    start_next_token: Option<u32>,
    plan: &ExecutionPlan,
    stream_batch_size: u32,
    mut on_progress: impl FnMut(u64, &[u8]),
) -> Result<(), ExecutorError> {
    let start = Instant::now();
    let session_start = Instant::now();
    let mut session = program.bound_program().start(start_snapshot.clone())?;
    let session_start_ms = session_start.elapsed().as_millis();
    let mut generated_tokens = 0u64;
    let batch_size = usize::try_from(stream_batch_size.max(1)).unwrap_or(usize::MAX);
    let mut pending_batch = Vec::with_capacity(batch_size);
    let prompt_tokens = plan.input_ids.len();
    let mut prefill_chunks = 0usize;
    let mut next_token = if prompt_tokens == 0 {
        Some(session.step_text(&[])?)
    } else if start_prefix_len == prompt_tokens {
        start_next_token
    } else {
        None
    };

    if next_token.is_none() {
        let mut prefix_state = PrefixState::from_parts(start_prefix_len, start_prefix_hash);
        let mut cursor = start_prefix_len;
        while cursor < prompt_tokens {
            let next_boundary = next_checkpoint_boundary(cursor, prompt_tokens);
            let chunk = &plan.input_ids[cursor..next_boundary];
            let step_start = Instant::now();
            let predicted = session.step_text(chunk)?;
            prefill_chunks += 1;
            prefix_state.extend_tokens(chunk);
            cursor = next_boundary;
            program.cache_prefix(cursor, prefix_state.hash(), predicted, session.snapshot());

            if cursor == prompt_tokens {
                info!(
                    prompt_tokens,
                    cached_prompt_tokens = start_prefix_len,
                    prefill_input_tokens = prompt_tokens.saturating_sub(start_prefix_len),
                    first_token_step_ms = step_start.elapsed().as_millis(),
                    first_token_total_ms = start.elapsed().as_millis(),
                    "first token ready"
                );
                debug!(
                    prompt_tokens,
                    cached_prompt_tokens = start_prefix_len,
                    exact_prefix_hit = false,
                    session_start_ms,
                    prefill_chunks,
                    prefill_input_tokens = prompt_tokens.saturating_sub(start_prefix_len),
                    first_token_total_ms = start.elapsed().as_millis(),
                    "execute first-token phases"
                );
                next_token = Some(predicted);
            }
        }
    } else {
        info!(
            prompt_tokens,
            cached_prompt_tokens = start_prefix_len,
            prefill_input_tokens = prompt_tokens.saturating_sub(start_prefix_len),
            first_token_step_ms = 0,
            first_token_total_ms = start.elapsed().as_millis(),
            "first token ready"
        );
        debug!(
            prompt_tokens,
            cached_prompt_tokens = start_prefix_len,
            exact_prefix_hit = start_prefix_len == prompt_tokens,
            session_start_ms,
            prefill_chunks,
            prefill_input_tokens = prompt_tokens.saturating_sub(start_prefix_len),
            first_token_total_ms = start.elapsed().as_millis(),
            "execute first-token phases"
        );
    }

    let Some(mut current_token) = next_token else {
        return Err(ExecutorError::NoOutput);
    };

    for step_idx in 0..plan.max_new_tokens {
        if i32::try_from(current_token)
            .ok()
            .is_some_and(|token| plan.stop_token_ids.contains(&token))
        {
            break;
        }

        generated_tokens += 1;
        pending_batch.push(current_token);
        if pending_batch.len() >= batch_size {
            let chunk = encode_token_ids(&pending_batch);
            on_progress(generated_tokens, &chunk);
            pending_batch.clear();
        }

        if step_idx + 1 < plan.max_new_tokens {
            current_token = session.step_text(&[current_token])?;
        }
    }

    if !pending_batch.is_empty() {
        let chunk = encode_token_ids(&pending_batch);
        on_progress(generated_tokens, &chunk);
    }

    Ok(())
}

fn next_checkpoint_boundary(cursor: usize, prompt_tokens: usize) -> usize {
    let next_stride = ((cursor / PREFIX_CACHE_STRIDE) + 1) * PREFIX_CACHE_STRIDE;
    next_stride.min(prompt_tokens).max(cursor + 1)
}
