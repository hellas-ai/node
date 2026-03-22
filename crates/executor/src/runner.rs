use crate::state::ExecutionPlan;
use crate::ExecutorError;
use crate::backend::ExecBackend;
use catgrad_llm::BoundProgram;
use hellas_rpc::encode_token_ids;
use std::time::Instant;

pub fn run_bound_program_streaming(
    bound_program: &BoundProgram<ExecBackend>,
    plan: &ExecutionPlan,
    stream_batch_size: u32,
    mut on_progress: impl FnMut(u64, &[u8]),
) -> Result<(), ExecutorError> {
    let start = Instant::now();
    let mut session = bound_program.start(bound_program.empty_snapshot())?;
    let mut token_ids = plan.input_ids.clone();
    let mut generated_tokens = 0u64;
    let batch_size = usize::try_from(stream_batch_size.max(1)).unwrap_or(usize::MAX);
    let mut pending_batch = Vec::with_capacity(batch_size);

    for step_idx in 0..plan.max_new_tokens {
        let step_start = Instant::now();
        let next_token = session.step_text(&token_ids)?;
        if step_idx == 0 {
            info!(
                prompt_tokens = plan.input_ids.len(),
                prefill_input_tokens = token_ids.len(),
                first_token_step_ms = step_start.elapsed().as_millis(),
                first_token_total_ms = start.elapsed().as_millis(),
                "first token ready"
            );
        }
        if i32::try_from(next_token)
            .ok()
            .is_some_and(|token| plan.stop_token_ids.contains(&token))
        {
            break;
        }

        generated_tokens += 1;
        pending_batch.push(next_token);
        if pending_batch.len() >= batch_size {
            let chunk = encode_token_ids(&pending_batch);
            on_progress(generated_tokens, &chunk);
            pending_batch.clear();
        }

        token_ids = vec![next_token];
    }

    if !pending_batch.is_empty() {
        let chunk = encode_token_ids(&pending_batch);
        on_progress(generated_tokens, &chunk);
    }

    Ok(())
}
