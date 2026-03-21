use crate::backend::create_backend;
use crate::state::ExecutionPlan;
use crate::weights::WeightsBundle;
use crate::ExecutorError;
use catgrad::category::core::{Dtype, Shape};
use catgrad::category::lang::TypedTerm;
use catgrad::interpreter::{self, Backend, Interpreter};
use catgrad::prelude::*;
use catgrad_llm::utils::get_model;
use hellas_rpc::{decode_token_ids, encode_token_ids};

fn initialize_state_tensors(
    interpreter: &Interpreter<crate::backend::ExecBackend>,
    state_types: &[(Dtype, Shape)],
) -> Result<Vec<interpreter::Value<crate::backend::ExecBackend>>, ExecutorError> {
    state_types
        .iter()
        .map(|(dtype, shape)| match dtype {
            Dtype::F32 => {
                let data = vec![0.0f32; shape.0.iter().product()];
                interpreter::tensor(&interpreter.backend, shape.clone(), data)
                    .map_err(ExecutorError::Backend)
            }
            Dtype::U32 => {
                let data = vec![0u32; shape.0.iter().product()];
                interpreter::tensor(&interpreter.backend, shape.clone(), data)
                    .map_err(ExecutorError::Backend)
            }
        })
        .collect()
}

fn extract_generated_token(
    backend: &crate::backend::ExecBackend,
    output: interpreter::Value<crate::backend::ExecBackend>,
) -> Result<u32, ExecutorError> {
    let tokens = match output {
        interpreter::Value::Tensor(arr) => match backend.to_vec(arr) {
            interpreter::TaggedVec::U32(values) => values,
            _ => return Err(ExecutorError::UnexpectedOutput),
        },
        _ => return Err(ExecutorError::UnexpectedOutput),
    };

    tokens
        .last()
        .copied()
        .ok_or(ExecutorError::UnexpectedOutput)
}

pub fn run_graph_streaming(
    bundle: &WeightsBundle,
    plan: &ExecutionPlan,
    typed_term: &TypedTerm,
    stream_batch_size: u32,
    mut on_progress: impl FnMut(u64, &[u8]),
) -> Result<(), ExecutorError> {
    let input_ids = decode_token_ids(&plan.input)
        .map_err(|err| ExecutorError::InvalidTokenPayload(err.to_string()))?;
    let expected_prompt_tokens = usize::try_from(plan.prompt_tokens).unwrap_or(usize::MAX);
    if input_ids.len() != expected_prompt_tokens {
        return Err(ExecutorError::InvalidTokenPayload(format!(
            "prompt token count mismatch: plan says {}, input decodes to {}",
            plan.prompt_tokens,
            input_ids.len()
        )));
    }

    let backend = create_backend()?;
    let max_sequence_length = input_ids.len() + plan.max_new_tokens as usize;
    let model_config: serde_json::Value =
        serde_json::from_slice(&plan.model_config_json).map_err(|err| {
            ExecutorError::InvalidQuoteRequest(format!("invalid model config JSON: {err}"))
        })?;
    let model = get_model(&model_config, max_sequence_length)?;

    let mut env = stdlib();
    env.declarations
        .extend(to_load_ops(model.path(), bundle.parameter_types.keys()));
    let interpreter = Interpreter::new(backend.clone(), env, bundle.parameter_values.clone());

    let mut state_tensors = initialize_state_tensors(&interpreter, &model.empty_state_type())?;
    let mut token_ids = input_ids;
    let mut generated_tokens = 0u64;
    let batch_size = usize::try_from(stream_batch_size.max(1)).unwrap_or(usize::MAX);
    let mut pending_batch = Vec::with_capacity(batch_size);

    for _ in 0..plan.max_new_tokens {
        let input_tensor = interpreter::tensor(
            &interpreter.backend,
            Shape(vec![1, token_ids.len()]),
            token_ids.clone(),
        )
        .map_err(ExecutorError::Backend)?;

        let mut sources = vec![input_tensor];
        sources.append(&mut state_tensors);

        let mut results = interpreter.run(typed_term.term.clone(), sources)?;
        if results.is_empty() {
            return Err(ExecutorError::NoOutput);
        }
        let output = results.remove(0);
        state_tensors = results;

        let next_token = extract_generated_token(&interpreter.backend, output)?;
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
