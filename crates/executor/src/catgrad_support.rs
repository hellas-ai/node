use crate::backend::create_backend;
use crate::weights::ModelBundle;
use crate::ExecutorError;
use catgrad::category::core::{Dtype, Shape};
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
                interpreter::tensor(&interpreter.backend, shape.clone(), Vec::<f32>::new())
                    .map_err(ExecutorError::Backend)
            }
            Dtype::U32 => {
                interpreter::tensor(&interpreter.backend, shape.clone(), Vec::<u32>::new())
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

/// Execute the provided TypedTerm and stream generated token batches.
pub fn run_graph_streaming(
    bundle: &ModelBundle,
    model_config_json: &[u8],
    encoded_input: &[u8],
    typed_term: &catgrad::category::lang::TypedTerm,
    prompt_tokens: u32,
    max_new_tokens: u32,
    stop_token_ids: &[u32],
    stream_batch_size: u32,
    mut on_progress: impl FnMut(u64, &[u8]),
) -> Result<(), ExecutorError> {
    let input_ids = decode_token_ids(encoded_input)
        .map_err(|err| ExecutorError::InvalidTokenPayload(err.to_string()))?;
    let expected_prompt_tokens = usize::try_from(prompt_tokens).unwrap_or(usize::MAX);
    if input_ids.len() != expected_prompt_tokens {
        return Err(ExecutorError::InvalidTokenPayload(format!(
            "prompt token count mismatch: plan says {prompt_tokens}, input decodes to {}",
            input_ids.len()
        )));
    }

    let backend = create_backend();
    let max_sequence_length = input_ids.len() + max_new_tokens as usize;
    let model_config: serde_json::Value =
        serde_json::from_slice(model_config_json).map_err(|err| {
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

    for _ in 0..max_new_tokens {
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
        if stop_token_ids.contains(&next_token) {
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
