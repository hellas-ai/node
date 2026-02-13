use crate::backend::create_backend;
use crate::weights::ModelBundle;
use crate::ExecutorError;
use catgrad::interpreter::{self, Backend, Interpreter};
use catgrad::prelude::*;
use catgrad_llm::utils::{get_model, render_chat_template};
use tracing::warn;

/// Format a user prompt using the model's chat template when available.
/// Falls back to the raw prompt if no template exists or rendering fails.
fn prepare_prompt(model_id: &str, chat_template: Option<&str>, prompt: &str) -> String {
    let Some(template) = chat_template.filter(|t| !t.trim().is_empty()) else {
        return prompt.to_string();
    };

    // SmolLM3 and a few other templates wrap generation blocks we don't need for single-shot use.
    let template = template
        .replace("{% generation %}", "")
        .replace("{% endgeneration %}", "");

    match render_chat_template(&template, prompt, false, false) {
        Ok(r) => r,
        Err(err) => {
            warn!("failed to render chat template for {model_id}: {err}");
            prompt.to_string()
        }
    }
}

/// Build and serialize a catgrad graph for a HF model id and prompt, returning the templated input.
pub fn build_graph_from_llm_prompt(
    bundle: &ModelBundle,
    prompt: &str,
    max_new_tokens: u32,
) -> Result<(Vec<u8>, String), ExecutorError> {
    use catgrad_llm::LLMError;

    let prepared_prompt = prepare_prompt(
        &bundle.key.model_id.0,
        bundle.chat_template.as_deref(),
        prompt,
    );
    let config = &bundle.config;
    let tokenizer = &bundle.tokenizer;

    let encoding = tokenizer
        .encode(prepared_prompt.clone(), true)
        .map_err(LLMError::from)?;
    let prompt_tokens = encoding.get_ids().len();
    let max_sequence_length = prompt_tokens + max_new_tokens as usize;

    let (model, _cfg) = get_model(config, max_sequence_length)?;
    let typed_term = model
        .term()
        .ok_or_else(|| ExecutorError::ModelConstruction(model.path().to_string()))?;

    let graph_bytes = serde_json::to_vec_pretty(&typed_term)?;
    Ok((graph_bytes, prepared_prompt))
}

/// Fetch weights, build the environment, and execute the provided TypedTerm, streaming decoded text.
pub fn run_graph_streaming(
    bundle: &ModelBundle,
    prepared_input: &str,
    typed_term: &catgrad::category::lang::TypedTerm,
    max_seq: u32,
    mut on_progress: impl FnMut(u64, &[u8], Option<&str>, bool),
) -> Result<(), ExecutorError> {
    use catgrad_llm::LLMError;

    let backend = create_backend();
    let config = &bundle.config;
    let tokenizer = &bundle.tokenizer;
    let parameter_values = &bundle.parameter_values;
    let parameter_types = &bundle.parameter_types;

    let encoding = tokenizer
        .encode(prepared_input, true)
        .map_err(LLMError::from)?;
    let tokens: Vec<u32> = encoding.get_ids().to_vec();

    let max_sequence_length = tokens.len() + max_seq as usize;
    let (model, llm_config) = get_model(config, max_sequence_length)?;

    let mut env = stdlib();
    env.declarations
        .extend(to_load_ops(model.path(), parameter_types.keys()));

    let interpreter = Interpreter::new(backend.clone(), env, parameter_values.clone());

    let mut decoded = String::new();
    let mut progress: u64 = 0;

    // Initialize empty KV caches for the first (prefill) pass.
    let num_layers = llm_config.num_hidden_layers();
    let num_kv_heads = llm_config.num_key_value_heads();
    let qk_head_dim = llm_config.get_qk_head_dim();
    let v_head_dim = llm_config.get_v_head_dim();

    let mut k_cache = interpreter::tensor(
        &interpreter.backend,
        Shape(vec![num_layers, 1, num_kv_heads, 0, qk_head_dim]),
        Vec::<f32>::new(),
    )
    .map_err(ExecutorError::Backend)?;

    let mut v_cache = interpreter::tensor(
        &interpreter.backend,
        Shape(vec![num_layers, 1, num_kv_heads, 0, v_head_dim]),
        Vec::<f32>::new(),
    )
    .map_err(ExecutorError::Backend)?;

    // First iteration uses the full prompt; subsequent iterations use only the new token.
    let mut token_ids = tokens;

    for _ in 0..max_seq {
        let input_tensor = interpreter::tensor(
            &interpreter.backend,
            Shape(vec![1, token_ids.len()]),
            token_ids.clone(),
        )
        .map_err(ExecutorError::Backend)?;

        let mut results = interpreter.run(
            typed_term.term.clone(),
            vec![input_tensor, k_cache, v_cache],
        )?;

        // Results order: [next_token, k_cache_out, v_cache_out]
        v_cache = results.pop().ok_or(ExecutorError::NoOutput)?;
        k_cache = results.pop().ok_or(ExecutorError::NoOutput)?;
        let output = results.pop().ok_or(ExecutorError::NoOutput)?;

        let next_token = match output {
            interpreter::Value::Tensor(arr) => match interpreter.backend.to_vec(arr) {
                interpreter::TaggedVec::U32(v) => v.last().copied(),
                _ => None,
            },
            _ => None,
        }
        .ok_or(ExecutorError::UnexpectedOutput)?;

        // Decode and append
        let piece = tokenizer
            .decode(&[next_token], false)
            .unwrap_or_else(|_| next_token.to_string());
        decoded.push_str(&piece);
        progress += 1;

        let done = llm_config
            .get_eos_token_ids()
            .contains(&(next_token as i32));
        on_progress(progress, piece.as_bytes(), Some(piece.as_str()), done);

        // Stop if EOS
        if done {
            break;
        }

        // Subsequent iterations: only feed the newly generated token.
        token_ids = vec![next_token];
    }

    Ok(())
}
