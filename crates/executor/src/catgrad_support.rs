use crate::weights::ModelBundle;
use crate::ExecutorError;
use catgrad::interpreter::{self, backend::ndarray::NdArrayBackend, Backend, Interpreter};
use catgrad::prelude::*;
use catgrad_llm::utils::get_model;
use minijinja::{context, Environment};
use minijinja_contrib::pycompat::unknown_method_callback;
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

    let mut env = Environment::new();
    env.set_unknown_method_callback(unknown_method_callback);

    if let Err(err) = env.add_template("chat", &template) {
        warn!("failed to parse chat template for {model_id}: {err}");
        return prompt.to_string();
    }

    let tmpl = match env.get_template("chat") {
        Ok(t) => t,
        Err(err) => {
            warn!("failed to load chat template for {model_id}: {err}");
            return prompt.to_string();
        }
    };

    match tmpl.render(context! {
        messages => vec![context!(role => "user", content => prompt)],
        add_generation_prompt => true,
    }) {
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

    let model = get_model(config, max_sequence_length)?;
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

    let backend = NdArrayBackend;
    let config = &bundle.config;
    let tokenizer = &bundle.tokenizer;
    let parameter_values = &bundle.parameter_values;
    let parameter_types = &bundle.parameter_types;

    let encoding = tokenizer
        .encode(prepared_input, true)
        .map_err(LLMError::from)?;
    let tokens: Vec<u32> = encoding.get_ids().to_vec();

    let max_sequence_length = tokens.len() + max_seq as usize;
    let model = get_model(config, max_sequence_length)?;

    let mut env = stdlib();
    env.declarations
        .extend(to_load_ops(model.path(), parameter_types.keys()));

    let interpreter = Interpreter::new(backend.clone(), env, parameter_values.clone());

    let mut decoded = String::new();
    let mut current_tokens = tokens;
    let mut progress: u64 = 0;

    for _ in 0..max_seq {
        let input_tensor = interpreter::tensor(
            &interpreter.backend,
            Shape(vec![1, current_tokens.len()]),
            current_tokens.clone(),
        )
        .map_err(ExecutorError::Backend)?;

        let mut results = interpreter.run(typed_term.term.clone(), vec![input_tensor])?;

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
        current_tokens.push(next_token);
        progress += 1;

        let done = config.get_eos_token_ids().contains(&(next_token as i32));
        on_progress(progress, piece.as_bytes(), Some(piece.as_str()), done);

        // Stop if EOS
        if done {
            break;
        }
    }

    Ok(())
}
