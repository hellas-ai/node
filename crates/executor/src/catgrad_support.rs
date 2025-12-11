use anyhow::{anyhow, Context, Result};
use catgrad::interpreter::{self, backend::ndarray::NdArrayBackend, Backend, Interpreter};
use catgrad::path::path;
use catgrad::prelude::Dtype;
use catgrad::prelude::*;
use catgrad::typecheck;
use catgrad::typecheck::value_types::{DtypeExpr, NatExpr, NdArrayType, ShapeExpr, TypeExpr};
use catgrad_llm::legacy::models::utils::Config;
use catgrad_llm::models::{deepseek, gemma3, gpt2, granite, llama, qwen3};
use catgrad_llm::utils::{get_model_chat_template, get_model_files};
use half::bf16;
use memmap2::Mmap;
use minijinja::{context, Environment};
use minijinja_contrib::pycompat::unknown_method_callback;
use safetensors::SafeTensors;
use serde_json;
use tokenizers::tokenizer::Tokenizer;
use tracing::warn;

const DEFAULT_REVISION: &str = "main";

fn resolve_revision(revision: Option<&str>) -> &str {
    revision.unwrap_or(DEFAULT_REVISION)
}

/// Format a user prompt using the model's chat template when available.
/// Falls back to the raw prompt if no template exists or rendering fails.
fn prepare_prompt(model_id: &str, revision: Option<&str>, prompt: &str) -> Result<String> {
    let revision = resolve_revision(revision);
    let template = match get_model_chat_template(model_id, revision) {
        Ok(t) if !t.trim().is_empty() => t,
        _ => return Ok(prompt.to_string()),
    };

    // SmolLM3 and a few other templates wrap generation blocks we don't need for single-shot use.
    let template = template
        .replace("{% generation %}", "")
        .replace("{% endgeneration %}", "");

    let mut env = Environment::new();
    env.set_unknown_method_callback(unknown_method_callback);
    if let Err(err) = env.add_template("chat", &template) {
        warn!("failed to parse chat template for {model_id}@{revision}: {err}");
        return Ok(prompt.to_string());
    }
    let tmpl = match env.get_template("chat") {
        Ok(t) => t,
        Err(err) => {
            warn!("failed to load chat template for {model_id}@{revision}: {err}");
            return Ok(prompt.to_string());
        }
    };

    let rendered = match tmpl.render(context! {
        messages => vec![context!(role => "user", content => prompt)],
        add_generation_prompt => true,
    }) {
        Ok(r) => r,
        Err(err) => {
            warn!("failed to render chat template for {model_id}@{revision}: {err}");
            return Ok(prompt.to_string());
        }
    };

    Ok(rendered)
}

fn load_config_and_tokenizer(model_id: &str, revision: Option<&str>) -> Result<(Config, Tokenizer)> {
    let revision = resolve_revision(revision);

    let (_weights, config_path, tokenizer_path, _tok_config) =
        get_model_files(model_id, revision)?;
    let config: Config = serde_json::from_str(&std::fs::read_to_string(config_path)?)?;
    let tokenizer =
        Tokenizer::from_file(tokenizer_path).map_err(|e| anyhow!("tokenizer load error: {e}"))?;

    Ok((config, tokenizer))
}

fn build_model(config: &Config, max_sequence_length: usize) -> Result<Box<dyn Module<1, 1>>> {
    let arch = config
        .architectures
        .get(0)
        .ok_or_else(|| anyhow!("missing architecture in config"))?
        .as_str();

    let model: Box<dyn Module<1, 1>> = match arch {
        "LlamaForCausalLM" => Box::new(llama::LlamaModel {
            config: config.clone(),
            max_sequence_length,
        }),
        "Gemma3ForCausalLM" => Box::new(gemma3::Gemma3Model {
            config: config.clone(),
            max_sequence_length,
        }),
        "Qwen3ForCausalLM" | "Qwen3MoeForCausalLM" => Box::new(qwen3::Qwen3Model {
            config: config.clone(),
            max_sequence_length,
        }),
        "GraniteForCausalLM" | "GraniteMoeForCausalLM" => Box::new(granite::GraniteModel {
            config: config.clone(),
            max_sequence_length,
        }),
        "DeepseekV3ForCausalLM" => Box::new(deepseek::DeepSeekModel {
            config: config.clone(),
            max_sequence_length,
        }),
        "GPT2LMHeadModel" => Box::new(gpt2::GPT2Model {
            config: config.clone(),
            max_sequence_length,
        }),
        other => return Err(anyhow!("unsupported architecture {other}")),
    };

    Ok(model)
}

fn concat_moe_experts(
    config: &Config,
    backend: &NdArrayBackend,
    parameter_values: &mut interpreter::Parameters<NdArrayBackend>,
    parameter_types: &mut typecheck::Parameters,
) -> Result<()> {
    use catgrad::typecheck::*;

    let proj_names = ["down_proj", "gate_proj", "up_proj"];

    for layer_idx in 0..config.num_hidden_layers {
        for proj_name in &proj_names {
            let mut expert_tensors = Vec::new();
            let mut expert_keys = Vec::new();

            for expert_idx in 0..config.num_local_experts {
                let key_str = format!(
                    "model.layers.{}.mlp.experts.{}.{}.weight",
                    layer_idx, expert_idx, proj_name
                );
                let key = path(key_str.split('.').collect()).expect("invalid param path");

                if let Some(interpreter::Value::Tensor(tensor)) = parameter_values.0.get(&key) {
                    expert_tensors.push(tensor.clone());
                    expert_keys.push(key);
                }
            }

            if expert_tensors.is_empty() {
                continue;
            }

            if expert_tensors.len() != config.num_local_experts {
                return Err(anyhow!(
                    "Expected {} experts for layer {} {}, found {}",
                    config.num_local_experts,
                    layer_idx,
                    proj_name,
                    expert_tensors.len()
                ));
            }

            let original_shape = expert_tensors[0].shape();
            let original_dims = original_shape.0.clone();

            let mut new_shape_dims = vec![config.num_local_experts];
            new_shape_dims.extend(original_dims.clone());

            let mut reshaped_tensors = Vec::new();
            for tensor in expert_tensors {
                let mut reshape_dims = vec![1];
                reshape_dims.extend(original_dims.clone());
                let reshaped = backend.reshape(tensor, Shape(reshape_dims));
                reshaped_tensors.push(reshaped);
            }

            let mut concatenated = reshaped_tensors[0].clone();
            for tensor in &reshaped_tensors[1..] {
                concatenated = backend.concat(concatenated, tensor.clone(), 0);
            }

            let new_key_str = format!(
                "model.layers.{}.mlp.router.{}_expert.weight",
                layer_idx, proj_name
            );
            let new_key = path(new_key_str.split('.').collect()).expect("invalid param path");

            let new_type = Type::Tensor(TypeExpr::NdArrayType(NdArrayType {
                dtype: DtypeExpr::Constant(Dtype::F32),
                shape: ShapeExpr::Shape(
                    new_shape_dims
                        .iter()
                        .copied()
                        .map(NatExpr::Constant)
                        .collect(),
                ),
            }));
            parameter_values
                .0
                .insert(new_key.clone(), interpreter::Value::Tensor(concatenated));
            parameter_types.0.insert(new_key, new_type);

            for key in expert_keys {
                parameter_values.0.remove(&key);
                parameter_types.0.remove(&key);
            }
        }
    }

    Ok(())
}

fn post_process_weights(
    config: &Config,
    backend: &NdArrayBackend,
    parameter_values: &mut interpreter::Parameters<NdArrayBackend>,
    parameter_types: &mut typecheck::Parameters,
) -> Result<()> {
    if config.num_local_experts == 0 {
        return Ok(());
    }

    concat_moe_experts(config, backend, parameter_values, parameter_types)
}

fn load_weights_and_types(
    model_id: &str,
    revision: Option<&str>,
    backend: &NdArrayBackend,
) -> Result<(
    interpreter::Parameters<NdArrayBackend>,
    typecheck::Parameters,
    Config,
    Tokenizer,
)> {
    let revision = resolve_revision(revision);
    let (model_paths, config_path, tokenizer_path, _) = get_model_files(model_id, revision)?;
    let config: Config = serde_json::from_str(&std::fs::read_to_string(config_path)?)?;
    let tokenizer =
        Tokenizer::from_file(tokenizer_path).map_err(|e| anyhow!("tokenizer load error: {e}"))?;

    let mut type_map = std::collections::HashMap::new();
    let mut data_map = std::collections::HashMap::new();

    for file_path in model_paths {
        let file = std::fs::File::open(&file_path)
            .with_context(|| format!("failed to open {}", file_path.display()))?;
        let data = unsafe { Mmap::map(&file)? };
        let tensors = SafeTensors::deserialize(&data)?;

        for (name, view) in tensors.tensors() {
            let shape = view.shape().to_vec();
            let tensor_data = view.data();

            let data: Vec<f32> = match view.dtype() {
                safetensors::Dtype::F32 => tensor_data
                    .chunks_exact(4)
                    .map(|b| f32::from_le_bytes(b.try_into().unwrap()))
                    .collect(),
                safetensors::Dtype::BF16 => tensor_data
                    .chunks_exact(2)
                    .map(|b| bf16::from_le_bytes(b.try_into().unwrap()).to_f32())
                    .collect(),
                other => {
                    return Err(anyhow!("unsupported dtype in weights: {:?}", other));
                }
            };

            let tensor = interpreter::tensor(backend, Shape(shape.clone()), data)
                .expect("failed to create tensor");
            let key = path(name.split('.').collect()).expect("invalid param path");
            data_map.insert(key.clone(), tensor);

            let dims = shape.iter().copied().map(NatExpr::Constant).collect();
            let tensor_type = Type::Tensor(TypeExpr::NdArrayType(NdArrayType {
                dtype: DtypeExpr::Constant(Dtype::F32),
                shape: ShapeExpr::Shape(dims),
            }));
            type_map.insert(key, tensor_type);
        }
    }

    let mut parameter_values = interpreter::Parameters::from(data_map);
    let mut parameter_types = typecheck::Parameters::from(type_map);

    post_process_weights(
        &config,
        backend,
        &mut parameter_values,
        &mut parameter_types,
    )?;

    Ok((parameter_values, parameter_types, config, tokenizer))
}

/// Build and serialize a catgrad graph for a HF model id and prompt, returning the templated input.
pub fn build_graph_from_llm_prompt(
    model_id: &str,
    prompt: &str,
    max_new_tokens: u32,
    revision: Option<&str>,
) -> Result<(Vec<u8>, String)> {
    let prepared_prompt = prepare_prompt(model_id, revision, prompt)?;
    let (config, tokenizer) = load_config_and_tokenizer(model_id, revision)?;

    let encoding = tokenizer
        .encode(prepared_prompt.clone(), true)
        .map_err(|e| anyhow!("tokenizer encode error: {e}"))?;
    let prompt_tokens = encoding.get_ids().len();
    let max_sequence_length = prompt_tokens + max_new_tokens as usize;

    let model = build_model(&config, max_sequence_length)?;
    let typed_term = model
        .term()
        .ok_or_else(|| anyhow!("failed to construct typed term for model {}", model.path()))?;

    let graph_bytes = serde_json::to_vec_pretty(&typed_term)?;
    Ok((graph_bytes, prepared_prompt))
}

/// Fetch weights, build the environment, and execute the provided TypedTerm, streaming decoded text.
pub fn run_graph_streaming(
    model_id: &str,
    prepared_input: &str,
    typed_term: &catgrad::category::lang::TypedTerm,
    max_seq: u32,
    revision: Option<&str>,
    mut on_partial: impl FnMut(&str, bool),
) -> Result<()> {
    let backend = NdArrayBackend;
    let (parameter_values, parameter_types, config, tokenizer) =
        load_weights_and_types(model_id, revision, &backend)?;

    let encoding = tokenizer
        .encode(prepared_input, true)
        .map_err(|e| anyhow!("tokenizer encode error: {e}"))?;
    let tokens: Vec<u32> = encoding.get_ids().to_vec();

    let max_sequence_length = tokens.len() + max_seq as usize;
    let model = build_model(&config, max_sequence_length)?;

    let mut env = stdlib();
    env.declarations
        .extend(to_load_ops(model.path(), parameter_types.keys()));

    let interpreter = Interpreter::new(backend.clone(), env, parameter_values.clone());

    let mut decoded = String::new();
    let mut current_tokens = tokens;

    for _ in 0..max_seq {
        let input_tensor = interpreter::tensor(
            &interpreter.backend,
            Shape(vec![1, current_tokens.len()]),
            current_tokens.clone(),
        )
        .map_err(|e| anyhow!("failed to build input tensor: {e:?}"))?;

        let mut results = interpreter
            .run(typed_term.term.clone(), vec![input_tensor])
            .map_err(|e| anyhow!("execution error: {e:?}"))?;

        let output = results
            .pop()
            .ok_or_else(|| anyhow!("no output from graph"))?;

        let next_token = match output {
            interpreter::Value::Tensor(arr) => match interpreter.backend.to_vec(arr) {
                interpreter::TaggedVec::U32(v) => v.last().copied(),
                _ => None,
            },
            _ => None,
        }
        .ok_or_else(|| anyhow!("unexpected output value"))?;

        // Decode and append
        let piece = tokenizer
            .decode(&[next_token], false)
            .unwrap_or_else(|_| next_token.to_string());
        decoded.push_str(&piece);
        current_tokens.push(next_token);

        let done = config.get_eos_token_ids().contains(&(next_token as i32));
        on_partial(decoded.as_str(), done);

        // Stop if EOS
        if done {
            break;
        }
    }

    Ok(())
}
