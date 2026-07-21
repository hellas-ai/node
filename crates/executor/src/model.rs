use catgrad::interpreter::backend::candle::CandleBackend;
use catgrad::interpreter::{self, Backend};
use catgrad::prelude::{Dtype, Shape, TypedTerm, stdlib, to_load_ops};
use catgrad_llm::utils::{empty_state_cache, load_model};
use catgrad_llm::{LLMError, Result};
use catgrad_llm_models::helpers::LLMModel;
use catgrad_llm_models::utils::get_model;

pub(crate) struct ModelEngine {
    backend: CandleBackend,
    parameters: interpreter::Parameters<CandleBackend>,
    parameter_types: catgrad::typecheck::Parameters,
    config: serde_json::Value,
    eos_token_ids: Vec<u32>,
    dtype: Dtype,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenerationTermination {
    Stop,
    MaxTokens,
    Cancelled,
}

impl ModelEngine {
    pub(crate) fn load(
        model: &str,
        revision: &str,
        backend: CandleBackend,
        dtype: Dtype,
    ) -> Result<Self> {
        let (parameters, parameter_types, config, _, _, _) =
            load_model(model, revision, &backend, dtype)?;
        let eos_token_ids = get_model(&config, 1, None, dtype)?
            .config()
            .get_eos_token_ids()
            .into_iter()
            .map(|token| {
                u32::try_from(token).map_err(|_| {
                    LLMError::InvalidModelConfig(format!("negative EOS token id {token}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            backend,
            parameters,
            parameter_types,
            config,
            eos_token_ids,
            dtype,
        })
    }

    pub(crate) fn generate(
        &self,
        input_ids: &[u32],
        stop_token_ids: &[u32],
        max_tokens: u32,
        mut on_token: impl FnMut(u32) -> bool,
    ) -> Result<GenerationTermination> {
        let max_sequence_length = input_ids
            .len()
            .checked_add(max_tokens as usize)
            .ok_or_else(|| LLMError::InvalidModelConfig("sequence length overflow".to_string()))?;
        let mut runner = ModelRunner::new(self, max_sequence_length)?;
        let mut step_tokens = input_ids.to_vec();

        for _ in 0..max_tokens {
            let token = runner.generate_next_token(&step_tokens)?;
            if self.eos_token_ids.contains(&token) || stop_token_ids.contains(&token) {
                return Ok(GenerationTermination::Stop);
            }
            if !on_token(token) {
                return Ok(GenerationTermination::Cancelled);
            }
            step_tokens.clear();
            step_tokens.push(token);
        }
        Ok(GenerationTermination::MaxTokens)
    }
}

struct ModelRunner {
    model: Box<dyn LLMModel>,
    term: TypedTerm,
    interpreter: interpreter::Interpreter<CandleBackend>,
    state_cache: Vec<interpreter::Value<CandleBackend>>,
    max_sequence_length: usize,
}

impl ModelRunner {
    fn new(engine: &ModelEngine, max_sequence_length: usize) -> Result<Self> {
        let model = get_model(&engine.config, max_sequence_length, None, engine.dtype)?;
        let term = model.term().ok_or_else(|| {
            LLMError::InvalidModelConfig("model graph does not have a typed term".to_string())
        })?;
        let mut environment = stdlib();
        environment
            .declarations
            .extend(to_load_ops(model.path(), engine.parameter_types.keys()));
        let interpreter = interpreter::Interpreter::new(
            engine.backend.clone(),
            environment,
            engine.parameters.clone(),
        );
        let state_cache = empty_state_cache(&engine.backend, model.as_ref())?;
        Ok(Self {
            model,
            term,
            interpreter,
            state_cache,
            max_sequence_length,
        })
    }

    fn generate_next_token(&mut self, tokens: &[u32]) -> Result<u32> {
        let mut inputs = Vec::with_capacity(self.state_cache.len() + 3);
        inputs.push(
            interpreter::tensor(
                &self.interpreter.backend,
                Shape(vec![1, tokens.len()]),
                tokens.to_vec(),
            )
            .map_err(|error| {
                LLMError::InvalidModelConfig(format!("input tensor error: {error:?}"))
            })?,
        );
        inputs.extend(self.state_cache.iter().cloned());
        inputs.push(interpreter::Value::Nat(self.max_sequence_length));
        if let Some(extra) = self.model.extra_nat_input(tokens.len()) {
            inputs.push(interpreter::Value::Nat(extra));
        }

        let mut results = self
            .interpreter
            .run(self.term.term.clone(), inputs)
            .map_err(|error| LLMError::InvalidModelConfig(format!("inference failed: {error}")))?;
        if results.is_empty() {
            return Err(LLMError::InvalidModelConfig(
                "model returned no outputs".to_string(),
            ));
        }
        self.state_cache = if results.len() > 1 {
            results.split_off(1)
        } else {
            Vec::new()
        };
        match results.remove(0) {
            interpreter::Value::Tensor(tensor) => match self.interpreter.backend.to_vec(tensor) {
                interpreter::TaggedVec::U32(tokens) => tokens.last().copied().ok_or_else(|| {
                    LLMError::InvalidModelConfig("token output tensor was empty".to_string())
                }),
                _ => Err(LLMError::InvalidModelConfig(
                    "token output tensor was not u32".to_string(),
                )),
            },
            output => Err(LLMError::InvalidModelConfig(format!(
                "model output was not a tensor: {output:?}"
            ))),
        }
    }
}
