use anyhow::{anyhow, Context};
use catgrad::prelude::*;
use catgrad::typecheck::{DtypeExpr, NatExpr, NdArrayType, ShapeExpr, TypeExpr};
use catgrad_llm::helpers::LLMModel;
use catgrad_llm::utils::get_model_chat_template;
use catgrad_llm::utils::{get_model, get_model_files};
use catgrad_llm::LLMError;
use catgrad_llm::PreparedPrompt;
use hellas_rpc::encode_token_ids;
use hellas_rpc::pb::hellas::GetQuoteRequest;
use serde_json::Value;
use tokenizers::Tokenizer;

pub const DEFAULT_HUGGINGFACE_REVISION: &str = "main";

#[derive(Clone, Debug, PartialEq, Eq)]
struct ModelSpec {
    id: String,
    revision: String,
}

impl ModelSpec {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(anyhow!("model id is empty"));
        }

        let (id, revision) = match raw.rsplit_once('@') {
            Some((id, revision)) => {
                let id = id.trim();
                let revision = revision.trim();
                if id.is_empty() {
                    return Err(anyhow!("model id is empty"));
                }
                if revision.is_empty() {
                    return Err(anyhow!("model revision is empty"));
                }
                (id.to_string(), revision.to_string())
            }
            None => (raw.to_string(), DEFAULT_HUGGINGFACE_REVISION.to_string()),
        };

        Ok(Self { id, revision })
    }
}

struct GreedyTokenGraph<'a> {
    inner: &'a dyn LLMModel,
}

impl DynModule for GreedyTokenGraph<'_> {
    fn ty(&self) -> (Vec<Type>, Vec<Type>) {
        let (source_type, target_type) = self.inner.ty();
        let token_type = Type::Tensor(TypeExpr::NdArrayType(NdArrayType {
            dtype: DtypeExpr::Constant(Dtype::U32),
            shape: ShapeExpr::Shape(vec![NatExpr::Var(0), NatExpr::Var(1), NatExpr::Constant(1)]),
        }));

        let mut wrapped_target_type = vec![token_type];
        wrapped_target_type.extend(target_type.into_iter().skip(1));
        (source_type, wrapped_target_type)
    }

    fn path(&self) -> Path {
        self.inner.path()
    }

    fn def(&self, builder: &Builder, args: Vec<Var>) -> Vec<Var> {
        let mut targets = self.inner.inline(builder, args);
        let logits = targets.remove(0);
        let next_tokens = ops::argmax(builder, logits);

        let mut wrapped_targets = vec![next_tokens];
        wrapped_targets.extend(targets);
        wrapped_targets
    }
}

pub struct LocalModelAssets {
    model: ModelSpec,
    config: Value,
    model_config_json: Vec<u8>,
    tokenizer: Tokenizer,
    chat_template: Option<String>,
    stop_token_ids: Vec<i32>,
}

impl LocalModelAssets {
    pub fn load(model_name: &str) -> anyhow::Result<Self> {
        let model = ModelSpec::parse(model_name)?;
        let (_, config_path, tokenizer_path, _) =
            get_model_files(&model.id, &model.revision).context("failed to locate model files")?;
        let model_config_json = std::fs::read(&config_path)
            .with_context(|| format!("failed to read model config {config_path:?}"))?;
        let config: Value =
            serde_json::from_slice(&model_config_json).context("failed to parse model config")?;

        let graph_model = get_model(&config, 1).context("failed to construct model config")?;
        let stop_token_ids = graph_model.config().get_eos_token_ids();

        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|err| anyhow!("failed to load tokenizer: {err}"))?;

        let chat_template = match get_model_chat_template(&model.id, &model.revision) {
            Ok(template) => Some(
                template
                    .replace("{% generation %}", "")
                    .replace("{% endgeneration %}", ""),
            ),
            Err(_) => None,
        };

        Ok(Self {
            model,
            config,
            model_config_json,
            tokenizer,
            chat_template,
            stop_token_ids,
        })
    }

    pub fn build_quote_request(
        &self,
        prepared_prompt: &PreparedPrompt,
        max_seq: u32,
    ) -> anyhow::Result<GetQuoteRequest> {
        let max_sequence_length = prepared_prompt.input_ids.len() + max_seq as usize;
        let graph = build_graph_bytes(&self.config, max_sequence_length)?;
        let input_ids: Vec<u32> = prepared_prompt
            .input_ids
            .iter()
            .map(|token| {
                u32::try_from(*token)
                    .map_err(|_| anyhow!("negative token id {token} cannot be encoded"))
            })
            .collect::<Result<_, _>>()?;
        let stop_token_ids = prepared_prompt
            .stop_token_ids
            .iter()
            .map(|token| {
                u32::try_from(*token)
                    .map_err(|_| anyhow!("negative stop token id {token} cannot be encoded"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(GetQuoteRequest {
            huggingface_model_id: self.model.id.clone(),
            huggingface_revision: self.model.revision.clone(),
            model_config_json: self.model_config_json.clone(),
            graph,
            input: encode_token_ids(&input_ids),
            prompt_tokens: prepared_prompt.input_ids.len() as u32,
            max_new_tokens: max_seq,
            stop_token_ids,
        })
    }

    pub fn prepare_plain_prompt(&self, prompt: &str) -> anyhow::Result<PreparedPrompt> {
        PreparedPrompt::from_prompt(&self.tokenizer, prompt, &self.stop_token_ids)
            .map_err(anyhow::Error::from)
    }

    pub fn prepare_messages(
        &self,
        messages: &[catgrad_llm::types::Message],
    ) -> anyhow::Result<PreparedPrompt> {
        let chat_template = self
            .chat_template
            .as_ref()
            .ok_or_else(|| anyhow!("model does not expose a chat template"))?;
        PreparedPrompt::from_messages(
            &self.tokenizer,
            chat_template,
            messages,
            &self.stop_token_ids,
        )
        .context("failed to prepare chat messages")
    }

    pub fn decode_tokens(&self, token_ids: &[i32]) -> catgrad_llm::Result<String> {
        let token_ids: Vec<u32> = token_ids
            .iter()
            .map(|token| {
                u32::try_from(*token).map_err(|_| {
                    LLMError::TokenizerError(format!("negative token id {token} cannot be decoded"))
                })
            })
            .collect::<Result<_, _>>()?;
        self.tokenizer
            .decode(&token_ids, false)
            .map_err(LLMError::from)
    }
}

fn build_graph_bytes(config: &Value, max_sequence_length: usize) -> anyhow::Result<Vec<u8>> {
    let model = get_model(config, max_sequence_length).context("failed to build graph model")?;
    let typed_term = GreedyTokenGraph { inner: &*model }
        .term()
        .ok_or_else(|| anyhow!("failed to construct typed graph term"))?;
    serde_json::to_vec_pretty(&typed_term).context("failed to serialize graph")
}

#[cfg(test)]
mod tests {
    use super::{ModelSpec, DEFAULT_HUGGINGFACE_REVISION};

    #[test]
    fn parses_default_revision_when_not_specified() {
        let spec = ModelSpec::parse("HuggingFaceTB/SmolLM2-135M-Instruct").unwrap();
        assert_eq!(spec.id, "HuggingFaceTB/SmolLM2-135M-Instruct");
        assert_eq!(spec.revision, DEFAULT_HUGGINGFACE_REVISION);
    }

    #[test]
    fn parses_explicit_revision_suffix() {
        let spec = ModelSpec::parse("foo/bar@refs/pr/7").unwrap();
        assert_eq!(spec.id, "foo/bar");
        assert_eq!(spec.revision, "refs/pr/7");
    }

    #[test]
    fn rejects_empty_revision_suffix() {
        let err = ModelSpec::parse("foo/bar@").unwrap_err();
        assert!(err.to_string().contains("revision"));
    }
}
