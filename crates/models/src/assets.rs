use std::sync::Arc;

use catgrad_llm_models::utils::{get_model, get_model_architecture};
use hellas_rpc::{ContentId, DagCborEncoder, Dtype, EvaluateProgramManifest};
use serde_json::Value;
use tokenizers::Tokenizer;

use super::hf::{get_model_metadata_files, get_program_files};
use super::prompt::render_chat_prompt;
use super::{ModelAssetsError, Result};
use hellas_rpc::{decode_token_ids, spec::ModelSpec};

pub use super::prompt::{ChatMessage, PreparedPrompt};

pub fn program_manifest(
    model: &str,
    dtype: Dtype,
    backend_profile: &str,
) -> Result<EvaluateProgramManifest> {
    let spec = ModelSpec::parse(model)?;
    let (mut weight_paths, config_path, tokenizer_path, tokenizer_config_path) =
        get_program_files(&spec)?;
    weight_paths.sort();
    let weights = weight_paths
        .iter()
        .map(|path| content_id_of(path))
        .collect::<Result<Vec<_>>>()?;
    let config_bytes = read_asset(&config_path)?;
    let config: Value = serde_json::from_slice(&config_bytes)
        .map_err(|source| ModelAssetsError::ParseModelMetadata { source })?;
    let graph = get_model(&config, 1, None, to_catgrad_dtype(dtype))?
        .term()
        .ok_or(ModelAssetsError::InvalidProgramGraph)?;
    let graph = ContentId::hash(
        &serde_json::to_vec(&graph)
            .map_err(|source| ModelAssetsError::SerializeProgram { source })?,
    );
    let tokenizer = content_id_of(&tokenizer_path)?;
    let tokenizer_config = content_id_of(&tokenizer_config_path)?;
    let mut tokenizer_manifest = DagCborEncoder::new();
    tokenizer_manifest.array(3);
    tokenizer_manifest.str("hellas.program.tokenizer.v2");
    tokenizer_manifest.bytes(tokenizer.as_bytes());
    tokenizer_manifest.bytes(tokenizer_config.as_bytes());
    let resolved_revision = config_path
        .parent()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .ok_or(ModelAssetsError::UnresolvedRevision)?
        .to_string();
    let build = ContentId::hash(
        format!("hellas:{}:{}", hellas_rpc::VERSION, hellas_rpc::GIT_REV).as_bytes(),
    );
    Ok(EvaluateProgramManifest {
        weights,
        graph,
        config: ContentId::hash(&config_bytes),
        tokenizer: ContentId::hash(&tokenizer_manifest.into_bytes()),
        resolved_revision,
        numeric_profile: dtype.as_wire().to_string(),
        backend_profile: backend_profile.to_string(),
        build,
    })
}

/// Content id of the file at `path`.
///
/// Delegates to the content store, which streams rather than holding
/// the file and remembers what it hashed. The manifest and the store
/// must agree on ids by construction, not by coincidence — this is the
/// same code path, not a second implementation of it.
pub fn content_id_of(path: &std::path::Path) -> Result<ContentId> {
    let indexed = store()
        .index(path)
        .map_err(|source| ModelAssetsError::Index { source })?;
    Ok(ContentId::from_bytes(indexed.id.into_bytes()))
}

/// The process-wide store the model layer indexes into.
///
/// A single instance so a weight file hashed for one quote is not
/// hashed again for the next.
pub fn store() -> &'static hellas_store::ContentStore {
    static STORE: std::sync::OnceLock<hellas_store::ContentStore> = std::sync::OnceLock::new();
    STORE.get_or_init(hellas_store::ContentStore::new)
}

fn read_asset(path: &std::path::Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|source| ModelAssetsError::ReadAsset {
        path: path.to_path_buf(),
        source,
    })
}

/// Model-domain result of preparing a prompt for a quote: everything the
/// model layer contributes to a `QuotePreparedTextRequest`, minus the
/// protocol framing (start marker, runner key) the caller adds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedQuote {
    pub huggingface_model_id: String,
    pub huggingface_revision: String,
    pub prompt_token_ids: Vec<u32>,
    pub stop_token_ids: Vec<u32>,
    pub accept_dtype: String,
}

pub struct ModelAssets {
    model: ModelSpec,
    config: Value,
    tokenizer: Arc<Tokenizer>,
    tokenizer_config: Arc<Value>,
    chat_template: Option<Arc<str>>,
    stop_token_ids: Arc<[u32]>,
    dtype: Dtype,
}

impl ModelAssets {
    pub fn load(model_name: &str, dtype: Dtype) -> Result<Self> {
        let model = ModelSpec::parse(model_name)?;
        let (config_path, tokenizer_path, tokenizer_config_path, chat_template_path) =
            get_model_metadata_files(&model)?;
        let config_bytes = read_asset(&config_path)?;
        let config: Value = serde_json::from_slice(&config_bytes)
            .map_err(|source| ModelAssetsError::ParseModelMetadata { source })?;
        let tokenizer_config_bytes = read_asset(&tokenizer_config_path)?;
        let tokenizer_config: Value = serde_json::from_slice(&tokenizer_config_bytes)
            .map_err(|source| ModelAssetsError::ParseModelMetadata { source })?;

        let graph_model = get_model(&config, 1, None, to_catgrad_dtype(dtype))?;
        let stop_token_ids = graph_model
            .config()
            .get_eos_token_ids()
            .into_iter()
            .map(|token| {
                u32::try_from(token).map_err(|_| ModelAssetsError::NegativeStopTokenId { token })
            })
            .collect::<Result<Vec<_>>>()?;

        let tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(|source| {
            ModelAssetsError::LoadTokenizer {
                path: tokenizer_path,
                source,
            }
        })?;

        let chat_template = match chat_template_path {
            Some(path) => Some(
                std::fs::read_to_string(&path)
                    .map_err(|source| ModelAssetsError::ReadAsset { path, source })?,
            ),
            None => tokenizer_config
                .get("chat_template")
                .and_then(Value::as_str)
                .map(str::to_string),
        }
        .map(sanitize_chat_template)
        .map(Arc::<str>::from);

        Ok(Self {
            model,
            config,
            tokenizer: Arc::new(tokenizer),
            tokenizer_config: Arc::new(tokenizer_config),
            chat_template,
            stop_token_ids: Arc::from(stop_token_ids.as_slice()),
            dtype,
        })
    }

    /// Encode a prepared prompt into the model-domain pieces of a quote:
    /// model identity, validated token streams, and the model's dtype.
    /// Assembling the wire `QuotePreparedTextRequest` (start marker,
    /// runner key) is the caller's job — the model layer owns no protocol
    /// shape.
    pub fn prepare_quote(&self, prepared_prompt: &PreparedPrompt) -> PreparedQuote {
        PreparedQuote {
            huggingface_model_id: self.model.id.clone(),
            huggingface_revision: self.model.revision.clone(),
            prompt_token_ids: prepared_prompt.input_ids.clone(),
            stop_token_ids: prepared_prompt.stop_token_ids.clone(),
            accept_dtype: self.dtype.as_wire().to_string(),
        }
    }

    pub fn has_chat_template(&self) -> bool {
        self.chat_template.is_some()
    }

    pub fn prepare_chat(&self, messages: &[ChatMessage]) -> Result<PreparedPrompt> {
        self.prepare_chat_with_options(messages, None, false)
    }

    pub fn prepare_chat_with_options(
        &self,
        messages: &[ChatMessage],
        tools: Option<&[serde_json::Value]>,
        enable_thinking: bool,
    ) -> Result<PreparedPrompt> {
        let template = self
            .chat_template
            .as_deref()
            .ok_or(ModelAssetsError::MissingChatTemplate)?;
        let prompt = render_chat_prompt(
            template,
            &self.tokenizer_config,
            messages,
            tools,
            enable_thinking,
        )
        .map_err(|source| ModelAssetsError::RenderChatTemplate { source })?;
        self.prepare_plain(&prompt)
    }

    pub fn prepare_plain(&self, prompt: &str) -> Result<PreparedPrompt> {
        PreparedPrompt::from_prompt(self.tokenizer.as_ref(), prompt, &self.stop_token_ids)
            .map_err(|source| ModelAssetsError::TokenizePrompt { source })
    }

    pub fn decode_tokens(&self, token_ids: &[u32]) -> Result<String> {
        self.tokenizer
            .decode(token_ids, false)
            .map_err(|source| ModelAssetsError::DecodeTokens { source })
    }

    pub fn stop_token_ids(&self) -> &[u32] {
        &self.stop_token_ids
    }

    pub fn architecture(&self) -> Result<String> {
        get_model_architecture(&self.config)
            .map(str::to_string)
            .map_err(Into::into)
    }
}

/// Stateful decoder for streamed token batches.
///
/// The decoder preserves detokenizer state across chunks, including partial
/// byte sequences and stop-token handling.
pub struct TextOutputDecoder {
    assets: Arc<ModelAssets>,
    stop_token_ids: Vec<u32>,
    token_ids: Vec<u32>,
    decoded: String,
    stopped: bool,
}

impl TextOutputDecoder {
    pub fn new(assets: Arc<ModelAssets>, stop_token_ids: &[u32]) -> Self {
        Self {
            assets,
            stop_token_ids: stop_token_ids.to_vec(),
            token_ids: Vec::new(),
            decoded: String::new(),
            stopped: false,
        }
    }

    pub fn for_model(assets: Arc<ModelAssets>) -> Self {
        let stop_token_ids = assets.stop_token_ids().to_vec();
        Self::new(assets, &stop_token_ids)
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<String> {
        if self.stopped {
            return Ok(String::new());
        }
        let previous_len = self.token_ids.len();
        for token in decode_token_ids(bytes)? {
            if self.stop_token_ids.contains(&token) {
                self.stopped = true;
                break;
            }
            self.token_ids.push(token);
        }
        if self.token_ids.len() == previous_len {
            return Ok(String::new());
        }
        let next = self.assets.decode_tokens(&self.token_ids)?;
        let delta = next
            .strip_prefix(&self.decoded)
            .unwrap_or(&next)
            .to_string();
        self.decoded = next;
        Ok(delta)
    }
}

fn sanitize_chat_template(template: String) -> String {
    template
        .replace("{% generation %}", "")
        .replace("{%- generation -%}", "")
        .replace("{% endgeneration %}", "")
        .replace("{%- endgeneration -%}", "")
}

pub fn to_catgrad_dtype(dtype: Dtype) -> catgrad::prelude::Dtype {
    match dtype {
        Dtype::F32 => catgrad::prelude::Dtype::F32,
        Dtype::F16 => catgrad::prelude::Dtype::F16,
        Dtype::BF16 => catgrad::prelude::Dtype::BF16,
        Dtype::F8 => catgrad::prelude::Dtype::F8,
        Dtype::U32 => catgrad::prelude::Dtype::U32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenizers::models::wordlevel::WordLevel;

    #[test]
    fn streamed_decoder_preserves_state_and_suppresses_stop_tokens() {
        let tokenizer = WordLevel::builder()
            .vocab(
                [
                    ("[UNK]".to_string(), 0),
                    ("hello".to_string(), 1),
                    ("world".to_string(), 2),
                ]
                .into_iter()
                .collect(),
            )
            .unk_token("[UNK]".to_string())
            .build()
            .unwrap();
        let assets = Arc::new(ModelAssets {
            model: ModelSpec::parse("test/model").unwrap(),
            config: Value::Null,
            tokenizer: Arc::new(Tokenizer::new(tokenizer)),
            tokenizer_config: Arc::new(Value::Null),
            chat_template: None,
            stop_token_ids: Arc::from([99]),
            dtype: Dtype::F32,
        });
        let mut decoder = TextOutputDecoder::new(assets, &[99]);
        assert_eq!(
            decoder
                .push_bytes(&hellas_rpc::encode_token_ids(&[1]))
                .unwrap(),
            "hello"
        );
        assert_eq!(
            decoder
                .push_bytes(&hellas_rpc::encode_token_ids(&[2, 99, 1]))
                .unwrap(),
            " world"
        );
        assert_eq!(
            decoder
                .push_bytes(&hellas_rpc::encode_token_ids(&[1]))
                .unwrap(),
            ""
        );
    }

    #[test]
    fn strips_generation_markers_from_hugging_face_templates() {
        assert_eq!(
            sanitize_chat_template("a{% generation %}b{%- endgeneration -%}c".to_string()),
            "abc"
        );
    }
}
