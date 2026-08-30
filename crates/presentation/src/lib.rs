//! Optional conversion between user-facing text and token IDs.
//!
//! Nothing in this crate is part of Catena's execution package or Hellas's
//! execution guarantee. The protocol commits the resulting input token IDs,
//! caller-selected generation policy, exact Catena execution package, and
//! output token IDs. A caller or node operator selects this local presentation
//! configuration independently.

use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use tokenizers::Tokenizer;

pub struct TextPresentation {
    tokenizer: Tokenizer,
}

impl TextPresentation {
    /// Load an application-selected tokenizer.
    ///
    /// This performs local file I/O only. It deliberately has no package
    /// directory, URL, or model-name argument: neither Catena nor an RPC peer
    /// selects presentation for the caller.
    pub fn load(tokenizer_path: &Path) -> Result<Self> {
        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("failed to load tokenizer {}", tokenizer_path.display()))?;
        Ok(Self { tokenizer })
    }

    /// Plain text tokenization. Chat rendering is deliberately absent until a
    /// separately specified presentation policy supplies an exact template.
    pub fn encode(&self, text: &str) -> Result<Vec<u32>> {
        Ok(self
            .tokenizer
            .encode(text, true)
            .map_err(anyhow::Error::msg)
            .context("failed to tokenize prompt")?
            .get_ids()
            .to_vec())
    }

    pub fn decode(&self, tokens: &[u32]) -> Result<String> {
        self.tokenizer
            .decode(tokens, true)
            .map_err(anyhow::Error::msg)
            .context("failed to decode tokens")
    }
}

/// Stateful streamed-token decoder for presentation UIs.
pub struct TextOutputDecoder {
    presentation: Arc<TextPresentation>,
    token_ids: Vec<u32>,
    decoded: String,
}

impl TextOutputDecoder {
    pub fn new(presentation: Arc<TextPresentation>) -> Self {
        Self {
            presentation,
            token_ids: Vec::new(),
            decoded: String::new(),
        }
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<String> {
        let tokens = hellas_rpc::decode_token_ids(bytes)?;
        if tokens.is_empty() {
            return Ok(String::new());
        }
        self.token_ids.extend(tokens);
        let next = self.presentation.decode(&self.token_ids)?;
        let delta = next
            .strip_prefix(&self.decoded)
            .context(
                "tokenizer revised already-emitted text; this tokenizer cannot be decoded as an append-only stream",
            )?
            .to_string();
        self.decoded = next;
        Ok(delta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn presentation() -> Arc<TextPresentation> {
        let tokenizer = Tokenizer::from_bytes(
            br#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":{"type":"Whitespace"},"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hello":0,"world":1,"<unk>":2},"unk_token":"<unk>"}}"#,
        )
        .unwrap();
        Arc::new(TextPresentation { tokenizer })
    }

    #[test]
    fn plain_text_is_only_local_presentation() {
        let presentation = presentation();
        assert_eq!(presentation.encode("hello world").unwrap(), [0, 1]);
    }

    #[test]
    fn streamed_decode_emits_only_new_text() {
        let mut decoder = TextOutputDecoder::new(presentation());
        assert_eq!(
            decoder
                .push_bytes(&hellas_rpc::encode_token_ids(&[0]))
                .unwrap(),
            "hello"
        );
        assert_eq!(
            decoder
                .push_bytes(&hellas_rpc::encode_token_ids(&[1]))
                .unwrap(),
            " world"
        );
    }
}
