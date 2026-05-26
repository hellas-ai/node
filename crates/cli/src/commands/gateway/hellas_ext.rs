//! Wire-extension helpers for stamping hellas-namespaced metadata onto
//! protocol-native streaming/non-streaming JSON envelopes.
//!
//! The wrapper pattern keeps catgrad-llm's wire types
//! (`openai::ChatCompletionChunk`, `anthropic::MessageStreamEvent`,
//! `plain::CompletionChunk`, etc.) clean and protocol-neutral —
//! `WithHellas<T>` adds a sibling `"hellas"` field at the gateway
//! emission boundary via `#[serde(flatten)]`.
//!
use hellas_rpc::provenance::{CatnixReceiptCommitment, ExecutionProvenance, encode_hex};
use serde::Serialize;

#[derive(Serialize, Default, Debug, Clone)]
pub(super) struct HellasExt {
    /// Catnix CallCommitment (`x-hellas-commitment` in headers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    /// Catnix ReceiptCommitment (`x-hellas-receipt` in headers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
}

impl HellasExt {
    pub fn is_empty(&self) -> bool {
        self.commitment.is_none() && self.receipt.is_none()
    }

    pub fn commitment(prov: &ExecutionProvenance) -> Self {
        Self {
            commitment: prov.catnix_call_commitment.as_ref().map(encode_hex),
            receipt: None,
        }
    }

    pub fn receipt(catnix: Option<&CatnixReceiptCommitment>) -> Self {
        Self {
            commitment: None,
            receipt: catnix.map(|c| encode_hex(&c.0)),
        }
    }

    pub fn both(prov: &ExecutionProvenance, catnix: Option<&CatnixReceiptCommitment>) -> Self {
        Self {
            commitment: prov.catnix_call_commitment.as_ref().map(encode_hex),
            receipt: catnix.map(|c| encode_hex(&c.0)),
        }
    }
}

/// Wraps any `Serialize` value with a sibling `"hellas"` field.
/// `#[serde(flatten)]` on `inner` produces the merged JSON, so wrapping
/// `ChatCompletionChunk` yields `{...chunk fields..., "hellas": {...}}`.
///
/// Empty `HellasExt` is skipped at serialization, so `WithHellas` with
/// a default-constructed `hellas` is wire-equivalent to the unwrapped
/// inner value.
#[derive(Serialize, Debug)]
pub(super) struct WithHellas<T: Serialize> {
    #[serde(flatten)]
    pub inner: T,
    #[serde(skip_serializing_if = "HellasExt::is_empty")]
    pub hellas: HellasExt,
}

impl<T: Serialize> WithHellas<T> {
    pub fn new(inner: T, hellas: HellasExt) -> Self {
        Self { inner, hellas }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_hellas_skipped() {
        #[derive(Serialize)]
        struct Inner {
            a: u32,
        }
        let wrapped = WithHellas::new(Inner { a: 1 }, HellasExt::default());
        let v = serde_json::to_value(&wrapped).unwrap();
        assert_eq!(v, json!({ "a": 1 }));
    }

    #[test]
    fn commitment_renders_as_lowercase_hex() {
        let prov = ExecutionProvenance {
            commitment_id: [0xab; 32],
            catnix_call_commitment: Some([0xcd; 32]),
        };
        let hellas = HellasExt::commitment(&prov);
        assert_eq!(hellas.commitment.as_deref(), Some("cd".repeat(32).as_str()));
        assert!(hellas.receipt.is_none());
    }

    #[test]
    fn receipt_renders_as_lowercase_hex() {
        let receipt = CatnixReceiptCommitment([0xcd; 32]);
        let hellas = HellasExt::receipt(Some(&receipt));
        assert_eq!(hellas.receipt.as_deref(), Some("cd".repeat(32).as_str()));
        assert!(hellas.commitment.is_none());
    }

    #[test]
    fn flatten_merges_sibling_hellas_field() {
        #[derive(Serialize)]
        struct Inner {
            id: &'static str,
            choices: Vec<u32>,
        }
        let prov = ExecutionProvenance {
            commitment_id: [0x12; 32],
            catnix_call_commitment: Some([0x34; 32]),
        };
        let wrapped = WithHellas::new(
            Inner {
                id: "chatcmpl-1",
                choices: vec![0],
            },
            HellasExt::commitment(&prov),
        );
        let v = serde_json::to_value(&wrapped).unwrap();
        assert_eq!(
            v,
            json!({
                "id": "chatcmpl-1",
                "choices": [0],
                "hellas": {
                    "commitment": "34".repeat(32),
                },
            })
        );
    }

    #[test]
    fn both_carries_commitment_and_receipt() {
        let prov = ExecutionProvenance {
            commitment_id: [1; 32],
            catnix_call_commitment: Some([3; 32]),
        };
        let receipt = CatnixReceiptCommitment([2; 32]);
        let hellas = HellasExt::both(&prov, Some(&receipt));
        assert_eq!(hellas.commitment.as_deref(), Some("03".repeat(32).as_str()));
        assert_eq!(hellas.receipt.as_deref(), Some("02".repeat(32).as_str()));
    }
}
