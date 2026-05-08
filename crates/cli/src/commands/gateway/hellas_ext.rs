//! Wire-extension helpers for stamping hellas-namespaced metadata onto
//! protocol-native streaming/non-streaming JSON envelopes.
//!
//! The wrapper pattern keeps catgrad-llm's wire types
//! (`openai::ChatCompletionChunk`, `anthropic::MessageStreamEvent`,
//! `plain::CompletionChunk`, etc.) clean and protocol-neutral —
//! `WithHellas<T>` adds a sibling `"hellas"` field at the gateway
//! emission boundary via `#[serde(flatten)]`.
//!
//! See `docs/GATEWAY_HELLAS_WIRE.md` (TODO) and the approved plan in
//! `~/.claude/plans/yeah-lets-try-to-parallel-diffie.md`.

use catgrad::cid::Cid;
use catgrad_llm::runtime::TextReceipt;
use hellas_rpc::provenance::{ExecutionProvenance, encode_hex};
use serde::Serialize;

#[derive(Serialize, Default, Debug, Clone)]
pub(super) struct HellasExt {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
}

impl HellasExt {
    pub fn is_empty(&self) -> bool {
        self.commitment_id.is_none() && self.receipt_id.is_none()
    }

    pub fn commitment(prov: &ExecutionProvenance) -> Self {
        Self {
            commitment_id: Some(encode_hex(&prov.commitment_id)),
            receipt_id: None,
        }
    }

    pub fn receipt(cid: &Cid<TextReceipt>) -> Self {
        Self {
            commitment_id: None,
            receipt_id: Some(cid.to_string()),
        }
    }

    pub fn both(prov: &ExecutionProvenance, cid: &Cid<TextReceipt>) -> Self {
        Self {
            commitment_id: Some(encode_hex(&prov.commitment_id)),
            receipt_id: Some(cid.to_string()),
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
        };
        let hellas = HellasExt::commitment(&prov);
        assert_eq!(
            hellas.commitment_id.as_deref(),
            Some("ab".repeat(32).as_str())
        );
        assert!(hellas.receipt_id.is_none());
    }

    #[test]
    fn receipt_renders_as_lowercase_hex() {
        let cid = Cid::<TextReceipt>::from_bytes([0xcd; 32]);
        let hellas = HellasExt::receipt(&cid);
        assert_eq!(hellas.receipt_id.as_deref(), Some("cd".repeat(32).as_str()));
        assert!(hellas.commitment_id.is_none());
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
                "hellas": { "commitment_id": "12".repeat(32) },
            })
        );
    }

    #[test]
    fn both_carries_commitment_and_receipt() {
        let prov = ExecutionProvenance {
            commitment_id: [1; 32],
        };
        let cid = Cid::<TextReceipt>::from_bytes([2; 32]);
        let hellas = HellasExt::both(&prov, &cid);
        assert_eq!(
            hellas.commitment_id.as_deref(),
            Some("01".repeat(32).as_str())
        );
        assert_eq!(hellas.receipt_id.as_deref(), Some("02".repeat(32).as_str()));
    }
}
