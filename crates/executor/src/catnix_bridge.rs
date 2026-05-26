//! Builds catnix `Term`/`Value` projections from executor runtime inputs.
//!
//! The executor uses this module to derive catnix call commitments at
//! quote time and matching catnix receipt commitments at completion.
//!
//! # Placeholder ValueIds
//!
//! The runtime currently lacks first-class digests for the
//! constituent Values of a CatgradText `Term`:
//!
//! - `program`: catgrad `Cid<Program>` is content-addressed and
//!   stable, so we use its bytes directly as the catnix
//!   `ValueId`.
//! - `parameters`, `tokenizer`: the runtime keys these by
//!   `HuggingFaceLocator { model_id, revision, dtype }` strings, not
//!   by canonical content. We BLAKE3 the locator string under a
//!   per-role tag to derive a deterministic placeholder `ValueId`.
//!   This is not a content digest; it should be replaced when model
//!   artifacts expose stable content-addressed identifiers.
//! - `from` (initial state): cold-start quotes use the canonical
//!   catnix empty `TextState` (`TokenIds([]) -> TextState`). Anchored
//!   execution is not wired yet; once it is, this must be derived from
//!   the prior catnix state.

use catnix::{Canonical, TextPolicy as CatnixTextPolicy, TextState, TokenId, TokenIds, ValueId};
use hellas_core::adaptors::catgrad_text::{CatgradText, CatgradTextRequest};
use hellas_core::protocol::{Call, ProjectCall, ProjectionContext, ProjectionError};
use hellas_runtime::cid::Cid;
use hellas_runtime::graph::Program;
use hellas_runtime::runtime::{TextPolicy as RuntimeTextPolicy, TextReceipt};

use crate::inputs::HuggingFaceLocator;
use crate::state::Invocation;

const PARAMETERS_PLACEHOLDER_TAG: &str = "hellas_runtime.parameters.locator_hash.v1";
const TOKENIZER_PLACEHOLDER_TAG: &str = "hellas_runtime.tokenizer.locator_hash.v1";

/// BLAKE3 a per-role tag plus the locator's `model_id@revision:dtype`
/// string to derive a deterministic placeholder `ValueId`.
fn locator_placeholder(tag: &str, locator: &HuggingFaceLocator) -> ValueId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag.as_bytes());
    hasher.update(b"\0");
    hasher.update(locator.model_id.as_bytes());
    hasher.update(b"@");
    hasher.update(locator.revision.as_bytes());
    hasher.update(b":");
    hasher.update(format!("{:?}", locator.dtype).as_bytes());
    let digest = *hasher.finalize().as_bytes();
    ValueId::from_bytes(digest)
}

/// Convert a runtime `TextPolicy` into the catnix-shaped one. The two
/// types carry the same fields (max_new_tokens, sorted-deduped stop
/// token ids) but live in different crates today.
pub fn catnix_text_policy_from_runtime(runtime: &RuntimeTextPolicy) -> CatnixTextPolicy {
    let stops = runtime.stop_token_ids().iter().filter_map(|id| {
        // Negative stop token ids should never reach here (runtime
        // already validates), but we filter rather than panic to keep
        // the bridge layer non-fatal.
        u32::try_from(*id).ok().map(TokenId::new)
    });
    CatnixTextPolicy::new(runtime.max_new_tokens(), stops)
}

/// Derive the catnix `TextState` ValueId for a decoder state whose
/// materialized token history is `tokens`.
pub fn text_state_value_id_for_tokens(tokens: impl IntoIterator<Item = u32>) -> ValueId {
    let token_ids = TokenIds::from_u32s(tokens);
    TextState::new(token_ids.value_id()).value_id()
}

/// Cold-start state: no prior decoder tokens.
pub fn empty_text_state_value_id() -> ValueId {
    text_state_value_id_for_tokens(std::iter::empty())
}

/// Build a `CatgradTextRequest` from the same runtime-side inputs
/// that produce today's `Cid<TextExecution>` commitment.
///
/// See module docs about placeholder `ValueId`s for parameters /
/// tokenizer / `from`.
pub fn build_catgrad_text_request(
    program_cid: Cid<Program>,
    weights_locator: &HuggingFaceLocator,
    _initial_receipt_id: Cid<TextReceipt>,
    invocation: &Invocation,
    policy: &RuntimeTextPolicy,
) -> CatgradTextRequest {
    let prompt_tokens = TokenIds::from_u32s(invocation.input_ids.iter().copied());
    CatgradTextRequest {
        program: ValueId::from_bytes(*program_cid.as_bytes()),
        parameters: locator_placeholder(PARAMETERS_PLACEHOLDER_TAG, weights_locator),
        tokenizer: locator_placeholder(TOKENIZER_PLACEHOLDER_TAG, weights_locator),
        from: empty_text_state_value_id(),
        prompt_tokens,
        policy: catnix_text_policy_from_runtime(policy),
    }
}

/// Project a `CatgradTextRequest` to a kernel-level [`Call`] via the
/// CatgradText adaptor. Pure — propagates the adaptor's
/// [`ProjectionError`].
pub fn project_call_for_request(request: &CatgradTextRequest) -> Result<Call, ProjectionError> {
    CatgradText::project_call(request, &ProjectionContext::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use catgrad::prelude::Dtype;

    fn locator() -> HuggingFaceLocator {
        HuggingFaceLocator::new(
            "Qwen/Qwen3-0.6B".to_string(),
            "main".to_string(),
            Dtype::F32,
        )
    }

    fn invocation() -> Invocation {
        Invocation {
            input_ids: vec![1, 2, 3],
            max_new_tokens: 16,
            stop_token_ids: vec![2],
        }
    }

    fn policy() -> RuntimeTextPolicy {
        RuntimeTextPolicy::new(16, vec![2])
    }

    #[test]
    fn locator_placeholder_is_deterministic() {
        let a = locator_placeholder(PARAMETERS_PLACEHOLDER_TAG, &locator());
        let b = locator_placeholder(PARAMETERS_PLACEHOLDER_TAG, &locator());
        assert_eq!(a, b);
    }

    #[test]
    fn locator_placeholder_distinguishes_roles() {
        let params = locator_placeholder(PARAMETERS_PLACEHOLDER_TAG, &locator());
        let tokenizer = locator_placeholder(TOKENIZER_PLACEHOLDER_TAG, &locator());
        assert_ne!(params, tokenizer);
    }

    #[test]
    fn locator_placeholder_changes_with_locator() {
        let a = locator_placeholder(PARAMETERS_PLACEHOLDER_TAG, &locator());
        let b = locator_placeholder(
            PARAMETERS_PLACEHOLDER_TAG,
            &HuggingFaceLocator::new(
                "Qwen/Qwen3-0.6B".to_string(),
                "alt-revision".to_string(),
                Dtype::F32,
            ),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn text_state_value_id_uses_catnix_text_state_shape() {
        let empty = empty_text_state_value_id();
        let explicit_empty = text_state_value_id_for_tokens([]);
        let non_empty = text_state_value_id_for_tokens([1, 2, 3]);

        assert_eq!(empty, explicit_empty);
        assert_ne!(empty, non_empty);
    }

    #[test]
    fn cold_start_request_uses_empty_catnix_state() {
        let program_cid = Cid::<Program>::from_bytes([0xaa; 32]);
        let runtime_receipt_id = Cid::<TextReceipt>::from_bytes([0xbb; 32]);
        let inv = invocation();
        let pol = policy();
        let loc = locator();

        let req = build_catgrad_text_request(program_cid, &loc, runtime_receipt_id, &inv, &pol);

        assert_eq!(req.from, empty_text_state_value_id());
        assert_ne!(
            req.from,
            ValueId::from_bytes(*runtime_receipt_id.as_bytes())
        );
    }

    #[test]
    fn build_then_project_is_deterministic() {
        let program_cid = Cid::<Program>::from_bytes([0xaa; 32]);
        let runtime_receipt_id = Cid::<TextReceipt>::from_bytes([0xbb; 32]);
        let inv = invocation();
        let pol = policy();
        let loc = locator();

        let req_a = build_catgrad_text_request(program_cid, &loc, runtime_receipt_id, &inv, &pol);
        let req_b = build_catgrad_text_request(program_cid, &loc, runtime_receipt_id, &inv, &pol);
        assert_eq!(req_a, req_b);

        let call_a = project_call_for_request(&req_a).unwrap();
        let call_b = project_call_for_request(&req_b).unwrap();
        assert_eq!(call_a.commitment(), call_b.commitment());
    }

    #[test]
    fn different_program_cid_produces_different_call() {
        let runtime_receipt_id = Cid::<TextReceipt>::from_bytes([0xbb; 32]);
        let inv = invocation();
        let pol = policy();
        let loc = locator();

        let a = build_catgrad_text_request(
            Cid::<Program>::from_bytes([1; 32]),
            &loc,
            runtime_receipt_id,
            &inv,
            &pol,
        );
        let b = build_catgrad_text_request(
            Cid::<Program>::from_bytes([2; 32]),
            &loc,
            runtime_receipt_id,
            &inv,
            &pol,
        );
        let call_a = project_call_for_request(&a).unwrap();
        let call_b = project_call_for_request(&b).unwrap();
        assert_ne!(call_a.commitment(), call_b.commitment());
    }
}
