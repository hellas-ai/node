//! The `CatgradText` adaptor: catgrad-LLM text inference, indeterminate.
//!
//! A typed wire request specifies (program, parameters, tokenizer,
//! initial-state, prompt-tokens, policy) and the projection builds a
//! catnix [`Term`] whose canonical bytes ARE the `Call::payload`.
//!
//! # ProtocolId today: `OPAQUE`
//!
//! `CatgradText` claims [`ProtocolId::OPAQUE`] (not `SYMBOLIC`) because
//! today's catgrad-text isn't `Determinate` — sampling and other
//! sources of indeterminism mean two honest producers given the same
//! `Call` may produce different output bytes. The protocol's only
//! commitment is the producer signature on the receipt. When
//! catgrad-text becomes `Determinate` only with a fixed seed,
//! deterministic kernels, fixed dtype/layout, and all such inputs
//! committed into the request bytes. That requires a versioned
//! `ProtocolId::SYMBOLIC` adaptor with its own request shape and
//! `Determinate` marker impl.
//!
//! # Why `catnix.term.v1` and not `hellas.catgrad_text.request.v1`
//!
//! Per AXES.md §"Per-adaptor canonical tags", the `catnix.*` tag
//! prefix is blessed as a valid Hellas adaptor canonical-tag namespace
//! for catgrad-shaped adaptors. The canonical payload bytes start with
//! `catnix.term.v1` (the catnix `Term`'s outer tag) and contain the
//! Term's bindings sorted by canonical key bytes. No additional Hellas
//! envelope is wrapped around them.

use std::collections::BTreeMap;

use catnix::{
    BindingKey, Canonical, CanonicalDecode, Term, TermId, TextPolicy, TextRunOutput, TokenIds,
    ValueId,
};

use crate::protocol::{
    Adaptor, Call, CallResult, CanonicalPayload, ProjectCall, ProjectResult, ProjectionContext,
    ProjectionError, ProtocolId,
};

/// Adaptor marker for catgrad-LLM text inference.
pub struct CatgradText;

/// Wire request for a single CatgradText invocation.
///
/// Every field is settlement-relevant. Concrete `ValueId`s for the
/// "big" inputs (program, parameters, tokenizer, initial state) are
/// expected to have been resolved by the caller already (either by
/// looking up canonical bytes in the executor's artifact store, or by
/// computing them client-side). The typed `prompt_tokens` and `policy`
/// are carried inline and the projection derives their `ValueId`s as
/// part of building the [`Term`].
///
/// Nothing in this struct is implicit: any "ambient default" (latest
/// model, current time, default dtype) must already be resolved into a
/// concrete `ValueId` before the request reaches projection. The empty
/// [`ProjectionContext`] is sufficient — no additional resolution
/// happens at projection time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatgradTextRequest {
    /// `ValueId` of the catgrad text-stepper program. Different
    /// programs (different compiled graphs, different dtypes) hash to
    /// different `ValueId`s.
    pub program: ValueId,
    /// `ValueId` of the model parameters. Bound under the canonical
    /// `BindingKey::Path(["parameters"])` to match catgrad's path-keyed
    /// parameter store convention.
    pub parameters: ValueId,
    /// `ValueId` of the tokenizer configuration + vocabulary.
    pub tokenizer: ValueId,
    /// `ValueId` of the initial decoder state — either a "genesis"
    /// empty-state Value or a previously-produced
    /// [`catnix::TextRunOutput::state`].
    pub from: ValueId,
    /// Prompt token ids, carried inline. The projection hashes these
    /// to derive their `ValueId` and binds it into the Term.
    pub prompt_tokens: TokenIds,
    /// Decoding policy, carried inline; the projection hashes it.
    pub policy: TextPolicy,
}

/// The reply CatgradText produces: a canonical [`TextRunOutput`]
/// recording the executed Term and the resulting Values.
///
/// `term` in the output IS the `TermId` of the projected `Call`
/// payload — they must match for `Receipt::verify_delivery` to accept
/// the receipt. The catnix bytes of `TextRunOutput` ARE the
/// `CallResult::payload`.
pub type CatgradTextReply = TextRunOutput;

// ---- Binding keys --------------------------------------------------------
//
// The binding-key conventions used by this adaptor. Documented here
// rather than baked into magic strings at call sites — any change here
// is a wire-format change for CatgradText specifically and gets
// versioned via either a new adaptor (`CatgradTextV2`) or a
// `ProtocolId::SYMBOLIC` adaptor with its own request shape.

// All bindings use `BindingKey::Named` for consistency. These are
// *settlement-identity* keys (they distinguish this CatgradText Term
// from another in canonical bytes), NOT catgrad's runtime call ABI —
// the executor maps from these named bindings into whatever positional
// args / path-keyed parameters the catgrad runtime actually expects.
//
// `parameters` is the aggregate parameter-store ValueId (a bundle, not
// an individual tensor). If a future adaptor wants per-tensor
// catgrad-faithful Paths, it would build the Term with many
// `BindingKey::Path(...)` entries instead of one `Named("parameters")`.

fn parameters_key() -> BindingKey {
    BindingKey::Named("parameters".to_string())
}

fn tokenizer_key() -> BindingKey {
    BindingKey::Named("tokenizer".to_string())
}

fn from_key() -> BindingKey {
    BindingKey::Named("from".to_string())
}

fn prompt_tokens_key() -> BindingKey {
    BindingKey::Named("prompt_tokens".to_string())
}

fn policy_key() -> BindingKey {
    BindingKey::Named("policy".to_string())
}

/// Build the catnix [`Term`] for a CatgradText request.
///
/// Pure function: given the same request, produces the same Term
/// bytes on every honest implementation. The Term's `program` is
/// `req.program`; its bindings are the parameters/tokenizer/from
/// ValueIds passed through, plus the prompt-tokens and policy
/// ValueIds derived by hashing the inline typed Values.
pub fn build_term(req: &CatgradTextRequest) -> Term {
    let mut bindings: BTreeMap<BindingKey, ValueId> = BTreeMap::new();
    bindings.insert(parameters_key(), req.parameters);
    bindings.insert(tokenizer_key(), req.tokenizer);
    bindings.insert(from_key(), req.from);
    bindings.insert(prompt_tokens_key(), req.prompt_tokens.value_id());
    bindings.insert(policy_key(), req.policy.value_id());
    Term::new(req.program, bindings)
}

impl Adaptor for CatgradText {
    type Request = CatgradTextRequest;
    type Output = CatgradTextReply;
    const PROTOCOL: ProtocolId = ProtocolId::OPAQUE;
}

impl ProjectCall for CatgradText {
    fn project_call(
        request: &Self::Request,
        _ctx: &ProjectionContext,
    ) -> Result<Call, ProjectionError> {
        let term = build_term(request);
        Ok(Call {
            protocol: <Self as Adaptor>::PROTOCOL,
            payload: CanonicalPayload::from_canonical_unchecked(term.canonical_bytes()),
        })
    }
}

impl ProjectResult for CatgradText {
    fn project_result(output: &Self::Output, call: &Call) -> Result<CallResult, ProjectionError> {
        // Enforce: the output records the same Term we projected as the
        // call. Without this check, a producer could emit a
        // TextRunOutput whose `term` field references an unrelated
        // run, and the projected CallResult would still hash cleanly.
        let projected_term_id = call_payload_term_id(call)?;
        if output.term != projected_term_id {
            return Err(ProjectionError::InvalidField {
                name: "term",
                reason: format!(
                    "TextRunOutput.term ({}) does not match the projected Call's TermId ({})",
                    output.term, projected_term_id,
                ),
            });
        }
        // Reject UNSPECIFIED and unknown stop reasons. Decoding keeps
        // unknown bytes for forward compatibility, but this projection
        // version only knows how to settle the three concrete reasons.
        if !output.stop_reason.is_known_concrete() {
            return Err(ProjectionError::InvalidField {
                name: "stop_reason",
                reason: "TextRunOutput.stop_reason must be a known concrete termination \
                         reason (END_OF_SEQUENCE, MAX_OUTPUT, CANCELLED)"
                    .to_string(),
            });
        }
        Ok(CallResult {
            payload: CanonicalPayload::from_canonical_unchecked(output.canonical_bytes()),
        })
    }
}

/// Compute the [`TermId`] for a CatgradText Call.
///
/// For CatgradText, `Call::payload` bytes ARE a Term's canonical
/// bytes, so the BLAKE3 of the payload IS the TermId. **This function
/// also decodes the payload as a `Term` and rejects malformed
/// payloads.** Without the decode, a malicious caller could put
/// arbitrary bytes in the payload, set `TextRunOutput.term =
/// blake3(those bytes)`, and `project_result` would accept the
/// drift; `Receipt::verify_delivery` only checks commitments, not
/// adaptor schema.
fn call_payload_term_id(call: &Call) -> Result<TermId, ProjectionError> {
    if call.protocol != CatgradText::PROTOCOL {
        return Err(ProjectionError::ProtocolMismatch {
            expected: CatgradText::PROTOCOL,
            actual: call.protocol,
        });
    }
    // Decode and re-canonicalize-check via Term::from_canonical_bytes.
    // The catnix decoder verifies the bytes round-trip exactly to the
    // canonical form (no trailing bytes, correct schema tag, sorted
    // bindings, etc.) — any malformed payload is rejected here.
    Term::from_canonical_bytes(call.payload.as_bytes()).map_err(|err| {
        ProjectionError::BadCanonicalization(format!(
            "CatgradText Call payload is not a valid catnix Term: {err}"
        ))
    })?;
    let digest = catnix::Digest::from_canonical_bytes(call.payload.as_bytes());
    Ok(TermId::from_digest(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ProjectionContext;
    use catnix::StopReason;

    fn sample_request() -> CatgradTextRequest {
        CatgradTextRequest {
            program: ValueId::from_bytes([0xaa; 32]),
            parameters: ValueId::from_bytes([0xbb; 32]),
            tokenizer: ValueId::from_bytes([0xcc; 32]),
            from: ValueId::from_bytes([0xdd; 32]),
            prompt_tokens: TokenIds::from([1, 2, 3]),
            policy: TextPolicy::from_u32_stop_tokens(16, [2]),
        }
    }

    #[test]
    fn project_call_is_pure() {
        let req = sample_request();
        let a = CatgradText::project_call(&req, &ProjectionContext::default()).unwrap();
        let b = CatgradText::project_call(&req, &ProjectionContext::default()).unwrap();
        assert_eq!(a.protocol, b.protocol);
        assert_eq!(a.payload.as_bytes(), b.payload.as_bytes());
    }

    #[test]
    fn project_call_claims_opaque_today() {
        let call =
            CatgradText::project_call(&sample_request(), &ProjectionContext::default()).unwrap();
        assert_eq!(call.protocol, ProtocolId::OPAQUE);
    }

    #[test]
    fn project_call_payload_is_a_term_canonical_bytes() {
        let req = sample_request();
        let call = CatgradText::project_call(&req, &ProjectionContext::default()).unwrap();
        let expected = build_term(&req).canonical_bytes();
        assert_eq!(call.payload.as_bytes(), expected.as_slice());
    }

    #[test]
    fn changing_any_field_changes_call_commitment() {
        let req = sample_request();
        let base = CatgradText::project_call(&req, &ProjectionContext::default())
            .unwrap()
            .commitment();

        let cases = [
            CatgradTextRequest {
                program: ValueId::from_bytes([0x01; 32]),
                ..req.clone()
            },
            CatgradTextRequest {
                parameters: ValueId::from_bytes([0x01; 32]),
                ..req.clone()
            },
            CatgradTextRequest {
                tokenizer: ValueId::from_bytes([0x01; 32]),
                ..req.clone()
            },
            CatgradTextRequest {
                from: ValueId::from_bytes([0x01; 32]),
                ..req.clone()
            },
            CatgradTextRequest {
                prompt_tokens: TokenIds::from([9, 9, 9]),
                ..req.clone()
            },
            CatgradTextRequest {
                policy: TextPolicy::from_u32_stop_tokens(99, [42]),
                ..req.clone()
            },
        ];

        for variant in cases {
            let other = CatgradText::project_call(&variant, &ProjectionContext::default())
                .unwrap()
                .commitment();
            assert_ne!(base, other, "varying a field should change the commitment");
        }
    }

    #[test]
    fn project_result_accepts_matching_term() {
        let req = sample_request();
        let call = CatgradText::project_call(&req, &ProjectionContext::default()).unwrap();
        let term_id = call_payload_term_id(&call).unwrap();
        let out = TextRunOutput::new(
            term_id,
            5,
            ValueId::from_bytes([0x55; 32]),
            ValueId::from_bytes([0x66; 32]),
            StopReason::END_OF_SEQUENCE,
        );
        let result = CatgradText::project_result(&out, &call).unwrap();
        // CallResult::payload IS the TextRunOutput canonical bytes.
        assert_eq!(result.payload.as_bytes(), out.canonical_bytes().as_slice());
    }

    #[test]
    fn project_result_rejects_mismatched_term() {
        let req = sample_request();
        let call = CatgradText::project_call(&req, &ProjectionContext::default()).unwrap();
        // Use a TermId that does NOT match the projected call.
        let wrong_term = TermId::from_bytes([0xff; 32]);
        let out = TextRunOutput::new(
            wrong_term,
            5,
            ValueId::from_bytes([0x55; 32]),
            ValueId::from_bytes([0x66; 32]),
            StopReason::END_OF_SEQUENCE,
        );
        let err = CatgradText::project_result(&out, &call).unwrap_err();
        assert!(matches!(
            err,
            ProjectionError::InvalidField { name: "term", .. }
        ));
    }

    #[test]
    fn project_result_rejects_wrong_protocol_call() {
        // Construct a Call with the WRONG protocol byte but with our
        // payload bytes. project_result should refuse to bind a
        // TextRunOutput to it.
        let req = sample_request();
        let mut call = CatgradText::project_call(&req, &ProjectionContext::default()).unwrap();
        call.protocol = ProtocolId::SYMBOLIC;
        let out = TextRunOutput::new(
            TermId::from_bytes([0; 32]),
            0,
            ValueId::from_bytes([0; 32]),
            ValueId::from_bytes([0; 32]),
            StopReason::END_OF_SEQUENCE,
        );
        let err = CatgradText::project_result(&out, &call).unwrap_err();
        assert!(matches!(
            err,
            ProjectionError::ProtocolMismatch {
                expected: ProtocolId::OPAQUE,
                ..
            }
        ));
    }

    #[test]
    fn canonical_vector_pinned() {
        // Locks the exact canonical-bytes digest of the projected Call
        // for a known input (`sample_request`). If this fails, either:
        //   - the CatgradText projection's binding-key conventions
        //     changed (wire-format change — bump adaptor version, then
        //     rev EXPECTED_HEX),
        //   - the catnix Term canonical encoding changed (wire-format
        //     change in catnix — bump there + rev EXPECTED_HEX), or
        //   - sample_request's inputs changed (rev the test).
        let req = sample_request();
        let call = CatgradText::project_call(&req, &ProjectionContext::default()).unwrap();
        let digest = catnix::Digest::from_canonical_bytes(call.payload.as_bytes());
        let actual_hex = format!("{digest}");
        // Pinned vector. Update only with an intentional wire-format bump.
        const EXPECTED_HEX: &str =
            "e71911184573eb72dc7e30ee96c435a92af799a14804ed3bd55c42bdf748b51c";
        assert_eq!(
            actual_hex, EXPECTED_HEX,
            "CatgradText canonical wire format drifted"
        );
    }

    #[test]
    fn project_result_rejects_non_concrete_stop_reason() {
        // A producer signing a TextRunOutput with UNSPECIFIED or an
        // unknown stop reason is hiding what happened (completed /
        // max-tokens / cancelled). project_result rejects both as a
        // settlement footgun.
        let req = sample_request();
        let call = CatgradText::project_call(&req, &ProjectionContext::default()).unwrap();
        let term_id = call_payload_term_id(&call).unwrap();
        for stop_reason in [StopReason::UNSPECIFIED, StopReason::unknown(255)] {
            let out = TextRunOutput::new(
                term_id,
                5,
                ValueId::from_bytes([0x55; 32]),
                ValueId::from_bytes([0x66; 32]),
                stop_reason,
            );
            let err = CatgradText::project_result(&out, &call).unwrap_err();
            assert!(matches!(
                err,
                ProjectionError::InvalidField {
                    name: "stop_reason",
                    ..
                }
            ));
        }
    }

    #[test]
    fn call_payload_term_id_rejects_garbage_payload() {
        // A malicious caller could put non-Term bytes in the payload
        // and set TextRunOutput.term = blake3(those bytes). Without a
        // decode check, call_payload_term_id would happily return that
        // blake3 as a TermId, and project_result's `output.term ==
        // projected_term_id` check would pass. The decode check rejects
        // the malformed payload before we get there.
        let call = Call {
            protocol: ProtocolId::OPAQUE,
            payload: CanonicalPayload::from_canonical_unchecked(b"not a catnix Term".to_vec()),
        };
        let out = TextRunOutput::new(
            TermId::from_digest(catnix::Digest::from_canonical_bytes(b"not a catnix Term")),
            0,
            ValueId::from_bytes([0; 32]),
            ValueId::from_bytes([0; 32]),
            StopReason::END_OF_SEQUENCE,
        );
        let err = CatgradText::project_result(&out, &call).unwrap_err();
        assert!(matches!(err, ProjectionError::BadCanonicalization(_)));
    }

    /// End-to-end pin of the CatgradText settlement preimage.
    ///
    /// Runs the full pipeline — `sample_request` →
    /// `CatgradText::project_call` → build a deterministic
    /// `TextRunOutput` → `CatgradText::project_result` →
    /// `Claim::for_delivery` → `signature_preimage` — and locks the
    /// resulting digest. This catches drift in *any* of the layers
    /// between the wire request and the signed claim preimage, without
    /// depending on the k256 ECDSA signature (which is intentionally
    /// non-deterministic per RFC 6979's interaction with our entropy
    /// source).
    ///
    /// If this fails, one of:
    ///   - CatgradText `project_call` shape changed (wire-format change),
    ///   - CatgradText `project_result` shape changed,
    ///   - catnix `Term` / `TextRunOutput` canonical encoding changed,
    ///   - the `Claim` preimage tag/encoding changed,
    ///   - the `ProducerId` derivation changed,
    ///   - `sample_request` constants changed.
    ///
    /// All entries except `sample_request` are canonical wire changes; update
    /// the adaptor version and EXPECTED_HEX when they change.
    #[test]
    fn end_to_end_claim_preimage_pinned() {
        use crate::ProducerSigningKey;
        use crate::protocol::{Claim, EvidenceBinding};

        let req = sample_request();
        let call = CatgradText::project_call(&req, &ProjectionContext::default()).unwrap();
        let term_id = call_payload_term_id(&call).unwrap();
        // Deterministic output shape: position 7 generated tokens, with
        // a fixed state ValueId and a TokenIds payload of [42, 43, 44].
        let output_tokens = TokenIds::from([42_u32, 43, 44]);
        let state = ValueId::from_bytes([0x77; 32]);
        let run = TextRunOutput::new(
            term_id,
            (req.prompt_tokens.len() as u64) + (output_tokens.len() as u64),
            state,
            output_tokens.value_id(),
            StopReason::END_OF_SEQUENCE,
        );
        let result = CatgradText::project_result(&run, &call).unwrap();

        let key = ProducerSigningKey::deterministic_for_tests();
        let producer = crate::ProducerId::from_public_key(&key.public_key());
        let claim = Claim::for_delivery(&call, &result, producer, EvidenceBinding::None);
        let preimage = format!("{}", claim.signature_preimage());
        const EXPECTED_HEX: &str =
            "93198227b244615efef51fcc7055a66c6a448dba896b8249189a9f3ef1c8de9f";
        assert_eq!(preimage, EXPECTED_HEX, "CatgradText claim preimage drifted");
    }
}
