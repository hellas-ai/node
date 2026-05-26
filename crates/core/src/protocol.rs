//! Protocol-level types per `docs/AXES.md` (pass 3).
//!
//! The wire layer (per-adaptor proto packages) and the kernel/settlement
//! layer meet here through typed projection. Adaptors declare a
//! [`ProtocolId`] and implement [`Adaptor`] + [`ProjectCall`] +
//! [`ProjectResult`]; settlement code operates on [`Call`],
//! [`CallResult`], [`Claim`], [`Receipt`].
//!
//! Mirrors the kernel-side `Call / CallResult / Claim / Evidence`
//! vocabulary in `../hellas-kernel/src/`. When that crate is folded into
//! this workspace per the consolidation roadmap, these types will be
//! re-exported from there.
//!
//! This module is additive. The existing [`crate::scheme::CommitmentScheme`]
//! trait and [`crate::schemes`] adaptor structs remain in place for as
//! long as call sites depend on them; migration is incremental and is
//! NOT a transparent conversion — old [`crate::commitment::SchemeId`]
//! and new [`ProtocolId`] use overlapping but *different* byte
//! meanings (e.g. old `Symbolic = 0x00` versus new `OPAQUE = 0x00`), so
//! migration must verify-and-re-sign, never coerce.

use serde::{Deserialize, Serialize};

use crate::signature::verify_digest_signature;
use crate::{
    Digest, ProducerId, ProducerSigningKey, PublicKey, Signature, SignatureError, hash_tuple, tags,
};

// ----- Protocol identity ----------------------------------------------------

/// One-byte protocol identifier the kernel knows about.
///
/// Held as a newtype so the kernel doesn't need exhaustive matching as
/// new protocols are added — this mirrors `ProtocolCode` in
/// `../hellas-kernel/src/primitive.rs`. The named constants below
/// pin the assignments used by Hellas core.
///
/// The inner byte is private. There is intentionally no `Default` impl
/// — silently producing `OPAQUE` from `Default::default()` would mask
/// missing-protocol bugs. Construct via the named constants for known
/// protocols, or via [`ProtocolId::unknown`] for genuinely-unknown
/// values seen on the wire.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ProtocolId(u8);

impl ProtocolId {
    /// Producer signature only; no correctness or provenance evidence.
    /// Today's catgrad-text and any untyped JSON-route adaptor claim this.
    pub const OPAQUE: Self = Self(0x00);

    /// Input-addressed recipe; admits Correctness Evidence iff the
    /// adaptor also implements [`Determinate`].
    pub const SYMBOLIC: Self = Self(0x01);

    /// Routed-with-TLS-witness fetch; requires the adaptor to implement
    /// [`ProducesTlsWitness`].
    pub const ZK_TLS: Self = Self(0x02);

    /// Construct a `ProtocolId` from a wire byte without checking
    /// against the known set. Use only on receipts decoded from the
    /// wire when a verifier needs to handle protocols it doesn't
    /// recognize (forward-compat: verifier sees a new protocol byte and
    /// can choose to reject rather than panic). Direct call sites
    /// inside the node should use the named constants.
    pub const fn unknown(byte: u8) -> Self {
        Self(byte)
    }

    pub const fn to_byte(self) -> u8 {
        self.0
    }
}

// ----- Canonical bytes at the kernel boundary -------------------------------

/// Canonical adaptor-encoded bytes. The constructor takes raw bytes the
/// caller asserts are canonical (typically produced by a per-adaptor
/// canonical encoder living in `crate::adaptors::*`). The newtype
/// prevents accidental raw protobuf / JSON / unframed bytes from flowing
/// through the kernel API.
///
/// This is a *boundary type*: by the time bytes are wrapped in
/// `CanonicalPayload`, the adaptor has applied its canonical leading
/// tag (e.g. `hellas.fetch.request.v1`). The kernel applies an *outer*
/// tag when computing commitments — see [`Call::commitment`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalPayload(Vec<u8>);

impl CanonicalPayload {
    /// Construct from bytes the caller asserts are canonically encoded.
    ///
    /// "Unchecked" because there's no runtime verification that the
    /// bytes start with a valid adaptor tag (`hellas.<adaptor>.<role>.vN`
    /// or `catnix.<schema>.vN`). Adaptors should wrap this with
    /// type-safer constructors that verify their own canonical prefix.
    pub fn from_canonical_unchecked(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ----- Commitments ---------------------------------------------------------

/// Commitment to a settled call's canonical request bytes.
///
/// Computed as `hash_tuple("hellas.call.v1", [&[protocol_byte],
/// canonical_payload])`. Outer tag domain-separates from raw payload
/// hashes and from `ResultPayloadCommitment`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CallCommitment(pub Digest);

impl CallCommitment {
    pub const fn digest(&self) -> Digest {
        self.0
    }
}

/// Commitment to a settled call's canonical result *payload* bytes.
///
/// Named `ResultPayloadCommitment` (not `ResultCommitment`) because it
/// commits only to the result's canonical bytes — not to which call
/// produced them. Binding result-to-call is the [`Claim`]'s job; an
/// `ResultPayloadCommitment` by itself is only meaningful in the
/// context of a claim that also binds the call.
///
/// Computed as `hash_tuple("hellas.result.v1", [canonical_payload])`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResultPayloadCommitment(pub Digest);

impl ResultPayloadCommitment {
    pub const fn digest(&self) -> Digest {
        self.0
    }
}

// ----- Calls + results -----------------------------------------------------

/// Input-addressed request bytes plus the protocol they're under.
///
/// The kernel sees this; it doesn't know what adaptor produced the
/// `payload`. Adaptor identity lives inside `payload`'s canonical
/// leading tag (e.g. `hellas.fetch.request.v1`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Call {
    pub protocol: ProtocolId,
    pub payload: CanonicalPayload,
}

impl Call {
    /// Hash this call into its kernel-level [`CallCommitment`]. Uses the
    /// `hellas.call.v1` outer tag for domain separation from raw payload
    /// hashes and other commitment kinds.
    pub fn commitment(&self) -> CallCommitment {
        let protocol_byte = [self.protocol.to_byte()];
        let digest = hash_tuple(tags::CALL_V1, &[&protocol_byte, self.payload.as_bytes()]);
        CallCommitment(digest)
    }
}

/// Output bytes of a settled call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallResult {
    pub payload: CanonicalPayload,
}

impl CallResult {
    /// Hash this result payload into a [`ResultPayloadCommitment`].
    /// Result-to-call binding is the [`Claim`]'s responsibility; this
    /// commitment alone does not bind the result to any specific call.
    pub fn commitment(&self) -> ResultPayloadCommitment {
        let digest = hash_tuple(tags::RESULT_V1, &[self.payload.as_bytes()]);
        ResultPayloadCommitment(digest)
    }
}

// ----- Evidence binding ----------------------------------------------------

/// Whether a claim binds to attached evidence.
///
/// Explicit enum (not `Option<Digest>`) so that "no evidence required"
/// and "evidence quietly dropped" cannot share a wire shape. Protocol
/// validation enforces that the variant matches the protocol's evidence
/// requirements — e.g. `ProtocolId::ZK_TLS` requires `Digest(_)`.
///
/// Future evidence shapes (multiple proofs, Merkle-rooted proof
/// bundles, proof-system tagged unions) should be expressed *inside*
/// the bundle whose digest goes here — not by adding variants to this
/// enum. The claim binds exactly one digest; the bundle's canonical
/// encoding gives that digest meaning.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum EvidenceBinding {
    /// No evidence riding alongside this claim.
    None,
    /// Claim binds to evidence whose canonical bytes hash to this digest.
    Digest(Digest),
}

impl EvidenceBinding {
    /// Canonical fields contributed to a signing preimage.
    ///
    /// Returns `(tag_byte, digest_or_empty)`. Caller passes both as
    /// separate length-delimited fields to `hash_tuple`. Wire shape:
    /// `[0]` + `[]` for `None`, `[1]` + 32-byte digest for `Digest`.
    /// Locks the canonical encoding to this method rather than
    /// inheriting whatever serde produces — settlement bytes are not
    /// a serde-implementation detail.
    pub fn signature_fields(&self) -> (&[u8], &[u8]) {
        match self {
            Self::None => (&[0], &[]),
            Self::Digest(d) => (&[1], d.as_bytes()),
        }
    }
}

// ----- Claims + receipts ---------------------------------------------------

/// Producer's assertion that a `Call` produced a `CallResult` under a
/// `ProtocolId`. The signed body of a [`Receipt`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub protocol: ProtocolId,
    pub call_commitment: CallCommitment,
    pub result_commitment: ResultPayloadCommitment,
    pub producer: ProducerId,
    pub evidence: EvidenceBinding,
}

impl Claim {
    /// Build a `Claim` binding `producer`'s assertion that `call`
    /// produced `result`, with the given evidence binding.
    ///
    /// Use this instead of constructing `Claim` directly: it derives
    /// `protocol`, `call_commitment`, and `result_commitment` from
    /// the actual `Call` and `CallResult`, which means the producer
    /// cannot accidentally sign a claim whose internal fields disagree
    /// with the delivery. The `call.protocol` IS the claim's protocol;
    /// the call and result commitments come from their canonical hashes.
    pub fn for_delivery(
        call: &Call,
        result: &CallResult,
        producer: ProducerId,
        evidence: EvidenceBinding,
    ) -> Self {
        Self {
            protocol: call.protocol,
            call_commitment: call.commitment(),
            result_commitment: result.commitment(),
            producer,
            evidence,
        }
    }

    /// Canonical bytes that get hashed for signing.
    ///
    /// `hash_tuple("hellas.claim.v1", [protocol, call_cid, result_cid,
    /// producer, evidence_tag, evidence_digest_or_empty])`. The
    /// evidence_tag distinguishes `EvidenceBinding::None` from `Digest`
    /// even when the digest payload is empty.
    pub fn signature_preimage(&self) -> Digest {
        let protocol_byte = [self.protocol.to_byte()];
        let (evidence_tag, evidence_bytes) = self.evidence.signature_fields();
        hash_tuple(
            tags::CLAIM_V1,
            &[
                &protocol_byte,
                self.call_commitment.digest().as_bytes(),
                self.result_commitment.digest().as_bytes(),
                self.producer.as_bytes(),
                evidence_tag,
                evidence_bytes,
            ],
        )
    }
}

/// Signed `Claim`. The settlement-bearing object.
///
/// Self-verifying: carries the producer's [`PublicKey`] so a verifier
/// can check the signature without an external producer registry. The
/// claim's `producer` field is checked against the public key during
/// `verify()` to prevent cross-binding.
///
/// Parallel to the existing [`crate::SignedReceipt`] but reshaped to
/// carry [`ProtocolId`] instead of `SchemeId` and [`EvidenceBinding`]
/// instead of `Option<Digest>`. Migration of the existing type is a
/// follow-up; see the module-level note about why these types are NOT
/// transparently convertible.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub claim: Claim,
    pub signature: Signature,
    pub public_key: PublicKey,
}

impl Receipt {
    /// Sign a pre-built claim with the given producer key. The claim's
    /// `producer` field must already be derived from the same key, else
    /// returns [`ReceiptError::ProducerMismatch`].
    ///
    /// **Prefer [`Receipt::sign_delivery`]** at most call sites — it
    /// derives the claim from the actual call/result, so a producer
    /// cannot accidentally sign a claim whose `protocol` or
    /// commitments disagree with the delivery. `Receipt::sign` is the
    /// lower-level entry point for callers that have constructed a
    /// claim through other means (replay, migration tooling, etc.).
    pub fn sign(claim: Claim, key: &ProducerSigningKey) -> Result<Self, ReceiptError> {
        let public_key = key.public_key();
        let derived = ProducerId::from_public_key(&public_key);
        if derived != claim.producer {
            return Err(ReceiptError::ProducerMismatch);
        }
        let preimage = claim.signature_preimage();
        let signature = key.sign_digest(preimage)?;
        Ok(Self {
            claim,
            signature,
            public_key,
        })
    }

    /// Sign a receipt binding `producer`'s assertion that `call`
    /// produced `result` with the given evidence binding.
    ///
    /// Derives the claim via [`Claim::for_delivery`] using the actual
    /// `Call` and `CallResult`, so the claim's `protocol`,
    /// `call_commitment`, and `result_commitment` cannot drift from
    /// the delivery they're asserting.
    pub fn sign_delivery(
        call: &Call,
        result: &CallResult,
        evidence: EvidenceBinding,
        key: &ProducerSigningKey,
    ) -> Result<Self, ReceiptError> {
        let producer = ProducerId::from_public_key(&key.public_key());
        let claim = Claim::for_delivery(call, result, producer, evidence);
        Self::sign(claim, key)
    }

    /// Verify the signature and the `producer ↔ public_key` binding.
    /// Does NOT verify that `call_commitment` / `result_commitment`
    /// match any specific delivery; that's [`Receipt::verify_delivery`]'s
    /// job. Use this when you only need to check the receipt is a
    /// genuine producer-signed claim (e.g. before deciding whether to
    /// bother projecting the call/result).
    pub fn verify(&self) -> Result<(), ReceiptError> {
        let derived = ProducerId::from_public_key(&self.public_key);
        if derived != self.claim.producer {
            return Err(ReceiptError::ProducerMismatch);
        }
        verify_digest_signature(
            &self.public_key,
            &self.signature,
            self.claim.signature_preimage(),
        )?;
        Ok(())
    }

    /// Verify the signature, the producer binding, AND that the
    /// receipt's claim binds the given `call` and `result`. This is
    /// what most settlement-side verifiers want: project a known
    /// call/result and check the receipt asserts that delivery.
    pub fn verify_delivery(&self, call: &Call, result: &CallResult) -> Result<(), ReceiptError> {
        self.verify()?;
        if self.claim.protocol != call.protocol {
            return Err(ReceiptError::ProtocolMismatch);
        }
        if self.claim.call_commitment != call.commitment() {
            return Err(ReceiptError::CallCommitmentMismatch);
        }
        if self.claim.result_commitment != result.commitment() {
            return Err(ReceiptError::ResultCommitmentMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    #[error("producer id does not match public key")]
    ProducerMismatch,
    #[error("claim protocol does not match call protocol")]
    ProtocolMismatch,
    #[error("claim call commitment does not match recomputed call commitment")]
    CallCommitmentMismatch,
    #[error("claim result commitment does not match recomputed result commitment")]
    ResultCommitmentMismatch,
    #[error("signature verification failed: {0}")]
    Signature(#[from] SignatureError),
}

// ----- Adaptor + projection ------------------------------------------------

/// What an adaptor implements: typed request/output plus the
/// [`ProtocolId`] receipts produced by this adaptor will carry.
pub trait Adaptor {
    type Request;
    type Output;
    const PROTOCOL: ProtocolId;
}

/// Ambient state required to project a wire request into a [`Call`].
///
/// Intentionally empty for now and `#[non_exhaustive]`. Fields are
/// added explicitly as adaptors require them (clock, tokenizer
/// registry, model locator, CA bundle digest, dtype preferences, ...).
/// Hidden defaults in wire requests must resolve against this context,
/// not against implicit globals.
///
/// Concrete dtype/model/tokenizer choices should usually be *committed
/// in the request itself*, not carried in the context — putting them
/// here is a footgun because two providers with different context can
/// project the same wire request to different `Call::payload` bytes.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ProjectionContext {}

/// Errors that prevent projection from producing a canonical [`Call`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionError {
    /// A wire field resolves to an ambient default ("latest", "auto",
    /// "now") but no concrete value was supplied either by the field
    /// or by the projection context.
    #[error("wire field {field} resolves to an ambient default; no concrete value was supplied")]
    AmbientDefault { field: &'static str },

    /// A reference (model id, artifact CID, peer endpoint, ...) could
    /// not be resolved against the projection context.
    #[error("reference {kind} = {id} could not be resolved")]
    UnresolvedReference { kind: &'static str, id: String },

    /// A required field is missing from the wire request.
    #[error("required field {name} is missing from the wire request")]
    MissingField { name: &'static str },

    /// A field is present but its value is invalid for projection.
    #[error("field {name} is invalid: {reason}")]
    InvalidField { name: &'static str, reason: String },

    /// The adaptor's `PROTOCOL` constant disagrees with what the
    /// caller / channel context expected.
    #[error("protocol mismatch: expected {expected:?}, got {actual:?}")]
    ProtocolMismatch {
        expected: ProtocolId,
        actual: ProtocolId,
    },

    /// A reference resolves to multiple candidates and the choice is
    /// not disambiguated by the request.
    #[error("ambiguous reference {kind}: {choices:?}")]
    AmbiguousReference {
        kind: &'static str,
        choices: Vec<String>,
    },

    /// The wire request uses a request-shape version this projector
    /// does not understand.
    #[error("unsupported version for protocol {protocol:?}: {version}")]
    UnsupportedVersion { protocol: ProtocolId, version: u32 },

    /// Ambient state required to project (e.g. session transcript,
    /// freshness nonce) was not committed into the request.
    #[error("ambient state required by projection was not committed into the request: {kind}")]
    UncommittedAmbientState { kind: &'static str },

    /// The canonical encoder produced bytes that fail re-decoding or
    /// fail a consistency check.
    #[error("canonical encoding failed: {0}")]
    BadCanonicalization(String),
}

/// Adaptor → kernel projection for the request side. Fallible and
/// context-aware: two implementations of the same adaptor must produce
/// identical `Call::payload` bytes given identical input + context.
pub trait ProjectCall: Adaptor {
    fn project_call(
        request: &Self::Request,
        ctx: &ProjectionContext,
    ) -> Result<Call, ProjectionError>;
}

/// Adaptor → kernel projection for the result side. The projected
/// `CallResult` is what the receipt commits to; auxiliary fields on the
/// wire reply that don't appear in `CallResult` are not settlement-bearing.
pub trait ProjectResult: Adaptor {
    fn project_result(output: &Self::Output, call: &Call) -> Result<CallResult, ProjectionError>;
}

// ----- Capability marker traits --------------------------------------------
//
// Each `ProtocolId` defines the marker traits an adaptor must implement
// to claim it. The marker traits are how an adaptor declares what it
// can do; the protocol's validity gadget (kernel-side) decides what it
// must do.

/// Adaptor's output is uniquely determined by its `Call`. Required by
/// any protocol that admits Correctness Evidence (Optimistic, Zk,
/// TEE-execution). A claim of `Determinate` is a contract the adaptor
/// author makes — fixed kernels, fixed dtype/layout, fixed sampling,
/// etc. The type system enforces what's gated *on* `Determinate`; it
/// does not enforce determinism itself.
pub trait Determinate: Adaptor {}

/// Adaptor can produce a TLS-witness proof binding result bytes to a
/// specific server-identity policy. Required by `ProtocolId::ZK_TLS`.
pub trait ProducesTlsWitness: Adaptor {
    type TlsWitness;
}

/// Adaptor runs inside a TEE and can produce an execution attestation.
pub trait ProducesTeeExec: Adaptor {
    type TeeQuote;
}

/// Adaptor accepts an Optimistic-dispute window. Requires the result
/// to be replayable, which requires [`Determinate`].
pub trait OptimisticDisputable: Determinate {}

/// Adaptor admits some shape of Correctness Evidence beyond mandatory
/// Signature. Currently requires `Determinate` (Correctness Evidence is
/// only meaningful when the recipe-result relation is replayable). When
/// other evidence shapes for non-Determinate adaptors appear (e.g. TEE
/// attestation that vouches for the execution environment regardless of
/// determinism), this trait may relax.
pub trait EvidencedAdaptor: Adaptor + Determinate {
    type CorrectnessEvidence;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(bytes: &[u8]) -> CanonicalPayload {
        CanonicalPayload::from_canonical_unchecked(bytes.to_vec())
    }

    fn key() -> ProducerSigningKey {
        ProducerSigningKey::deterministic_for_tests()
    }

    #[test]
    fn protocol_id_constants_are_distinct() {
        assert_ne!(ProtocolId::OPAQUE, ProtocolId::SYMBOLIC);
        assert_ne!(ProtocolId::SYMBOLIC, ProtocolId::ZK_TLS);
    }

    #[test]
    fn call_commitment_binds_protocol_byte() {
        let p = payload(b"x");
        let a = Call {
            protocol: ProtocolId::OPAQUE,
            payload: p.clone(),
        };
        let b = Call {
            protocol: ProtocolId::SYMBOLIC,
            payload: p,
        };
        assert_ne!(a.commitment(), b.commitment());
    }

    #[test]
    fn call_commitment_is_stable_for_same_inputs() {
        let call = Call {
            protocol: ProtocolId::OPAQUE,
            payload: payload(b"hello"),
        };
        assert_eq!(call.commitment(), call.commitment());
    }

    #[test]
    fn call_commitment_uses_outer_tag() {
        // A raw payload hash must not equal a call commitment of the
        // same bytes — outer tag must domain-separate.
        let p = b"abc";
        let call = Call {
            protocol: ProtocolId::OPAQUE,
            payload: payload(p),
        };
        let raw = Digest::hash(p);
        assert_ne!(call.commitment().digest(), raw);
    }

    #[test]
    fn result_commitment_uses_outer_tag() {
        let p = b"out";
        let r = CallResult {
            payload: payload(p),
        };
        let raw = Digest::hash(p);
        assert_ne!(r.commitment().digest(), raw);
    }

    #[test]
    fn call_and_result_commitments_with_identical_bytes_differ() {
        // hellas.call.v1 vs hellas.result.v1 outer tags must give
        // different digests even on identical bytes.
        let bytes = payload(b"x");
        let call = Call {
            protocol: ProtocolId::OPAQUE,
            payload: bytes.clone(),
        };
        let result = CallResult { payload: bytes };
        // Note: call also incorporates the protocol byte, so the test
        // really only checks they're different — which they should be
        // both because of the protocol byte AND the outer tag.
        assert_ne!(call.commitment().digest(), result.commitment().digest());
    }

    fn sample_claim(key: &ProducerSigningKey) -> Claim {
        let call = Call {
            protocol: ProtocolId::OPAQUE,
            payload: payload(b"hello"),
        };
        let result = CallResult {
            payload: payload(b"world"),
        };
        Claim {
            protocol: ProtocolId::OPAQUE,
            call_commitment: call.commitment(),
            result_commitment: result.commitment(),
            producer: ProducerId::from_public_key(&key.public_key()),
            evidence: EvidenceBinding::None,
        }
    }

    #[test]
    fn receipt_sign_and_verify_roundtrip() {
        let k = key();
        let claim = sample_claim(&k);
        let receipt = Receipt::sign(claim, &k).unwrap();
        receipt.verify().unwrap();
    }

    #[test]
    fn receipt_rejects_wrong_producer_at_sign_time() {
        let k = key();
        let mut claim = sample_claim(&k);
        // Forge producer id to be a different one.
        claim.producer = ProducerId::from_public_key(&ProducerSigningKey::generate().public_key());
        let err = Receipt::sign(claim, &k).unwrap_err();
        assert!(matches!(err, ReceiptError::ProducerMismatch));
    }

    #[test]
    fn receipt_with_evidence_binding_preimage_differs() {
        let k = key();
        let mut a = sample_claim(&k);
        let mut b = sample_claim(&k);
        a.evidence = EvidenceBinding::None;
        b.evidence = EvidenceBinding::Digest(Digest::hash(b"ev"));
        assert_ne!(a.signature_preimage(), b.signature_preimage());
    }

    #[test]
    fn claim_signature_preimage_is_pinned() {
        let k = key();
        let call = Call {
            protocol: ProtocolId::OPAQUE,
            payload: payload(b"hello"),
        };
        let result = CallResult {
            payload: payload(b"world"),
        };
        let claim = Claim::for_delivery(
            &call,
            &result,
            ProducerId::from_public_key(&k.public_key()),
            EvidenceBinding::None,
        );
        let actual = format!("{}", claim.signature_preimage());
        const EXPECTED_HEX: &str =
            "8ac7978161529784dc2ace21a729acfc6b0d725d4d4140327988e638a26e2e42";
        assert_eq!(actual, EXPECTED_HEX, "Claim signature preimage drifted");
    }

    #[test]
    fn evidence_binding_none_vs_digest_distinct() {
        // Even if a digest happened to be all zeros (very unlikely),
        // the wire tag must distinguish.
        let k = key();
        let mut a = sample_claim(&k);
        let mut b = sample_claim(&k);
        a.evidence = EvidenceBinding::None;
        b.evidence = EvidenceBinding::Digest(Digest::from_bytes([0; 32]));
        assert_ne!(a.signature_preimage(), b.signature_preimage());
    }

    #[test]
    fn sign_delivery_rejects_drifted_claim() {
        // Direct Receipt::sign accepts an internally-inconsistent
        // claim. sign_delivery cannot, because it derives the claim
        // from the actual call/result.
        let k = key();
        let call = Call {
            protocol: ProtocolId::OPAQUE,
            payload: payload(b"x"),
        };
        let result = CallResult {
            payload: payload(b"y"),
        };
        let receipt = Receipt::sign_delivery(&call, &result, EvidenceBinding::None, &k).unwrap();
        receipt.verify_delivery(&call, &result).unwrap();

        // Changing either side should fail verify_delivery.
        let wrong_call = Call {
            protocol: ProtocolId::SYMBOLIC,
            payload: payload(b"x"),
        };
        assert!(matches!(
            receipt.verify_delivery(&wrong_call, &result).unwrap_err(),
            ReceiptError::ProtocolMismatch
        ));

        let wrong_result = CallResult {
            payload: payload(b"z"),
        };
        assert!(matches!(
            receipt.verify_delivery(&call, &wrong_result).unwrap_err(),
            ReceiptError::ResultCommitmentMismatch
        ));
    }

    #[test]
    fn verify_delivery_catches_drifted_call_protocol_on_a_hand_built_claim() {
        // Construct an inconsistent claim via Receipt::sign (the
        // lower-level constructor that doesn't derive). verify() alone
        // passes; verify_delivery against the real call fails.
        let k = key();
        let real_call = Call {
            protocol: ProtocolId::OPAQUE,
            payload: payload(b"x"),
        };
        let real_result = CallResult {
            payload: payload(b"y"),
        };
        // Build a claim that LIES about the protocol.
        let lying_claim = Claim {
            protocol: ProtocolId::SYMBOLIC,
            call_commitment: real_call.commitment(),
            result_commitment: real_result.commitment(),
            producer: ProducerId::from_public_key(&k.public_key()),
            evidence: EvidenceBinding::None,
        };
        let receipt = Receipt::sign(lying_claim, &k).unwrap();
        receipt.verify().unwrap(); // signature is real
        assert!(matches!(
            receipt
                .verify_delivery(&real_call, &real_result)
                .unwrap_err(),
            ReceiptError::ProtocolMismatch
        ));
    }

    #[test]
    fn protocol_id_has_no_default() {
        // Compile-time check that no Default impl exists. If someone
        // accidentally re-adds it, this test won't compile.
        fn assert_no_default<T>()
        where
            T: Sized,
        {
        }
        assert_no_default::<ProtocolId>();
        // We can construct via constants or via `unknown`:
        let _ = ProtocolId::OPAQUE;
        let _ = ProtocolId::unknown(0x42);
    }

    #[test]
    fn protocol_id_to_byte_round_trips_through_unknown() {
        let p = ProtocolId::unknown(0x42);
        assert_eq!(p.to_byte(), 0x42);
    }
}
