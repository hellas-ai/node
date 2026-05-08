use serde::{Deserialize, Serialize};

use crate::signature::verify_digest_signature;
use crate::{
    Commitment, CommitmentScheme, DagCborEncoder, EvidenceCommitment, EvidencedScheme, JsonBytes,
    Opaque, OpaqueRequest, ProducerId, ProducerSigningKey, PublicKey, ReceiptCommitment, SchemeId,
    Signature, SignatureError, Symbolic, SymbolicEvidence, SymbolicOutput, SymbolicRequest,
    hash_tuple, tags,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RequestCommitment(pub Commitment);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ResultCommitment(pub Commitment);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptBody {
    scheme: SchemeId,
    request: RequestCommitment,
    result: ResultCommitment,
    producer: ProducerId,
}

impl ReceiptBody {
    pub fn new(
        scheme: SchemeId,
        request: RequestCommitment,
        result: ResultCommitment,
        producer: ProducerId,
    ) -> Self {
        Self {
            scheme,
            request,
            result,
            producer,
        }
    }

    pub const fn scheme(&self) -> SchemeId {
        self.scheme
    }

    pub const fn request(&self) -> RequestCommitment {
        self.request
    }

    pub const fn result(&self) -> ResultCommitment {
        self.result
    }

    pub const fn producer(&self) -> ProducerId {
        self.producer
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        let mut encoder = DagCborEncoder::new();
        encoder.array(5);
        encoder.str(tags::RECEIPT_BODY_V1);
        encoder.u64(self.scheme.to_byte() as u64);
        encoder.bytes(self.request.0.as_bytes());
        encoder.bytes(self.result.0.as_bytes());
        encoder.bytes(self.producer.as_bytes());
        Ok(encoder.into_bytes())
    }

    pub fn receipt_commitment(&self) -> Result<ReceiptCommitment, VerifyError> {
        Ok(ReceiptCommitment(Commitment::from_canonical_bytes(
            &self.canonical_bytes()?,
        )))
    }

    pub fn signature_preimage(&self) -> Result<crate::Digest, VerifyError> {
        Ok(hash_tuple(
            tags::RECEIPT_SIGNATURE_V1,
            &[&self.canonical_bytes()?],
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencedReceiptBody {
    base: ReceiptBody,
    evidence_commitment: EvidenceCommitment,
}

impl EvidencedReceiptBody {
    pub fn new(base: ReceiptBody, evidence_commitment: EvidenceCommitment) -> Self {
        Self {
            base,
            evidence_commitment,
        }
    }

    pub const fn base(&self) -> &ReceiptBody {
        &self.base
    }

    pub const fn evidence_commitment(&self) -> EvidenceCommitment {
        self.evidence_commitment
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        let mut encoder = DagCborEncoder::new();
        encoder.array(6);
        encoder.str(tags::EVIDENCED_RECEIPT_BODY_V1);
        encoder.u64(self.base.scheme.to_byte() as u64);
        encoder.bytes(self.base.request.0.as_bytes());
        encoder.bytes(self.base.result.0.as_bytes());
        encoder.bytes(self.base.producer.as_bytes());
        encoder.bytes(self.evidence_commitment.0.as_bytes());
        Ok(encoder.into_bytes())
    }

    pub fn receipt_commitment(&self) -> Result<ReceiptCommitment, VerifyError> {
        Ok(ReceiptCommitment(Commitment::from_canonical_bytes(
            &self.canonical_bytes()?,
        )))
    }

    pub fn signature_preimage(&self) -> Result<crate::Digest, VerifyError> {
        Ok(hash_tuple(
            tags::RECEIPT_SIGNATURE_V1,
            &[&self.canonical_bytes()?],
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReceipt<B> {
    body: B,
    signature: Signature,
    public_key: PublicKey,
}

impl SignedReceipt<ReceiptBody> {
    pub fn sign<S>(
        request: &S::Request,
        output: &S::Output,
        key: &ProducerSigningKey,
    ) -> Result<Self, VerifyError>
    where
        S: CommitmentScheme,
    {
        let public_key = key.public_key();
        let body = ReceiptBody::new(
            S::SCHEME,
            RequestCommitment(S::commit_request(request)),
            ResultCommitment(S::commit_output(output)),
            ProducerId::from_public_key(&public_key),
        );
        let signature = key.sign_digest(body.signature_preimage()?)?;
        let receipt = Self {
            body,
            signature,
            public_key,
        };
        receipt.verify()?;
        Ok(receipt)
    }

    pub fn from_parts_verified(
        body: ReceiptBody,
        signature: Signature,
        public_key: PublicKey,
    ) -> Result<Self, VerifyError> {
        let receipt = Self {
            body,
            signature,
            public_key,
        };
        receipt.verify()?;
        Ok(receipt)
    }

    pub const fn body(&self) -> &ReceiptBody {
        &self.body
    }

    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn verify(&self) -> Result<(), VerifyError> {
        if ProducerId::from_public_key(&self.public_key) != self.body.producer {
            return Err(VerifyError::ProducerMismatch);
        }
        verify_digest_signature(
            &self.public_key,
            &self.signature,
            self.body.signature_preimage()?,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEvidenceReceipt<B, E> {
    body: B,
    signature: Signature,
    public_key: PublicKey,
    evidence: E,
}

impl<E> SignedEvidenceReceipt<EvidencedReceiptBody, E> {
    pub const fn body(&self) -> &EvidencedReceiptBody {
        &self.body
    }

    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub const fn evidence(&self) -> &E {
        &self.evidence
    }
}

impl SignedEvidenceReceipt<EvidencedReceiptBody, SymbolicEvidence> {
    pub fn sign_symbolic(
        request: &SymbolicRequest,
        output: &SymbolicOutput,
        evidence: SymbolicEvidence,
        key: &ProducerSigningKey,
    ) -> Result<Self, VerifyError> {
        Self::sign::<Symbolic>(request, output, evidence, key)
    }

    pub fn from_parts_verified_symbolic(
        body: EvidencedReceiptBody,
        signature: Signature,
        public_key: PublicKey,
        evidence: SymbolicEvidence,
    ) -> Result<Self, VerifyError> {
        let receipt = Self {
            body,
            signature,
            public_key,
            evidence,
        };
        receipt.verify_symbolic()?;
        Ok(receipt)
    }

    pub fn verify_symbolic(&self) -> Result<(), VerifyError> {
        if self.body.base.scheme != SchemeId::Symbolic {
            return Err(VerifyError::WrongScheme {
                expected: SchemeId::Symbolic,
                actual: self.body.base.scheme,
            });
        }
        if ProducerId::from_public_key(&self.public_key) != self.body.base.producer {
            return Err(VerifyError::ProducerMismatch);
        }
        if self.body.evidence_commitment
            != EvidenceCommitment(Symbolic::commit_evidence(&self.evidence))
        {
            return Err(VerifyError::EvidenceCommitmentMismatch);
        }
        verify_digest_signature(
            &self.public_key,
            &self.signature,
            self.body.signature_preimage()?,
        )?;
        Ok(())
    }
}

impl<B, E> SignedEvidenceReceipt<B, E> {
    pub fn sign<S>(
        request: &S::Request,
        output: &S::Output,
        evidence: S::Evidence,
        key: &ProducerSigningKey,
    ) -> Result<SignedEvidenceReceipt<EvidencedReceiptBody, S::Evidence>, VerifyError>
    where
        S: EvidencedScheme,
    {
        let public_key = key.public_key();
        let base = ReceiptBody::new(
            S::SCHEME,
            RequestCommitment(S::commit_request(request)),
            ResultCommitment(S::commit_output(output)),
            ProducerId::from_public_key(&public_key),
        );
        let body =
            EvidencedReceiptBody::new(base, EvidenceCommitment(S::commit_evidence(&evidence)));
        let signature = key.sign_digest(body.signature_preimage()?)?;
        Ok(SignedEvidenceReceipt {
            body,
            signature,
            public_key,
            evidence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptEnvelope {
    Symbolic(SignedEvidenceReceipt<EvidencedReceiptBody, SymbolicEvidence>),
    Opaque(SignedReceipt<ReceiptBody>),
}

impl ReceiptEnvelope {
    pub fn receipt_commitment(&self) -> Result<ReceiptCommitment, VerifyError> {
        match self {
            Self::Symbolic(receipt) => receipt.body.receipt_commitment(),
            Self::Opaque(receipt) => receipt.body.receipt_commitment(),
        }
    }
}

pub enum DeliveryRequest<'a> {
    Symbolic(&'a SymbolicRequest),
    Opaque(&'a OpaqueRequest),
}

pub enum DeliveryOutput<'a> {
    Symbolic(&'a SymbolicOutput),
    Opaque(&'a JsonBytes),
}

pub fn verify_receipt(envelope: &ReceiptEnvelope) -> Result<(), VerifyError> {
    match envelope {
        ReceiptEnvelope::Symbolic(receipt) => receipt.verify_symbolic(),
        ReceiptEnvelope::Opaque(receipt) => {
            if receipt.body.scheme != SchemeId::Opaque {
                return Err(VerifyError::WrongScheme {
                    expected: SchemeId::Opaque,
                    actual: receipt.body.scheme,
                });
            }
            receipt.verify()
        }
    }
}

pub fn verify_delivery(
    request: DeliveryRequest<'_>,
    output: DeliveryOutput<'_>,
    envelope: &ReceiptEnvelope,
) -> Result<(), VerifyError> {
    verify_receipt(envelope)?;

    match (request, output, envelope) {
        (
            DeliveryRequest::Symbolic(request),
            DeliveryOutput::Symbolic(output),
            ReceiptEnvelope::Symbolic(receipt),
        ) => {
            let body = receipt.body.base();
            if body.request != RequestCommitment(Symbolic::commit_request(request)) {
                return Err(VerifyError::RequestCommitmentMismatch);
            }
            if body.result != ResultCommitment(Symbolic::commit_output(output)) {
                return Err(VerifyError::ResultCommitmentMismatch);
            }
            Ok(())
        }
        (
            DeliveryRequest::Opaque(request),
            DeliveryOutput::Opaque(output),
            ReceiptEnvelope::Opaque(receipt),
        ) => {
            if receipt.body.request != RequestCommitment(Opaque::commit_request(request)) {
                return Err(VerifyError::RequestCommitmentMismatch);
            }
            if receipt.body.result != ResultCommitment(Opaque::commit_output(output)) {
                return Err(VerifyError::ResultCommitmentMismatch);
            }
            Ok(())
        }
        _ => Err(VerifyError::SchemeMismatch),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("producer id does not match public key")]
    ProducerMismatch,
    #[error("expected scheme {expected:?}, got {actual:?}")]
    WrongScheme {
        expected: SchemeId,
        actual: SchemeId,
    },
    #[error("request commitment does not match request witness")]
    RequestCommitmentMismatch,
    #[error("result commitment does not match output witness")]
    ResultCommitmentMismatch,
    #[error("evidence commitment does not match evidence witness")]
    EvidenceCommitmentMismatch,
    #[error("delivery witness scheme does not match receipt envelope")]
    SchemeMismatch,
    #[error("signature verification failed: {0}")]
    Signature(#[from] SignatureError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Digest, JsonBytes};

    fn symbolic_request() -> SymbolicRequest {
        SymbolicRequest {
            text_execution_cid: Digest::from_bytes([4; 32]),
        }
    }

    fn symbolic_output() -> SymbolicOutput {
        SymbolicOutput {
            text_artifact_cid: Digest::from_bytes([9; 32]),
        }
    }

    #[test]
    fn opaque_receipt_verifies_delivery() {
        let key = ProducerSigningKey::deterministic_for_tests();
        let request = OpaqueRequest {
            service: "vllm".to_string(),
            method: "generate".to_string(),
            payload: JsonBytes::new(br#"{"prompt":"hi"}"#.to_vec()),
        };
        let output = JsonBytes::new(br#"{"text":"hello"}"#.to_vec());
        let receipt =
            SignedReceipt::<ReceiptBody>::sign::<Opaque>(&request, &output, &key).unwrap();
        let envelope = ReceiptEnvelope::Opaque(receipt);

        verify_delivery(
            DeliveryRequest::Opaque(&request),
            DeliveryOutput::Opaque(&output),
            &envelope,
        )
        .unwrap();
    }

    #[test]
    fn symbolic_receipt_verifies_delivery() {
        let key = ProducerSigningKey::deterministic_for_tests();
        let request = symbolic_request();
        let output = symbolic_output();
        let evidence = SymbolicEvidence::TextArtifactCid(Digest::from_bytes([9; 32]));
        let receipt =
            SignedEvidenceReceipt::<EvidencedReceiptBody, SymbolicEvidence>::sign_symbolic(
                &request, &output, evidence, &key,
            )
            .unwrap();
        let envelope = ReceiptEnvelope::Symbolic(receipt);

        verify_delivery(
            DeliveryRequest::Symbolic(&request),
            DeliveryOutput::Symbolic(&output),
            &envelope,
        )
        .unwrap();
    }

    #[test]
    fn verify_delivery_rejects_wrong_output() {
        let key = ProducerSigningKey::deterministic_for_tests();
        let request = OpaqueRequest {
            service: "vllm".to_string(),
            method: "generate".to_string(),
            payload: JsonBytes::new(br#"{"prompt":"hi"}"#.to_vec()),
        };
        let output = JsonBytes::new(br#"{"text":"hello"}"#.to_vec());
        let wrong = JsonBytes::new(br#"{"text":"bye"}"#.to_vec());
        let receipt =
            SignedReceipt::<ReceiptBody>::sign::<Opaque>(&request, &output, &key).unwrap();
        let envelope = ReceiptEnvelope::Opaque(receipt);

        assert_eq!(
            verify_delivery(
                DeliveryRequest::Opaque(&request),
                DeliveryOutput::Opaque(&wrong),
                &envelope,
            )
            .unwrap_err(),
            VerifyError::ResultCommitmentMismatch
        );
    }

    #[test]
    fn receipt_commitment_excludes_signature() {
        let key = ProducerSigningKey::deterministic_for_tests();
        let request = OpaqueRequest {
            service: "vllm".to_string(),
            method: "generate".to_string(),
            payload: JsonBytes::new(br#"{"prompt":"hi"}"#.to_vec()),
        };
        let output = JsonBytes::new(br#"{"text":"hello"}"#.to_vec());
        let receipt =
            SignedReceipt::<ReceiptBody>::sign::<Opaque>(&request, &output, &key).unwrap();

        let body_commitment = receipt.body().receipt_commitment().unwrap();
        let mut changed_signature = *receipt.signature();
        let mut bytes = *changed_signature.bytes();
        bytes[0] ^= 0x01;
        changed_signature = Signature::from_compact_secp256k1(bytes);
        let rebuilt = SignedReceipt::<ReceiptBody> {
            body: receipt.body().clone(),
            signature: changed_signature,
            public_key: *receipt.public_key(),
        };

        assert_eq!(
            body_commitment,
            rebuilt.body().receipt_commitment().unwrap()
        );
        assert!(rebuilt.verify().is_err());
    }

    #[test]
    fn receipt_envelope_round_trips_through_dag_cbor() {
        let key = ProducerSigningKey::deterministic_for_tests();
        let request = OpaqueRequest {
            service: "vllm".to_string(),
            method: "generate".to_string(),
            payload: JsonBytes::new(br#"{"prompt":"hi"}"#.to_vec()),
        };
        let output = JsonBytes::new(br#"{"text":"hello"}"#.to_vec());
        let receipt =
            SignedReceipt::<ReceiptBody>::sign::<Opaque>(&request, &output, &key).unwrap();
        let envelope = ReceiptEnvelope::Opaque(receipt);

        let bytes = crate::canonical_dag_cbor(&envelope).unwrap();
        let decoded: ReceiptEnvelope = crate::decode_dag_cbor(&bytes).unwrap();

        assert_eq!(decoded, envelope);
        verify_receipt(&decoded).unwrap();
    }
}
