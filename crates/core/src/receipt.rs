use serde::{Deserialize, Serialize};

use crate::signature::verify_digest_signature;
use crate::{
    CommitmentScheme, DagCborEncoder, JsonBytes, Opaque, OpaqueRequest, ProducerId,
    ProducerSigningKey, PublicKey, ReceiptCommitment, RequestCommitment, ResultCommitment,
    SchemeId, Signature, SignatureError, Symbolic, SymbolicOutput, SymbolicRequest, hash_tuple,
    tags,
};

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
        encoder.bytes(self.request.as_bytes());
        encoder.bytes(self.result.as_bytes());
        encoder.bytes(self.producer.as_bytes());
        Ok(encoder.into_bytes())
    }

    pub fn receipt_commitment(&self) -> Result<ReceiptCommitment, VerifyError> {
        Ok(ReceiptCommitment::from_canonical_bytes(
            &self.canonical_bytes()?,
        ))
    }

    pub fn signature_preimage(&self) -> Result<crate::Digest, VerifyError> {
        Ok(hash_tuple(
            tags::RECEIPT_SIGNATURE_V1,
            &[&self.canonical_bytes()?],
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReceipt {
    body: ReceiptBody,
    signature: Signature,
    public_key: PublicKey,
}

impl SignedReceipt {
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
            S::commit_request(request),
            S::commit_output(output),
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

    pub fn receipt_commitment(&self) -> Result<ReceiptCommitment, VerifyError> {
        self.body.receipt_commitment()
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

pub fn verify_receipt(receipt: &SignedReceipt) -> Result<(), VerifyError> {
    receipt.verify()
}

pub fn verify_delivery(
    request: DeliveryRequest<'_>,
    output: DeliveryOutput<'_>,
    receipt: &SignedReceipt,
) -> Result<(), VerifyError> {
    verify_receipt(receipt)?;

    match (request, output, receipt.body.scheme) {
        (
            DeliveryRequest::Symbolic(request),
            DeliveryOutput::Symbolic(output),
            SchemeId::Symbolic,
        ) => {
            if receipt.body.request != Symbolic::commit_request(request) {
                return Err(VerifyError::RequestCommitmentMismatch);
            }
            if receipt.body.result != Symbolic::commit_output(output) {
                return Err(VerifyError::ResultCommitmentMismatch);
            }
            Ok(())
        }
        (DeliveryRequest::Opaque(request), DeliveryOutput::Opaque(output), SchemeId::Opaque) => {
            if receipt.body.request != Opaque::commit_request(request) {
                return Err(VerifyError::RequestCommitmentMismatch);
            }
            if receipt.body.result != Opaque::commit_output(output) {
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
    #[error("request commitment does not match request witness")]
    RequestCommitmentMismatch,
    #[error("result commitment does not match output witness")]
    ResultCommitmentMismatch,
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
        let receipt = SignedReceipt::sign::<Opaque>(&request, &output, &key).unwrap();
        let envelope = receipt;

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
        let receipt = SignedReceipt::sign::<Symbolic>(&request, &output, &key).unwrap();
        let envelope = receipt;

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
        let receipt = SignedReceipt::sign::<Opaque>(&request, &output, &key).unwrap();
        let envelope = receipt;

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
        let receipt = SignedReceipt::sign::<Opaque>(&request, &output, &key).unwrap();

        let body_commitment = receipt.body().receipt_commitment().unwrap();
        let mut changed_signature = *receipt.signature();
        let mut bytes = *changed_signature.bytes();
        bytes[0] ^= 0x01;
        changed_signature = Signature::from_compact_secp256k1(bytes);
        let rebuilt = SignedReceipt {
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
        let receipt = SignedReceipt::sign::<Opaque>(&request, &output, &key).unwrap();
        let envelope = receipt;

        let bytes = crate::canonical_dag_cbor(&envelope).unwrap();
        let decoded: SignedReceipt = crate::decode_dag_cbor(&bytes).unwrap();

        assert_eq!(decoded, envelope);
        verify_receipt(&decoded).unwrap();
    }
}
