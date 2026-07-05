use serde::{Deserialize, Serialize};

use crate::signature::verify_digest_signature;
use crate::{
    AssuranceStrategy, CommitmentScheme, DagCborEncoder, Evaluate, EvaluateOutput, EvaluateRequest,
    ProducerId, ProducerSigningKey, PublicKey, ReceiptCommitment, RequestCommitment,
    ResultCommitment, SchemeId, Signature, SignatureError, hash_tuple, tags,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptBody {
    scheme: SchemeId,
    strategy: AssuranceStrategy,
    request: RequestCommitment,
    result: ResultCommitment,
    producer: ProducerId,
}

impl ReceiptBody {
    pub fn new(
        scheme: SchemeId,
        strategy: AssuranceStrategy,
        request: RequestCommitment,
        result: ResultCommitment,
        producer: ProducerId,
    ) -> Self {
        Self {
            scheme,
            strategy,
            request,
            result,
            producer,
        }
    }

    pub const fn scheme(&self) -> SchemeId {
        self.scheme
    }

    pub const fn strategy(&self) -> AssuranceStrategy {
        self.strategy
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
        encoder.array(6);
        encoder.str(tags::RECEIPT_BODY_V2);
        encoder.u64(self.scheme.to_byte() as u64);
        encoder.u64(self.strategy.to_byte() as u64);
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
            AssuranceStrategy::ProducerAttested,
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
    Evaluate(&'a EvaluateRequest),
}

pub enum DeliveryOutput<'a> {
    Evaluate(&'a EvaluateOutput),
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

    match (request, output, receipt.body.scheme, receipt.body.strategy) {
        (
            DeliveryRequest::Evaluate(request),
            DeliveryOutput::Evaluate(output),
            SchemeId::Evaluate,
            AssuranceStrategy::ProducerAttested,
        ) => {
            if receipt.body.request != Evaluate::commit_request(request) {
                return Err(VerifyError::RequestCommitmentMismatch);
            }
            if receipt.body.result != Evaluate::commit_output(output) {
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
    use crate::Digest;

    fn evaluate_request() -> EvaluateRequest {
        let key = ProducerSigningKey::deterministic_for_tests();
        EvaluateRequest {
            text_execution: Digest::from_bytes([4; 32]),
            runner_public_key: key.public_key(),
        }
    }

    fn evaluate_output() -> EvaluateOutput {
        EvaluateOutput {
            text_artifact: Digest::from_bytes([9; 32]),
        }
    }

    #[test]
    fn evaluate_receipt_verifies_delivery() {
        let key = ProducerSigningKey::deterministic_for_tests();
        let request = evaluate_request();
        let output = evaluate_output();
        let receipt = SignedReceipt::sign::<Evaluate>(&request, &output, &key).unwrap();
        let envelope = receipt;

        verify_delivery(
            DeliveryRequest::Evaluate(&request),
            DeliveryOutput::Evaluate(&output),
            &envelope,
        )
        .unwrap();
    }

    #[test]
    fn verify_delivery_rejects_wrong_output() {
        let key = ProducerSigningKey::deterministic_for_tests();
        let request = evaluate_request();
        let output = evaluate_output();
        let wrong = EvaluateOutput {
            text_artifact: Digest::from_bytes([8; 32]),
        };
        let receipt = SignedReceipt::sign::<Evaluate>(&request, &output, &key).unwrap();
        let envelope = receipt;

        assert_eq!(
            verify_delivery(
                DeliveryRequest::Evaluate(&request),
                DeliveryOutput::Evaluate(&wrong),
                &envelope,
            )
            .unwrap_err(),
            VerifyError::ResultCommitmentMismatch
        );
    }

    #[test]
    fn receipt_commitment_excludes_signature() {
        let key = ProducerSigningKey::deterministic_for_tests();
        let request = evaluate_request();
        let output = evaluate_output();
        let receipt = SignedReceipt::sign::<Evaluate>(&request, &output, &key).unwrap();

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
        let request = evaluate_request();
        let output = evaluate_output();
        let receipt = SignedReceipt::sign::<Evaluate>(&request, &output, &key).unwrap();
        let envelope = receipt;

        let bytes = crate::canonical_dag_cbor(&envelope).unwrap();
        let decoded: SignedReceipt = crate::decode_dag_cbor(&bytes).unwrap();

        assert_eq!(decoded, envelope);
        verify_receipt(&decoded).unwrap();
    }
}
