use serde::{Deserialize, Serialize};

use crate::{ContentId, DagCborEncoder, Digest, PublicKey, RequestCommitment};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluateRequest {
    /// Content-addressed TextExecution artifact.
    pub text_execution: Digest,
    pub runner_public_key: PublicKey,
    pub execution_environment: ContentId,
    pub nonce: [u8; 32],
}

pub struct Evaluate;

impl Evaluate {
    pub fn commit_request(request: &EvaluateRequest) -> RequestCommitment {
        let mut encoder = DagCborEncoder::new();
        encoder.array(6);
        encoder.str("hellas.evaluate.request.v2");
        encoder.bytes(request.text_execution.as_bytes());
        encoder.bytes(request.execution_environment.as_bytes());
        encoder.bytes(&request.nonce);
        encoder.u64(request.runner_public_key.kind().to_byte() as u64);
        encoder.bytes(request.runner_public_key.bytes());
        RequestCommitment::from_canonical_bytes(&encoder.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProducerSigningKey;

    fn key(byte: u8) -> PublicKey {
        ProducerSigningKey::from_secret_bytes([byte; 32])
            .expect("valid test key")
            .public_key()
    }

    #[test]
    fn request_commitment_binds_runner_key() {
        let text_execution = Digest::from_bytes([4; 32]);
        let first = EvaluateRequest {
            text_execution,
            runner_public_key: key(1),
            execution_environment: ContentId::from_bytes([5; 32]),
            nonce: [6; 32],
        };
        let second = EvaluateRequest {
            text_execution,
            runner_public_key: key(2),
            execution_environment: ContentId::from_bytes([5; 32]),
            nonce: [6; 32],
        };

        assert_ne!(
            Evaluate::commit_request(&first),
            Evaluate::commit_request(&second)
        );
        let mut third = first.clone();
        third.nonce[0] ^= 1;
        assert_ne!(
            Evaluate::commit_request(&first),
            Evaluate::commit_request(&third)
        );
    }
}
