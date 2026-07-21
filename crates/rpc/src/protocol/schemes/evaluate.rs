use serde::{Deserialize, Serialize};

use crate::{
    Assurance, ContentId, DagCborEncoder, Digest, PublicKey, RequestCommitment, Retention,
};

const fn retain_by_default() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluateRequest {
    /// Content-addressed TextExecution artifact.
    pub text_execution: Digest,
    pub runner_public_key: PublicKey,
    pub execution_environment: ContentId,
    pub nonce: [u8; 32],
    pub assurance: Assurance,
    #[serde(default = "retain_by_default")]
    pub retain: bool,
}

impl EvaluateRequest {
    pub const fn retention(&self) -> Retention {
        Retention::from_retain(self.retain)
    }
}

pub struct Evaluate;

impl Evaluate {
    pub fn commit_request(request: &EvaluateRequest) -> RequestCommitment {
        let mut encoder = DagCborEncoder::new();
        encoder.array(8);
        encoder.str("hellas.evaluate.request.v3");
        encoder.bytes(request.text_execution.as_bytes());
        encoder.bytes(request.execution_environment.as_bytes());
        encoder.bytes(&request.nonce);
        encoder.u64(request.runner_public_key.kind().to_byte() as u64);
        encoder.bytes(request.runner_public_key.bytes());
        encoder.u64(request.assurance.to_byte() as u64);
        encoder.u64(request.retain as u64);
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
            assurance: Assurance::ProducerSigned,
            retain: true,
        };
        let second = EvaluateRequest {
            text_execution,
            runner_public_key: key(2),
            execution_environment: ContentId::from_bytes([5; 32]),
            nonce: [6; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
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
        let mut fourth = first.clone();
        fourth.assurance = Assurance::AppleAppAttest;
        assert_ne!(
            Evaluate::commit_request(&first),
            Evaluate::commit_request(&fourth)
        );
        let mut fifth = first.clone();
        fifth.retain = false;
        assert_ne!(
            Evaluate::commit_request(&first),
            Evaluate::commit_request(&fifth)
        );
        assert_eq!(
            Evaluate::commit_request(&first).digest().to_string(),
            "f166bb42c7de9a5be0e1daf7a165c8d50241e82b27644b4c50b91bcd8481e4c6"
        );
    }
}
