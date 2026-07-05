use serde::{Deserialize, Serialize};

use crate::{
    CommitmentScheme, DagCborEncoder, Digest, PublicKey, RequestCommitment, ResultCommitment,
    SchemeId,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluateRequest {
    /// Content-addressed TextExecution artifact.
    pub text_execution: Digest,
    pub runner_public_key: PublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluateOutput {
    /// Content-addressed TextArtifact artifact.
    pub text_artifact: Digest,
}

pub struct Evaluate;

impl CommitmentScheme for Evaluate {
    type Request = EvaluateRequest;
    type Output = EvaluateOutput;

    const SCHEME: SchemeId = SchemeId::Evaluate;

    fn commit_request(request: &Self::Request) -> RequestCommitment {
        let mut encoder = DagCborEncoder::new();
        encoder.array(4);
        encoder.str("hellas.evaluate.request.v1");
        encoder.bytes(request.text_execution.as_bytes());
        encoder.u64(request.runner_public_key.kind().to_byte() as u64);
        encoder.bytes(request.runner_public_key.bytes());
        RequestCommitment::from_canonical_bytes(&encoder.into_bytes())
    }

    fn commit_output(output: &Self::Output) -> ResultCommitment {
        ResultCommitment::from_digest(output.text_artifact)
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
        };
        let second = EvaluateRequest {
            text_execution,
            runner_public_key: key(2),
        };

        assert_ne!(
            Evaluate::commit_request(&first),
            Evaluate::commit_request(&second)
        );
    }
}
