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

/// Returns the canonical DAG-CBOR array [`Evaluate::commit_request`] hashes.
///
/// Exposed as bytes because a second protocol — the paid-work bundle in
/// [`crate::protocol::artifacts::PreparedPaidInputV1`] — must carry the
/// exact preimage of the request commitment, not a second spelling of the
/// same fields. There is one encoder and one field order; a caller that
/// re-derived these bytes could disagree with the commitment they claim
/// to prepare.
pub fn evaluate_request_bytes(request: &EvaluateRequest) -> Vec<u8> {
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
    encoder.into_bytes()
}

pub struct Evaluate;

impl Evaluate {
    pub fn commit_request(request: &EvaluateRequest) -> RequestCommitment {
        RequestCommitment::from_canonical_bytes(&evaluate_request_bytes(request))
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

    /// The commitment preimage is a wire format two protocols share, so
    /// it is pinned as bytes and not merely as a digest: a field order
    /// that moved in both the encoder and a re-derived comparison would
    /// leave every round-trip test passing.
    #[test]
    fn request_bytes_are_the_pinned_commitment_preimage() {
        let request = EvaluateRequest {
            text_execution: Digest::from_bytes([4; 32]),
            runner_public_key: key(1),
            execution_environment: ContentId::from_bytes([5; 32]),
            nonce: [6; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
        };
        let bytes = evaluate_request_bytes(&request);
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();

        // 88                      array(8)
        // 78 1a "hellas.evaluate.request.v3"
        // 58 20 04*32             text_execution
        // 58 20 05*32             execution_environment
        // 58 20 06*32             nonce
        // 01                      runner key kind
        // 58 21 <33>              runner key bytes
        // 00                      assurance = ProducerSigned
        // 01                      retain = true
        assert_eq!(
            hex,
            concat!(
                "88",
                "781a", "68656c6c61732e6576616c756174652e726571756573742e7633",
                "5820", "0404040404040404040404040404040404040404040404040404040404040404",
                "5820", "0505050505050505050505050505050505050505050505050505050505050505",
                "5820", "0606060606060606060606060606060606060606060606060606060606060606",
                "01",
                "5821", "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
                "00",
                "01",
            )
        );
        assert_eq!(
            RequestCommitment::from_canonical_bytes(&bytes),
            Evaluate::commit_request(&request)
        );
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
