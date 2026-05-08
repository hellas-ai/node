use serde::{Deserialize, Serialize};

use crate::{
    Commitment, CommitmentScheme, DagCborEncoder, Digest, EvidencedScheme, SchemeId, tags,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolicRequest {
    Genesis(SymbolicGenesisRequest),
    Step(SymbolicStepRequest),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicGenesisRequest {
    pub binding_cid: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicStepRequest {
    pub binding_cid: Digest,
    pub previous_execution_cid: Digest,
    pub input_tokens_cid: Digest,
    pub policy: SymbolicPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicPolicy {
    pub max_new_tokens: u32,
    pub stop_token_ids: Vec<i32>,
}

impl SymbolicPolicy {
    pub fn new(max_new_tokens: u32, mut stop_token_ids: Vec<i32>) -> Self {
        stop_token_ids.sort_unstable();
        stop_token_ids.dedup();
        Self {
            max_new_tokens,
            stop_token_ids,
        }
    }

    fn encode(&self, encoder: &mut DagCborEncoder) {
        encoder.array(3);
        encoder.str(tags::SYMBOLIC_TEXT_POLICY_V1);
        encoder.u64(self.max_new_tokens as u64);
        encoder.array(self.stop_token_ids.len() as u64);
        for token in &self.stop_token_ids {
            encoder.i64(*token as i64);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicOutput {
    pub text_receipt_cid: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolicEvidence {
    TextReceiptCid(Digest),
}

pub struct Symbolic;

impl CommitmentScheme for Symbolic {
    type Request = SymbolicRequest;
    type Output = SymbolicOutput;

    const SCHEME: SchemeId = SchemeId::Symbolic;

    fn commit_request(request: &Self::Request) -> Commitment {
        Commitment::from_canonical_bytes(&Self::request_bytes(request))
    }

    fn commit_output(output: &Self::Output) -> Commitment {
        Commitment::from_digest(output.text_receipt_cid)
    }
}

impl EvidencedScheme for Symbolic {
    type Evidence = SymbolicEvidence;

    fn commit_evidence(evidence: &Self::Evidence) -> Commitment {
        match evidence {
            SymbolicEvidence::TextReceiptCid(cid) => Commitment::from_digest(*cid),
        }
    }
}

impl Symbolic {
    /// Canonical request bytes matching catgrad-llm `TextExecution`.
    ///
    /// This preserves the important invariant that a symbolic request
    /// commitment is the same 32-byte BLAKE3 address as the corresponding
    /// `Cid<TextExecution>` artifact.
    pub fn request_bytes(request: &SymbolicRequest) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        match request {
            SymbolicRequest::Genesis(genesis) => {
                encoder.array(2);
                encoder.str(tags::SYMBOLIC_TEXT_EXECUTION_GENESIS_V1);
                encoder.bytes(genesis.binding_cid.as_bytes());
            }
            SymbolicRequest::Step(step) => {
                encoder.array(5);
                encoder.str(tags::SYMBOLIC_TEXT_EXECUTION_STEP_V1);
                encoder.bytes(step.binding_cid.as_bytes());
                encoder.bytes(step.previous_execution_cid.as_bytes());
                encoder.bytes(step.input_tokens_cid.as_bytes());
                step.policy.encode(&mut encoder);
            }
        }
        encoder.into_bytes()
    }
}
