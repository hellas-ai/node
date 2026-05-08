use serde::{Deserialize, Serialize};

use crate::{Commitment, CommitmentScheme, Digest, EvidencedScheme, SchemeId};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicRequest {
    /// catnix InputId<TextExecution>.
    pub text_execution_cid: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicOutput {
    /// catnix OutputId<TextArtifact>.
    pub text_artifact_cid: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolicEvidence {
    TextArtifactCid(Digest),
}

pub struct Symbolic;

impl CommitmentScheme for Symbolic {
    type Request = SymbolicRequest;
    type Output = SymbolicOutput;

    const SCHEME: SchemeId = SchemeId::Symbolic;

    fn commit_request(request: &Self::Request) -> Commitment {
        Commitment::from_digest(request.text_execution_cid)
    }

    fn commit_output(output: &Self::Output) -> Commitment {
        Commitment::from_digest(output.text_artifact_cid)
    }
}

impl EvidencedScheme for Symbolic {
    type Evidence = SymbolicEvidence;

    fn commit_evidence(evidence: &Self::Evidence) -> Commitment {
        match evidence {
            SymbolicEvidence::TextArtifactCid(cid) => Commitment::from_digest(*cid),
        }
    }
}
