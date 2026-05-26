use serde::{Deserialize, Serialize};

use crate::{CommitmentScheme, Digest, RequestCommitment, ResultCommitment, SchemeId};

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

pub struct Symbolic;

impl CommitmentScheme for Symbolic {
    type Request = SymbolicRequest;
    type Output = SymbolicOutput;

    const SCHEME: SchemeId = SchemeId::Symbolic;

    fn commit_request(request: &Self::Request) -> RequestCommitment {
        RequestCommitment::from_digest(request.text_execution_cid)
    }

    fn commit_output(output: &Self::Output) -> ResultCommitment {
        ResultCommitment::from_digest(output.text_artifact_cid)
    }
}
