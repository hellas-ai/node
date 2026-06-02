use serde::{Deserialize, Serialize};

use crate::{CommitmentScheme, Digest, RequestCommitment, ResultCommitment, SchemeId};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicRequest {
    /// catnix InputId<TextExecution>.
    pub text_execution: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicOutput {
    /// catnix OutputId<TextArtifact>.
    pub text_artifact: Digest,
}

pub struct Symbolic;

impl CommitmentScheme for Symbolic {
    type Request = SymbolicRequest;
    type Output = SymbolicOutput;

    const SCHEME: SchemeId = SchemeId::Symbolic;

    fn commit_request(request: &Self::Request) -> RequestCommitment {
        RequestCommitment::from_digest(request.text_execution)
    }

    fn commit_output(output: &Self::Output) -> ResultCommitment {
        ResultCommitment::from_digest(output.text_artifact)
    }
}
