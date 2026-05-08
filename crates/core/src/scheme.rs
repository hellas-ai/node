use crate::{RequestCommitment, ResultCommitment, SchemeId};

pub trait CommitmentScheme {
    type Request;
    type Output;

    const SCHEME: SchemeId;

    fn commit_request(request: &Self::Request) -> RequestCommitment;
    fn commit_output(output: &Self::Output) -> ResultCommitment;
}
