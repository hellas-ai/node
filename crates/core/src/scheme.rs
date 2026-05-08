use crate::{Commitment, SchemeId};

pub trait CommitmentScheme {
    type Request;
    type Output;

    const SCHEME: SchemeId;

    fn commit_request(request: &Self::Request) -> Commitment;
    fn commit_output(output: &Self::Output) -> Commitment;
}

pub trait EvidencedScheme: CommitmentScheme {
    type Evidence;

    fn commit_evidence(evidence: &Self::Evidence) -> Commitment;
}
