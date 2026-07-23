use crate::{Assurance, ContentId, DagCborEncoder, RequestCommitment};

pub const APPLE_APP_ATTEST: &str = "apple.app-attest.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobTerms {
    pub request: RequestCommitment,
    pub provider_genesis: ContentId,
    pub assurance: Assurance,
    pub amount: u64,
    pub ttl_ms: u64,
}

impl JobTerms {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = DagCborEncoder::new();
        e.array(6);
        e.str("hellas.job.terms.v2");
        e.bytes(self.request.as_bytes());
        e.bytes(self.provider_genesis.as_bytes());
        e.u64(self.assurance.to_byte() as u64);
        e.u64(self.amount);
        e.u64(self.ttl_ms);
        e.into_bytes()
    }
}
