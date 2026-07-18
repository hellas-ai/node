use crate::{ContentId, DagCborEncoder, RequestCommitment};

pub const APPLE_APP_ATTEST: &str = "apple.app-attest.v1";
pub const AMD_SEV_SNP: &str = "amd.sev-snp.v1";
pub const TPM2_QUOTE: &str = "tpm2.quote.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssuranceRequirement {
    codec: String,
    policy: ContentId,
}

impl AssuranceRequirement {
    pub fn new(codec: impl Into<String>, policy: ContentId) -> Result<Self, JobTermsError> {
        let codec = codec.into();
        if !matches!(codec.as_str(), APPLE_APP_ATTEST | AMD_SEV_SNP | TPM2_QUOTE) {
            return Err(JobTermsError::UnknownCodec(codec));
        }
        Ok(Self { codec, policy })
    }

    pub fn codec(&self) -> &str {
        &self.codec
    }

    pub const fn policy(&self) -> ContentId {
        self.policy
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobTerms {
    pub request: RequestCommitment,
    pub provider_genesis: ContentId,
    pub assurance: AssuranceRequirement,
    pub amount: u64,
    pub ttl_ms: u64,
}

impl JobTerms {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = DagCborEncoder::new();
        e.array(7);
        e.str("hellas.job.terms.v2");
        e.bytes(self.request.as_bytes());
        e.bytes(self.provider_genesis.as_bytes());
        e.str(self.assurance.codec());
        e.bytes(self.assurance.policy().as_bytes());
        e.u64(self.amount);
        e.u64(self.ttl_ms);
        e.into_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JobTermsError {
    #[error("unknown assurance evidence codec {0}")]
    UnknownCodec(String),
}
