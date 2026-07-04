use crate::{CONSENSUS_NAMESPACE, ConsensusInfo, LatestBlock, QueryError};
use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::simplex::types::Finalization as SimplexFinalization;
use commonware_cryptography::{certificate::Scheme as _, sha256::Digest};
use commonware_parallel::Sequential;
use hellas_kernel::domain::{Scheme, ThresholdVariant};
use rand::rngs::OsRng;
use thiserror::Error;

pub type Finalization = SimplexFinalization<Scheme, Digest>;

type ConsensusIdentity =
    <ThresholdVariant as commonware_cryptography::bls12381::primitives::variant::Variant>::Public;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConsensusVerificationError {
    #[error("threshold identity was empty")]
    EmptyThresholdIdentity,
    #[error("invalid threshold identity")]
    InvalidThresholdIdentity,
    #[error("invalid finalization")]
    InvalidFinalization,
    #[error("finalization payload mismatch")]
    PayloadMismatch,
    #[error("finalization verification failed")]
    VerificationFailed,
}

impl From<ConsensusVerificationError> for QueryError {
    fn from(err: ConsensusVerificationError) -> Self {
        Self::Remote(err.to_string())
    }
}

#[derive(Clone)]
pub struct ConsensusVerifier {
    scheme: Scheme,
}

impl ConsensusVerifier {
    pub fn new(info: &ConsensusInfo) -> Result<Self, ConsensusVerificationError> {
        if info.threshold_identity.is_empty() {
            return Err(ConsensusVerificationError::EmptyThresholdIdentity);
        }
        let identity = ConsensusIdentity::decode(info.threshold_identity.as_slice())
            .map_err(|_| ConsensusVerificationError::InvalidThresholdIdentity)?;
        Ok(Self {
            scheme: Scheme::certificate_verifier(CONSENSUS_NAMESPACE, identity),
        })
    }

    pub const fn scheme(&self) -> &Scheme {
        &self.scheme
    }

    pub fn decode_finalization(encoded: &[u8]) -> Result<Finalization, ConsensusVerificationError> {
        Finalization::decode_cfg(encoded, &Scheme::certificate_codec_config_unbounded())
            .map_err(|_| ConsensusVerificationError::InvalidFinalization)
    }

    pub fn verify_finalization(
        &self,
        finalization: &Finalization,
        expected_payload: Digest,
    ) -> Result<(), ConsensusVerificationError> {
        if finalization.proposal.payload != expected_payload {
            return Err(ConsensusVerificationError::PayloadMismatch);
        }
        let mut rng = OsRng;
        if !finalization.verify(&mut rng, &self.scheme, &Sequential) {
            return Err(ConsensusVerificationError::VerificationFailed);
        }
        Ok(())
    }

    pub fn verify_snapshot(
        &self,
        snapshot: &LatestBlock,
    ) -> Result<(), ConsensusVerificationError> {
        let finalization = Self::decode_finalization(&snapshot.finalization)?;
        self.verify_finalization(&finalization, snapshot.payload)
    }
}
