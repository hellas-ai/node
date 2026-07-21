use crate::pb::execute::{
    AssuranceRequirement as PbAssuranceRequirement, JobTerms as PbJobTerms,
    PublicKey as PbPublicKey, RunTicketRequest, Signature as PbSignature, Ticket, public_key,
    signature,
};
use crate::signature::verify_digest_signature;
use crate::{
    AssuranceRequirement, ContentId, Digest, JobTerms, ProducerSigningKey, PublicKey,
    RequestCommitment, Signature, SignatureError, hash_tuple, tags,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRunTicket {
    pub terms: JobTerms,
    pub public_key: PublicKey,
}

pub fn ticket_to_pb(
    terms: JobTerms,
    provider_genesis: Vec<u8>,
) -> Result<Ticket, RunTicketAuthError> {
    if ContentId::hash(&provider_genesis) != terms.provider_genesis {
        return Err(RunTicketAuthError::ProviderGenesisMismatch);
    }
    Ok(Ticket {
        request_commitment: terms.request.as_bytes().to_vec(),
        terms: Some(PbJobTerms {
            provider_genesis: terms.provider_genesis.as_bytes().to_vec(),
            assurance: Some(PbAssuranceRequirement {
                codec: terms.assurance.codec().to_string(),
                policy: terms.assurance.policy().as_bytes().to_vec(),
            }),
            amount: terms.amount,
            ttl_ms: terms.ttl_ms,
        }),
        provider_genesis,
    })
}

pub fn job_terms_from_pb(ticket: &Ticket) -> Result<JobTerms, RunTicketAuthError> {
    let request = RequestCommitment::from_digest(Digest::from_bytes(fixed(
        "request_commitment",
        &ticket.request_commitment,
    )?));
    let terms = ticket
        .terms
        .as_ref()
        .ok_or(RunTicketAuthError::MissingTerms)?;
    let provider_genesis = ContentId::from_bytes(fixed(
        "provider_genesis ContentId",
        &terms.provider_genesis,
    )?);
    if ContentId::hash(&ticket.provider_genesis) != provider_genesis {
        return Err(RunTicketAuthError::ProviderGenesisMismatch);
    }
    let assurance = terms
        .assurance
        .as_ref()
        .ok_or(RunTicketAuthError::MissingAssurance)?;
    let assurance = AssuranceRequirement::new(
        assurance.codec.clone(),
        ContentId::from_bytes(fixed("assurance policy ContentId", &assurance.policy)?),
    )
    .map_err(|error| RunTicketAuthError::InvalidAssurance(error.to_string()))?;
    Ok(JobTerms {
        request,
        provider_genesis,
        assurance,
        amount: terms.amount,
        ttl_ms: terms.ttl_ms,
    })
}

pub fn sign_run_ticket(
    ticket: Ticket,
    key: &ProducerSigningKey,
) -> Result<RunTicketRequest, RunTicketAuthError> {
    let terms = job_terms_from_pb(&ticket)?;
    let signature = key.sign_digest(run_ticket_preimage(&terms))?;
    Ok(RunTicketRequest {
        ticket: Some(ticket),
        signature: Some(signature_to_pb(&signature)),
        public_key: Some(public_key_to_pb(&key.public_key())),
    })
}

pub fn verify_run_ticket(
    request: &RunTicketRequest,
) -> Result<VerifiedRunTicket, RunTicketAuthError> {
    let ticket = request
        .ticket
        .as_ref()
        .ok_or(RunTicketAuthError::MissingTicket)?;
    let terms = job_terms_from_pb(ticket)?;
    let public_key = public_key_from_pb(
        request
            .public_key
            .clone()
            .ok_or(RunTicketAuthError::MissingPublicKey)?,
    )?;
    let signature = signature_from_pb(
        request
            .signature
            .clone()
            .ok_or(RunTicketAuthError::MissingSignature)?,
    )?;
    verify_digest_signature(&public_key, &signature, run_ticket_preimage(&terms))?;
    Ok(VerifiedRunTicket { terms, public_key })
}

fn run_ticket_preimage(terms: &JobTerms) -> Digest {
    hash_tuple(tags::RUN_TICKET_SIGNATURE_V2, &[&terms.canonical_bytes()])
}

pub fn public_key_to_pb(key: &PublicKey) -> PbPublicKey {
    let kind = match key {
        PublicKey::Secp256k1(bytes) => public_key::Kind::Secp256k1(bytes.to_vec()),
        PublicKey::Ed25519(bytes) => public_key::Kind::Ed25519(bytes.to_vec()),
        PublicKey::P256(bytes) => public_key::Kind::P256(bytes.to_vec()),
    };
    PbPublicKey { kind: Some(kind) }
}

pub fn public_key_from_pb(key: PbPublicKey) -> Result<PublicKey, RunTicketAuthError> {
    match key.kind.ok_or(RunTicketAuthError::MissingPublicKeyKind)? {
        public_key::Kind::Secp256k1(bytes) => {
            Ok(PublicKey::Secp256k1(fixed("secp256k1 public key", &bytes)?))
        }
        public_key::Kind::Ed25519(bytes) => {
            Ok(PublicKey::Ed25519(fixed("Ed25519 public key", &bytes)?))
        }
        public_key::Kind::P256(bytes) => Ok(PublicKey::P256(fixed("P-256 public key", &bytes)?)),
    }
}

pub fn signature_to_pb(value: &Signature) -> PbSignature {
    let kind = match value {
        Signature::Secp256k1(bytes) => signature::Kind::Secp256k1(bytes.to_vec()),
        Signature::Ed25519(bytes) => signature::Kind::Ed25519(bytes.to_vec()),
        Signature::P256(bytes) => signature::Kind::P256(bytes.to_vec()),
    };
    PbSignature { kind: Some(kind) }
}

pub fn signature_from_pb(value: PbSignature) -> Result<Signature, RunTicketAuthError> {
    match value.kind.ok_or(RunTicketAuthError::MissingSignatureKind)? {
        signature::Kind::Secp256k1(bytes) => {
            Ok(Signature::Secp256k1(fixed("secp256k1 signature", &bytes)?))
        }
        signature::Kind::Ed25519(bytes) => {
            Ok(Signature::Ed25519(fixed("Ed25519 signature", &bytes)?))
        }
        signature::Kind::P256(bytes) => Ok(Signature::P256(fixed("P-256 signature", &bytes)?)),
    }
}

fn fixed<const N: usize>(field: &'static str, bytes: &[u8]) -> Result<[u8; N], RunTicketAuthError> {
    bytes
        .try_into()
        .map_err(|_| RunTicketAuthError::WrongLength {
            field,
            expected: N,
            actual: bytes.len(),
        })
}

#[derive(Debug, thiserror::Error)]
pub enum RunTicketAuthError {
    #[error("run ticket is missing ticket")]
    MissingTicket,
    #[error("run ticket is missing job terms")]
    MissingTerms,
    #[error("run ticket is missing assurance requirement")]
    MissingAssurance,
    #[error("run ticket is missing public_key")]
    MissingPublicKey,
    #[error("run ticket public_key has no kind")]
    MissingPublicKeyKind,
    #[error("run ticket is missing signature")]
    MissingSignature,
    #[error("run ticket signature has no kind")]
    MissingSignatureKind,
    #[error("{field} must be {expected} bytes, got {actual}")]
    WrongLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("ticket provider genesis does not match its ContentId")]
    ProviderGenesisMismatch,
    #[error("invalid assurance requirement: {0}")]
    InvalidAssurance(String),
    #[error("run ticket signature verification failed: {0}")]
    Signature(#[from] SignatureError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket() -> Ticket {
        let genesis = b"genesis".to_vec();
        ticket_to_pb(
            JobTerms {
                request: RequestCommitment::from_digest(Digest::from_bytes([7; 32])),
                provider_genesis: ContentId::hash(&genesis),
                assurance: AssuranceRequirement::new(
                    crate::protocol::job::APPLE_APP_ATTEST,
                    ContentId::from_bytes([8; 32]),
                )
                .unwrap(),
                amount: 10,
                ttl_ms: 20,
            },
            genesis,
        )
        .unwrap()
    }

    #[test]
    fn signed_run_ticket_verifies() {
        let key = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
        let verified = verify_run_ticket(&sign_run_ticket(ticket(), &key).unwrap()).unwrap();
        assert_eq!(verified.terms.request.as_bytes(), &[7; 32]);
        assert_eq!(verified.public_key, key.public_key());
    }

    #[test]
    fn tampered_job_terms_reject() {
        let key = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
        let mut request = sign_run_ticket(ticket(), &key).unwrap();
        request
            .ticket
            .as_mut()
            .unwrap()
            .terms
            .as_mut()
            .unwrap()
            .amount += 1;
        assert!(verify_run_ticket(&request).is_err());
    }
}
