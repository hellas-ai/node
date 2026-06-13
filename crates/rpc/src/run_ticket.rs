use hellas_core::signature::verify_digest_signature;
use hellas_core::{
    Digest, ProducerSigningKey, PublicKey, Signature, SignatureError, SignatureKind, hash_tuple,
    tags,
};

use crate::pb::execute::{PublicKey as PbPublicKey, RunTicketRequest, Signature as PbSignature};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedRunTicket {
    pub request_commitment: [u8; Digest::LEN],
    pub public_key: PublicKey,
}

pub fn sign_run_ticket(
    request_commitment: [u8; Digest::LEN],
    key: &ProducerSigningKey,
) -> Result<RunTicketRequest, RunTicketAuthError> {
    let signature = key.sign_digest(run_ticket_preimage(&request_commitment))?;
    Ok(RunTicketRequest {
        request_commitment: request_commitment.to_vec(),
        signature: Some(signature_to_pb(&signature)),
        public_key: Some(public_key_to_pb(&key.public_key())),
    })
}

pub fn verify_run_ticket(
    request: &RunTicketRequest,
) -> Result<VerifiedRunTicket, RunTicketAuthError> {
    let request_commitment: [u8; Digest::LEN] = request
        .request_commitment
        .as_slice()
        .try_into()
        .map_err(|_| RunTicketAuthError::WrongCommitmentLength {
            actual: request.request_commitment.len(),
        })?;
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
    verify_digest_signature(
        &public_key,
        &signature,
        run_ticket_preimage(&request_commitment),
    )?;
    Ok(VerifiedRunTicket {
        request_commitment,
        public_key,
    })
}

fn run_ticket_preimage(request_commitment: &[u8; Digest::LEN]) -> Digest {
    hash_tuple(tags::RUN_TICKET_SIGNATURE_V1, &[request_commitment])
}

pub fn public_key_to_pb(key: &PublicKey) -> PbPublicKey {
    PbPublicKey {
        kind: u32::from(key.kind().to_byte()),
        bytes: key.bytes().to_vec(),
    }
}

pub fn public_key_from_pb(key: PbPublicKey) -> Result<PublicKey, RunTicketAuthError> {
    let kind = u8::try_from(key.kind)
        .map_err(|_| RunTicketAuthError::SignatureKindOutOfRange { value: key.kind })?;
    match SignatureKind::from_byte(kind)? {
        SignatureKind::Secp256k1 => {
            let bytes: [u8; PublicKey::LEN] = key.bytes.as_slice().try_into().map_err(|_| {
                RunTicketAuthError::WrongPublicKeyLength {
                    actual: key.bytes.len(),
                }
            })?;
            Ok(PublicKey::from_compressed_sec1(bytes))
        }
    }
}

fn signature_to_pb(signature: &Signature) -> PbSignature {
    PbSignature {
        kind: u32::from(signature.kind().to_byte()),
        bytes: signature.bytes().to_vec(),
    }
}

fn signature_from_pb(signature: PbSignature) -> Result<Signature, RunTicketAuthError> {
    let kind =
        u8::try_from(signature.kind).map_err(|_| RunTicketAuthError::SignatureKindOutOfRange {
            value: signature.kind,
        })?;
    match SignatureKind::from_byte(kind)? {
        SignatureKind::Secp256k1 => {
            let bytes: [u8; Signature::LEN] =
                signature.bytes.as_slice().try_into().map_err(|_| {
                    RunTicketAuthError::WrongSignatureLength {
                        actual: signature.bytes.len(),
                    }
                })?;
            Ok(Signature::from_compact_secp256k1(bytes))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RunTicketAuthError {
    #[error("run ticket request_commitment must be 32 bytes, got {actual}")]
    WrongCommitmentLength { actual: usize },
    #[error("run ticket is missing public_key")]
    MissingPublicKey,
    #[error("run ticket is missing signature")]
    MissingSignature,
    #[error("run ticket public_key bytes must be 33 bytes, got {actual}")]
    WrongPublicKeyLength { actual: usize },
    #[error("run ticket signature bytes must be 64 bytes, got {actual}")]
    WrongSignatureLength { actual: usize },
    #[error("run ticket signature kind is out of range: {value}")]
    SignatureKindOutOfRange { value: u32 },
    #[error("run ticket signature verification failed: {0}")]
    Signature(#[from] SignatureError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_run_ticket_verifies() {
        let key = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
        let request = sign_run_ticket([7; 32], &key).unwrap();

        let verified = verify_run_ticket(&request).unwrap();

        assert_eq!(verified.request_commitment, [7; 32]);
        assert_eq!(verified.public_key, key.public_key());
    }

    #[test]
    fn tampered_run_ticket_signature_rejects() {
        let key = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
        let mut request = sign_run_ticket([7; 32], &key).unwrap();
        request.request_commitment[0] ^= 1;

        assert!(verify_run_ticket(&request).is_err());
    }
}
