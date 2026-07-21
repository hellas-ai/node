use hellas_rpc::pb::execute::AssuranceEvidence;
use hellas_rpc::{ContentId, TPM2_QUOTE};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{AnchorTime, AttestationError, Binding, Validity};

const SHA256_ALGORITHM: u16 = 0x000b;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredTpmCredential {
    pub id: ContentId,
    pub aik_public_key: [u8; 33],
    pub not_before: u64,
    pub not_after: u64,
}

/// A machine holding this enrolled AIK was in this measured boot state at quote time.
/// This does not prove anything about the hellas binary, its config, or the job; generic-Linux PCRs stop at the OS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TpmClaims {
    pub selected_pcrs: Vec<(u8, [u8; 32])>,
    pub event_count: u32,
    pub credential: Validity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TpmPolicy {
    pub expected_pcrs: Vec<(u8, [u8; 32])>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpmVerdict {
    Accepted,
    CredentialNotYetValid,
    CredentialExpired,
    BootStateDenied,
}

pub fn appraise_tpm(claims: &TpmClaims, policy: &TpmPolicy) -> TpmVerdict {
    match claims.credential {
        Validity::NotYetValid => TpmVerdict::CredentialNotYetValid,
        Validity::Expired => TpmVerdict::CredentialExpired,
        Validity::Current if claims.selected_pcrs != policy.expected_pcrs => {
            TpmVerdict::BootStateDenied
        }
        Validity::Current => TpmVerdict::Accepted,
    }
}

pub fn tpm_evidence(
    credential: ContentId,
    quote: &[u8],
    signature: &[u8],
    event_log: &[u8],
) -> Result<AssuranceEvidence, AttestationError> {
    let quote_len =
        u32::try_from(quote.len()).map_err(|_| AttestationError::Malformed("TPM proof"))?;
    let signature_len =
        u32::try_from(signature.len()).map_err(|_| AttestationError::Malformed("TPM proof"))?;
    let mut proof = Vec::with_capacity(8 + quote.len() + signature.len() + event_log.len());
    proof.extend_from_slice(&quote_len.to_be_bytes());
    proof.extend_from_slice(&signature_len.to_be_bytes());
    proof.extend_from_slice(quote);
    proof.extend_from_slice(signature);
    proof.extend_from_slice(event_log);
    Ok(AssuranceEvidence {
        codec: TPM2_QUOTE.into(),
        credential: credential.as_bytes().to_vec(),
        proof,
    })
}

pub fn verify_tpm(
    evidence: &AssuranceEvidence,
    expected: Binding,
    credential: &RegisteredTpmCredential,
    anchor: AnchorTime,
) -> Result<TpmClaims, AttestationError> {
    if evidence.codec != TPM2_QUOTE {
        return Err(AttestationError::Codec);
    }
    if evidence.credential != credential.id.as_bytes() {
        return Err(AttestationError::Credential);
    }
    if credential.not_before > credential.not_after {
        return Err(AttestationError::Credential);
    }
    let proof = proof_parts(&evidence.proof)?;
    let parsed = parse_quote(proof.quote, expected)?;
    verify_signature(
        parsed.attestation,
        proof.signature,
        &credential.aik_public_key,
    )?;
    let (pcrs, event_count) = replay_event_log(proof.event_log)?;
    let selected_pcrs: Vec<_> = parsed
        .selection
        .iter()
        .enumerate()
        .flat_map(|(byte, bits)| {
            (0..8).filter_map(move |bit| ((bits >> bit) & 1 == 1).then_some((byte * 8 + bit) as u8))
        })
        .map(|index| (index, pcrs[index as usize]))
        .collect();
    let mut digest = Sha256::new();
    for (_, pcr) in &selected_pcrs {
        digest.update(pcr);
    }
    if selected_pcrs.is_empty() || digest.finalize().as_slice() != parsed.pcr_digest {
        return Err(AttestationError::EventLog);
    }
    Ok(TpmClaims {
        selected_pcrs,
        event_count,
        credential: Validity::at(anchor, credential.not_before, credential.not_after),
    })
}

struct ParsedQuote<'a> {
    attestation: &'a [u8],
    selection: &'a [u8],
    pcr_digest: &'a [u8],
}

struct ProofParts<'a> {
    quote: &'a [u8],
    signature: &'a [u8],
    event_log: &'a [u8],
}

fn proof_parts(proof: &[u8]) -> Result<ProofParts<'_>, AttestationError> {
    let mut cursor = Cursor::new(proof);
    let quote_len = cursor.be_u32()? as usize;
    let signature_len = cursor.be_u32()? as usize;
    let quote = cursor.take(quote_len)?;
    let signature = cursor.take(signature_len)?;
    let event_log = cursor.rest();
    if event_log.is_empty() {
        return Err(AttestationError::Malformed("TPM proof"));
    }
    Ok(ProofParts {
        quote,
        signature,
        event_log,
    })
}

fn parse_quote(quote: &[u8], expected: Binding) -> Result<ParsedQuote<'_>, AttestationError> {
    let mut outer = Cursor::new(quote);
    let size = outer.be_u16()? as usize;
    let attestation = outer.take(size)?;
    outer.end("TPM quote")?;
    let mut cursor = Cursor::new(attestation);
    if cursor.be_u32()? != 0xff54_4347 || cursor.be_u16()? != 0x8018 {
        return Err(AttestationError::Malformed("TPM quote"));
    }
    cursor.tpm2b()?;
    if cursor.tpm2b()? != expected.as_bytes() {
        return Err(AttestationError::Binding);
    }
    cursor.take(25)?;
    if cursor.be_u32()? != 1 || cursor.be_u16()? != SHA256_ALGORITHM {
        return Err(AttestationError::Malformed("TPM PCR selection"));
    }
    let selection_len = cursor.u8()? as usize;
    let selection = cursor.take(selection_len)?;
    if selection.len() > 3 {
        return Err(AttestationError::Malformed("TPM PCR selection"));
    }
    let pcr_digest = cursor.tpm2b()?;
    if pcr_digest.len() != 32 {
        return Err(AttestationError::Malformed("TPM PCR digest"));
    }
    cursor.end("TPM quote")?;
    Ok(ParsedQuote {
        attestation,
        selection,
        pcr_digest,
    })
}

fn verify_signature(
    attestation: &[u8],
    signature: &[u8],
    public_key: &[u8; 33],
) -> Result<(), AttestationError> {
    let mut cursor = Cursor::new(signature);
    if cursor.be_u16()? != 0x0018 || cursor.be_u16()? != SHA256_ALGORITHM {
        return Err(AttestationError::Malformed("TPM signature"));
    }
    let r = scalar(cursor.tpm2b()?)?;
    let s = scalar(cursor.tpm2b()?)?;
    cursor.end("TPM signature")?;
    let signature = Signature::from_scalars(r, s).map_err(|_| AttestationError::Signature)?;
    let key =
        VerifyingKey::from_sec1_bytes(public_key).map_err(|_| AttestationError::Credential)?;
    key.verify_prehash(&Sha256::digest(attestation), &signature)
        .map_err(|_| AttestationError::Signature)
}

fn scalar(bytes: &[u8]) -> Result<[u8; 32], AttestationError> {
    if bytes.is_empty() || bytes.len() > 32 {
        return Err(AttestationError::Malformed("TPM signature"));
    }
    let mut scalar = [0; 32];
    scalar[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(scalar)
}

fn replay_event_log(log: &[u8]) -> Result<([[u8; 32]; 24], u32), AttestationError> {
    let mut cursor = Cursor::new(log);
    if cursor.le_u32()? != 0 || cursor.le_u32()? != 3 || cursor.take(20)? != [0; 20] {
        return Err(AttestationError::Malformed("TPM event log"));
    }
    let spec_len = cursor.le_u32()? as usize;
    let mut spec = Cursor::new(cursor.take(spec_len)?);
    if spec.take(16)? != b"Spec ID Event03\0" {
        return Err(AttestationError::Malformed("TPM event log"));
    }
    spec.take(8)?;
    let algorithm_count = spec.le_u32()?;
    if algorithm_count == 0 || algorithm_count > 8 {
        return Err(AttestationError::Malformed("TPM event log"));
    }
    let mut algorithms = Vec::with_capacity(algorithm_count as usize);
    for _ in 0..algorithm_count {
        algorithms.push((spec.le_u16()?, spec.le_u16()? as usize));
    }
    if !algorithms.contains(&(SHA256_ALGORITHM, 32)) {
        return Err(AttestationError::Malformed("TPM event log"));
    }
    let vendor_size = spec.u8()? as usize;
    spec.take(vendor_size)?;
    spec.end("TPM event log")?;

    let mut pcrs = [[0; 32]; 24];
    let mut event_count = 0_u32;
    while !cursor.rest().is_empty() {
        let pcr = cursor.le_u32()? as usize;
        let event_type = cursor.le_u32()?;
        let digest_count = cursor.le_u32()?;
        if pcr >= pcrs.len() || digest_count == 0 || digest_count > algorithm_count {
            return Err(AttestationError::Malformed("TPM event log"));
        }
        let mut sha256 = None;
        for _ in 0..digest_count {
            let algorithm = cursor.le_u16()?;
            let size = algorithms
                .iter()
                .find_map(|(id, size)| (*id == algorithm).then_some(*size))
                .ok_or(AttestationError::Malformed("TPM event log"))?;
            let digest = cursor.take(size)?;
            if algorithm == SHA256_ALGORITHM {
                sha256 = Some(digest);
            }
        }
        let event_len = cursor.le_u32()? as usize;
        cursor.take(event_len)?;
        if event_type != 3 {
            let digest = sha256.ok_or(AttestationError::Malformed("TPM event log"))?;
            let mut extend = Sha256::new();
            extend.update(pcrs[pcr]);
            extend.update(digest);
            pcrs[pcr].copy_from_slice(&extend.finalize());
            event_count = event_count.saturating_add(1);
        }
    }
    Ok((pcrs, event_count))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], AttestationError> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(AttestationError::Malformed("TPM bytes"))?;
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn rest(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn end(&self, name: &'static str) -> Result<(), AttestationError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(AttestationError::Malformed(name))
        }
    }

    fn u8(&mut self) -> Result<u8, AttestationError> {
        Ok(self.take(1)?[0])
    }

    fn be_u16(&mut self) -> Result<u16, AttestationError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn be_u32(&mut self) -> Result<u32, AttestationError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn le_u16(&mut self) -> Result<u16, AttestationError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn le_u32(&mut self) -> Result<u32, AttestationError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn tpm2b(&mut self) -> Result<&'a [u8], AttestationError> {
        let len = self.be_u16()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TPM_STATEMENT_V1, Validity};
    use hellas_rpc::{Digest as ProtocolDigest, EventCommitment};
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    fn fixture() -> (AssuranceEvidence, RegisteredTpmCredential, Binding) {
        let key = SigningKey::from_bytes((&[5; 32]).into()).unwrap();
        let terminal = EventCommitment::from_digest(ProtocolDigest::from_bytes([6; 32]));
        let binding = Binding::new(TPM_STATEMENT_V1, terminal);
        let log = event_log();
        let pcr0 = Sha256::digest([[0; 32].as_slice(), &[1; 32]].concat());
        let pcr7 = Sha256::digest([[0; 32].as_slice(), &[2; 32]].concat());
        let pcr_digest = Sha256::digest([pcr0.as_slice(), pcr7.as_slice()].concat());

        let mut attestation = Vec::new();
        attestation.extend_from_slice(&0xff54_4347_u32.to_be_bytes());
        attestation.extend_from_slice(&0x8018_u16.to_be_bytes());
        attestation.extend_from_slice(&0_u16.to_be_bytes());
        attestation.extend_from_slice(&32_u16.to_be_bytes());
        attestation.extend_from_slice(binding.as_bytes());
        attestation.extend_from_slice(&[0; 25]);
        attestation.extend_from_slice(&1_u32.to_be_bytes());
        attestation.extend_from_slice(&SHA256_ALGORITHM.to_be_bytes());
        attestation.push(3);
        attestation.extend_from_slice(&[0x81, 0, 0]);
        attestation.extend_from_slice(&32_u16.to_be_bytes());
        attestation.extend_from_slice(&pcr_digest);
        let mut quote = Vec::new();
        quote.extend_from_slice(&u16::try_from(attestation.len()).unwrap().to_be_bytes());
        quote.extend_from_slice(&attestation);

        let signature: Signature = key.sign_prehash(&Sha256::digest(&attestation)).unwrap();
        let bytes = signature.to_bytes();
        let mut tpm_signature = Vec::new();
        tpm_signature.extend_from_slice(&0x0018_u16.to_be_bytes());
        tpm_signature.extend_from_slice(&SHA256_ALGORITHM.to_be_bytes());
        tpm_signature.extend_from_slice(&32_u16.to_be_bytes());
        tpm_signature.extend_from_slice(&bytes[..32]);
        tpm_signature.extend_from_slice(&32_u16.to_be_bytes());
        tpm_signature.extend_from_slice(&bytes[32..]);

        let id = ContentId::hash(b"test AIK credential");
        let public = key.verifying_key().to_encoded_point(true);
        let credential = RegisteredTpmCredential {
            id,
            aik_public_key: public.as_bytes().try_into().unwrap(),
            not_before: 10,
            not_after: 20,
        };
        (
            tpm_evidence(id, &quote, &tpm_signature, &log).unwrap(),
            credential,
            binding,
        )
    }

    fn event_log() -> Vec<u8> {
        let mut spec = Vec::new();
        spec.extend_from_slice(b"Spec ID Event03\0");
        spec.extend_from_slice(&0_u32.to_le_bytes());
        spec.extend_from_slice(&[0, 2, 0, 2]);
        spec.extend_from_slice(&1_u32.to_le_bytes());
        spec.extend_from_slice(&SHA256_ALGORITHM.to_le_bytes());
        spec.extend_from_slice(&32_u16.to_le_bytes());
        spec.push(0);

        let mut log = Vec::new();
        log.extend_from_slice(&0_u32.to_le_bytes());
        log.extend_from_slice(&3_u32.to_le_bytes());
        log.extend_from_slice(&[0; 20]);
        log.extend_from_slice(&u32::try_from(spec.len()).unwrap().to_le_bytes());
        log.extend_from_slice(&spec);
        event(&mut log, 0, [1; 32], b"firmware");
        event(&mut log, 7, [2; 32], b"policy");
        log
    }

    fn event(log: &mut Vec<u8>, pcr: u32, digest: [u8; 32], data: &[u8]) {
        log.extend_from_slice(&pcr.to_le_bytes());
        log.extend_from_slice(&5_u32.to_le_bytes());
        log.extend_from_slice(&1_u32.to_le_bytes());
        log.extend_from_slice(&SHA256_ALGORITHM.to_le_bytes());
        log.extend_from_slice(&digest);
        log.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        log.extend_from_slice(data);
    }

    #[test]
    fn verifies_quote_signature_and_event_log() {
        let (evidence, credential, binding) = fixture();
        let claims = verify_tpm(&evidence, binding, &credential, AnchorTime(15)).unwrap();
        assert_eq!(claims.event_count, 2);
        assert_eq!(claims.selected_pcrs.len(), 2);
        assert_eq!(claims.credential, Validity::Current);
        assert_eq!(
            appraise_tpm(
                &claims,
                &TpmPolicy {
                    expected_pcrs: claims.selected_pcrs.clone()
                }
            ),
            TpmVerdict::Accepted
        );
        assert_eq!(
            appraise_tpm(
                &claims,
                &TpmPolicy {
                    expected_pcrs: Vec::new()
                }
            ),
            TpmVerdict::BootStateDenied
        );
        assert_eq!(
            appraise_tpm(
                &verify_tpm(&evidence, binding, &credential, AnchorTime(21)).unwrap(),
                &TpmPolicy {
                    expected_pcrs: claims.selected_pcrs
                }
            ),
            TpmVerdict::CredentialExpired
        );
    }

    #[test]
    fn rejects_wrong_binding_and_log() {
        let (mut evidence, credential, binding) = fixture();
        let other = Binding::new(
            TPM_STATEMENT_V1,
            EventCommitment::from_digest(ProtocolDigest::from_bytes([1; 32])),
        );
        assert_eq!(
            verify_tpm(&evidence, other, &credential, AnchorTime(15)),
            Err(AttestationError::Binding)
        );
        let offset = evidence
            .proof
            .windows(32)
            .position(|window| window == [2; 32])
            .unwrap();
        evidence.proof[offset] ^= 1;
        assert_eq!(
            verify_tpm(&evidence, binding, &credential, AnchorTime(15)),
            Err(AttestationError::EventLog)
        );
    }
}
