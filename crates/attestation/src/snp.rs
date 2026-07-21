use hellas_rpc::AMD_SEV_SNP;
use hellas_rpc::pb::execute::AssuranceEvidence;
use p384::ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha384};

use crate::{AnchorTime, AttestationError, Binding, Validity};

const REPORT_LEN: usize = 1184;
const SIGNED_LEN: usize = 0x2a0;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnpCollateral {
    pub verifying_key: [u8; 49],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnpEndorsement {
    Vcek,
    Vlek,
    Masked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnpPolicy {
    pub minimum_tcb: [u8; 8],
    pub launch_measurements: Vec<[u8; 48]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnpVerdict {
    Accepted,
    CollateralNotYetValid,
    CollateralExpired,
    TcbBelowMinimum,
    LaunchMeasurementDenied,
}

/// A genuine platform launched a guest with this initial-memory measurement, which endorsed this statement.
/// This does not prove runtime-loaded model weights match the manifest; launch measurement excludes them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnpClaims {
    pub launch_measurement: [u8; 48],
    pub reported_tcb: [u8; 8],
    pub endorsement: SnpEndorsement,
    pub collateral: Validity,
}

pub fn appraise_snp(claims: &SnpClaims, policy: &SnpPolicy) -> SnpVerdict {
    match claims.collateral {
        Validity::NotYetValid => SnpVerdict::CollateralNotYetValid,
        Validity::Expired => SnpVerdict::CollateralExpired,
        Validity::Current
            if ![0, 1, 6, 7]
                .into_iter()
                .all(|i| claims.reported_tcb[i] >= policy.minimum_tcb[i]) =>
        {
            SnpVerdict::TcbBelowMinimum
        }
        Validity::Current
            if !policy
                .launch_measurements
                .contains(&claims.launch_measurement) =>
        {
            SnpVerdict::LaunchMeasurementDenied
        }
        Validity::Current => SnpVerdict::Accepted,
    }
}

pub fn verify_snp(
    evidence: &AssuranceEvidence,
    expected: Binding,
    collateral: &SnpCollateral,
    anchor: AnchorTime,
) -> Result<SnpClaims, AttestationError> {
    if evidence.codec != AMD_SEV_SNP {
        return Err(AttestationError::Codec);
    }
    if !evidence.credential.is_empty() {
        return Err(AttestationError::Credential);
    }
    if collateral.not_before > collateral.not_after {
        return Err(AttestationError::Malformed("SNP collateral"));
    }
    let report: &[u8; REPORT_LEN] = evidence
        .proof
        .as_slice()
        .try_into()
        .map_err(|_| AttestationError::Malformed("SNP report"))?;
    let version = u32::from_le_bytes(report[0..4].try_into().unwrap());
    let signature_algorithm = u32::from_le_bytes(report[0x34..0x38].try_into().unwrap());
    if !(2..=5).contains(&version) || signature_algorithm != 1 {
        return Err(AttestationError::Malformed("SNP report"));
    }
    if report[0x50..0x70] != expected.as_bytes()[..] || report[0x70..0x90] != [0; 32] {
        return Err(AttestationError::Binding);
    }

    let key_info = u32::from_le_bytes(report[0x48..0x4c].try_into().unwrap());
    let endorsement = match ((key_info >> 1) & 1, (key_info >> 2) & 7) {
        (0, 0) => SnpEndorsement::Vcek,
        (0, 1) => SnpEndorsement::Vlek,
        (1, 0) => SnpEndorsement::Masked,
        _ => return Err(AttestationError::Malformed("SNP key info")),
    };
    let signature = Signature::from_scalars(
        scalar(report, SIGNED_LEN)?,
        scalar(report, SIGNED_LEN + 72)?,
    )
    .map_err(|_| AttestationError::Signature)?;
    let key = VerifyingKey::from_sec1_bytes(&collateral.verifying_key)
        .map_err(|_| AttestationError::Credential)?;
    key.verify_prehash(&Sha384::digest(&report[..SIGNED_LEN]), &signature)
        .map_err(|_| AttestationError::Signature)?;

    let mut launch_measurement = [0; 48];
    launch_measurement.copy_from_slice(&report[0x90..0xc0]);
    let mut reported_tcb = [0; 8];
    reported_tcb.copy_from_slice(&report[0x180..0x188]);
    Ok(SnpClaims {
        launch_measurement,
        reported_tcb,
        endorsement,
        collateral: Validity::at(anchor, collateral.not_before, collateral.not_after),
    })
}

fn scalar(report: &[u8; REPORT_LEN], offset: usize) -> Result<[u8; 48], AttestationError> {
    if report[offset + 48..offset + 72] != [0; 24] {
        return Err(AttestationError::Malformed("SNP signature"));
    }
    let mut scalar = [0; 48];
    for (to, from) in scalar.iter_mut().rev().zip(&report[offset..offset + 48]) {
        *to = *from;
    }
    Ok(scalar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Binding, SNP_STATEMENT_V1};
    use hellas_rpc::{Digest as ProtocolDigest, EventCommitment};
    use p384::ecdsa::SigningKey;
    use p384::ecdsa::signature::hazmat::PrehashSigner;

    fn fixture(
        endorsement: SnpEndorsement,
        tcb: [u8; 8],
    ) -> (AssuranceEvidence, SnpCollateral, Binding) {
        let key = SigningKey::from_bytes((&[7; 48]).into()).unwrap();
        let terminal = EventCommitment::from_digest(ProtocolDigest::from_bytes([8; 32]));
        let binding = Binding::new(SNP_STATEMENT_V1, terminal);
        let mut report = [0; REPORT_LEN];
        report[..4].copy_from_slice(&3_u32.to_le_bytes());
        report[0x34..0x38].copy_from_slice(&1_u32.to_le_bytes());
        let key_info = match endorsement {
            SnpEndorsement::Vcek => 0,
            SnpEndorsement::Vlek => 1 << 2,
            SnpEndorsement::Masked => 1 << 1,
        };
        report[0x48..0x4c].copy_from_slice(&u32::to_le_bytes(key_info));
        report[0x50..0x70].copy_from_slice(binding.as_bytes());
        report[0x90..0xc0].copy_from_slice(&[9; 48]);
        report[0x180..0x188].copy_from_slice(&tcb);
        let signature: Signature = key
            .sign_prehash(&Sha384::digest(&report[..SIGNED_LEN]))
            .unwrap();
        let bytes = signature.to_bytes();
        for (to, from) in report[SIGNED_LEN..SIGNED_LEN + 48]
            .iter_mut()
            .zip(bytes[..48].iter().rev())
        {
            *to = *from;
        }
        for (to, from) in report[SIGNED_LEN + 72..SIGNED_LEN + 120]
            .iter_mut()
            .zip(bytes[48..].iter().rev())
        {
            *to = *from;
        }
        let verifying_key = key.verifying_key().to_encoded_point(true);
        (
            AssuranceEvidence {
                codec: AMD_SEV_SNP.into(),
                credential: Vec::new(),
                proof: report.to_vec(),
            },
            SnpCollateral {
                verifying_key: verifying_key.as_bytes().try_into().unwrap(),
                not_before: 10,
                not_after: 20,
            },
            binding,
        )
    }

    #[test]
    fn verifies_report_and_models_verdicts() {
        let policy = SnpPolicy {
            minimum_tcb: [1, 1, 0, 0, 0, 0, 1, 1],
            launch_measurements: vec![[9; 48]],
        };
        for endorsement in [
            SnpEndorsement::Vcek,
            SnpEndorsement::Vlek,
            SnpEndorsement::Masked,
        ] {
            let (evidence, collateral, binding) = fixture(endorsement, [2; 8]);
            let claims = verify_snp(&evidence, binding, &collateral, AnchorTime(15)).unwrap();
            assert_eq!(claims.endorsement, endorsement);
            assert_eq!(claims.collateral, Validity::Current);
            assert_eq!(claims.launch_measurement, [9; 48]);
            assert_eq!(appraise_snp(&claims, &policy), SnpVerdict::Accepted);
            assert_eq!(
                appraise_snp(
                    &claims,
                    &SnpPolicy {
                        minimum_tcb: policy.minimum_tcb,
                        launch_measurements: Vec::new()
                    }
                ),
                SnpVerdict::LaunchMeasurementDenied
            );
        }

        let (evidence, collateral, binding) = fixture(SnpEndorsement::Vcek, [0; 8]);
        let claims = verify_snp(&evidence, binding, &collateral, AnchorTime(9)).unwrap();
        assert_eq!(claims.collateral, Validity::NotYetValid);
        assert_eq!(
            appraise_snp(&claims, &policy),
            SnpVerdict::CollateralNotYetValid
        );
        let current = verify_snp(&evidence, binding, &collateral, AnchorTime(15)).unwrap();
        assert_eq!(appraise_snp(&current, &policy), SnpVerdict::TcbBelowMinimum);
        assert_eq!(
            appraise_snp(
                &verify_snp(&evidence, binding, &collateral, AnchorTime(21)).unwrap(),
                &policy
            ),
            SnpVerdict::CollateralExpired
        );
    }

    #[test]
    fn rejects_wrong_binding_and_tampering() {
        let (mut evidence, collateral, binding) = fixture(SnpEndorsement::Vcek, [2; 8]);
        let other = Binding::new(
            SNP_STATEMENT_V1,
            EventCommitment::from_digest(ProtocolDigest::from_bytes([1; 32])),
        );
        assert_eq!(
            verify_snp(&evidence, other, &collateral, AnchorTime(15)),
            Err(AttestationError::Binding)
        );
        evidence.proof[0x90] ^= 1;
        assert_eq!(
            verify_snp(&evidence, binding, &collateral, AnchorTime(15)),
            Err(AttestationError::Signature)
        );
    }
}
