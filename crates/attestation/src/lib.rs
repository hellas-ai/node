#[cfg(feature = "apple-app-attest")]
mod apple;
#[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
mod apple_macos;

use std::future::Future;

use hellas_rpc::pb::execute::{AssuranceEvidence, WorkFinished};
use hellas_rpc::stream::output_event_to_pb;
use hellas_rpc::{DagCborEncoder, Digest, EventCommitment, OutputEventEnvelope};

#[cfg(feature = "apple-app-attest")]
pub use apple::{
    AppleClaims, AppleCredential, ApplePolicy, AppleVerdict, RegisteredAppleCredential,
    apple_credential_identity, appraise_apple, register_apple, verify_apple,
    verify_apple_assertion,
};
#[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
pub use apple_macos::{AppleAppAttest, client_data_hash};

#[cfg(feature = "apple-app-attest")]
pub const APPLE_STATEMENT_V1: &str = "hellas.attestation.apple.app-attest.statement.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding(Digest);

impl Binding {
    pub fn new(statement_tag: &str, terminal: EventCommitment) -> Self {
        let mut e = DagCborEncoder::new();
        e.array(2);
        e.str(statement_tag);
        e.bytes(terminal.as_bytes());
        Self(Digest::hash(&e.into_bytes()))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorTime(pub u64);

pub trait Attester {
    fn attest(
        &self,
        binding: Binding,
    ) -> impl Future<Output = Result<AssuranceEvidence, AttestationError>> + Send;
}

pub struct Attested<S, A> {
    pub signed: S,
    pub attester: A,
    pub statement_tag: &'static str,
}

impl<S, A> Attested<S, A>
where
    S: AsRef<[OutputEventEnvelope]> + IntoIterator<Item = OutputEventEnvelope>,
    A: Attester,
{
    pub async fn finish(self) -> Result<WorkFinished, AttestationError> {
        let terminal = self
            .signed
            .as_ref()
            .last()
            .ok_or(AttestationError::Malformed("signed transcript"))?
            .event_commitment();
        let evidence = self
            .attester
            .attest(Binding::new(self.statement_tag, terminal))
            .await?;
        Ok(WorkFinished {
            output_events: self
                .signed
                .into_iter()
                .map(|event| output_event_to_pb(&event))
                .collect(),
            assurance_evidence: vec![evidence],
        })
    }
}

#[derive(Clone)]
pub struct MockAttester {
    pub codec: &'static str,
    pub credential: Vec<u8>,
}

impl Attester for MockAttester {
    async fn attest(&self, binding: Binding) -> Result<AssuranceEvidence, AttestationError> {
        Ok(AssuranceEvidence {
            codec: self.codec.into(),
            credential: self.credential.clone(),
            proof: binding.as_bytes().to_vec(),
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("wrong evidence codec")]
    Codec,
    #[error("invalid evidence credential")]
    Credential,
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("evidence does not bind the terminal event")]
    Binding,
    #[error("evidence signature is invalid")]
    Signature,
    #[cfg(all(target_os = "macos", feature = "apple-app-attest"))]
    #[error("Apple App Attest failed: {0}")]
    Platform(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::{
        APPLE_APP_ATTEST, CanonicalizationId, Digest, InputCommitment, OutputTranscriptBuilder,
        ProducerSigningKey, SchemeId,
    };

    const TEST_STATEMENT: &str = "hellas.attestation.test.statement.v1";

    #[tokio::test]
    async fn attested_preserves_signed_value_and_binds_terminal() {
        let key = ProducerSigningKey::from_secret_bytes([7; 32]).unwrap();
        let mut builder = OutputTranscriptBuilder::new(
            SchemeId::Evaluate,
            InputCommitment::from_digest(Digest::from_bytes([8; 32])),
            &key,
            CanonicalizationId::from_bytes(b"test"),
        );
        builder.push("terminal", b"done").unwrap();
        let (events, terminal) = builder.finish().unwrap();
        let finished = Attested {
            signed: events,
            attester: MockAttester {
                codec: APPLE_APP_ATTEST,
                credential: Vec::new(),
            },
            statement_tag: TEST_STATEMENT,
        }
        .finish()
        .await
        .unwrap();

        assert_eq!(finished.output_events.len(), 1);
        let evidence = &finished.assurance_evidence[0];
        assert_eq!(
            evidence.proof,
            Binding::new(TEST_STATEMENT, terminal).as_bytes()
        );
    }
}
