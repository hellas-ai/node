pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_REV: &str = match option_env!("GIT_REV") {
    Some(rev) => rev,
    None => "unknown",
};

#[cfg(feature = "node")]
pub mod error;

#[cfg(feature = "node")]
pub mod model;

pub mod call;
#[cfg(feature = "fetch")]
pub mod fetch;
pub mod peers;
pub mod protocol;
#[cfg(feature = "execute")]
pub mod run_ticket;
pub mod serve;
pub mod spec;
#[cfg(feature = "execute")]
pub mod stream;
pub use spec::ModelSpec;

#[cfg(feature = "node")]
pub mod policy;

pub mod provenance;

pub use protocol::{
    AssuranceStrategy, CanonicalizationId, CommitmentScheme, DagCborDecodeError,
    DagCborEncodeError, DagCborEncoder, DeliveryOutput, DeliveryRequest, Digest, Evaluate,
    EvaluateOutput, EvaluateRequest, EventCommitment, InputCommitment, InputEventBody,
    InputEventBodyParts, InputEventEnvelope, InputTranscriptBuilder, JsonBytes, OutputEventBody,
    OutputEventBodyParts, OutputEventEnvelope, OutputTranscriptBuilder, ProducerId,
    ProducerSigningKey, PublicKey, ReceiptBody, ReceiptCommitment, RequestCommitment,
    ResultCommitment, SchemeId, Signature, SignatureError, SignatureKind, SignedInputEvent,
    SignedOutputEvent, SignedReceipt, StreamId, StreamVerifyError, VerifyError, canonical_dag_cbor,
    decode_dag_cbor, hash_tuple, input_genesis, output_genesis, verify_delivery,
    verify_input_event_envelopes, verify_input_transcript, verify_output_event_envelopes,
    verify_output_transcript, verify_receipt,
};
pub use protocol::{commitment, digest, signature, tags, value};

/// Protobuf-generated message types plus per-service typed client traits,
/// method markers, and server dispatchers. The bare `pb` module is
/// doc-hidden; use the per-service re-exports under
/// `pb::{courtesy, swarm, execute, fetch, evaluate}` or the marker and
/// handler modules under `pb::services::*`.
#[doc(hidden)]
pub mod pb;

/// Service marker and handler modules.
pub use crate::pb::services;

#[cfg(feature = "node")]
pub use error::ExecutorError;

#[cfg(feature = "node")]
pub use model::ModelAssetsError;

/// Default bound on the in-memory execution queue carried by `hellas_executor::Executor`.
#[cfg(feature = "node")]
pub const DEFAULT_EXECUTION_QUEUE_CAPACITY: usize = 8;

/// Default maximum number of Fetch provider streams running at once.
#[cfg(feature = "node")]
pub const DEFAULT_FETCH_MAX_IN_FLIGHT: usize = 16;

/// Default bound on Fetch executions waiting behind active provider streams.
#[cfg(feature = "node")]
pub const DEFAULT_FETCH_QUEUE_CAPACITY: usize = 64;

const TOKEN_BYTES_LEN: usize = std::mem::size_of::<u32>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBytesError {
    len: usize,
}

impl std::fmt::Display for TokenBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "token byte payload length {} is not divisible by 4",
            self.len
        )
    }
}

impl std::error::Error for TokenBytesError {}

impl From<TokenBytesError> for hellas_wire::WireStatus {
    fn from(err: TokenBytesError) -> Self {
        hellas_wire::WireStatus::new(hellas_wire::WireCode::InvalidArgument, err.to_string())
    }
}

pub fn encode_token_ids(token_ids: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(token_ids.len() * TOKEN_BYTES_LEN);
    for token_id in token_ids {
        bytes.extend_from_slice(&token_id.to_le_bytes());
    }
    bytes
}

pub fn decode_token_ids(bytes: &[u8]) -> Result<Vec<u32>, TokenBytesError> {
    let (chunks, remainder) = bytes.as_chunks::<TOKEN_BYTES_LEN>();
    if !remainder.is_empty() {
        return Err(TokenBytesError { len: bytes.len() });
    }

    Ok(chunks
        .iter()
        .map(|chunk| u32::from_le_bytes(*chunk))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{TokenBytesError, decode_token_ids, encode_token_ids};

    #[test]
    fn token_ids_round_trip_through_bytes() {
        let token_ids = [1, 42, u32::MAX, 7];
        let encoded = encode_token_ids(&token_ids);
        let decoded = decode_token_ids(&encoded).expect("token bytes should decode");
        assert_eq!(decoded, token_ids);
    }

    #[test]
    fn decode_rejects_partial_token_bytes() {
        let err = decode_token_ids(&[1, 2, 3]).expect_err("partial token bytes must fail");
        assert_eq!(err, TokenBytesError { len: 3 });
    }
}
