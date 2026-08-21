pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_REV: &str = match option_env!("GIT_REV") {
    Some(rev) => rev,
    None => "unknown",
};

pub mod call;
#[cfg(feature = "evaluate")]
pub mod evaluate;
#[cfg(feature = "fetch")]
pub mod fetch;
#[cfg(feature = "execute")]
pub mod open;
#[cfg(feature = "fetch")]
pub mod output;
/// Peer registry, admission, and connection directory module.
pub mod peers;
pub mod protocol;
#[cfg(feature = "execute")]
pub mod run_ticket;
pub mod serve;
pub mod spec;
#[cfg(feature = "execute")]
pub mod stream;
/// The paid-work RPC: the acceptance exchange, its two endpoints, and
/// the refusals they answer with.
#[cfg(feature = "work")]
pub mod work;
/// Settling paid work on chain: the finalized cursor every deadline is
/// measured against, and the close that spends a certificate.
#[cfg(feature = "work")]
pub mod work_close;
/// Durable endpoint state for paid work: the setup journal, the channel
/// journal, and the counterparty loss ledger.
#[cfg(feature = "work")]
pub mod work_store;
pub use spec::ModelSpec;

/// Execution authorization policy module.
#[cfg(feature = "execute")]
pub mod policy;

pub mod provenance;

#[cfg(feature = "execute")]
mod tokens;
#[cfg(feature = "execute")]
pub use tokens::{TokenBytesError, decode_token_ids, encode_token_ids};

pub use protocol::{
    APPLE_APP_ATTEST, AppleAppAttestEnrollment, Assurance, CanonicalizationId, ContentId,
    DagCborDecodeError, DagCborDecoder, DagCborEncodeError, DagCborEncoder, Digest, Dtype,
    Evaluate, EvaluateProgramManifest, EvaluateRequest, EventCommitment, FetchProgramManifest,
    InputCommitment, InputEventBody, InputEventBodyParts, InputEventEnvelope,
    InputTranscriptBuilder, JobTerms, JsonBytes, OPEN_EXPORTER_LEN, OPEN_NONCE_LEN,
    OPEN_PROOF_DOMAIN, OPEN_PROVIDER_ROLE, Operation, OutputEventBody, OutputEventBodyParts,
    OutputEventEnvelope, OutputTranscriptBuilder, ParseDtypeError, PlatformCredential,
    PlatformEnrollment, ProducerId, ProducerSigningKey, ProgramManifest, ProviderEnrollmentBundle,
    ProviderGenesisDecodeError, ProviderGenesisStatement, ProviderIdentityV1, PublicKey,
    RequestCommitment, Retention, RootKind, RootProof, SchemeId, Signature, SignatureError,
    SignatureKind, SignedInputEvent, SignedOutputEvent, SignedProviderGenesis, StreamId,
    StreamVerifyError, canonical_dag_cbor, decode_dag_cbor, hash_tuple, input_genesis,
    open_proof_binding, output_genesis, scheme_id, verify_input_event_envelopes,
    verify_input_transcript, verify_output_event_envelopes, verify_output_transcript,
};
pub use protocol::{commitment, digest, retention, signature, tags, value};

/// Protobuf-generated message types plus per-service typed client traits,
/// method markers, and server dispatchers. The bare `pb` module is
/// doc-hidden; use the per-service re-exports under
/// `pb::{courtesy, swarm, execute, fetch, evaluate}` or the marker and
/// handler modules under `pb::services::*`.
#[doc(hidden)]
pub mod pb;

/// Service marker and handler modules.
pub use crate::pb::services;

/// ALPN/FQN service aliases derived from this crate's generated service
/// catalogue, for injecting into [`peers::PeerDirectoryConfig`]. p2p is
/// protocol-agnostic and ships an empty alias table; this is where the
/// concrete services get wired in.
pub fn peer_service_aliases() -> Vec<peers::ServiceAlias> {
    crate::services::KNOWN_SERVICES
        .iter()
        .flat_map(|entry| {
            [
                peers::ServiceAlias::new(entry.alpn, entry.name),
                peers::ServiceAlias::new(entry.name, entry.name),
            ]
        })
        .collect()
}

/// A [`peers::PeerDirectoryConfig`] preseeded with [`peer_service_aliases`].
pub fn peer_directory_config() -> peers::PeerDirectoryConfig {
    peers::PeerDirectoryConfig {
        service_aliases: peer_service_aliases(),
        ..Default::default()
    }
}

/// Default bound on the in-memory execution queue carried by `hellas_executor::Executor`.
#[cfg(feature = "execute")]
pub const DEFAULT_EXECUTION_QUEUE_CAPACITY: usize = 8;

/// Default maximum number of Fetch provider streams running at once.
#[cfg(feature = "execute")]
pub const DEFAULT_FETCH_MAX_IN_FLIGHT: usize = 16;

/// Default bound on Fetch executions waiting behind active provider streams.
#[cfg(feature = "execute")]
pub const DEFAULT_FETCH_QUEUE_CAPACITY: usize = 64;
