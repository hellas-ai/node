//! Protocol primitives for Hellas commitments and signed streams.

pub mod commitment;
pub mod digest;
pub mod dtype;
pub mod identity;
pub mod job;
pub mod manifest;
pub mod schemes;
pub mod signature;
pub mod stream;
pub mod tags;
pub mod value;

pub use commitment::{RequestCommitment, SchemeId};
pub use digest::{ContentId, Digest, hash_tuple};
pub use dtype::{Dtype, ParseDtypeError};
pub use identity::{
    PlatformCredential, ProviderGenesisStatement, ProviderIdentityV1, RootKind, RootProof,
    SignedProviderGenesis,
};
pub use job::{AMD_SEV_SNP, APPLE_APP_ATTEST, AssuranceRequirement, JobTerms, TPM2_QUOTE};
pub use manifest::{EvaluateProgramManifest, FetchProgramManifest, ProgramManifest};
pub use schemes::evaluate::{Evaluate, EvaluateRequest};
pub use signature::{
    ProducerId, ProducerSigningKey, PublicKey, Signature, SignatureError, SignatureKind,
};
pub use stream::{
    CanonicalizationId, EventCommitment, InputCommitment, InputEventBody, InputEventBodyParts,
    InputEventEnvelope, InputTranscriptBuilder, OutputEventBody, OutputEventBodyParts,
    OutputEventEnvelope, OutputTranscriptBuilder, SignedInputEvent, SignedOutputEvent, StreamId,
    StreamVerifyError, input_genesis, output_genesis, verify_input_event_envelopes,
    verify_input_transcript, verify_output_event_envelopes, verify_output_transcript,
};
pub use value::{
    DagCborDecodeError, DagCborEncodeError, DagCborEncoder, JsonBytes, canonical_dag_cbor,
    decode_dag_cbor,
};
