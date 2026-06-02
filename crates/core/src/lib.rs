//! Protocol primitives for Hellas commitments and producer receipts.

pub mod commitment;
pub mod digest;
pub mod receipt;
pub mod scheme;
pub mod schemes;
pub mod signature;
pub mod stream;
pub mod tags;
pub mod value;

pub use commitment::{ReceiptCommitment, RequestCommitment, ResultCommitment, SchemeId};
pub use digest::{Digest, hash_tuple};
pub use receipt::{
    DeliveryOutput, DeliveryRequest, ReceiptBody, SignedReceipt, VerifyError, verify_delivery,
    verify_receipt,
};
pub use scheme::CommitmentScheme;
pub use schemes::symbolic::{Symbolic, SymbolicOutput, SymbolicRequest};
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
