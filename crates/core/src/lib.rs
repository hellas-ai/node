//! Protocol primitives for Hellas commitments and producer receipts.

pub mod commitment;
pub mod digest;
pub mod receipt;
pub mod scheme;
pub mod schemes;
pub mod signature;
pub mod tags;
pub mod value;

pub use commitment::{Commitment, EvidenceCommitment, ReceiptCommitment, SchemeId};
pub use digest::{Digest, hash_tuple};
pub use receipt::{
    DeliveryOutput, DeliveryRequest, EvidencedReceiptBody, ReceiptBody, ReceiptEnvelope,
    RequestCommitment, ResultCommitment, SignedEvidenceReceipt, SignedReceipt, VerifyError,
    verify_delivery, verify_receipt,
};
pub use scheme::{CommitmentScheme, EvidencedScheme};
pub use schemes::opaque::{Opaque, OpaqueRequest};
pub use schemes::symbolic::{Symbolic, SymbolicEvidence, SymbolicOutput, SymbolicRequest};
pub use signature::{
    ProducerId, ProducerSigningKey, PublicKey, Signature, SignatureError, SignatureKind,
};
pub use value::{
    DagCborDecodeError, DagCborEncodeError, DagCborEncoder, JsonBytes, canonical_dag_cbor,
    decode_dag_cbor,
};
