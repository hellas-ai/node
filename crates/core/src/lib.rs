//! Protocol primitives for Hellas commitments and producer receipts.

pub mod adaptors;
pub mod commitment;
pub mod digest;
pub mod protocol;
pub mod receipt;
pub mod scheme;
pub mod schemes;
pub mod signature;
pub mod tags;
pub mod value;

pub use commitment::{ReceiptCommitment, RequestCommitment, ResultCommitment, SchemeId};
pub use digest::{Digest, hash_tuple};
// Keep protocol-layer types under `protocol::` so callers explicitly
// choose the commitment domain they are operating in. Some byte values
// overlap between domains but carry different semantics.
pub use receipt::{
    DeliveryOutput, DeliveryRequest, ReceiptBody, SignedReceipt, VerifyError, verify_delivery,
    verify_receipt,
};
pub use scheme::CommitmentScheme;
pub use schemes::opaque::{Opaque, OpaqueRequest};
pub use schemes::symbolic::{Symbolic, SymbolicOutput, SymbolicRequest};
pub use signature::{
    ProducerId, ProducerSigningKey, PublicKey, Signature, SignatureError, SignatureKind,
};
pub use value::{
    DagCborDecodeError, DagCborEncodeError, DagCborEncoder, JsonBytes, canonical_dag_cbor,
    decode_dag_cbor,
};
