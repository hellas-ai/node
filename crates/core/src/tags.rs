pub const HASH_TUPLE_V1: &str = "hellas.hash_tuple.v1";
pub const RECEIPT_SIGNATURE_V1: &str = "hellas.commitment.receipt.v1";
pub const PRODUCER_ID_V1: &str = "hellas.producer_id.v1";

pub const OPAQUE_REQUEST_V1: &str = "hellas.opaque.request.v1";
pub const OPAQUE_RESULT_V1: &str = "hellas.opaque.result.v1";
pub const RECEIPT_BODY_V1: &str = "hellas.receipt.body.v1";

pub const SCHEME_SYMBOLIC: u8 = 0x00;
pub const SCHEME_OPAQUE: u8 = 0x01;
pub const SCHEME_ZKTLS: u8 = 0x02;

pub const SIGNATURE_SECP256K1: u8 = 0x00;

// ---- AXES.md pass 3 protocol-layer tags (used by `crate::protocol`).
// Domain separation for kernel-level commitments. Per-adaptor canonical
// payload bytes carry their own `hellas.<adaptor>.{request,result}.vN`
// tag inside `CanonicalPayload`; these outer tags wrap the kernel-level
// commitment computation so a raw payload hash can't collide with a
// commitment hash.

pub const CALL_V1: &str = "hellas.call.v1";
pub const RESULT_V1: &str = "hellas.result.v1";
pub const CLAIM_V1: &str = "hellas.claim.v1";
