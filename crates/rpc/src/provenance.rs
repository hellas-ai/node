//! Execution provenance — content-addressed identifiers that travel
//! alongside every gateway/executor RPC. Two boundaries to cross:
//!
//! - **Executor → gateway** over tonic Response metadata using the
//!   `x-hellas-*` keys defined below. Mirrors the OTel W3C trace-context
//!   propagation pattern; this module is the read/write half on both sides.
//! - **Gateway → HTTP client** over response headers (same names) and named
//!   SSE events. Translation happens in the gateway's tower layer and SSE
//!   handlers, not here.
//!
//! Wire form everywhere: 64-char lowercase hex of the underlying 32-byte
//! CID. Matches `hellas_runtime::cid::Cid<T>::Display` so a single value renders
//! identically in tracing logs, headers, and metadata. We carry raw bytes
//! in `ExecutionProvenance` rather than typed `Cid<T>` so this module
//! doesn't pull catgrad into the rpc crate's `client` feature; callers
//! reconstitute typed CIDs via `Cid::from_bytes` at their boundary.

use std::fmt::Write;
use thiserror::Error;
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};

/// Tonic metadata key for the runtime request commitment
/// (`Cid<TextExecution>`).
pub const COMMITMENT_HEADER: &str = "x-hellas-commitment-id";

/// Tonic metadata key for the runtime terminal receipt
/// (`Cid<TextReceipt>`).
pub const RECEIPT_HEADER: &str = "x-hellas-receipt-id";

/// HTTP header / tonic metadata key for the catnix `CallCommitment`.
/// This is the public gateway commitment header.
pub const CATNIX_COMMITMENT_HEADER: &str = "x-hellas-commitment";

/// HTTP header / tonic metadata key for the catnix receipt commitment.
/// Emitted by the gateway when a completed response attaches a terminal
/// [`CatnixReceiptCommitment`] extension.
pub const CATNIX_RECEIPT_HEADER: &str = "x-hellas-receipt";

/// Terminal catnix receipt commitment — BLAKE3 of the signed
/// `Claim`'s canonical body. The provenance tower layer renders it as
/// the `x-hellas-receipt` header. Lifetime is post-completion (only known when the
/// streaming `Outcome::Completed` arrives), in contrast to the
/// pre-flight `ExecutionProvenance::catnix_call_commitment`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CatnixReceiptCommitment(pub [u8; 32]);

impl std::fmt::Display for CatnixReceiptCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for CatnixReceiptCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// Pre-flight provenance for a single execution. The catnix receipt
/// commitment is terminal and travels via the streaming
/// `Outcome::Completed` payload.
///
/// `catnix_call_commitment` is the commitment over the projected
/// catnix `Term`. `None` when the executor could not project it.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecutionProvenance {
    pub commitment_id: [u8; 32],
    pub catnix_call_commitment: Option<[u8; 32]>,
}

/// Renders as the commitment's lowercase-hex string, matching how it
/// appears in tonic metadata and HTTP headers. Lets callers log
/// provenance with `%prov` (or `?Option<ExecutionProvenance>` for the
/// `Some(deadbeef…) | None` form tracing produces) instead of
/// hand-rolling the hex render.
impl std::fmt::Display for ExecutionProvenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.commitment_id {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Debug == Display so `?provenance` and `?Option<ExecutionProvenance>`
/// stay readable in tracing output. The default derive would render
/// `ExecutionProvenance { commitment_id: [171, 171, …] }` which is the
/// opposite of useful.
impl std::fmt::Debug for ExecutionProvenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProvenanceError {
    #[error("provenance metadata missing key `{key}`")]
    Missing { key: &'static str },
    #[error("provenance metadata key `{key}` is not printable ASCII")]
    NotAscii { key: &'static str },
    #[error("provenance metadata key `{key}` is not 64-char lowercase hex (got {len} chars)")]
    BadLength { key: &'static str, len: usize },
    #[error("provenance metadata key `{key}` contains a non-hex character")]
    BadHex { key: &'static str },
}

impl From<ProvenanceError> for tonic::Status {
    fn from(err: ProvenanceError) -> Self {
        tonic::Status::internal(err.to_string())
    }
}

/// Render a 32-byte CID as 64-char lowercase hex. Matches
/// `hellas_runtime::cid::Cid<T>::Display`.
pub fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in bytes {
        write!(&mut s, "{byte:02x}").expect("writing to String never fails");
    }
    s
}

/// Build an ASCII-typed tonic metadata value from a CID's bytes.
pub fn cid_bytes_to_metadata(bytes: &[u8; 32]) -> MetadataValue<Ascii> {
    encode_hex(bytes)
        .parse()
        .expect("64-char hex is always valid ASCII metadata")
}

/// Read a single CID-bearing key out of a tonic metadata map and decode
/// the hex value back into raw bytes.
pub fn cid_bytes_from_metadata(
    md: &MetadataMap,
    key: &'static str,
) -> Result<[u8; 32], ProvenanceError> {
    let value = md.get(key).ok_or(ProvenanceError::Missing { key })?;
    let s = value
        .to_str()
        .map_err(|_| ProvenanceError::NotAscii { key })?;
    if s.len() != 64 {
        return Err(ProvenanceError::BadLength { key, len: s.len() });
    }
    let bytes = s.as_bytes();
    let mut out = [0_u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[idx * 2]).ok_or(ProvenanceError::BadHex { key })?;
        let lo = hex_nibble(bytes[idx * 2 + 1]).ok_or(ProvenanceError::BadHex { key })?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

/// Read the pre-flight provenance from a tonic metadata map. Returns
/// `Err(Missing)` if the runtime commitment key is absent. The catnix
/// commitment is optional for compatibility with producers that do not
/// emit it yet.
pub fn read_provenance_metadata(md: &MetadataMap) -> Result<ExecutionProvenance, ProvenanceError> {
    let commitment_id = cid_bytes_from_metadata(md, COMMITMENT_HEADER)?;
    let catnix_call_commitment = match cid_bytes_from_metadata(md, CATNIX_COMMITMENT_HEADER) {
        Ok(bytes) => Some(bytes),
        // The new header is optional; absence is fine, only flag
        // genuinely-malformed values.
        Err(ProvenanceError::Missing { .. }) => None,
        Err(err) => return Err(err),
    };
    Ok(ExecutionProvenance {
        commitment_id,
        catnix_call_commitment,
    })
}

/// Insert pre-flight provenance into a tonic metadata map. Used
/// server-side on `Response::metadata_mut()` for both unary and
/// streaming RPCs.
pub fn write_provenance_metadata(md: &mut MetadataMap, prov: &ExecutionProvenance) {
    md.insert(
        COMMITMENT_HEADER,
        cid_bytes_to_metadata(&prov.commitment_id),
    );
    if let Some(catnix) = &prov.catnix_call_commitment {
        md.insert(CATNIX_COMMITMENT_HEADER, cid_bytes_to_metadata(catnix));
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ExecutionProvenance {
        ExecutionProvenance {
            commitment_id: [0xab; 32],
            catnix_call_commitment: None,
        }
    }

    fn sample_with_catnix() -> ExecutionProvenance {
        ExecutionProvenance {
            commitment_id: [0xab; 32],
            catnix_call_commitment: Some([0xcd; 32]),
        }
    }

    #[test]
    fn encode_hex_renders_lowercase_hex() {
        let s = encode_hex(&[0xab; 32]);
        assert_eq!(s.len(), 64);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(s, "ab".repeat(32));
    }

    #[test]
    fn round_trip_through_metadata() {
        let prov = sample();
        let mut md = MetadataMap::new();
        write_provenance_metadata(&mut md, &prov);
        let decoded = read_provenance_metadata(&md).expect("round-trip should succeed");
        assert_eq!(decoded, prov);
        assert!(!md.contains_key(CATNIX_COMMITMENT_HEADER));
    }

    #[test]
    fn round_trip_with_catnix_commitment() {
        let prov = sample_with_catnix();
        let mut md = MetadataMap::new();
        write_provenance_metadata(&mut md, &prov);
        // Both headers should be present.
        assert!(md.contains_key(COMMITMENT_HEADER));
        assert!(md.contains_key(CATNIX_COMMITMENT_HEADER));
        let decoded = read_provenance_metadata(&md).expect("round-trip should succeed");
        assert_eq!(decoded, prov);
    }

    #[test]
    fn missing_catnix_commitment_reads_as_none() {
        let mut md = MetadataMap::new();
        md.insert(COMMITMENT_HEADER, "ab".repeat(32).parse().unwrap());
        let decoded = read_provenance_metadata(&md).expect("runtime commitment should parse");
        assert_eq!(decoded.commitment_id, [0xab; 32]);
        assert_eq!(decoded.catnix_call_commitment, None);
    }

    #[test]
    fn missing_key_reports_which_key() {
        let md = MetadataMap::new();
        let err = read_provenance_metadata(&md).expect_err("empty metadata must fail");
        assert_eq!(
            err,
            ProvenanceError::Missing {
                key: COMMITMENT_HEADER
            }
        );
    }

    #[test]
    fn bad_length_reports_actual_length() {
        let mut md = MetadataMap::new();
        md.insert(COMMITMENT_HEADER, "deadbeef".parse().unwrap());
        let err = read_provenance_metadata(&md).expect_err("too-short value must fail");
        assert_eq!(
            err,
            ProvenanceError::BadLength {
                key: COMMITMENT_HEADER,
                len: 8
            }
        );
    }

    #[test]
    fn bad_hex_rejected() {
        let mut md = MetadataMap::new();
        md.insert(COMMITMENT_HEADER, "z".repeat(64).parse().unwrap());
        let err = read_provenance_metadata(&md).expect_err("non-hex value must fail");
        assert_eq!(
            err,
            ProvenanceError::BadHex {
                key: COMMITMENT_HEADER
            }
        );
    }

    #[test]
    fn uppercase_hex_rejected() {
        // Display is lowercase; we reject uppercase so the wire form is unambiguous.
        let mut md = MetadataMap::new();
        md.insert(COMMITMENT_HEADER, "AB".repeat(32).parse().unwrap());
        let err = read_provenance_metadata(&md).expect_err("uppercase hex must fail");
        assert_eq!(
            err,
            ProvenanceError::BadHex {
                key: COMMITMENT_HEADER
            }
        );
    }

    /// `CATNIX_COMMITMENT_HEADER` is optional, but a present malformed
    /// value must be rejected rather than silently dropped.
    #[test]
    fn catnix_commitment_bad_length_rejected() {
        let mut md = MetadataMap::new();
        md.insert(COMMITMENT_HEADER, "ab".repeat(32).parse().unwrap());
        md.insert(CATNIX_COMMITMENT_HEADER, "deadbeef".parse().unwrap());
        let err = read_provenance_metadata(&md).expect_err("short catnix header must fail");
        assert_eq!(
            err,
            ProvenanceError::BadLength {
                key: CATNIX_COMMITMENT_HEADER,
                len: 8,
            }
        );
    }

    #[test]
    fn catnix_commitment_bad_hex_rejected() {
        let mut md = MetadataMap::new();
        md.insert(COMMITMENT_HEADER, "ab".repeat(32).parse().unwrap());
        md.insert(CATNIX_COMMITMENT_HEADER, "z".repeat(64).parse().unwrap());
        let err = read_provenance_metadata(&md).expect_err("non-hex catnix header must fail");
        assert_eq!(
            err,
            ProvenanceError::BadHex {
                key: CATNIX_COMMITMENT_HEADER,
            }
        );
    }

    #[test]
    fn catnix_commitment_uppercase_hex_rejected() {
        let mut md = MetadataMap::new();
        md.insert(COMMITMENT_HEADER, "ab".repeat(32).parse().unwrap());
        md.insert(CATNIX_COMMITMENT_HEADER, "AB".repeat(32).parse().unwrap());
        let err = read_provenance_metadata(&md).expect_err("uppercase catnix header must fail");
        assert_eq!(
            err,
            ProvenanceError::BadHex {
                key: CATNIX_COMMITMENT_HEADER,
            }
        );
    }
}
