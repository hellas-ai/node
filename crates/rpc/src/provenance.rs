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
//! CID. Matches `catgrad::cid::Cid<T>::Display` so a single value renders
//! identically in tracing logs, headers, and metadata. We carry raw bytes
//! in `ExecutionProvenance` rather than typed `Cid<T>` so this module
//! doesn't pull catgrad into the rpc crate's `client` feature; callers
//! reconstitute typed CIDs via `Cid::from_bytes` at their boundary.

use std::fmt::Write;
use thiserror::Error;
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};

/// HTTP header / tonic metadata key for the request commitment
/// (`Cid<TextExecution>` — hash over program, parameter CIDs, prompt
/// tokens, policy). The commitment transitively names the program, so we
/// don't expose the program CID separately.
pub const COMMITMENT_HEADER: &str = "x-hellas-commitment-id";

/// HTTP header / tonic metadata key for the terminal execution receipt
/// (`Cid<TextReceipt>`). On streaming responses this only appears as an
/// SSE in-band event, not as a header (the receipt is unknown at
/// header-flush time).
pub const RECEIPT_HEADER: &str = "x-hellas-receipt-id";

/// Pre-flight provenance for a single execution. The receipt CID is
/// terminal and not part of this struct — it travels via the streaming
/// `Outcome::Completed` payload (and from there into a separate
/// `Cid<TextReceipt>` extension on the HTTP response when applicable).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionProvenance {
    pub commitment_id: [u8; 32],
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProvenanceError {
    #[error("provenance metadata missing key `{key}`")]
    Missing { key: &'static str },
    #[error("provenance metadata key `{key}` is not printable ASCII")]
    NotAscii { key: &'static str },
    #[error(
        "provenance metadata key `{key}` is not 64-char lowercase hex (got {len} chars)"
    )]
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
/// `catgrad::cid::Cid<T>::Display`.
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
/// `Err(Missing)` if the commitment key is absent, so older servers that
/// don't set provenance are detectable.
pub fn read_provenance_metadata(md: &MetadataMap) -> Result<ExecutionProvenance, ProvenanceError> {
    Ok(ExecutionProvenance {
        commitment_id: cid_bytes_from_metadata(md, COMMITMENT_HEADER)?,
    })
}

/// Insert pre-flight provenance into a tonic metadata map. Used
/// server-side on `Response::metadata_mut()` for both unary and
/// streaming RPCs.
pub fn write_provenance_metadata(md: &mut MetadataMap, prov: &ExecutionProvenance) {
    md.insert(COMMITMENT_HEADER, cid_bytes_to_metadata(&prov.commitment_id));
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
        }
    }

    #[test]
    fn encode_hex_renders_lowercase_hex() {
        let s = encode_hex(&[0xab; 32]);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(s, "ab".repeat(32));
    }

    #[test]
    fn round_trip_through_metadata() {
        let prov = sample();
        let mut md = MetadataMap::new();
        write_provenance_metadata(&mut md, &prov);
        let decoded = read_provenance_metadata(&md).expect("round-trip should succeed");
        assert_eq!(decoded, prov);
    }

    #[test]
    fn missing_key_reports_which_key() {
        let md = MetadataMap::new();
        let err = read_provenance_metadata(&md).expect_err("empty metadata must fail");
        assert_eq!(err, ProvenanceError::Missing { key: COMMITMENT_HEADER });
    }

    #[test]
    fn bad_length_reports_actual_length() {
        let mut md = MetadataMap::new();
        md.insert(COMMITMENT_HEADER, "deadbeef".parse().unwrap());
        let err = read_provenance_metadata(&md).expect_err("too-short value must fail");
        assert_eq!(err, ProvenanceError::BadLength { key: COMMITMENT_HEADER, len: 8 });
    }

    #[test]
    fn bad_hex_rejected() {
        let mut md = MetadataMap::new();
        md.insert(COMMITMENT_HEADER, "z".repeat(64).parse().unwrap());
        let err = read_provenance_metadata(&md).expect_err("non-hex value must fail");
        assert_eq!(err, ProvenanceError::BadHex { key: COMMITMENT_HEADER });
    }

    #[test]
    fn uppercase_hex_rejected() {
        // Display is lowercase; we reject uppercase so the wire form is unambiguous.
        let mut md = MetadataMap::new();
        md.insert(COMMITMENT_HEADER, "AB".repeat(32).parse().unwrap());
        let err = read_provenance_metadata(&md).expect_err("uppercase hex must fail");
        assert_eq!(err, ProvenanceError::BadHex { key: COMMITMENT_HEADER });
    }
}
