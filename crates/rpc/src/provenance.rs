//! Execution provenance commitments that travel alongside gateway/executor RPCs.
//!
//! The wire form is 64-char lowercase hex over 32 canonical bytes. RPC metadata,
//! HTTP headers, SSE events, and tracing output all use the same rendering.

use std::fmt::Write;

use thiserror::Error;
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};

/// Tonic metadata and HTTP header key for the request call commitment.
pub const COMMITMENT_HEADER: &str = "x-hellas-commitment";

/// Tonic metadata and HTTP header key for the terminal receipt commitment.
pub const RECEIPT_HEADER: &str = "x-hellas-receipt";

/// Request call commitment rendered as the `x-hellas-commitment` header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CallCommitment(pub [u8; 32]);

impl std::fmt::Display for CallCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&encode_hex(&self.0))
    }
}

impl std::fmt::Debug for CallCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// Producer receipt commitment rendered as the `x-hellas-receipt` header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReceiptCommitment(pub [u8; 32]);

impl std::fmt::Display for ReceiptCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&encode_hex(&self.0))
    }
}

impl std::fmt::Debug for ReceiptCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// Pre-flight provenance for a single execution.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecutionProvenance {
    pub call_commitment: CallCommitment,
}

impl std::fmt::Display for ExecutionProvenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.call_commitment, f)
    }
}

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

/// Render 32 commitment bytes as 64-char lowercase hex.
pub fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in bytes {
        write!(&mut s, "{byte:02x}").expect("writing to String never fails");
    }
    s
}

/// Build an ASCII-typed tonic metadata value from commitment bytes.
pub fn commitment_bytes_to_metadata(bytes: &[u8; 32]) -> MetadataValue<Ascii> {
    encode_hex(bytes)
        .parse()
        .expect("64-char hex is always valid ASCII metadata")
}

/// Read one commitment-bearing key out of a tonic metadata map.
pub fn commitment_bytes_from_metadata(
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

/// Read pre-flight provenance from a tonic metadata map.
pub fn read_provenance_metadata(md: &MetadataMap) -> Result<ExecutionProvenance, ProvenanceError> {
    Ok(ExecutionProvenance {
        call_commitment: CallCommitment(commitment_bytes_from_metadata(md, COMMITMENT_HEADER)?),
    })
}

/// Insert pre-flight provenance into a tonic metadata map.
pub fn write_provenance_metadata(md: &mut MetadataMap, prov: &ExecutionProvenance) {
    md.insert(
        COMMITMENT_HEADER,
        commitment_bytes_to_metadata(&prov.call_commitment.0),
    );
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
            call_commitment: CallCommitment([0xab; 32]),
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
    fn commitment_display_is_hex() {
        assert_eq!(CallCommitment([0xcd; 32]).to_string(), "cd".repeat(32));
        assert_eq!(ReceiptCommitment([0xef; 32]).to_string(), "ef".repeat(32));
    }

    #[test]
    fn round_trip_through_metadata() {
        let prov = sample();
        let mut md = MetadataMap::new();
        write_provenance_metadata(&mut md, &prov);
        let decoded = read_provenance_metadata(&md).expect("round-trip should succeed");
        assert_eq!(decoded, prov);
        assert!(md.contains_key(COMMITMENT_HEADER));
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
}
