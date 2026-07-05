use serde::Serialize;
use serde::de::DeserializeOwned;

pub type DagCborEncodeError = serde_ipld_dagcbor::EncodeError<std::collections::TryReserveError>;
pub type DagCborDecodeError = serde_ipld_dagcbor::DecodeError<std::convert::Infallible>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, serde::Deserialize)]
pub struct JsonBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl JsonBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

pub fn canonical_dag_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, DagCborEncodeError> {
    serde_ipld_dagcbor::to_vec(value)
}

pub fn decode_dag_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DagCborDecodeError> {
    serde_ipld_dagcbor::from_slice(bytes)
}

/// Minimal strict DAG-CBOR encoder for commitment blobs whose byte layout is
/// part of the protocol. Use this when serde's struct/enum representation would
/// obscure the exact canonical preimage.
pub struct DagCborEncoder {
    bytes: Vec<u8>,
}

impl DagCborEncoder {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn array(&mut self, len: u64) {
        self.header(4, len);
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.header(2, value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    pub fn str(&mut self, value: &str) {
        self.header(3, value.len() as u64);
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.header(0, value);
    }

    pub fn i64(&mut self, value: i64) {
        if value >= 0 {
            self.header(0, value as u64);
        } else {
            self.header(1, (-1_i128 - value as i128) as u64);
        }
    }

    fn header(&mut self, major: u8, value: u64) {
        let major = major << 5;
        match value {
            0..=23 => self.bytes.push(major | value as u8),
            24..=0xff => self.bytes.extend_from_slice(&[major | 24, value as u8]),
            0x100..=0xffff => {
                self.bytes.push(major | 25);
                self.bytes.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.bytes.push(major | 26);
                self.bytes.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.bytes.push(major | 27);
                self.bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
}

impl Default for DagCborEncoder {
    fn default() -> Self {
        Self::new()
    }
}
