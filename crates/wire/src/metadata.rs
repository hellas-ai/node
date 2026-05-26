//! Opaque key/value metadata carried in OpenFrame headers + EndFrame
//! trailers. Ordered (matches gRPC HTTP/2 header ordering semantics).

use bytes::Bytes;
use smol_str::SmolStr;

use crate::status::WireCode;

#[derive(Clone, Debug)]
pub enum MetadataValue {
    Text(SmolStr),
    Bytes(Bytes),
}

impl MetadataValue {
    pub fn text(value: impl Into<SmolStr>) -> Self {
        Self::Text(value.into())
    }

    pub fn binary(value: impl Into<Bytes>) -> Self {
        Self::Bytes(value.into())
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            Self::Bytes(_) => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Text(_) => None,
            Self::Bytes(b) => Some(b),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Metadata {
    entries: Vec<(SmolStr, MetadataValue)>,
}

impl Metadata {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            entries: Vec::with_capacity(cap),
        }
    }

    pub fn insert(&mut self, key: impl Into<SmolStr>, value: MetadataValue) {
        self.entries.push((key.into(), value));
    }

    pub fn insert_text(&mut self, key: impl Into<SmolStr>, value: impl Into<SmolStr>) {
        self.insert(key, MetadataValue::Text(value.into()));
    }

    pub fn insert_bytes(&mut self, key: impl Into<SmolStr>, value: impl Into<Bytes>) {
        self.insert(key, MetadataValue::Bytes(value.into()));
    }

    pub fn get(&self, key: &str) -> Option<&MetadataValue> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn get_all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a MetadataValue> + 'a {
        self.entries
            .iter()
            .filter(move |(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub fn remove(&mut self, key: &str) {
        self.entries.retain(|(k, _)| k != key);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SmolStr, &MetadataValue)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Trailer-side metadata carried on `Frame::End`.
#[derive(Clone, Debug)]
pub struct Trailer {
    pub status: WireCode,
    pub message: SmolStr,
    pub metadata: Metadata,
}

impl Default for Trailer {
    fn default() -> Self {
        Self {
            status: WireCode::Ok,
            message: SmolStr::new_static(""),
            metadata: Metadata::default(),
        }
    }
}

impl Trailer {
    pub fn ok() -> Self {
        Self::default()
    }

    pub fn from_status(status: WireCode, message: impl Into<SmolStr>) -> Self {
        Self {
            status,
            message: message.into(),
            metadata: Metadata::default(),
        }
    }
}

impl From<crate::status::WireStatus> for Trailer {
    fn from(s: crate::status::WireStatus) -> Self {
        Self {
            status: s.code,
            message: s.message,
            metadata: s.metadata,
        }
    }
}
