use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::AdaptorResult;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawRequest {
    bytes: Vec<u8>,
    value: JsonValue,
}

impl RawRequest {
    pub fn from_slice(bytes: &[u8]) -> AdaptorResult<Self> {
        let value = serde_json::from_slice(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            value,
        })
    }

    pub fn from_value(value: JsonValue) -> AdaptorResult<Self> {
        let bytes = serde_json::to_vec(&value)?;
        Ok(Self { bytes, value })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn value(&self) -> &JsonValue {
        &self.value
    }

    pub fn into_parts(self) -> (Vec<u8>, JsonValue) {
        (self.bytes, self.value)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FieldPath {
    segments: Vec<String>,
}

impl FieldPath {
    pub fn root() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    pub fn new(segments: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            segments: segments.into_iter().map(Into::into).collect(),
        }
    }

    pub fn child(&self, segment: impl Into<String>) -> Self {
        let mut segments = self.segments.clone();
        segments.push(segment.into());
        Self { segments }
    }

    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }
}

impl From<&str> for FieldPath {
    fn from(value: &str) -> Self {
        Self::new([value])
    }
}

impl From<Vec<String>> for FieldPath {
    fn from(value: Vec<String>) -> Self {
        Self { segments: value }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PassthroughField {
    pub path: FieldPath,
    pub value: JsonValue,
}

impl PassthroughField {
    pub fn new(path: impl Into<FieldPath>, value: JsonValue) -> Self {
        Self {
            path: path.into(),
            value,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PassthroughBag {
    fields: Vec<PassthroughField>,
}

impl PassthroughBag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, path: impl Into<FieldPath>, value: JsonValue) {
        self.fields.push(PassthroughField::new(path, value));
    }

    pub fn fields(&self) -> &[PassthroughField] {
        &self.fields
    }

    pub fn into_fields(self) -> Vec<PassthroughField> {
        self.fields
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn raw_request_preserves_bytes_and_value() {
        let raw = RawRequest::from_slice(br#"{"model":"m","input":"hi"}"#).unwrap();
        assert_eq!(raw.bytes(), br#"{"model":"m","input":"hi"}"#);
        assert_eq!(raw.value(), &json!({"model": "m", "input": "hi"}));
    }

    #[test]
    fn passthrough_bag_keeps_field_paths() {
        let mut bag = PassthroughBag::new();
        bag.push(FieldPath::new(["reasoning", "effort"]), json!("low"));
        assert_eq!(bag.fields()[0].path.segments(), &["reasoning", "effort"]);
        assert_eq!(bag.fields()[0].value, json!("low"));
    }
}
