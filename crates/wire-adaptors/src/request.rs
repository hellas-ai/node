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
}
