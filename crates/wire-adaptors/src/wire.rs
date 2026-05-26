use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub type WireHeaders = BTreeMap<String, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderContext {
    pub response_id: String,
    pub message_id: String,
    pub created_at: i64,
}

impl RenderContext {
    pub fn new(
        response_id: impl Into<String>,
        message_id: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            response_id: response_id.into(),
            message_id: message_id.into(),
            created_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireResponse {
    pub status: u16,
    pub headers: WireHeaders,
    pub body: WireBody,
}

impl WireResponse {
    pub fn json(status: u16, body: JsonValue) -> Self {
        let mut headers = WireHeaders::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        Self {
            status,
            headers,
            body: WireBody::Json(body),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum WireBody {
    Json(JsonValue),
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireStreamEvent {
    pub name: Option<String>,
    pub data: WireEventData,
}

impl WireStreamEvent {
    pub fn json(name: impl Into<Option<String>>, data: JsonValue) -> Self {
        Self {
            name: name.into(),
            data: WireEventData::Json(data),
        }
    }

    pub fn text(name: impl Into<Option<String>>, data: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            data: WireEventData::Text(data.into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum WireEventData {
    Json(JsonValue),
    Text(String),
    Bytes(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_response_sets_content_type() {
        let response = WireResponse::json(200, json!({"ok": true}));
        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
    }

    #[test]
    fn stream_event_can_be_named_json() {
        let event = WireStreamEvent::json(Some("response.created".to_string()), json!({"x": 1}));
        assert_eq!(event.name.as_deref(), Some("response.created"));
        assert_eq!(event.data, WireEventData::Json(json!({"x": 1})));
    }
}
