use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{AdaptorError, AdaptorResult};

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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SseDecoder {
    buffer: Vec<u8>,
}

impl SseDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) -> AdaptorResult<Vec<WireStreamEvent>> {
        self.buffer.extend_from_slice(bytes);
        let mut events = Vec::new();
        while let Some(frame) = self.take_frame() {
            if let Some(event) = parse_sse_frame(&frame)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    pub fn finish(&mut self) -> AdaptorResult<Vec<WireStreamEvent>> {
        if self.buffer.iter().all(u8::is_ascii_whitespace) {
            self.buffer.clear();
            return Ok(Vec::new());
        }
        let frame = std::mem::take(&mut self.buffer);
        Ok(parse_sse_frame(&frame)?.into_iter().collect())
    }

    fn take_frame(&mut self) -> Option<Vec<u8>> {
        let (index, delimiter_len) = find_sse_delimiter(&self.buffer)?;
        let frame = self.buffer[..index].to_vec();
        self.buffer.drain(..index + delimiter_len);
        Some(frame)
    }
}

fn find_sse_delimiter(buffer: &[u8]) -> Option<(usize, usize)> {
    let lf = buffer.windows(2).position(|window| window == b"\n\n");
    let crlf = buffer.windows(4).position(|window| window == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(lf), Some(crlf)) if crlf < lf => Some((crlf, 4)),
        (Some(lf), _) => Some((lf, 2)),
        (None, Some(crlf)) => Some((crlf, 4)),
        (None, None) => None,
    }
}

fn parse_sse_frame(frame: &[u8]) -> AdaptorResult<Option<WireStreamEvent>> {
    let text = std::str::from_utf8(frame).map_err(|source| {
        AdaptorError::invalid_response(format!("invalid UTF-8 in SSE stream: {source}"))
    })?;
    let mut name = None;
    let mut data = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => name = Some(value.to_string()),
            "data" => data.push(value.to_string()),
            _ => {}
        }
    }

    if data.is_empty() {
        return Ok(None);
    }
    Ok(Some(WireStreamEvent::text(name, data.join("\n"))))
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

    #[test]
    fn sse_decoder_parses_split_lf_frames() {
        let mut decoder = SseDecoder::new();
        assert!(decoder.push(b"event: a\nda").unwrap().is_empty());
        let events = decoder.push(b"ta: one\n\n").unwrap();
        assert_eq!(
            events,
            vec![WireStreamEvent::text(Some("a".to_string()), "one")]
        );
        assert!(decoder.finish().unwrap().is_empty());
    }

    #[test]
    fn sse_decoder_parses_crlf_and_multiline_data() {
        let mut decoder = SseDecoder::new();
        let events = decoder
            .push(b"event: delta\r\ndata: one\r\ndata: two\r\n\r\n")
            .unwrap();
        assert_eq!(
            events,
            vec![WireStreamEvent::text(Some("delta".to_string()), "one\ntwo")]
        );
    }
}
