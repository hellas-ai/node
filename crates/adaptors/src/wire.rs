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
    received_bytes: usize,
    frames: u64,
    events: u64,
    ignored_lines: u64,
    noncanonical_lines: u64,
}

/// Maximum raw bytes in a complete SSE response accepted by the built-in
/// Fetch HTTP drivers.
///
/// This is part of the built-in Fetch driver contract: changing it requires a
/// new driver identity in the Fetch environment manifest.
pub const MAX_SSE_RESPONSE_BYTES: usize = 3 * 1024 * 1024;

const MAX_SSE_DELIMITER_BYTES: usize = 4;

/// Maximum raw bytes in one SSE frame, excluding its blank-line delimiter.
///
/// Responses lifecycle terminals may repeat the complete generated output in
/// one frame. Reserving only the longest delimiter keeps a complete maximum
/// frame inside the response-wide byte bound. The semantic projector still
/// applies Hellas's smaller signed-payload bound.
pub const MAX_SSE_FRAME_BYTES: usize = MAX_SSE_RESPONSE_BYTES - MAX_SSE_DELIMITER_BYTES;

/// Maximum semantic data events in one SSE response. Comment keepalives and
/// empty frames do not consume this budget; the response-wide byte ceiling
/// bounds those raw frames instead. This is deliberately above the number of
/// ordinary provider events that can fit in the byte ceiling while retaining
/// a separate allocation/dispatch guard for unusually tiny data events.
pub const MAX_SSE_EVENTS: u64 = 65_536;

impl SseDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of raw SSE frames consumed, including comment-only frames.
    /// Strict adaptors use this to reject semantically invisible framing.
    pub const fn frame_count(&self) -> u64 {
        self.frames
    }

    /// Number of comment, unknown, malformed, or duplicate `event` lines
    /// discarded while applying ordinary SSE semantics. Sealed adaptors use
    /// this to require a closed framing grammar without changing permissive
    /// presentation adaptors.
    pub const fn ignored_line_count(&self) -> u64 {
        self.ignored_lines
    }

    /// Number of lines which are meaningful under the permissive SSE grammar
    /// but not in the sealed one-event/one-data framing used by strict
    /// adaptors. Presentation adaptors retain ordinary SSE compatibility;
    /// sealed adaptors reject this counter instead of accepting and silently
    /// normalizing an alternative wire representation.
    pub const fn noncanonical_line_count(&self) -> u64 {
        self.noncanonical_lines
    }

    /// Bytes retained after the last complete frame delimiter.
    pub fn pending_bytes(&self) -> &[u8] {
        &self.buffer
    }

    pub fn push(&mut self, mut bytes: &[u8]) -> AdaptorResult<Vec<WireStreamEvent>> {
        self.received_bytes = self
            .received_bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_SSE_RESPONSE_BYTES)
            .ok_or_else(sse_response_limit_error)?;
        let mut events = Vec::new();

        while !bytes.is_empty() {
            let buffer_limit = MAX_SSE_FRAME_BYTES
                .checked_add(MAX_SSE_DELIMITER_BYTES)
                .expect("SSE buffer limit fits usize");
            let available = buffer_limit
                .checked_sub(self.buffer.len())
                .ok_or_else(sse_frame_limit_error)?;
            if available == 0 {
                return Err(sse_frame_limit_error());
            }

            let appended = available.min(bytes.len());
            let buffered = self
                .buffer
                .len()
                .checked_add(appended)
                .ok_or_else(sse_frame_limit_error)?;
            if buffered > buffer_limit {
                return Err(sse_frame_limit_error());
            }
            self.buffer.try_reserve_exact(appended).map_err(|_| {
                AdaptorError::invalid_response("SSE frame buffer allocation failed")
            })?;
            self.buffer.extend_from_slice(&bytes[..appended]);
            bytes = &bytes[appended..];

            self.drain_complete_frames(&mut events)?;
            self.ensure_pending_frame_within_limit()?;
        }

        Ok(events)
    }

    pub fn finish(&mut self) -> AdaptorResult<Vec<WireStreamEvent>> {
        if self.buffer.len() > MAX_SSE_FRAME_BYTES {
            return Err(sse_frame_limit_error());
        }
        if self.buffer.iter().all(u8::is_ascii_whitespace) {
            self.buffer.clear();
            return Ok(Vec::new());
        }
        self.record_frame()?;
        let frame = std::mem::take(&mut self.buffer);
        let (event, ignored_lines, noncanonical_lines) = parse_sse_frame(&frame)?;
        self.ignored_lines = self.ignored_lines.saturating_add(ignored_lines);
        self.noncanonical_lines = self.noncanonical_lines.saturating_add(noncanonical_lines);
        if event.is_some() {
            self.record_event()?;
        }
        Ok(event.into_iter().collect())
    }

    fn drain_complete_frames(&mut self, events: &mut Vec<WireStreamEvent>) -> AdaptorResult<()> {
        let mut consumed = 0;
        while let Some((frame_len, delimiter_len)) = find_sse_delimiter(&self.buffer[consumed..]) {
            if frame_len > MAX_SSE_FRAME_BYTES {
                return Err(sse_frame_limit_error());
            }
            self.record_frame()?;
            let frame_end = consumed + frame_len;
            let (event, ignored_lines, noncanonical_lines) =
                parse_sse_frame(&self.buffer[consumed..frame_end])?;
            self.ignored_lines = self.ignored_lines.saturating_add(ignored_lines);
            self.noncanonical_lines = self.noncanonical_lines.saturating_add(noncanonical_lines);
            if let Some(event) = event {
                self.record_event()?;
                events.push(event);
            }
            consumed = frame_end + delimiter_len;
        }
        self.buffer.drain(..consumed);
        Ok(())
    }

    fn record_frame(&mut self) -> AdaptorResult<()> {
        self.frames = self
            .frames
            .checked_add(1)
            .ok_or_else(|| AdaptorError::invalid_response("SSE raw frame count overflowed"))?;
        Ok(())
    }

    fn record_event(&mut self) -> AdaptorResult<()> {
        let events = self
            .events
            .checked_add(1)
            .ok_or_else(sse_event_count_limit_error)?;
        if events > MAX_SSE_EVENTS {
            return Err(sse_event_count_limit_error());
        }
        self.events = events;
        Ok(())
    }

    fn ensure_pending_frame_within_limit(&self) -> AdaptorResult<()> {
        if self.buffer.len() <= MAX_SSE_FRAME_BYTES
            || has_incomplete_delimiter_at_frame_limit(&self.buffer)
        {
            return Ok(());
        }
        Err(sse_frame_limit_error())
    }
}

fn has_incomplete_delimiter_at_frame_limit(buffer: &[u8]) -> bool {
    [b"\n\n".as_slice(), b"\r\n\r\n".as_slice()]
        .into_iter()
        .any(|delimiter| {
            (1..delimiter.len()).any(|prefix_len| {
                buffer.len().checked_sub(prefix_len).is_some_and(|start| {
                    start <= MAX_SSE_FRAME_BYTES && buffer[start..] == delimiter[..prefix_len]
                })
            })
        })
}

fn sse_frame_limit_error() -> AdaptorError {
    AdaptorError::invalid_response(format!(
        "SSE frame exceeds the {MAX_SSE_FRAME_BYTES}-byte limit"
    ))
}

fn sse_response_limit_error() -> AdaptorError {
    AdaptorError::invalid_response(format!(
        "SSE response exceeds the {MAX_SSE_RESPONSE_BYTES}-byte limit"
    ))
}

fn sse_event_count_limit_error() -> AdaptorError {
    AdaptorError::invalid_response(format!(
        "SSE response exceeds the {MAX_SSE_EVENTS}-event limit"
    ))
}

fn find_sse_delimiter(buffer: &[u8]) -> Option<(usize, usize)> {
    for index in 0..buffer.len().saturating_sub(1) {
        if buffer[index..].starts_with(b"\n\n") {
            return Some((index, 2));
        }
        if buffer[index..].starts_with(b"\r\n\r\n") {
            return Some((index, 4));
        }
    }
    None
}

fn parse_sse_frame(frame: &[u8]) -> AdaptorResult<(Option<WireStreamEvent>, u64, u64)> {
    let text = std::str::from_utf8(frame).map_err(|source| {
        AdaptorError::invalid_response(format!("invalid UTF-8 in SSE stream: {source}"))
    })?;
    let mut name = None;
    let mut data = Vec::new();
    let mut ignored_lines = 0_u64;
    let mut noncanonical_lines = 0_u64;

    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            noncanonical_lines = noncanonical_lines.saturating_add(1);
            continue;
        }
        if line.starts_with(':') {
            ignored_lines = ignored_lines.saturating_add(1);
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            ignored_lines = ignored_lines.saturating_add(1);
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" if name.is_none() => {
                if !data.is_empty() {
                    noncanonical_lines = noncanonical_lines.saturating_add(1);
                }
                name = Some(value.to_string());
            }
            "data" => {
                if name.is_none() || !data.is_empty() {
                    noncanonical_lines = noncanonical_lines.saturating_add(1);
                }
                data.push(value.to_string());
            }
            _ => ignored_lines = ignored_lines.saturating_add(1),
        }
    }

    if data.is_empty() {
        return Ok((None, ignored_lines, noncanonical_lines));
    }
    Ok((
        Some(WireStreamEvent::text(name, data.join("\n"))),
        ignored_lines,
        noncanonical_lines,
    ))
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

    #[test]
    fn sse_decoder_counts_lines_hidden_by_permissive_sse_semantics() {
        let mut decoder = SseDecoder::new();
        let events = decoder
            .push(b": comment\nevent: delta\nevent: duplicate\nid: hidden\ndata: one\n\n")
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(decoder.ignored_line_count(), 3);
    }

    #[test]
    fn sse_decoder_marks_permissive_data_framing_without_changing_its_output() {
        let mut decoder = SseDecoder::new();
        let events = decoder
            .push(b"data: one\nevent: delta\ndata: two\n\n")
            .unwrap();

        assert_eq!(
            events,
            vec![WireStreamEvent::text(Some("delta".to_string()), "one\ntwo")]
        );
        assert_eq!(decoder.noncanonical_line_count(), 3);
    }

    #[test]
    fn sse_decoder_rejects_delimiter_free_frame_over_limit() {
        let mut decoder = SseDecoder::new();
        let oversized = vec![b'x'; MAX_SSE_FRAME_BYTES + 1];

        let error = decoder.push(&oversized).unwrap_err();

        assert!(error.to_string().contains("SSE frame exceeds"));
        assert!(decoder.buffer.len() <= MAX_SSE_FRAME_BYTES + MAX_SSE_DELIMITER_BYTES);
    }

    #[test]
    fn sse_decoder_rejects_delimited_frame_over_limit_before_copying_frame() {
        let mut decoder = SseDecoder::new();
        let mut oversized = vec![b'x'; MAX_SSE_FRAME_BYTES + 1];
        oversized.extend_from_slice(b"\n\n");

        let error = decoder.push(&oversized).unwrap_err();

        assert!(error.to_string().contains("SSE frame exceeds"));
        assert!(decoder.buffer.len() <= MAX_SSE_FRAME_BYTES + MAX_SSE_DELIMITER_BYTES);
    }

    #[test]
    fn sse_decoder_accepts_limit_sized_frame_with_split_crlf_delimiter() {
        let mut decoder = SseDecoder::new();
        let mut frame = b"data: ".to_vec();
        frame.resize(MAX_SSE_FRAME_BYTES, b'x');
        frame.extend_from_slice(b"\r\n\r");

        assert!(decoder.push(&frame).unwrap().is_empty());
        let events = decoder.push(b"\n").unwrap();

        assert_eq!(events.len(), 1);
        let WireEventData::Text(data) = &events[0].data else {
            panic!("SSE data should decode as text");
        };
        assert_eq!(data.len(), MAX_SSE_FRAME_BYTES - b"data: ".len());
    }

    #[test]
    fn sse_decoder_accepts_response_made_of_many_bounded_frames() {
        let mut frame = b"data: ".to_vec();
        frame.resize(1022, b'x');
        frame.extend_from_slice(b"\n\n");
        let frame_count = MAX_SSE_RESPONSE_BYTES / frame.len();
        let mut aggregate = Vec::with_capacity(frame_count * frame.len());
        for _ in 0..frame_count {
            aggregate.extend_from_slice(&frame);
        }
        assert!(aggregate.len() <= MAX_SSE_RESPONSE_BYTES);

        let events = SseDecoder::new().push(&aggregate).unwrap();

        assert_eq!(events.len(), frame_count);
    }

    #[test]
    fn sse_decoder_caps_semantic_events_across_network_pushes() {
        let mut decoder = SseDecoder::new();
        let frame = b"data: x\n\n";
        let first_half = frame.repeat(MAX_SSE_EVENTS as usize / 2);
        let second_half = frame.repeat(MAX_SSE_EVENTS as usize / 2);

        assert_eq!(
            decoder.push(&first_half).unwrap().len(),
            MAX_SSE_EVENTS as usize / 2
        );
        assert_eq!(
            decoder.push(&second_half).unwrap().len(),
            MAX_SSE_EVENTS as usize / 2
        );
        let error = decoder.push(frame).unwrap_err();

        assert!(error.to_string().contains("65536-event limit"));
    }

    #[test]
    fn sse_comment_keepalives_do_not_consume_the_semantic_event_budget() {
        let mut decoder = SseDecoder::new();
        let keepalives = b": ping\n\n".repeat(MAX_SSE_EVENTS as usize + 1);

        assert!(decoder.push(&keepalives).unwrap().is_empty());
        assert_eq!(decoder.frame_count(), MAX_SSE_EVENTS + 1);
        assert_eq!(decoder.ignored_line_count(), MAX_SSE_EVENTS + 1);
    }

    #[test]
    fn sse_decoder_enforces_the_aggregate_response_byte_limit() {
        let mut decoder = SseDecoder::new();
        let mut exact = vec![b' '; MAX_SSE_FRAME_BYTES];
        exact.extend_from_slice(b"\r\n\r\n");
        assert_eq!(exact.len(), MAX_SSE_RESPONSE_BYTES);
        assert!(decoder.push(&exact).unwrap().is_empty());

        let error = decoder.push(b"x").unwrap_err();
        assert!(error.to_string().contains("response exceeds"));
    }
}
