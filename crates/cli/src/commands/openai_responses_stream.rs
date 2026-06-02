#[cfg(feature = "hellas-executor")]
use hellas_wire_adaptors::RenderContext;
use hellas_wire_adaptors::openai::responses::{
    OpenAiResponsesAdaptor, ParsedResponseRequest, ResponsesIngressState,
};
use hellas_wire_adaptors::{
    BackendError, OutputEvent, SseDecoder, WireEventData, WireIngress, WireStreamEvent,
};
use serde_json::Value as JsonValue;

pub(crate) struct ResponsesSseProjector {
    adaptor: OpenAiResponsesAdaptor,
    parsed: ParsedResponseRequest,
    state: ResponsesIngressState,
    decoder: SseDecoder,
    response_id: Option<String>,
    message_id: Option<String>,
    created_at: Option<i64>,
}

impl ResponsesSseProjector {
    pub(crate) fn new(parsed: ParsedResponseRequest) -> Self {
        let adaptor = OpenAiResponsesAdaptor;
        let state = adaptor.initial_ingress_state(&parsed);
        Self {
            adaptor,
            parsed,
            state,
            decoder: SseDecoder::new(),
            response_id: None,
            message_id: None,
            created_at: None,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<Vec<OutputEvent>, BackendError> {
        let frames = self
            .decoder
            .push(bytes)
            .map_err(|err| BackendError::failed(err.to_string()))?;
        self.decode_frames(frames)
    }

    pub(crate) fn finish(&mut self) -> Result<Vec<OutputEvent>, BackendError> {
        let frames = self
            .decoder
            .finish()
            .map_err(|err| BackendError::failed(err.to_string()))?;
        self.decode_frames(frames)
    }

    #[cfg(feature = "hellas-executor")]
    pub(crate) fn render_context(&self, fallback: RenderContext) -> RenderContext {
        RenderContext::new(
            self.response_id.clone().unwrap_or(fallback.response_id),
            self.message_id.clone().unwrap_or(fallback.message_id),
            self.created_at.unwrap_or(fallback.created_at),
        )
    }

    fn decode_frames(
        &mut self,
        frames: Vec<WireStreamEvent>,
    ) -> Result<Vec<OutputEvent>, BackendError> {
        let mut output = Vec::new();
        for frame in frames {
            self.capture_context(&frame);
            output.extend(
                self.adaptor
                    .decode_stream_event(&self.parsed, &mut self.state, frame)
                    .map_err(|err| BackendError::failed(err.to_string()))?,
            );
        }
        Ok(output)
    }

    fn capture_context(&mut self, frame: &WireStreamEvent) {
        let Some(value) = frame_json(frame) else {
            return;
        };

        let response = value.get("response").unwrap_or(&value);
        if let Some(id) = response.get("id").and_then(JsonValue::as_str) {
            self.response_id = Some(id.to_string());
        }
        if let Some(created_at) = response.get("created_at").and_then(JsonValue::as_i64) {
            self.created_at = Some(created_at);
        }
        if let Some(item) = value.get("item") {
            self.capture_message_id(item);
        }
        if let Some(items) = response.get("output").and_then(JsonValue::as_array) {
            for item in items {
                self.capture_message_id(item);
            }
        }
    }

    fn capture_message_id(&mut self, item: &JsonValue) {
        let is_message = item
            .get("type")
            .and_then(JsonValue::as_str)
            .is_some_and(|kind| kind == "message");
        if is_message && let Some(id) = item.get("id").and_then(JsonValue::as_str) {
            self.message_id = Some(id.to_string());
        }
    }
}

fn frame_json(frame: &WireStreamEvent) -> Option<JsonValue> {
    match &frame.data {
        WireEventData::Json(value) => Some(value.clone()),
        WireEventData::Text(value) if value == "[DONE]" => None,
        WireEventData::Text(value) => serde_json::from_str(value).ok(),
        WireEventData::Bytes(bytes) => serde_json::from_slice(bytes).ok(),
    }
}
