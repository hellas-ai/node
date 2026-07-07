use hellas_adaptors::openai::responses::{
    OpenAiResponsesAdaptor, ParsedResponseRequest, ResponsesIngressState,
};
use hellas_adaptors::{BackendError, OutputEvent, SseDecoder, WireIngress, WireStreamEvent};

pub(crate) struct ResponsesSseProjector {
    adaptor: OpenAiResponsesAdaptor,
    parsed: ParsedResponseRequest,
    state: ResponsesIngressState,
    decoder: SseDecoder,
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

    fn decode_frames(
        &mut self,
        frames: Vec<WireStreamEvent>,
    ) -> Result<Vec<OutputEvent>, BackendError> {
        let mut output = Vec::new();
        for frame in frames {
            output.extend(
                self.adaptor
                    .decode_stream_event(&self.parsed, &mut self.state, frame)
                    .map_err(|err| BackendError::failed(err.to_string()))?,
            );
        }
        Ok(output)
    }
}
