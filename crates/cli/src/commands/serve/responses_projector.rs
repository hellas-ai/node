use hellas_adaptors::openai::responses::{
    OpenAiResponsesAdaptor, ParsedResponseRequest, ResponsesSseProjector,
};
use hellas_adaptors::{OutputEvent, RawRequest, Usage, WireAdaptor};
use hellas_executor::{
    FetchProjectionError, FetchProjectionSession, FetchProjector, FetchProjectorFactory,
    FetchProviderRequest, FetchRequestView, ProjectedFetch,
};
use hellas_rpc::fetch::{encode_fetch_event_payload, encode_fetch_terminal_payload};

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ResponsesFetchProjectorFactory;

impl FetchProjectorFactory for ResponsesFetchProjectorFactory {
    fn create(
        &self,
        request: &FetchProviderRequest,
    ) -> Result<FetchProjectionSession, FetchProjectionError> {
        let parsed = parse_streaming_request(request)?;
        let request_view = FetchRequestView {
            service: request.service.clone(),
            method: request.method.clone(),
            model: Some(parsed.model.clone()),
            max_output_units: parsed.max_output_tokens.map(u64::from),
        };
        Ok(FetchProjectionSession {
            request_view,
            projector: Box::new(ResponsesFetchProjector::new(parsed)),
        })
    }
}

fn parse_streaming_request(
    request: &FetchProviderRequest,
) -> Result<ParsedResponseRequest, FetchProjectionError> {
    let adaptor = OpenAiResponsesAdaptor;
    let raw = RawRequest::from_slice(request.body.as_bytes()).map_err(|err| {
        FetchProjectionError::failed(format!("invalid OpenAI Responses request: {err}"))
    })?;
    let parsed = adaptor.parse(raw).map_err(|err| {
        FetchProjectionError::failed(format!("invalid OpenAI Responses request: {err}"))
    })?;
    if parsed.stream != Some(true) {
        return Err(FetchProjectionError::failed(
            "OpenAI Responses fetch requests must set stream=true".to_string(),
        ));
    }
    Ok(parsed)
}

struct ResponsesFetchProjector {
    projector: ResponsesSseProjector,
    usage: Option<Usage>,
    terminal_seen: bool,
}

impl ResponsesFetchProjector {
    fn new(parsed: ParsedResponseRequest) -> Self {
        Self {
            projector: ResponsesSseProjector::new(parsed),
            usage: None,
            terminal_seen: false,
        }
    }

    fn project_events(
        &mut self,
        events: Vec<OutputEvent>,
    ) -> Result<Vec<ProjectedFetch>, FetchProjectionError> {
        let mut projected = Vec::new();
        for event in events {
            match event {
                OutputEvent::Usage(usage) => {
                    self.usage = Some(usage);
                    projected.push(ProjectedFetch::Event(
                        encode_fetch_event_payload(&OutputEvent::Usage(usage))
                            .map_err(fetch_payload_error)?,
                    ));
                }
                OutputEvent::Finished { .. } => {
                    if self.terminal_seen {
                        return Err(FetchProjectionError::failed(
                            "Responses stream emitted multiple terminal events".to_string(),
                        ));
                    }
                    let OutputEvent::Finished { stop_reason, usage } = event else {
                        unreachable!()
                    };
                    let usage = usage.or(self.usage);
                    let event = OutputEvent::Finished { stop_reason, usage };
                    self.terminal_seen = true;
                    projected.push(ProjectedFetch::Terminal(
                        encode_fetch_terminal_payload(&event).map_err(fetch_payload_error)?,
                    ));
                }
                OutputEvent::Error { message, .. } => {
                    return Err(FetchProjectionError::failed(message));
                }
                event => {
                    if self.terminal_seen {
                        return Err(FetchProjectionError::failed(
                            "Responses stream emitted an event after terminal".to_string(),
                        ));
                    }
                    projected.push(ProjectedFetch::Event(
                        encode_fetch_event_payload(&event).map_err(fetch_payload_error)?,
                    ));
                }
            }
        }
        Ok(projected)
    }
}

impl FetchProjector for ResponsesFetchProjector {
    fn project(&mut self, bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchProjectionError> {
        let events = self
            .projector
            .push(bytes)
            .map_err(|err| FetchProjectionError::failed(err.to_string()))?;
        self.project_events(events)
    }

    fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchProjectionError> {
        let events = self
            .projector
            .finish()
            .map_err(|err| FetchProjectionError::failed(err.to_string()))?;
        self.project_events(events)
    }
}

fn fetch_payload_error(err: impl std::fmt::Display) -> FetchProjectionError {
    FetchProjectionError::failed(format!("fetch payload encoding failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::JsonBytes;

    fn request() -> FetchProviderRequest {
        FetchProviderRequest::new(
            "codex",
            "responses",
            JsonBytes::new(
                br#"{"model":"gpt-5.5-codex","input":"hi","stream":true,"max_output_tokens":8}"#
                    .to_vec(),
            ),
            hellas_rpc::InputCommitment::from_digest(hellas_rpc::Digest::from_bytes([7; 32])),
        )
    }

    fn stream_bytes() -> Vec<u8> {
        br#"data: {"type":"response.output_text.delta","item_id":"msg_1","delta":"hel"}

data: {"type":"response.output_text.delta","item_id":"msg_1","delta":"lo"}

data: {"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}}

"#
        .to_vec()
    }

    fn project(chunks: &[&[u8]]) -> Vec<ProjectedFetch> {
        let factory = ResponsesFetchProjectorFactory;
        let mut session = factory.create(&request()).unwrap();
        let mut projected = Vec::new();
        for chunk in chunks {
            projected.extend(session.projector.project(chunk).unwrap());
        }
        projected.extend(session.projector.finish().unwrap());
        projected
    }

    #[test]
    fn projection_is_independent_of_sse_chunk_boundaries() {
        let bytes = stream_bytes();
        let split_a = [&bytes[..]];
        let split_b = [&bytes[..17], &bytes[17..103], &bytes[103..]];

        let projected_a = project(&split_a);
        let projected_b = project(&split_b);

        assert_eq!(projected_a, projected_b);
        assert_eq!(projected_a.len(), 3);
        assert!(matches!(projected_a[0], ProjectedFetch::Event(_)));
        assert!(matches!(projected_a[1], ProjectedFetch::Event(_)));
        assert!(matches!(projected_a[2], ProjectedFetch::Terminal(_)));
    }
}
