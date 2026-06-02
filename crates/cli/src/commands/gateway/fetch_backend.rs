use async_stream::try_stream;
use axum::body::Bytes;
use futures::StreamExt;
use hellas_core::ProducerSigningKey;
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_wire_adaptors::openai::responses::OpenAiResponsesAdaptor;
use hellas_wire_adaptors::{
    BackendError, BackendFuture, BackendRequest, BackendStream, ExecutionBackend, OutputEvent,
    OutputItem, RawRequest, StructuredDelta, ToolCallArgumentsDelta, ToolCallEnd, ToolCallStart,
    WireAdaptor, WireIngress,
};
use serde_json::Value as JsonValue;
use std::sync::Arc;

use crate::commands::fetch::signed_input_events;
use crate::execution::{
    ExecutionRoute, ExecutionRuntime, FetchExecutionEvent, FetchOutcome, fetch_execution_stream,
};

const CODEX_SERVICE: &str = "codex";

#[derive(Clone)]
pub(super) struct ResponsesFetchBackend {
    runtime: ExecutionRuntime,
    route: ExecutionRoute,
    service: String,
    method: String,
    caller_key: Arc<ProducerSigningKey>,
}

impl ResponsesFetchBackend {
    pub(super) fn new(
        runtime: ExecutionRuntime,
        route: ExecutionRoute,
        service: &str,
        method: &str,
        caller_key: ProducerSigningKey,
    ) -> Self {
        Self {
            runtime,
            route,
            service: service.to_string(),
            method: method.to_string(),
            caller_key: Arc::new(caller_key),
        }
    }
}

impl ExecutionBackend for ResponsesFetchBackend {
    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream> {
        Box::pin(async move {
            let payload = provider_request_body(&request, &self.service)?;
            let fetch_request = FetchRequest {
                input: signed_input_events(
                    &self.service,
                    &self.method,
                    &payload,
                    self.caller_key.as_ref(),
                )
                .map_err(|source| {
                    BackendError::failed(format!("failed to sign fetch request: {source}"))
                })?,
            };
            Ok(BackendStream::new(
                fetch_events(
                    self.runtime.clone(),
                    self.route.clone(),
                    fetch_request,
                    payload,
                ),
                None,
            ))
        })
    }
}

fn fetch_events(
    runtime: ExecutionRuntime,
    route: ExecutionRoute,
    request: FetchRequest,
    provider_payload: Bytes,
) -> impl futures::Stream<Item = Result<OutputEvent, BackendError>> + Send {
    try_stream! {
        let adaptor = OpenAiResponsesAdaptor;
        let parsed = adaptor
            .parse(RawRequest::from_slice(&provider_payload).map_err(|err| {
                BackendError::rejected(format!("invalid Responses fetch request: {err}"))
            })?)
            .map_err(|err| BackendError::rejected(err.to_string()))?;
        let stream = fetch_execution_stream(runtime, request, route);
        tokio::pin!(stream);

        while let Some(event) = stream.next().await {
            match event.map_err(|err| BackendError::failed(err.to_string()))? {
                FetchExecutionEvent::Chunk { .. } => {}
                FetchExecutionEvent::Done(FetchOutcome::Completed { output }) => {
                    let result = adaptor
                        .decode_response(&parsed, &output)
                        .map_err(|err| BackendError::failed(err.to_string()))?;
                    for event in result_events(result) {
                        yield event;
                    }
                    return;
                }
                FetchExecutionEvent::Done(FetchOutcome::Failed { position, error }) => {
                    Err(BackendError::failed(format!(
                        "fetch execution failed at position {position}: {error}"
                    )))?;
                }
            }
        }

        Err(BackendError::failed("fetch execution stream ended without terminal outcome"))?;
    }
}

fn provider_request_body(request: &BackendRequest, service: &str) -> Result<Bytes, BackendError> {
    let JsonValue::Object(mut object) = request.raw.value().clone() else {
        return Err(BackendError::rejected(
            "Responses fetch request body must be a JSON object",
        ));
    };
    object.insert(
        "model".to_string(),
        JsonValue::String(request.execution.canonical.model.name.clone()),
    );
    object.insert("stream".to_string(), JsonValue::Bool(true));
    if service == CODEX_SERVICE {
        object.insert("store".to_string(), JsonValue::Bool(false));
    }
    serde_json::to_vec(&JsonValue::Object(object))
        .map(Bytes::from)
        .map_err(|source| {
            BackendError::failed(format!(
                "failed to encode Responses fetch request: {source}"
            ))
        })
}

fn result_events(result: hellas_wire_adaptors::ExecutionResult) -> Vec<OutputEvent> {
    let mut events = Vec::new();
    for (index, item) in result.output.into_iter().enumerate() {
        match item {
            OutputItem::Text { text, channel } => events.push(OutputEvent::TextDelta {
                index,
                delta: text,
                channel,
            }),
            OutputItem::ToolCall {
                id,
                name,
                arguments,
            } => {
                events.push(OutputEvent::ToolCallStart(ToolCallStart {
                    index,
                    id: Some(id),
                    name,
                }));
                events.push(OutputEvent::ToolCallArgumentsDelta(
                    ToolCallArgumentsDelta {
                        index,
                        delta: serde_json::to_string(&arguments)
                            .unwrap_or_else(|_| arguments.to_string()),
                    },
                ));
                events.push(OutputEvent::ToolCallEnd(ToolCallEnd { index, arguments }));
            }
            OutputItem::StructuredJson(value) | OutputItem::Raw(value) => {
                events.push(OutputEvent::StructuredOutputDelta(StructuredDelta::Json(
                    value,
                )));
            }
        }
    }
    if let Some(usage) = result.usage {
        events.push(OutputEvent::Usage(usage));
    }
    if let Some(provenance) = result.provenance {
        events.push(OutputEvent::Provenance(provenance));
    }
    events.push(OutputEvent::Finished {
        stop_reason: result.stop_reason,
        usage: result.usage,
    });
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_wire_adaptors::{
        CanonicalExecution, ExecutionRequest, Input, ModelRef, RawRequest, StopReason, TextChannel,
        Usage,
    };
    use serde_json::json;

    fn backend_request(body: &[u8], model: &str) -> BackendRequest {
        BackendRequest::new(
            ExecutionRequest::new(CanonicalExecution::new(
                ModelRef::new(model),
                Input::Text("hello".to_string()),
            )),
            RawRequest::from_slice(body).unwrap(),
        )
    }

    #[test]
    fn codex_provider_body_sets_stream_store_and_model() {
        let request = backend_request(
            br#"{"model":"client-model","input":"hello","stream":false,"store":true}"#,
            "gpt-5.5",
        );

        let body = provider_request_body(&request, CODEX_SERVICE).unwrap();
        let value: JsonValue = serde_json::from_slice(&body).unwrap();

        assert_eq!(value["model"], "gpt-5.5");
        assert_eq!(value["input"], "hello");
        assert_eq!(value["stream"], true);
        assert_eq!(value["store"], false);
    }

    #[test]
    fn non_codex_provider_body_does_not_set_store() {
        let request = backend_request(br#"{"model":"m","input":"hello"}"#, "m");

        let body = provider_request_body(&request, "openai").unwrap();
        let value: JsonValue = serde_json::from_slice(&body).unwrap();

        assert_eq!(value["stream"], true);
        assert!(value.get("store").is_none());
    }

    #[test]
    fn result_events_emit_tool_call_before_finished() {
        let result = hellas_wire_adaptors::ExecutionResult {
            output: vec![OutputItem::ToolCall {
                id: "call_1".to_string(),
                name: "lookup".to_string(),
                arguments: json!({"q": "hello"}),
            }],
            usage: Some(Usage {
                input_tokens: Some(1),
                output_tokens: Some(2),
                total_tokens: Some(3),
            }),
            stop_reason: StopReason::ToolCall,
            provenance: None,
        };

        let events = result_events(result);

        assert!(matches!(events[0], OutputEvent::ToolCallStart(_)));
        assert!(matches!(events[1], OutputEvent::ToolCallArgumentsDelta(_)));
        assert!(matches!(events[2], OutputEvent::ToolCallEnd(_)));
        assert!(matches!(events[3], OutputEvent::Usage(_)));
        assert!(matches!(
            events[4],
            OutputEvent::Finished {
                stop_reason: StopReason::ToolCall,
                ..
            }
        ));
    }

    #[test]
    fn result_events_emit_text_with_original_channel() {
        let result = hellas_wire_adaptors::ExecutionResult {
            output: vec![OutputItem::Text {
                text: "thinking".to_string(),
                channel: TextChannel::Reasoning,
            }],
            usage: None,
            stop_reason: StopReason::EndOfText,
            provenance: None,
        };

        let events = result_events(result);

        assert!(matches!(
            &events[0],
            OutputEvent::TextDelta {
                delta,
                channel: TextChannel::Reasoning,
                ..
            } if delta == "thinking"
        ));
    }
}
