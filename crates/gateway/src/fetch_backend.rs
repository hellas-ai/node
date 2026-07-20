use async_stream::try_stream;
use axum::body::Bytes;
use futures::StreamExt;
use hellas_adaptors::{
    BackendError, BackendFuture, BackendRequest, BackendStream, ExecutionBackend, OutputEvent,
    Provenance,
};
use hellas_rpc::fetch::{build_input_events, verify_input_events};
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::stream::input_event_to_pb;
use hellas_rpc::{ContentId, ProducerSigningKey};
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::sync::Arc;

use crate::execution::CliRuntime;
use hellas_client::iroh::fetch_execution_stream;
use hellas_client::{ExecutionRoute, FetchExecutionEvent, FetchOutcome, ProducerTrust};

#[derive(Clone)]
pub(super) struct ResponsesFetchBackend {
    runtime: CliRuntime,
    route: ExecutionRoute,
    service: String,
    method: String,
    execution_environment: ContentId,
    caller_key: Arc<ProducerSigningKey>,
    producer_trust: ProducerTrust,
    request_overrides: JsonMap<String, JsonValue>,
}

impl ResponsesFetchBackend {
    pub(super) fn new(
        runtime: CliRuntime,
        route: ExecutionRoute,
        target: (&str, &str, ContentId),
        caller_key: ProducerSigningKey,
        producer_trust: ProducerTrust,
        request_overrides: JsonMap<String, JsonValue>,
    ) -> Self {
        let (service, method, execution_environment) = target;
        Self {
            runtime,
            route,
            service: service.to_string(),
            method: method.to_string(),
            execution_environment,
            caller_key: Arc::new(caller_key),
            producer_trust,
            request_overrides,
        }
    }
}

impl ExecutionBackend for ResponsesFetchBackend {
    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream> {
        Box::pin(async move {
            let payload = provider_request_body(&request, &self.request_overrides)?;
            let (input, input_commitment) = signed_input_events_with_commitment(
                &self.service,
                &self.method,
                &payload,
                self.execution_environment,
                self.caller_key.as_ref(),
            )
            .map_err(|source| {
                BackendError::failed(format!("failed to sign fetch request: {source}"))
            })?;
            let fetch_request = FetchRequest { input };
            Ok(BackendStream::new(
                fetch_events(
                    self.runtime.clone(),
                    self.route.clone(),
                    fetch_request,
                    self.producer_trust.clone(),
                    self.caller_key.clone(),
                    payload,
                ),
                Some(Provenance {
                    call_commitment: Some(input_commitment),
                }),
            ))
        })
    }
}

fn signed_input_events_with_commitment(
    service: &str,
    method: &str,
    payload: &[u8],
    execution_environment: ContentId,
    key: &ProducerSigningKey,
) -> anyhow::Result<(Vec<hellas_rpc::pb::execute::InputEventEnvelope>, String)> {
    let events = build_input_events(service, method, payload, execution_environment, key)?;
    let input_commitment = verify_input_events(&events)?.input_commitment;
    Ok((
        events.iter().map(input_event_to_pb).collect(),
        input_commitment.digest().to_string(),
    ))
}

fn fetch_events(
    runtime: CliRuntime,
    route: ExecutionRoute,
    request: FetchRequest,
    trust: ProducerTrust,
    runner_key: Arc<ProducerSigningKey>,
    _provider_payload: Bytes,
) -> impl futures::Stream<Item = Result<OutputEvent, BackendError>> + Send {
    try_stream! {
        let stream = fetch_execution_stream(runtime, request, route, trust, runner_key);
        tokio::pin!(stream);

        while let Some(event) = stream.next().await {
            match event.map_err(|err| BackendError::failed(err.to_string()))? {
                FetchExecutionEvent::Chunk { event, .. } => {
                    yield event;
                }
                FetchExecutionEvent::Done(FetchOutcome::Completed { terminal, .. }) => {
                    yield terminal.to_output_event();
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

fn provider_request_body(
    request: &BackendRequest,
    request_overrides: &JsonMap<String, JsonValue>,
) -> Result<Bytes, BackendError> {
    let JsonValue::Object(mut object) = request.raw.value().clone() else {
        return Err(BackendError::rejected(
            "Responses fetch request body must be a JSON object",
        ));
    };
    for (key, value) in request_overrides {
        object.insert(key.clone(), value.clone());
    }
    object.insert(
        "model".to_string(),
        JsonValue::String(request.execution.canonical.model.name.clone()),
    );
    object.insert("stream".to_string(), JsonValue::Bool(true));
    serde_json::to_vec(&JsonValue::Object(object))
        .map(Bytes::from)
        .map_err(|source| {
            BackendError::failed(format!(
                "failed to encode Responses fetch request: {source}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_adaptors::{CanonicalExecution, ExecutionRequest, Input, ModelRef, RawRequest};

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
    fn provider_body_applies_request_overrides_stream_and_model() {
        let request = backend_request(
            br#"{"model":"client-model","input":"hello","stream":false,"store":true}"#,
            "gpt-5.5",
        );
        let overrides = JsonMap::from_iter([("store".to_string(), JsonValue::Bool(false))]);

        let body = provider_request_body(&request, &overrides).unwrap();
        let value: JsonValue = serde_json::from_slice(&body).unwrap();

        assert_eq!(value["model"], "gpt-5.5");
        assert_eq!(value["input"], "hello");
        assert_eq!(value["stream"], true);
        assert_eq!(value["store"], false);
    }

    #[test]
    fn provider_body_without_overrides_preserves_optional_fields() {
        let request = backend_request(br#"{"model":"m","input":"hello"}"#, "m");
        let overrides = JsonMap::new();

        let body = provider_request_body(&request, &overrides).unwrap();
        let value: JsonValue = serde_json::from_slice(&body).unwrap();

        assert_eq!(value["stream"], true);
        assert!(value.get("store").is_none());
    }

    #[test]
    fn signed_input_helper_returns_request_commitment() {
        let key = ProducerSigningKey::from_secret_bytes([3; 32]).unwrap();
        let (events, commitment) = signed_input_events_with_commitment(
            "codex",
            "responses",
            br#"{"input":"hi"}"#,
            ContentId::from_bytes([9; 32]),
            &key,
        )
        .unwrap();

        assert_eq!(events.len(), 6);
        assert_eq!(commitment.len(), 64);
    }
}
