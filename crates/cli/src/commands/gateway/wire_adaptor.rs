use axum::body::{Body, Bytes};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use axum::response::sse::Event;
use futures::StreamExt;
use hellas_rpc::provenance::{CatnixReceiptCommitment, ExecutionProvenance, encode_hex};
use hellas_runtime::runtime::chat::{
    DecodeEvent, IncrementalToolCallParser, StopReason as ParserStopReason,
};
use hellas_wire_adaptors::{
    AdaptorError, ExecutionRequest, ExecutionResult, OutputEvent, OutputItem, Provenance,
    RawRequest, RenderContext, StopReason as WireStopReason, TextChannel, Usage, WireAdaptor,
    WireBody, WireEventData, WireResponse, WireStreamEvent,
};

use crate::execution::{Outcome, StopReason as RuntimeStopReason};

use super::state::{GenerationEvent, PreparedGeneration, TextGenerationError};
use super::{json_error, next_id, sse_data, sse_event_data, sse_response};

pub(super) fn parse_execution_request<A: WireAdaptor>(
    adaptor: &A,
    body: &Bytes,
    surface: &str,
) -> Result<(A::ParsedRequest, ExecutionRequest), Response> {
    let raw = RawRequest::from_slice(body).map_err(|err| adaptor_error(surface, err))?;
    let parsed = adaptor
        .parse(raw)
        .map_err(|err| adaptor_error(surface, err))?;
    let execution = adaptor
        .to_execution_request(&parsed)
        .map_err(|err| adaptor_error(surface, err))?;
    Ok((parsed, execution))
}

pub(super) fn adaptor_error(surface: &str, error: AdaptorError) -> Response {
    let status = match error {
        AdaptorError::InvalidJson(_)
        | AdaptorError::InvalidRequest { .. }
        | AdaptorError::Unsupported { .. }
        | AdaptorError::Projection { .. } => StatusCode::BAD_REQUEST,
        AdaptorError::Render { .. } => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json_error(status, format!("{surface}: {error}"))
}

pub(super) fn usage(prompt_tokens: u32, output_tokens: u64) -> Usage {
    let input_tokens = u64::from(prompt_tokens);
    Usage {
        input_tokens: Some(input_tokens),
        output_tokens: Some(output_tokens),
        total_tokens: Some(input_tokens.saturating_add(output_tokens)),
    }
}

pub(super) fn provenance_from_parts(
    provenance: Option<&ExecutionProvenance>,
    receipt: Option<&CatnixReceiptCommitment>,
) -> Option<Provenance> {
    let mut out = provenance
        .and_then(provenance_from_execution)
        .unwrap_or_default();
    if let Some(receipt) = receipt {
        out.receipt_commitment = Some(encode_hex(&receipt.0));
    }
    (out.call_commitment.is_some() || out.receipt_commitment.is_some()).then_some(out)
}

pub(super) fn provenance_from_execution(provenance: &ExecutionProvenance) -> Option<Provenance> {
    provenance
        .catnix_call_commitment
        .as_ref()
        .map(encode_hex)
        .map(|call_commitment| Provenance {
            call_commitment: Some(call_commitment),
            receipt_commitment: None,
        })
}

pub(super) fn stop_reason_from_runtime(stop_reason: RuntimeStopReason) -> WireStopReason {
    match stop_reason {
        RuntimeStopReason::EndOfSequence => WireStopReason::EndOfText,
        RuntimeStopReason::MaxNewTokens => WireStopReason::MaxOutputTokens,
        RuntimeStopReason::Cancelled => WireStopReason::Cancelled,
    }
}

pub(super) fn wire_response(response: WireResponse) -> Result<Response, String> {
    let status = StatusCode::from_u16(response.status)
        .map_err(|err| format!("adaptor rendered invalid HTTP status: {err}"))?;
    let body = match response.body {
        WireBody::Json(value) => Body::from(
            serde_json::to_vec(&value)
                .map_err(|err| format!("failed to encode JSON response: {err}"))?,
        ),
        WireBody::Bytes(bytes) => Body::from(bytes),
    };

    let mut builder = Response::builder().status(status);
    for (name, value) in response.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|err| format!("adaptor rendered invalid header name `{name}`: {err}"))?;
        let value = HeaderValue::from_str(&value)
            .map_err(|err| format!("adaptor rendered invalid header value for `{name}`: {err}"))?;
        builder = builder.header(name, value);
    }

    builder
        .body(body)
        .map_err(|err| format!("failed to build HTTP response: {err}"))
}

pub(super) fn attach_provenance(
    response: &mut Response,
    provenance: Option<ExecutionProvenance>,
    receipt: Option<CatnixReceiptCommitment>,
) {
    if let Some(provenance) = provenance {
        response.extensions_mut().insert(provenance);
    }
    if let Some(receipt) = receipt {
        response.extensions_mut().insert(receipt);
    }
}

pub(super) fn sse_event(event: WireStreamEvent) -> axum::response::sse::Event {
    match (event.name, event.data) {
        (Some(name), WireEventData::Json(value)) => sse_event_data(&name, &value),
        (Some(name), WireEventData::Text(value)) => axum::response::sse::Event::default()
            .event(name)
            .data(value),
        (Some(name), WireEventData::Bytes(value)) => axum::response::sse::Event::default()
            .event(name)
            .data(String::from_utf8_lossy(&value)),
        (None, WireEventData::Json(value)) => sse_data(&value),
        (None, WireEventData::Text(value)) => axum::response::sse::Event::default().data(value),
        (None, WireEventData::Bytes(value)) => {
            axum::response::sse::Event::default().data(String::from_utf8_lossy(&value))
        }
    }
}

pub(super) fn wire_error_event(error: AdaptorError) -> axum::response::sse::Event {
    output_error_event(error.to_string())
}

pub(super) fn output_error_event(message: impl Into<String>) -> axum::response::sse::Event {
    sse_event_data(
        "error",
        &serde_json::json!({
            "error": { "message": message.into() }
        }),
    )
}

pub(super) async fn text_response<A>(
    adaptor: A,
    parsed: A::ParsedRequest,
    prepared: PreparedGeneration,
    context: RenderContext,
    surface: &'static str,
    ready_message: &'static str,
) -> Response
where
    A: WireAdaptor,
{
    let prompt_tokens = prepared.prompt_tokens;
    let initial_provenance = prepared.provenance.clone();
    let completed = match prepared.collect_text().await {
        Ok(completed) => {
            info!(
                %completed.receipt_cid,
                provenance = ?completed.provenance,
                total_tokens = completed.total_tokens,
                stop_reason = ?completed.stop_reason,
                message = ready_message,
                "gateway response ready"
            );
            completed
        }
        Err(TextGenerationError::Failed { position, error }) => {
            warn!(position, %error, surface, "gateway request failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Inference error: {error}"),
            );
        }
        Err(TextGenerationError::Stream(message)) => {
            error!(%message, surface, "gateway request failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, message);
        }
    };

    let provenance = completed.provenance.clone();
    let receipt = completed.catnix_receipt_commitment.clone();
    let result = ExecutionResult {
        output: vec![OutputItem::Text {
            text: completed.text,
            channel: TextChannel::Output,
        }],
        usage: Some(usage(prompt_tokens, completed.total_tokens)),
        stop_reason: stop_reason_from_runtime(completed.stop_reason),
        provenance: provenance_from_parts(provenance.as_ref(), receipt.as_ref()),
    };

    let wire = match adaptor.render_response(&parsed, result, context) {
        Ok(response) => response,
        Err(err) => return adaptor_error(surface, err),
    };
    let mut response = match wire_response(wire) {
        Ok(response) => response,
        Err(message) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, message),
    };
    attach_provenance(&mut response, provenance.or(initial_provenance), receipt);
    response
}

pub(super) fn text_stream_response<A>(
    adaptor: A,
    parsed: A::ParsedRequest,
    prepared: PreparedGeneration,
    context: RenderContext,
    ready_message: &'static str,
) -> Response
where
    A: WireAdaptor + Send + 'static,
    A::ParsedRequest: Send + 'static,
    A::StreamState: Send + 'static,
{
    let prompt_tokens = prepared.prompt_tokens;
    let initial_provenance = prepared.provenance.clone();
    let response_provenance = initial_provenance.clone();
    let deadline = prepared.deadline();

    let mut response = sse_response(async_stream::stream! {
        let mut state = adaptor.initial_state(&parsed, context);

        if let Some(provenance) = initial_provenance.as_ref().and_then(provenance_from_execution) {
            match render_events(adaptor.render_stream_event(
                &parsed,
                &mut state,
                OutputEvent::Provenance(provenance),
            )) {
                Ok(events) => {
                    for event in events {
                        yield Ok(event);
                    }
                }
                Err(event) => {
                    yield Ok(event);
                    return;
                }
            }
        }

        match render_events(adaptor.render_stream_start(&parsed, &mut state)) {
            Ok(events) => {
                for event in events {
                    yield Ok(event);
                }
            }
            Err(event) => {
                yield Ok(event);
                return;
            }
        }

        let inner = prepared.stream();
        tokio::pin!(inner);
        let mut stream_provenance = initial_provenance;

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Provenance(prov)))) => {
                    stream_provenance = Some(prov);
                    if let Some(provenance) = stream_provenance.as_ref().and_then(provenance_from_execution) {
                        match render_events(adaptor.render_stream_event(
                            &parsed,
                            &mut state,
                            OutputEvent::Provenance(provenance),
                        )) {
                            Ok(events) => {
                                for event in events {
                                    yield Ok(event);
                                }
                            }
                            Err(event) => {
                                yield Ok(event);
                                return;
                            }
                        }
                    }
                }
                Ok(Some(Ok(GenerationEvent::Delta(delta)))) => {
                    match render_events(adaptor.render_stream_event(
                        &parsed,
                        &mut state,
                        OutputEvent::TextDelta {
                            index: 0,
                            delta,
                            channel: TextChannel::Output,
                        },
                    )) {
                        Ok(events) => {
                            for event in events {
                                yield Ok(event);
                            }
                        }
                        Err(event) => {
                            yield Ok(event);
                            return;
                        }
                    }
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Completed {
                    total_tokens,
                    stop_reason,
                    receipt_cid,
                    catnix_receipt_commitment,
                })))) => {
                    info!(
                        %receipt_cid,
                        provenance = ?stream_provenance,
                        total_tokens,
                        ?stop_reason,
                        message = ready_message,
                        "gateway stream ready"
                    );
                    if let Some(provenance) = provenance_from_parts(
                        stream_provenance.as_ref(),
                        catnix_receipt_commitment.as_ref(),
                    ) {
                        match render_events(adaptor.render_stream_event(
                            &parsed,
                            &mut state,
                            OutputEvent::Provenance(provenance),
                        )) {
                            Ok(events) => {
                                for event in events {
                                    yield Ok(event);
                                }
                            }
                            Err(event) => {
                                yield Ok(event);
                                return;
                            }
                        }
                    }

                    match render_events(adaptor.render_stream_event(
                        &parsed,
                        &mut state,
                        OutputEvent::Finished {
                            stop_reason: stop_reason_from_runtime(stop_reason),
                            usage: Some(usage(prompt_tokens, total_tokens)),
                        },
                    )) {
                        Ok(events) => {
                            for event in events {
                                yield Ok(event);
                            }
                        }
                        Err(event) => yield Ok(event),
                    }
                    return;
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Failed { error, .. })))) => {
                    for event in render_error_events(
                        &adaptor,
                        &parsed,
                        &mut state,
                        format!("Inference error: {error}"),
                    ) {
                        yield Ok(event);
                    }
                    return;
                }
                Ok(Some(Err(err))) => {
                    for event in render_error_events(
                        &adaptor,
                        &parsed,
                        &mut state,
                        format!("Inference error: {err:#}"),
                    ) {
                        yield Ok(event);
                    }
                    return;
                }
                Ok(None) => {
                    for event in render_error_events(
                        &adaptor,
                        &parsed,
                        &mut state,
                        "execution stream ended without terminal outcome".to_string(),
                    ) {
                        yield Ok(event);
                    }
                    return;
                }
                Err(_) => {
                    for event in render_error_events(
                        &adaptor,
                        &parsed,
                        &mut state,
                        format!(
                            "inference timed out after {}s",
                            super::timeout_secs_until(deadline)
                        ),
                    ) {
                        yield Ok(event);
                    }
                    return;
                }
            }
        }
    });

    if let Some(provenance) = response_provenance {
        response.extensions_mut().insert(provenance);
    }
    response
}

pub(super) fn chat_stream_response<A>(
    adaptor: A,
    parsed: A::ParsedRequest,
    prepared: PreparedGeneration,
    context: RenderContext,
    tool_call_id_prefix: &'static str,
    ready_message: &'static str,
) -> Response
where
    A: WireAdaptor + Send + 'static,
    A::ParsedRequest: Send + 'static,
    A::StreamState: Send + 'static,
{
    let prompt_tokens = prepared.prompt_tokens;
    let initial_provenance = prepared.provenance.clone();
    let response_provenance = initial_provenance.clone();
    let deadline = prepared.deadline();
    let mut parser: Box<dyn IncrementalToolCallParser> = prepared
        .chat_turn
        .as_ref()
        .expect("chat stream preparation attaches a ChatTurn")
        .make_parser();

    let mut response = sse_response(async_stream::stream! {
        let mut state = adaptor.initial_state(&parsed, context);
        let mut saw_tool_call = false;

        if let Some(provenance) = initial_provenance.as_ref().and_then(provenance_from_execution) {
            match render_events(adaptor.render_stream_event(
                &parsed,
                &mut state,
                OutputEvent::Provenance(provenance),
            )) {
                Ok(events) => {
                    for event in events {
                        yield Ok(event);
                    }
                }
                Err(event) => {
                    yield Ok(event);
                    return;
                }
            }
        }

        match render_events(adaptor.render_stream_start(&parsed, &mut state)) {
            Ok(events) => {
                for event in events {
                    yield Ok(event);
                }
            }
            Err(event) => {
                yield Ok(event);
                return;
            }
        }

        let inner = prepared.stream();
        tokio::pin!(inner);
        let mut stream_provenance = initial_provenance;

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Provenance(prov)))) => {
                    stream_provenance = Some(prov);
                    if let Some(provenance) = stream_provenance.as_ref().and_then(provenance_from_execution) {
                        match render_events(adaptor.render_stream_event(
                            &parsed,
                            &mut state,
                            OutputEvent::Provenance(provenance),
                        )) {
                            Ok(events) => {
                                for event in events {
                                    yield Ok(event);
                                }
                            }
                            Err(event) => {
                                yield Ok(event);
                                return;
                            }
                        }
                    }
                }
                Ok(Some(Ok(GenerationEvent::Delta(delta)))) => {
                    match render_parser_events(
                        &adaptor,
                        &parsed,
                        &mut state,
                        parser.feed(&delta),
                        tool_call_id_prefix,
                        &mut saw_tool_call,
                    ) {
                        Ok(events) => {
                            for event in events {
                                yield Ok(event);
                            }
                        }
                        Err(events) => {
                            for event in events {
                                yield Ok(event);
                            }
                            return;
                        }
                    }
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Completed {
                    total_tokens,
                    stop_reason,
                    receipt_cid,
                    catnix_receipt_commitment,
                })))) => {
                    info!(
                        %receipt_cid,
                        provenance = ?stream_provenance,
                        total_tokens,
                        ?stop_reason,
                        message = ready_message,
                        "gateway stream ready"
                    );
                    match render_parser_events(
                        &adaptor,
                        &parsed,
                        &mut state,
                        parser.finish(parser_stop_from_runtime(stop_reason)),
                        tool_call_id_prefix,
                        &mut saw_tool_call,
                    ) {
                        Ok(events) => {
                            for event in events {
                                yield Ok(event);
                            }
                        }
                        Err(events) => {
                            for event in events {
                                yield Ok(event);
                            }
                            return;
                        }
                    }

                    if let Some(provenance) = provenance_from_parts(
                        stream_provenance.as_ref(),
                        catnix_receipt_commitment.as_ref(),
                    ) {
                        match render_events(adaptor.render_stream_event(
                            &parsed,
                            &mut state,
                            OutputEvent::Provenance(provenance),
                        )) {
                            Ok(events) => {
                                for event in events {
                                    yield Ok(event);
                                }
                            }
                            Err(event) => {
                                yield Ok(event);
                                return;
                            }
                        }
                    }

                    let stop_reason = if saw_tool_call {
                        WireStopReason::ToolCall
                    } else {
                        stop_reason_from_runtime(stop_reason)
                    };
                    match render_events(adaptor.render_stream_event(
                        &parsed,
                        &mut state,
                        OutputEvent::Finished {
                            stop_reason,
                            usage: Some(usage(prompt_tokens, total_tokens)),
                        },
                    )) {
                        Ok(events) => {
                            for event in events {
                                yield Ok(event);
                            }
                        }
                        Err(event) => yield Ok(event),
                    }
                    return;
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Failed { error, .. })))) => {
                    for event in render_error_events(
                        &adaptor,
                        &parsed,
                        &mut state,
                        format!("Inference error: {error}"),
                    ) {
                        yield Ok(event);
                    }
                    return;
                }
                Ok(Some(Err(err))) => {
                    for event in render_error_events(
                        &adaptor,
                        &parsed,
                        &mut state,
                        format!("Inference error: {err:#}"),
                    ) {
                        yield Ok(event);
                    }
                    return;
                }
                Ok(None) => {
                    for event in render_error_events(
                        &adaptor,
                        &parsed,
                        &mut state,
                        "execution stream ended without terminal outcome".to_string(),
                    ) {
                        yield Ok(event);
                    }
                    return;
                }
                Err(_) => {
                    for event in render_error_events(
                        &adaptor,
                        &parsed,
                        &mut state,
                        format!(
                            "inference timed out after {}s",
                            super::timeout_secs_until(deadline)
                        ),
                    ) {
                        yield Ok(event);
                    }
                    return;
                }
            }
        }
    });

    if let Some(provenance) = response_provenance {
        response.extensions_mut().insert(provenance);
    }
    response
}

fn render_events(events: Result<Vec<WireStreamEvent>, AdaptorError>) -> Result<Vec<Event>, Event> {
    events
        .map(|events| events.into_iter().map(sse_event).collect())
        .map_err(wire_error_event)
}

fn render_parser_events<A: WireAdaptor>(
    adaptor: &A,
    parsed: &A::ParsedRequest,
    state: &mut A::StreamState,
    events: Vec<DecodeEvent>,
    tool_call_id_prefix: &'static str,
    saw_tool_call: &mut bool,
) -> Result<Vec<Event>, Vec<Event>> {
    let mut rendered = Vec::new();
    for event in events {
        let output = match event {
            DecodeEvent::TextDelta(delta) => Some(OutputEvent::TextDelta {
                index: 0,
                delta,
                channel: TextChannel::Output,
            }),
            DecodeEvent::ToolCallStart { index, name } => {
                *saw_tool_call = true;
                Some(OutputEvent::ToolCallStart(
                    hellas_wire_adaptors::ToolCallStart {
                        index,
                        id: Some(next_id(tool_call_id_prefix)),
                        name,
                    },
                ))
            }
            DecodeEvent::ToolCallArgsDelta { index, delta } => {
                Some(OutputEvent::ToolCallArgumentsDelta(
                    hellas_wire_adaptors::ToolCallArgumentsDelta { index, delta },
                ))
            }
            DecodeEvent::ToolCallEnd { index, args } => Some(OutputEvent::ToolCallEnd(
                hellas_wire_adaptors::ToolCallEnd {
                    index,
                    arguments: args,
                },
            )),
            DecodeEvent::Stop {
                reason: ParserStopReason::ProtocolError,
            } => {
                return Err(render_error_events(
                    adaptor,
                    parsed,
                    state,
                    "tool-call protocol error".to_string(),
                ));
            }
            DecodeEvent::Stop { .. } => None,
            DecodeEvent::UnknownTool { name, .. } => {
                return Err(render_error_events(
                    adaptor,
                    parsed,
                    state,
                    format!("unknown tool `{name}`"),
                ));
            }
            DecodeEvent::InvalidArgs { name, errors, .. } => {
                let errors = errors
                    .into_iter()
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(render_error_events(
                    adaptor,
                    parsed,
                    state,
                    format!("invalid arguments for tool `{name}`: {errors}"),
                ));
            }
            DecodeEvent::ParseError { source, .. } => {
                return Err(render_error_events(
                    adaptor,
                    parsed,
                    state,
                    source.to_string(),
                ));
            }
        };

        if let Some(output) = output {
            match render_events(adaptor.render_stream_event(parsed, state, output)) {
                Ok(events) => rendered.extend(events),
                Err(event) => return Err(vec![event]),
            }
        }
    }
    Ok(rendered)
}

fn parser_stop_from_runtime(stop_reason: RuntimeStopReason) -> ParserStopReason {
    match stop_reason {
        RuntimeStopReason::EndOfSequence => ParserStopReason::EndOfText,
        RuntimeStopReason::MaxNewTokens => ParserStopReason::MaxTokens,
        RuntimeStopReason::Cancelled => ParserStopReason::EndOfText,
    }
}

fn render_error_events<A: WireAdaptor>(
    adaptor: &A,
    parsed: &A::ParsedRequest,
    state: &mut A::StreamState,
    message: String,
) -> Vec<Event> {
    match render_events(adaptor.render_stream_event(
        parsed,
        state,
        OutputEvent::Error {
            message: message.clone(),
            code: None,
        },
    )) {
        Ok(events) if !events.is_empty() => events,
        Ok(_) => vec![output_error_event(message)],
        Err(event) => vec![event],
    }
}
