use axum::body::{Body, Bytes};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use hellas_rpc::provenance::{CatnixReceiptCommitment, ExecutionProvenance, encode_hex};
use hellas_wire_adaptors::{
    AdaptorError, ExecutionRequest, Provenance, RawRequest, StopReason as WireStopReason, Usage,
    WireAdaptor, WireBody, WireEventData, WireResponse, WireStreamEvent,
};

use crate::execution::StopReason as RuntimeStopReason;

use super::{json_error, sse_data, sse_event_data};

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
