use async_stream::try_stream;
use futures::StreamExt;
use hellas_runtime::runtime::chat::{
    AssistantTurnAccumulator, DecodeEvent, DecodeFailure, DecodedPart, IncrementalToolCallParser,
    StopReason as ParserStopReason,
};
use hellas_wire_adaptors::{
    BackendError, ExecutionResult, OutputEvent, OutputItem, StopReason as WireStopReason,
    TextChannel,
};

use crate::execution::{Outcome, StopReason as RuntimeStopReason};

use super::super::next_id;
use super::super::state::PreparedGeneration;
use super::generation::{GenerationEvent, generation_stream};
use super::provenance::{
    provenance_from_execution, provenance_from_parts, stop_reason_from_runtime, usage,
};

pub(super) async fn execute_chat(
    prepared: PreparedGeneration,
    tool_call_id_prefix: &'static str,
    ready_message: &'static str,
) -> Result<ExecutionResult, BackendError> {
    let prompt_tokens = prepared.prompt_tokens;
    let mut provenance = prepared.provenance.clone();
    let mut parser = chat_parser(&prepared)?;
    let mut accumulator = AssistantTurnAccumulator::new();
    let deadline = prepared.deadline();
    let stream = generation_stream(prepared);
    tokio::pin!(stream);

    let (total_tokens, stop_reason, receipt_cid, catnix_receipt_commitment) = loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(GenerationEvent::Provenance(prov)))) => provenance = Some(prov),
            Ok(Some(Ok(GenerationEvent::Delta(delta)))) => {
                feed_decode_events(&mut accumulator, parser.feed(&delta))?;
            }
            Ok(Some(Ok(GenerationEvent::Done(Outcome::Completed {
                total_tokens,
                stop_reason,
                receipt_cid,
                catnix_receipt_commitment,
            })))) => {
                feed_decode_events(
                    &mut accumulator,
                    parser.finish(parser_stop_from_runtime(stop_reason)),
                )?;
                break (
                    total_tokens,
                    stop_reason,
                    receipt_cid,
                    catnix_receipt_commitment,
                );
            }
            Ok(Some(Ok(GenerationEvent::Done(Outcome::Failed { position, error })))) => {
                warn!(position, %error, "gateway chat request failed");
                return Err(BackendError::execution(format!("Inference error: {error}")));
            }
            Ok(Some(Err(err))) => {
                return Err(BackendError::execution(format!("Inference error: {err:#}")));
            }
            Ok(None) => {
                return Err(BackendError::execution(
                    "execution stream ended without terminal outcome",
                ));
            }
            Err(_) => {
                return Err(BackendError::execution(format!(
                    "inference timed out after {}s",
                    super::super::timeout_secs_until(deadline)
                )));
            }
        }
    };

    let turn = accumulator.snapshot().map_err(decode_failure)?;
    let output = output_items_from_turn(&turn, tool_call_id_prefix);
    let stop_reason = if output
        .iter()
        .any(|item| matches!(item, OutputItem::ToolCall { .. }))
    {
        WireStopReason::ToolCall
    } else {
        stop_reason_from_runtime(stop_reason)
    };
    info!(
        %receipt_cid,
        ?provenance,
        total_tokens,
        ?stop_reason,
        ?catnix_receipt_commitment,
        message = ready_message,
        "gateway response ready"
    );
    Ok(ExecutionResult {
        output,
        usage: Some(usage(prompt_tokens, total_tokens)),
        stop_reason,
        provenance: provenance_from_parts(provenance.as_ref(), catnix_receipt_commitment.as_ref()),
    })
}

pub(super) fn chat_events(
    prepared: PreparedGeneration,
    tool_call_id_prefix: &'static str,
    ready_message: &'static str,
) -> impl futures::Stream<Item = Result<OutputEvent, BackendError>> + Send {
    try_stream! {
        let prompt_tokens = prepared.prompt_tokens;
        let mut stream_provenance = prepared.provenance.clone();
        let mut parser = chat_parser(&prepared)?;
        let deadline = prepared.deadline();
        let inner = generation_stream(prepared);
        tokio::pin!(inner);
        let mut saw_tool_call = false;

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Provenance(prov)))) => {
                    let should_emit = stream_provenance.is_none();
                    stream_provenance = Some(prov.clone());
                    if should_emit
                        && let Some(provenance) = provenance_from_execution(&prov)
                    {
                        yield OutputEvent::Provenance(provenance);
                    }
                }
                Ok(Some(Ok(GenerationEvent::Delta(delta)))) => {
                    for event in output_events_from_decode(
                        parser.feed(&delta),
                        tool_call_id_prefix,
                        &mut saw_tool_call,
                    )? {
                        yield event;
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
                    for event in output_events_from_decode(
                        parser.finish(parser_stop_from_runtime(stop_reason)),
                        tool_call_id_prefix,
                        &mut saw_tool_call,
                    )? {
                        yield event;
                    }
                    if let Some(provenance) = provenance_from_parts(
                        stream_provenance.as_ref(),
                        catnix_receipt_commitment.as_ref(),
                    ) {
                        yield OutputEvent::Provenance(provenance);
                    }
                    let stop_reason = if saw_tool_call {
                        WireStopReason::ToolCall
                    } else {
                        stop_reason_from_runtime(stop_reason)
                    };
                    yield OutputEvent::Finished {
                        stop_reason,
                        usage: Some(usage(prompt_tokens, total_tokens)),
                    };
                    return;
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Failed { error, .. })))) => {
                    Err(BackendError::execution(format!("Inference error: {error}")))?;
                }
                Ok(Some(Err(err))) => Err(BackendError::execution(format!("Inference error: {err:#}")))?,
                Ok(None) => Err(BackendError::execution("execution stream ended without terminal outcome"))?,
                Err(_) => Err(BackendError::execution(format!(
                    "inference timed out after {}s",
                    super::super::timeout_secs_until(deadline)
                )))?,
            }
        }
    }
}

fn output_events_from_decode(
    events: Vec<DecodeEvent>,
    tool_call_id_prefix: &'static str,
    saw_tool_call: &mut bool,
) -> Result<Vec<OutputEvent>, BackendError> {
    let mut out = Vec::new();
    for event in events {
        match event {
            DecodeEvent::TextDelta(delta) => out.push(OutputEvent::TextDelta {
                index: 0,
                delta,
                channel: TextChannel::Output,
            }),
            DecodeEvent::ToolCallStart { index, name } => {
                *saw_tool_call = true;
                out.push(OutputEvent::ToolCallStart(
                    hellas_wire_adaptors::ToolCallStart {
                        index,
                        id: Some(next_id(tool_call_id_prefix)),
                        name,
                    },
                ));
            }
            DecodeEvent::ToolCallArgsDelta { index, delta } => {
                out.push(OutputEvent::ToolCallArgumentsDelta(
                    hellas_wire_adaptors::ToolCallArgumentsDelta { index, delta },
                ));
            }
            DecodeEvent::ToolCallEnd { index, args } => {
                out.push(OutputEvent::ToolCallEnd(
                    hellas_wire_adaptors::ToolCallEnd {
                        index,
                        arguments: args,
                    },
                ));
            }
            DecodeEvent::Stop {
                reason: ParserStopReason::ProtocolError,
            } => {
                return Err(BackendError::stream("tool-call protocol error"));
            }
            DecodeEvent::Stop { .. } => {}
            DecodeEvent::UnknownTool { name, .. } => {
                return Err(BackendError::stream(format!("unknown tool `{name}`")));
            }
            DecodeEvent::InvalidArgs { name, errors, .. } => {
                let errors = errors
                    .into_iter()
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(BackendError::stream(format!(
                    "invalid arguments for tool `{name}`: {errors}"
                )));
            }
            DecodeEvent::ParseError { source, .. } => {
                return Err(BackendError::stream(source.to_string()));
            }
        }
    }
    Ok(out)
}

fn output_items_from_turn(
    turn: &hellas_runtime::runtime::chat::DecodedAssistantTurn,
    tool_call_id_prefix: &'static str,
) -> Vec<OutputItem> {
    turn.parts
        .iter()
        .filter_map(|part| match part {
            DecodedPart::Text(text) if text.is_empty() => None,
            DecodedPart::Text(text) => Some(OutputItem::Text {
                text: text.clone(),
                channel: TextChannel::Output,
            }),
            DecodedPart::ToolCall(call) => Some(OutputItem::ToolCall {
                id: next_id(tool_call_id_prefix),
                name: call.name.clone(),
                arguments: call.args.clone(),
            }),
        })
        .collect()
}

fn feed_decode_events(
    accumulator: &mut AssistantTurnAccumulator,
    events: Vec<DecodeEvent>,
) -> Result<(), BackendError> {
    for event in events {
        accumulator.feed(event).map_err(decode_failure)?;
    }
    Ok(())
}

fn chat_parser(
    prepared: &PreparedGeneration,
) -> Result<Box<dyn IncrementalToolCallParser>, BackendError> {
    prepared
        .chat_turn
        .as_ref()
        .map(|turn| turn.make_parser())
        .ok_or_else(|| BackendError::execution("chat execution missing prepared chat turn"))
}

fn decode_failure(failure: DecodeFailure) -> BackendError {
    BackendError::stream(failure.to_string())
}

fn parser_stop_from_runtime(stop_reason: RuntimeStopReason) -> ParserStopReason {
    match stop_reason {
        RuntimeStopReason::EndOfSequence => ParserStopReason::EndOfText,
        RuntimeStopReason::MaxNewTokens => ParserStopReason::MaxTokens,
        RuntimeStopReason::Cancelled => ParserStopReason::EndOfText,
    }
}
