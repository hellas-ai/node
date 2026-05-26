use hellas_rpc::provenance::{CatnixReceiptCommitment, ExecutionProvenance, encode_hex};
use hellas_wire_adaptors::{Provenance, StopReason as WireStopReason, Usage};

use crate::execution::StopReason as RuntimeStopReason;

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
