use crate::execution::{ReceiptArtifact, StopReason as RuntimeStopReason};
use hellas_rpc::provenance::{ExecutionProvenance, encode_hex};
use hellas_wire_adaptors::{Provenance, StopReason, Usage};

pub(super) fn provenance_from_execution(provenance: &ExecutionProvenance) -> Provenance {
    Provenance {
        call_commitment: Some(encode_hex(&provenance.commitment_id)),
        receipt: None,
    }
}

pub(super) fn provenance_from_parts(
    provenance: Option<&ExecutionProvenance>,
    receipt: Option<&ReceiptArtifact>,
) -> Option<Provenance> {
    if provenance.is_none() && receipt.is_none() {
        return None;
    }
    Some(Provenance {
        call_commitment: provenance.map(|value| encode_hex(&value.commitment_id)),
        receipt: receipt.map(ReceiptArtifact::encoded),
    })
}

pub(super) fn usage(input_tokens: u32, total_tokens: u64) -> Usage {
    let input = u64::from(input_tokens);
    let output = total_tokens.saturating_sub(input);
    Usage {
        input_tokens: Some(input),
        output_tokens: Some(output),
        total_tokens: Some(total_tokens),
    }
}

pub(super) fn stop_reason_from_runtime(stop_reason: RuntimeStopReason) -> StopReason {
    match stop_reason {
        RuntimeStopReason::EndOfSequence => StopReason::EndOfText,
        RuntimeStopReason::MaxNewTokens => StopReason::MaxOutputTokens,
        RuntimeStopReason::Cancelled => StopReason::Cancelled,
    }
}
