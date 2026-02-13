use crate::execution::SpeculativeExecutionStore;
use hellas_types::{MAX_TXS_PER_BLOCK, Transaction};
use bytes::Bytes;
use commonware_codec::{ReadExt, ReadRangeExt, Write};
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use hellas_types::Context;
use std::collections::HashMap;
use thiserror::Error;

/// Milliseconds in the future to allow for block timestamps.
pub(super) const SYNCHRONY_BOUND: u64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(super) enum PayloadValidationError {
    #[error("digest mismatch: computed={computed:?} expected={expected:?}")]
    DigestMismatch { computed: Digest, expected: Digest },
    #[error("invalid payload encoding")]
    InvalidEncoding,
    #[error("round mismatch: parsed={parsed:?} expected={expected:?}")]
    RoundMismatch { parsed: Round, expected: Round },
    #[error("parent mismatch: parsed={parsed:?} expected={expected:?}")]
    ParentMismatch { parsed: Digest, expected: Digest },
    #[error("invalid parent payload encoding")]
    InvalidParentEncoding,
    #[error("timestamp too far in the future: timestamp={timestamp} now={now}")]
    FutureTimestamp { timestamp: u64, now: u64 },
    #[error("timestamp before parent: timestamp={timestamp} parent_timestamp={parent_timestamp}")]
    TimestampRegression {
        timestamp: u64,
        parent_timestamp: u64,
    },
}

pub(super) fn genesis_payload(epoch: Epoch) -> Bytes {
    let round = Round::new(epoch, View::zero());
    let parent = Digest::from([0u8; 32]);
    let anchor_payload = Digest::from([0u8; 32]);
    let anchor_root = Digest::from([0u8; 32]);
    encode_payload(round, parent, 0, anchor_payload, anchor_root, &[])
}

pub(super) fn genesis_digest(epoch: Epoch) -> Digest {
    payload_digest(&genesis_payload(epoch))
}

pub(super) fn encode_payload(
    round: Round,
    parent: Digest,
    timestamp: u64,
    anchor_payload: Digest,
    anchor_root: Digest,
    txs: &[Transaction],
) -> Bytes {
    let mut buf = bytes::BytesMut::new();
    round.write(&mut buf);
    parent.write(&mut buf);
    timestamp.write(&mut buf);
    anchor_payload.write(&mut buf);
    anchor_root.write(&mut buf);
    txs.write(&mut buf);
    buf.freeze()
}

fn decode_payload(
    contents: &Bytes,
) -> Option<(Round, Digest, u64, Digest, Digest, Vec<Transaction>)> {
    let mut reader = contents.clone();
    let round = Round::read(&mut reader).ok()?;
    let parent = Digest::read(&mut reader).ok()?;
    let timestamp = u64::read(&mut reader).ok()?;
    let anchor_payload = Digest::read(&mut reader).ok()?;
    let anchor_root = Digest::read(&mut reader).ok()?;
    let txs = Vec::<Transaction>::read_range(&mut reader, 0..=MAX_TXS_PER_BLOCK).ok()?;
    if !reader.is_empty() {
        return None;
    }
    Some((round, parent, timestamp, anchor_payload, anchor_root, txs))
}

pub(super) fn decode_execution_payload(
    seen: &HashMap<Digest, Bytes>,
    payload: Digest,
) -> Option<(Digest, Vec<Transaction>)> {
    let contents = seen.get(&payload)?;
    let (_, parent, _, _, _, txs) = decode_payload(contents)?;
    Some((parent, txs))
}

pub(super) fn decode_anchor(contents: &Bytes) -> Option<(Digest, Digest)> {
    let (_, _, _, anchor_payload, anchor_root, _) = decode_payload(contents)?;
    Some((anchor_payload, anchor_root))
}

pub(super) fn payload_digest(contents: &Bytes) -> Digest {
    Sha256::hash(contents)
}

/// Decode the timestamp from an encoded payload.
pub(super) fn decode_timestamp(contents: &Bytes) -> Option<u64> {
    let mut reader = contents.clone();
    let _ = Round::read(&mut reader).ok()?;
    let _ = Digest::read(&mut reader).ok()?;
    let timestamp = u64::read(&mut reader).ok()?;
    Some(timestamp)
}

pub(super) fn validate_payload(
    expected_round: Round,
    expected_parent: Digest,
    expected_payload: Digest,
    contents: &Bytes,
    now: u64,
    parent_contents: &Bytes,
) -> Result<Vec<Transaction>, PayloadValidationError> {
    let computed = payload_digest(contents);
    if computed != expected_payload {
        return Err(PayloadValidationError::DigestMismatch {
            computed,
            expected: expected_payload,
        });
    }

    let Some((parsed_round, parent, timestamp, _, _, txs)) = decode_payload(contents) else {
        return Err(PayloadValidationError::InvalidEncoding);
    };

    if parsed_round != expected_round {
        return Err(PayloadValidationError::RoundMismatch {
            parsed: parsed_round,
            expected: expected_round,
        });
    }

    if parent != expected_parent {
        return Err(PayloadValidationError::ParentMismatch {
            parsed: parent,
            expected: expected_parent,
        });
    }

    if timestamp > now.saturating_add(SYNCHRONY_BOUND) {
        return Err(PayloadValidationError::FutureTimestamp { timestamp, now });
    }

    let Some(parent_timestamp) = decode_timestamp(parent_contents) else {
        return Err(PayloadValidationError::InvalidParentEncoding);
    };
    if timestamp < parent_timestamp {
        return Err(PayloadValidationError::TimestampRegression {
            timestamp,
            parent_timestamp,
        });
    }

    Ok(txs)
}

pub(super) fn missing_dependency_or_execution(
    seen: &HashMap<Digest, Bytes>,
    speculative_store: &SpeculativeExecutionStore,
    context: &Context,
    payload: Digest,
) -> Option<Digest> {
    if !seen.contains_key(&payload) {
        return Some(payload);
    }
    first_missing_execution_dependency(seen, speculative_store, context.parent.1)
}

pub(super) fn first_missing_execution_dependency(
    seen: &HashMap<Digest, Bytes>,
    speculative_store: &SpeculativeExecutionStore,
    mut current: Digest,
) -> Option<Digest> {
    if !seen.contains_key(&current) {
        return Some(current);
    }
    if speculative_store.contains_execution(current) {
        return None;
    }

    // Walk parent links until we find the first missing payload bytes.
    // If links are malformed or cyclic, let verification fail as invalid
    // instead of deferring forever on an unresolvable dependency.
    for _ in 0..=seen.len() {
        let Some((parent, _txs)) = decode_execution_payload(seen, current) else {
            return None;
        };
        if parent == current {
            return None;
        }
        if !seen.contains_key(&parent) {
            return Some(parent);
        }
        if speculative_store.contains_execution(parent) {
            return None;
        }
        current = parent;
    }
    None
}
