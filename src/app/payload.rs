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
    #[error("round mismatch: parsed={parsed:?} expected={expected:?}")]
    RoundMismatch { parsed: Round, expected: Round },
    #[error("parent mismatch: parsed={parsed:?} expected={expected:?}")]
    ParentMismatch { parsed: Digest, expected: Digest },
    #[error("anchor root mismatch: claimed={claimed:?} local={local:?}")]
    AnchorRootMismatch { claimed: Digest, local: Digest },
    #[error("timestamp too far in the future: timestamp={timestamp} now={now}")]
    FutureTimestamp { timestamp: u64, now: u64 },
    #[error("timestamp before parent: timestamp={timestamp} parent_timestamp={parent_timestamp}")]
    TimestampRegression {
        timestamp: u64,
        parent_timestamp: u64,
    },
}

/// Decoded block fields shared by both [`SeenBlock`] variants.
#[derive(Debug, Clone)]
pub(super) struct BlockData {
    pub bytes: Bytes,
    pub round: Round,
    pub parent: Digest,
    pub timestamp: u64,
    pub anchor_payload: Digest,
    pub anchor_root: Digest,
    pub txs: Vec<Transaction>,
}

/// A block stored in the `seen` map. Starts as `Untrusted` (decoded but not
/// validated) and transitions to `Validated` after passing all checks.
#[derive(Debug, Clone)]
pub(super) enum SeenBlock {
    Untrusted(BlockData),
    Validated(BlockData),
}

impl SeenBlock {
    /// Decode raw payload bytes. Returns `None` if the bytes are malformed.
    pub fn decode(bytes: Bytes) -> Option<Self> {
        let mut reader = bytes.clone();
        let round = Round::read(&mut reader).ok()?;
        let parent = Digest::read(&mut reader).ok()?;
        let timestamp = u64::read(&mut reader).ok()?;
        let anchor_payload = Digest::read(&mut reader).ok()?;
        let anchor_root = Digest::read(&mut reader).ok()?;
        let txs = Vec::<Transaction>::read_range(&mut reader, 0..=MAX_TXS_PER_BLOCK).ok()?;
        if !reader.is_empty() {
            return None;
        }
        Some(Self::Untrusted(BlockData {
            bytes,
            round,
            parent,
            timestamp,
            anchor_payload,
            anchor_root,
            txs,
        }))
    }

    /// Access the decoded block data regardless of validation state.
    pub fn data(&self) -> &BlockData {
        match self {
            Self::Untrusted(d) | Self::Validated(d) => d,
        }
    }

    /// The raw wire bytes (for network transport / persistence).
    pub fn bytes(&self) -> &Bytes {
        &self.data().bytes
    }

    /// Validate and transition from `Untrusted` to `Validated`.
    ///
    /// Checks the digest, round, parent, and timestamp constraints.
    /// Consumes the block — on validation failure the invalid block is dropped.
    pub fn into_validated(
        self,
        expected_round: Round,
        expected_parent: Digest,
        expected_digest: Digest,
        now: u64,
        parent_timestamp: u64,
        local_anchor_root: Digest,
    ) -> Result<Self, PayloadValidationError> {
        let Self::Untrusted(data) = self else {
            return Ok(self);
        };

        let computed = payload_digest(&data.bytes);
        if computed != expected_digest {
            return Err(PayloadValidationError::DigestMismatch {
                computed,
                expected: expected_digest,
            });
        }

        if data.round != expected_round {
            return Err(PayloadValidationError::RoundMismatch {
                parsed: data.round,
                expected: expected_round,
            });
        }

        if data.parent != expected_parent {
            return Err(PayloadValidationError::ParentMismatch {
                parsed: data.parent,
                expected: expected_parent,
            });
        }

        if data.anchor_root != local_anchor_root {
            return Err(PayloadValidationError::AnchorRootMismatch {
                claimed: data.anchor_root,
                local: local_anchor_root,
            });
        }

        if data.timestamp > now.saturating_add(SYNCHRONY_BOUND) {
            return Err(PayloadValidationError::FutureTimestamp {
                timestamp: data.timestamp,
                now,
            });
        }

        if data.timestamp < parent_timestamp {
            return Err(PayloadValidationError::TimestampRegression {
                timestamp: data.timestamp,
                parent_timestamp,
            });
        }

        Ok(Self::Validated(data))
    }
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

pub(super) fn payload_digest(contents: &Bytes) -> Digest {
    Sha256::hash(contents)
}

pub(super) fn missing_dependency_or_execution(
    seen: &HashMap<Digest, SeenBlock>,
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
    seen: &HashMap<Digest, SeenBlock>,
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
        let block = seen.get(&current)?;
        let parent = block.data().parent;
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
