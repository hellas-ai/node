use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write};
use commonware_consensus::{
    Block, Heightable,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Digestible, Hasher, Sha256, sha256::Digest};
use hellas_types::{MAX_TXS_PER_BLOCK, Transaction};

/// Milliseconds in the future to allow for block timestamps.
pub(crate) const SYNCHRONY_BOUND: u64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ValidationError {
    #[error("digest mismatch: computed={computed:?} expected={expected:?}")]
    DigestMismatch { computed: Digest, expected: Digest },
    #[error("round mismatch: parsed={parsed:?} expected={expected:?}")]
    RoundMismatch { parsed: Round, expected: Round },
    #[error("parent mismatch: parsed={parsed:?} expected={expected:?}")]
    ParentMismatch { parsed: Digest, expected: Digest },
    #[error("height mismatch: parsed={parsed} expected={expected}")]
    HeightMismatch { parsed: Height, expected: Height },
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

#[derive(Debug, Clone)]
pub struct HellasBlock {
    digest: Digest,
    height: Height,
    round: Round,
    parent: Digest,
    timestamp: u64,
    anchor_payload: Digest,
    anchor_root: Digest,
    txs: Vec<Transaction>,
}

impl HellasBlock {
    pub fn genesis(epoch: Epoch) -> Self {
        Self::new(
            Height::zero(),
            Round::new(epoch, View::zero()),
            Digest::from([0u8; 32]),
            0,
            Digest::from([0u8; 32]),
            Digest::from([0u8; 32]),
            Vec::new(),
        )
    }

    pub fn new(
        height: Height,
        round: Round,
        parent: Digest,
        timestamp: u64,
        anchor_payload: Digest,
        anchor_root: Digest,
        txs: Vec<Transaction>,
    ) -> Self {
        let digest =
            payload_digest_bytes(round, parent, timestamp, anchor_payload, anchor_root, &txs);
        Self {
            digest,
            height,
            round,
            parent,
            timestamp,
            anchor_payload,
            anchor_root,
            txs,
        }
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn anchor_payload(&self) -> Digest {
        self.anchor_payload
    }

    pub fn anchor_root(&self) -> Digest {
        self.anchor_root
    }

    pub fn txs(&self) -> &[Transaction] {
        &self.txs
    }

    pub fn payload_bytes(&self) -> Bytes {
        encode_payload_bytes(
            self.round,
            self.parent,
            self.timestamp,
            self.anchor_payload,
            self.anchor_root,
            &self.txs,
        )
    }

    pub(crate) fn validate(
        &self,
        expected_height: Height,
        expected_round: Round,
        expected_parent: Digest,
        now: u64,
        parent_timestamp: u64,
        local_anchor_root: Digest,
    ) -> Result<(), ValidationError> {
        let computed = payload_digest_bytes(
            self.round,
            self.parent,
            self.timestamp,
            self.anchor_payload,
            self.anchor_root,
            &self.txs,
        );
        if computed != self.digest {
            return Err(ValidationError::DigestMismatch {
                computed,
                expected: self.digest,
            });
        }
        if self.height != expected_height {
            return Err(ValidationError::HeightMismatch {
                parsed: self.height,
                expected: expected_height,
            });
        }
        if self.round != expected_round {
            return Err(ValidationError::RoundMismatch {
                parsed: self.round,
                expected: expected_round,
            });
        }
        if self.parent != expected_parent {
            return Err(ValidationError::ParentMismatch {
                parsed: self.parent,
                expected: expected_parent,
            });
        }
        if self.anchor_root != local_anchor_root {
            return Err(ValidationError::AnchorRootMismatch {
                claimed: self.anchor_root,
                local: local_anchor_root,
            });
        }
        if self.timestamp > now.saturating_add(SYNCHRONY_BOUND) {
            return Err(ValidationError::FutureTimestamp {
                timestamp: self.timestamp,
                now,
            });
        }
        if self.timestamp < parent_timestamp {
            return Err(ValidationError::TimestampRegression {
                timestamp: self.timestamp,
                parent_timestamp,
            });
        }
        Ok(())
    }
}

impl Heightable for HellasBlock {
    fn height(&self) -> Height {
        self.height
    }
}

impl Digestible for HellasBlock {
    type Digest = Digest;

    fn digest(&self) -> Self::Digest {
        self.digest
    }
}

impl Block for HellasBlock {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl EncodeSize for HellasBlock {
    fn encode_size(&self) -> usize {
        self.height.encode_size()
            + self.round.encode_size()
            + self.parent.encode_size()
            + self.timestamp.encode_size()
            + self.anchor_payload.encode_size()
            + self.anchor_root.encode_size()
            + self.txs.encode_size()
    }
}

impl Write for HellasBlock {
    fn write(&self, buf: &mut impl BufMut) {
        self.height.write(buf);
        self.round.write(buf);
        self.parent.write(buf);
        self.timestamp.write(buf);
        self.anchor_payload.write(buf);
        self.anchor_root.write(buf);
        self.txs.write(buf);
    }
}

impl Read for HellasBlock {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let height = Height::read(buf)?;
        let round = Round::read(buf)?;
        let parent = Digest::read(buf)?;
        let timestamp = u64::read(buf)?;
        let anchor_payload = Digest::read(buf)?;
        let anchor_root = Digest::read(buf)?;
        let txs = Vec::<Transaction>::read_range(buf, 0..=MAX_TXS_PER_BLOCK)?;
        Ok(Self::new(
            height,
            round,
            parent,
            timestamp,
            anchor_payload,
            anchor_root,
            txs,
        ))
    }
}

pub(crate) fn encode_payload_bytes(
    round: Round,
    parent: Digest,
    timestamp: u64,
    anchor_payload: Digest,
    anchor_root: Digest,
    txs: &[Transaction],
) -> Bytes {
    let mut buf = BytesMut::new();
    round.write(&mut buf);
    parent.write(&mut buf);
    timestamp.write(&mut buf);
    anchor_payload.write(&mut buf);
    anchor_root.write(&mut buf);
    txs.write(&mut buf);
    buf.freeze()
}

pub(crate) fn payload_digest_bytes(
    round: Round,
    parent: Digest,
    timestamp: u64,
    anchor_payload: Digest,
    anchor_root: Digest,
    txs: &[Transaction],
) -> Digest {
    Sha256::hash(&encode_payload_bytes(
        round,
        parent,
        timestamp,
        anchor_payload,
        anchor_root,
        txs,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn genesis_digest_matches_payload_hash() {
        let block = HellasBlock::genesis(Epoch::zero());
        assert_eq!(
            block.digest(),
            payload_digest_bytes(
                block.round(),
                block.parent(),
                block.timestamp(),
                block.anchor_payload(),
                block.anchor_root(),
                block.txs(),
            )
        );
    }

    #[test]
    fn codec_round_trip_preserves_digest() {
        let block = HellasBlock::new(
            Height::new(7),
            Round::new(Epoch::zero(), View::new(7)),
            Digest::from([3u8; 32]),
            99,
            Digest::from([4u8; 32]),
            Digest::from([5u8; 32]),
            Vec::new(),
        );
        let encoded = block.encode();
        let decoded = HellasBlock::decode(encoded).expect("block should decode");
        assert_eq!(decoded.encode(), block.encode());
    }
}
