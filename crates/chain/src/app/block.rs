use crate::domain::{MAX_TXS_PER_BLOCK, PublicKey, Transaction};
use crate::execution::store::UtxoSyncTarget;
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_consensus::{
    Block, CertifiableBlock, Heightable,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Digest as _, Digestible, Hasher, Sha256, sha256::Digest};

#[cfg(feature = "validator")]
pub(crate) const SYNCHRONY_BOUND: u64 = 5_000;

#[cfg(feature = "validator")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ValidationError {
    #[error("context mismatch")]
    ContextMismatch,
    #[error("parent mismatch: parsed={parsed:?} expected={expected:?}")]
    ParentMismatch { parsed: Digest, expected: Digest },
    #[error("height mismatch: parsed={parsed} expected={expected}")]
    HeightMismatch { parsed: Height, expected: Height },
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
    context: Context<Digest, PublicKey>,
    parent: Digest,
    height: Height,
    timestamp: u64,
    state_root: Digest,
    sync_target: UtxoSyncTarget,
    txs: Vec<Transaction>,
}

impl HellasBlock {
    pub fn genesis(leader: PublicKey, state_root: Digest, sync_target: UtxoSyncTarget) -> Self {
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), Digest::EMPTY),
            },
            parent: Digest::EMPTY,
            height: Height::zero(),
            timestamp: 0,
            state_root,
            sync_target,
            txs: Vec::new(),
        }
    }

    pub fn new(
        context: Context<Digest, PublicKey>,
        parent: Digest,
        height: Height,
        timestamp: u64,
        state_root: Digest,
        sync_target: UtxoSyncTarget,
        txs: Vec<Transaction>,
    ) -> Self {
        Self {
            context,
            parent,
            height,
            timestamp,
            state_root,
            sync_target,
            txs,
        }
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn state_root(&self) -> Digest {
        self.state_root
    }

    pub fn sync_target(&self) -> UtxoSyncTarget {
        self.sync_target.clone()
    }

    pub fn txs(&self) -> &[Transaction] {
        &self.txs
    }

    /// The proposer-side check inside `StatefulApplication::verify`. A
    /// follower never runs it: it ingests blocks that already carry a
    /// finalization certificate, checked by `ConsensusVerifier`, so the
    /// context/height/timestamp agreement is already settled by the
    /// quorum that signed them.
    #[cfg(feature = "validator")]
    pub(crate) fn validate(
        &self,
        expected_context: &Context<Digest, PublicKey>,
        expected_height: Height,
        expected_parent: Digest,
        now: u64,
        parent_timestamp: u64,
    ) -> Result<(), ValidationError> {
        if &self.context != expected_context {
            return Err(ValidationError::ContextMismatch);
        }
        if self.parent != expected_parent {
            return Err(ValidationError::ParentMismatch {
                parsed: self.parent,
                expected: expected_parent,
            });
        }
        if self.height != expected_height {
            return Err(ValidationError::HeightMismatch {
                parsed: self.height,
                expected: expected_height,
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
        Sha256::hash(&self.encode())
    }
}

impl Block for HellasBlock {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl CertifiableBlock for HellasBlock {
    type Context = Context<Digest, PublicKey>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl EncodeSize for HellasBlock {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.timestamp.encode_size()
            + self.state_root.encode_size()
            + self.sync_target.encode_size()
            + self.txs.encode_size()
    }
}

impl Write for HellasBlock {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.timestamp.write(buf);
        self.state_root.write(buf);
        self.sync_target.write(buf);
        self.txs.write(buf);
    }
}

impl Read for HellasBlock {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let context = Context::read(buf)?;
        let parent = Digest::read(buf)?;
        let height = Height::read(buf)?;
        let timestamp = u64::read(buf)?;
        let state_root = Digest::read(buf)?;
        let sync_target = UtxoSyncTarget::read(buf)?;
        let txs = Vec::<Transaction>::read_range(buf, 0..=MAX_TXS_PER_BLOCK)?;
        Ok(Self {
            context,
            parent,
            height,
            timestamp,
            state_root,
            sync_target,
            txs,
        })
    }
}

// Exercises `validate`, which only exists on a `validator` build.
#[cfg(all(test, feature = "validator"))]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_storage::{merkle::Location, mmr};
    use commonware_utils::non_empty_range;

    fn context() -> Context<Digest, PublicKey> {
        Context {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (View::zero(), Digest::EMPTY),
        }
    }

    fn block(timestamp: u64) -> HellasBlock {
        let context = context();
        let sync_target = UtxoSyncTarget::new(
            Digest::EMPTY,
            non_empty_range!(
                Location::<mmr::Family>::new(0),
                Location::<mmr::Family>::new(1)
            ),
        );
        HellasBlock::new(
            context,
            Digest::EMPTY,
            Height::new(1),
            timestamp,
            Digest::EMPTY,
            sync_target,
            Vec::new(),
        )
    }

    #[test]
    fn validate_accepts_timestamp_at_synchrony_bound() {
        let context = context();

        let result = block(10_000 + SYNCHRONY_BOUND).validate(
            &context,
            Height::new(1),
            Digest::EMPTY,
            10_000,
            0,
        );

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn validate_rejects_timestamp_beyond_synchrony_bound() {
        let context = context();

        let result = block(10_000 + SYNCHRONY_BOUND + 1).validate(
            &context,
            Height::new(1),
            Digest::EMPTY,
            10_000,
            0,
        );

        assert_eq!(
            result,
            Err(ValidationError::FutureTimestamp {
                timestamp: 10_000 + SYNCHRONY_BOUND + 1,
                now: 10_000,
            })
        );
    }
}
