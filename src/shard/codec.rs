use super::protocol::{BlockKey, ShardMessage, ZodaCommitment, ZodaReShard, ZodaShard};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_coding::CodecConfig;
use commonware_consensus::types::Round;
use commonware_cryptography::sha256::Digest;
use hellas_types::PublicKey;

/// Wire-format shard message.
///
/// Sender is intentionally omitted from the wire payload. Sender identity must
/// come from authenticated transport metadata.
#[derive(Clone)]
pub(crate) enum WireShardMessage {
    Initial {
        key: BlockKey,
        commitment: ZodaCommitment,
        shard: ZodaShard,
        shard_index: u16,
    },
    ReShare {
        key: BlockKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        // Wire-level "ReShare" message carries a re-sharded fragment payload.
        reshard: ZodaReShard,
    },
}

#[derive(Clone, Copy)]
enum WireTag {
    Initial,
    ReShare,
}

impl WireTag {
    const INITIAL_TAG: u8 = 0;
    const RESHARE_TAG: u8 = 1;

    const fn as_u8(self) -> u8 {
        match self {
            Self::Initial => Self::INITIAL_TAG,
            Self::ReShare => Self::RESHARE_TAG,
        }
    }

    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            Self::INITIAL_TAG => Some(Self::Initial),
            Self::RESHARE_TAG => Some(Self::ReShare),
            _ => None,
        }
    }
}

/// Decode a typed payload from raw bytes (zero-copy `Bytes` slice).
fn decode_payload_part<T>(payload: Bytes) -> Option<T>
where
    T: Read<Cfg = CodecConfig>,
{
    let read_cfg = CodecConfig {
        maximum_shard_size: payload.len(),
    };
    let mut payload_reader = payload;
    let value = T::read_cfg(&mut payload_reader, &read_cfg).ok()?;
    if payload_reader.has_remaining() {
        return None;
    }
    Some(value)
}

/// Compute the encoded size of the common wire header (tag through shard_index).
fn header_encode_size(key: &BlockKey, commitment: &ZodaCommitment) -> usize {
    u8::SIZE // tag
        + key.round.encode_size()
        + key.digest.encode_size()
        + commitment.encode_size()
        + u16::SIZE // shard_index
}

/// Write the common wire header fields into a buffer.
fn write_header(
    buf: &mut impl BufMut,
    tag: WireTag,
    key: &BlockKey,
    commitment: &ZodaCommitment,
    shard_index: u16,
) {
    tag.as_u8().write(buf);
    key.round.write(buf);
    key.digest.write(buf);
    commitment.write(buf);
    shard_index.write(buf);
}

/// Read the common wire header fields from a buffer.
fn read_header(reader: &mut Bytes) -> Option<(WireTag, BlockKey, ZodaCommitment, u16)> {
    let tag = WireTag::from_u8(u8::read(reader).ok()?)?;
    let round = Round::read(reader).ok()?;
    let digest = Digest::read(reader).ok()?;
    let commitment = ZodaCommitment::read(reader).ok()?;
    let shard_index = u16::read(reader).ok()?;
    Some((tag, BlockKey::new(round, digest), commitment, shard_index))
}

impl WireShardMessage {
    /// Decode a wire shard message from a `Bytes` buffer.
    ///
    /// The payload section is sliced zero-copy from `buf` rather than copied
    /// into a new allocation.
    pub(crate) fn decode(buf: Bytes) -> Option<Self> {
        let mut reader = buf;
        let (tag, key, commitment, shard_index) = read_header(&mut reader)?;

        // Read Vec<u8>-compatible length prefix (u32), then zero-copy slice the
        // payload from the underlying Bytes buffer.
        let payload_len = u32::read(&mut reader).ok()? as usize;
        if reader.remaining() != payload_len {
            return None;
        }
        let payload = reader.copy_to_bytes(payload_len);

        match tag {
            WireTag::Initial => {
                let shard = decode_payload_part(payload)?;
                Some(Self::Initial {
                    key,
                    commitment,
                    shard,
                    shard_index,
                })
            }
            WireTag::ReShare => {
                let reshard = decode_payload_part(payload)?;
                Some(Self::ReShare {
                    key,
                    commitment,
                    shard_index,
                    reshard,
                })
            }
        }
    }

    pub(crate) fn with_sender(self, sender: PublicKey) -> ShardMessage {
        ShardMessage { sender, body: self }
    }
}

impl EncodeSize for WireShardMessage {
    fn encode_size(&self) -> usize {
        let (key, commitment, payload_size) = match self {
            Self::Initial {
                key,
                commitment,
                shard,
                ..
            } => (key, commitment, shard.encode_size()),
            Self::ReShare {
                key,
                commitment,
                reshard,
                ..
            } => (key, commitment, reshard.encode_size()),
        };
        header_encode_size(key, commitment)
            + u32::SIZE // payload length prefix
            + payload_size
    }
}

impl Write for WireShardMessage {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Initial {
                key,
                commitment,
                shard,
                shard_index,
            } => {
                write_header(buf, WireTag::Initial, key, commitment, *shard_index);
                (shard.encode_size() as u32).write(buf);
                shard.write(buf);
            }
            Self::ReShare {
                key,
                commitment,
                shard_index,
                reshard,
            } => {
                write_header(buf, WireTag::ReShare, key, commitment, *shard_index);
                (reshard.encode_size() as u32).write(buf);
                reshard.write(buf);
            }
        }
    }
}

impl Read for WireShardMessage {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let payload = buf.copy_to_bytes(buf.remaining());
        WireShardMessage::decode(payload).ok_or(CodecError::Invalid(
            "WireShardMessage",
            "unable to decode wire message",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::protocol::{CodingImpl, coding_config};
    use commonware_codec::Encode;
    use commonware_coding::Scheme as CodingScheme;
    use commonware_consensus::types::{Epoch, View};
    use commonware_cryptography::{Hasher, Sha256};
    use commonware_parallel::Sequential;

    fn sample_artifacts(
        payload: &[u8],
    ) -> (commonware_coding::Config, ZodaCommitment, Vec<ZodaShard>) {
        let config = coding_config(6);
        let (commitment, shards) = CodingImpl::encode(&config, payload, &Sequential).unwrap();
        (config, commitment, shards)
    }

    #[test]
    fn malformed_payloads_return_none() {
        assert!(WireShardMessage::decode(Bytes::from_static(&[])).is_none());
        assert!(WireShardMessage::decode(Bytes::from_static(&[WireTag::INITIAL_TAG])).is_none());
        assert!(WireShardMessage::decode(Bytes::from_static(&[0xFF])).is_none());

        let (_config, commitment, shards) = sample_artifacts(b"codec-malformed");
        let key = BlockKey::new(
            Round::new(Epoch::new(9), View::new(1)),
            Sha256::hash(b"codec-malformed"),
        );
        let message = WireShardMessage::Initial {
            key,
            commitment,
            shard: shards[0].clone(),
            shard_index: 0,
        };
        let encoded = message.encode();

        let truncated = encoded.slice(0..encoded.len().saturating_sub(1));
        assert!(WireShardMessage::decode(truncated).is_none());

        let mut extended = encoded.to_vec();
        extended.push(0xAA);
        assert!(WireShardMessage::decode(Bytes::from(extended)).is_none());
    }
}
