use super::{BlockKey, ShardMessage, ZodaCommitment, ZodaReShard, ZodaShard};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write,
};
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

#[derive(Clone, Copy)]
struct WireHeader {
    key: BlockKey,
    commitment: ZodaCommitment,
    shard_index: u16,
}

impl WireHeader {
    const fn new(key: BlockKey, commitment: ZodaCommitment, shard_index: u16) -> Self {
        Self {
            key,
            commitment,
            shard_index,
        }
    }
}

#[derive(Clone)]
struct WireEnvelope {
    tag: WireTag,
    header: WireHeader,
    payload: Vec<u8>,
}

impl WireEnvelope {
    fn encode(&self) -> Bytes {
        (
            self.tag.as_u8(),
            self.header.key.round,
            self.header.key.digest,
            self.header.commitment,
            self.header.shard_index,
            self.payload.clone(),
        )
            .encode()
    }

    fn decode(buf: &[u8]) -> Option<Self> {
        let mut reader = Bytes::copy_from_slice(buf);
        let tag = WireTag::from_u8(u8::read(&mut reader).ok()?)?;
        let round = Round::read(&mut reader).ok()?;
        let digest = Digest::read(&mut reader).ok()?;
        let commitment = ZodaCommitment::read(&mut reader).ok()?;
        let shard_index = u16::read(&mut reader).ok()?;
        let remaining = reader.remaining();
        let payload = Vec::<u8>::read_range(&mut reader, 0..=remaining).ok()?;
        if reader.has_remaining() {
            return None;
        }

        Some(Self {
            tag,
            header: WireHeader::new(BlockKey::new(round, digest), commitment, shard_index),
            payload,
        })
    }
}

fn decode_payload_part<T>(payload: Vec<u8>) -> Option<T>
where
    T: Read<Cfg = CodecConfig>,
{
    let read_cfg = CodecConfig {
        maximum_shard_size: payload.len(),
    };
    let mut payload_reader = Bytes::from(payload);
    let value = T::read_cfg(&mut payload_reader, &read_cfg).ok()?;
    if payload_reader.has_remaining() {
        return None;
    }
    Some(value)
}

impl WireShardMessage {
    pub(crate) fn encode(&self) -> Bytes {
        let envelope = match self {
            Self::Initial {
                key,
                commitment,
                shard,
                shard_index,
            } => WireEnvelope {
                tag: WireTag::Initial,
                header: WireHeader::new(*key, *commitment, *shard_index),
                payload: shard.encode().to_vec(),
            },
            Self::ReShare {
                key,
                commitment,
                shard_index,
                reshard,
            } => WireEnvelope {
                tag: WireTag::ReShare,
                header: WireHeader::new(*key, *commitment, *shard_index),
                payload: reshard.encode().to_vec(),
            },
        };
        envelope.encode()
    }

    pub(crate) fn decode(buf: &[u8]) -> Option<Self> {
        let envelope = WireEnvelope::decode(buf)?;
        let WireEnvelope {
            tag,
            header,
            payload,
        } = envelope;
        match tag {
            WireTag::Initial => {
                let shard = decode_payload_part(payload)?;
                Some(Self::Initial {
                    key: header.key,
                    commitment: header.commitment,
                    shard,
                    shard_index: header.shard_index,
                })
            }
            WireTag::ReShare => {
                let reshard = decode_payload_part(payload)?;
                Some(Self::ReShare {
                    key: header.key,
                    commitment: header.commitment,
                    shard_index: header.shard_index,
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
        WireShardMessage::encode(self).len()
    }
}

impl Write for WireShardMessage {
    fn write(&self, buf: &mut impl BufMut) {
        let encoded = WireShardMessage::encode(self);
        buf.put_slice(encoded.as_ref());
    }
}

impl Read for WireShardMessage {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let payload = buf.copy_to_bytes(buf.remaining());
        WireShardMessage::decode(payload.as_ref()).ok_or(CodecError::Invalid(
            "WireShardMessage",
            "unable to decode wire message",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::{CodingImpl, coding_config};
    use commonware_coding::Scheme as CodingScheme;
    use commonware_consensus::types::{Epoch, View};
    use commonware_cryptography::{Hasher, Sha256, Signer, ed25519};
    use commonware_parallel::Sequential;
    use proptest::prelude::*;

    fn sample_artifacts(
        payload: &[u8],
    ) -> (commonware_coding::Config, ZodaCommitment, Vec<ZodaShard>) {
        let config = coding_config(6);
        let (commitment, shards) = CodingImpl::encode(&config, payload, &Sequential).unwrap();
        (config, commitment, shards)
    }

    proptest! {
        #[test]
        fn wire_message_roundtrip_prop(
            payload in prop::collection::vec(any::<u8>(), 50..512),
            shard_index in 0u16..6u16,
            view in any::<u16>(),
            as_reshare in any::<bool>(),
        ) {
            let (config, commitment, shards) = sample_artifacts(payload.as_slice());
            let key = BlockKey::new(
                Round::new(Epoch::new(1), View::new(u64::from(view))),
                Sha256::hash(payload.as_slice()),
            );
            let wire = if as_reshare {
                let (_, _, reshard) = CodingImpl::reshard(
                    &config,
                    &commitment,
                    shard_index,
                    shards[usize::from(shard_index)].clone(),
                ).unwrap();
                WireShardMessage::ReShare {
                    key,
                    commitment,
                    shard_index,
                    reshard,
                }
            } else {
                WireShardMessage::Initial {
                    key,
                    commitment,
                    shard: shards[usize::from(shard_index)].clone(),
                    shard_index,
                }
            };

            let encoded = wire.encode();
            let decoded = WireShardMessage::decode(encoded.as_ref()).expect("decode should succeed");
            prop_assert_eq!(decoded.encode(), encoded);

            let sender = ed25519::PrivateKey::from_seed(9).public_key();
            let authenticated = decoded.with_sender(sender.clone());
            prop_assert_eq!(authenticated.sender(), &sender);
        }
    }
}
