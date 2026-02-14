use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_coding::{CodecConfig, Config as CodingConfig, Scheme as CodingScheme, Zoda};
use commonware_consensus::types::Round;
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_utils::{Faults, N5f1};
use hellas_types::PublicKey;

pub(crate) type CodingImpl = Zoda<Sha256>;
pub(crate) type ZodaShard = <CodingImpl as CodingScheme>::Shard;
pub(crate) type ZodaReShard = <CodingImpl as CodingScheme>::ReShard;
pub(crate) type ZodaCheckedShard = <CodingImpl as CodingScheme>::CheckedShard;
pub(crate) type ZodaCheckingData = <CodingImpl as CodingScheme>::CheckingData;
pub(crate) type ZodaCommitment = <CodingImpl as CodingScheme>::Commitment;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct BlockKey {
    pub round: Round,
    pub digest: Digest,
}

impl BlockKey {
    pub(crate) const fn new(round: Round, digest: Digest) -> Self {
        Self { round, digest }
    }
}

pub(crate) fn coding_config(validators: u16) -> CodingConfig {
    if validators == 0 {
        warn!(
            "validator set was empty; defaulting coding config to minimum_shards=1 extra_shards=0"
        );
        return CodingConfig {
            minimum_shards: 1,
            extra_shards: 0,
        };
    }
    // N5f1 means the configuration expects n >= 5f + 1.
    // `max_faults` returns the largest f for the current validator count.
    let faults = N5f1::max_faults(validators);
    let minimum_shards = match u16::try_from(faults.saturating_add(1)) {
        Ok(value) => value.clamp(1, validators),
        Err(_) => {
            warn!(
                faults,
                validators,
                "fault count overflowed u16; clamping minimum shards to validator count"
            );
            validators
        }
    };
    let extra_shards = validators.saturating_sub(minimum_shards);
    CodingConfig {
        minimum_shards,
        extra_shards,
    }
}

pub(crate) fn hash_encoded<T: Encode>(value: &T) -> Digest {
    Sha256::hash(&value.encode())
}

// ---------------------------------------------------------------------------
// Wire-format shard message
// ---------------------------------------------------------------------------

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
    FetchPayload {
        digest: Digest,
    },
    PayloadResponse {
        digest: Digest,
        payload: Bytes,
    },
}

#[derive(Clone, Copy)]
enum WireTag {
    Initial,
    ReShare,
    FetchPayload,
    PayloadResponse,
}

impl WireTag {
    const INITIAL_TAG: u8 = 0;
    const RESHARE_TAG: u8 = 1;
    const FETCH_PAYLOAD_TAG: u8 = 2;
    const PAYLOAD_RESPONSE_TAG: u8 = 3;

    const fn as_u8(self) -> u8 {
        match self {
            Self::Initial => Self::INITIAL_TAG,
            Self::ReShare => Self::RESHARE_TAG,
            Self::FetchPayload => Self::FETCH_PAYLOAD_TAG,
            Self::PayloadResponse => Self::PAYLOAD_RESPONSE_TAG,
        }
    }

    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            Self::INITIAL_TAG => Some(Self::Initial),
            Self::RESHARE_TAG => Some(Self::ReShare),
            Self::FETCH_PAYLOAD_TAG => Some(Self::FetchPayload),
            Self::PAYLOAD_RESPONSE_TAG => Some(Self::PayloadResponse),
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

impl WireShardMessage {
    /// Decode a wire shard message from a `Bytes` buffer.
    ///
    /// The payload section is sliced zero-copy from `buf` rather than copied
    /// into a new allocation.
    pub(crate) fn decode(buf: Bytes) -> Option<Self> {
        let mut reader = buf;
        let tag = WireTag::from_u8(u8::read(&mut reader).ok()?)?;

        match tag {
            WireTag::Initial | WireTag::ReShare => {
                let round = Round::read(&mut reader).ok()?;
                let digest = Digest::read(&mut reader).ok()?;
                let key = BlockKey::new(round, digest);
                let commitment = ZodaCommitment::read(&mut reader).ok()?;
                let shard_index = u16::read(&mut reader).ok()?;
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
                    _ => None,
                }
            }
            WireTag::FetchPayload => {
                let digest = Digest::read(&mut reader).ok()?;
                if reader.has_remaining() {
                    return None;
                }
                Some(Self::FetchPayload { digest })
            }
            WireTag::PayloadResponse => {
                let digest = Digest::read(&mut reader).ok()?;
                let payload_len = u32::read(&mut reader).ok()? as usize;
                if reader.remaining() != payload_len {
                    return None;
                }
                let payload = reader.copy_to_bytes(payload_len);
                Some(Self::PayloadResponse { digest, payload })
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
            Self::FetchPayload { digest } => {
                return u8::SIZE + digest.encode_size();
            }
            Self::PayloadResponse { digest, payload } => {
                return u8::SIZE + digest.encode_size() + u32::SIZE + payload.len();
            }
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
            Self::FetchPayload { digest } => {
                WireTag::FetchPayload.as_u8().write(buf);
                digest.write(buf);
            }
            Self::PayloadResponse { digest, payload } => {
                WireTag::PayloadResponse.as_u8().write(buf);
                digest.write(buf);
                (payload.len() as u32).write(buf);
                buf.put_slice(payload.as_ref());
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

// ---------------------------------------------------------------------------
// Authenticated shard message (transport-layer sender)
// ---------------------------------------------------------------------------

/// Internal shard message after transport authentication.
#[derive(Clone)]
pub(crate) struct ShardMessage {
    pub(crate) sender: PublicKey,
    pub(crate) body: WireShardMessage,
}

impl ShardMessage {
    #[cfg(test)]
    pub(crate) fn initial(
        sender: &PublicKey,
        key: BlockKey,
        commitment: ZodaCommitment,
        shard: ZodaShard,
        shard_index: u16,
    ) -> Self {
        Self {
            sender: sender.clone(),
            body: WireShardMessage::Initial {
                key,
                commitment,
                shard,
                shard_index,
            },
        }
    }

    pub(crate) fn reshare(
        sender: &PublicKey,
        key: BlockKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        reshard: ZodaReShard,
    ) -> Self {
        Self {
            sender: sender.clone(),
            body: WireShardMessage::ReShare {
                key,
                commitment,
                shard_index,
                reshard,
            },
        }
    }

    pub(crate) fn fetch_payload(sender: &PublicKey, digest: Digest) -> Self {
        Self {
            sender: sender.clone(),
            body: WireShardMessage::FetchPayload { digest },
        }
    }

    pub(crate) fn payload_response(sender: &PublicKey, digest: Digest, payload: Bytes) -> Self {
        Self {
            sender: sender.clone(),
            body: WireShardMessage::PayloadResponse { digest, payload },
        }
    }

    pub(crate) const fn key(&self) -> Option<BlockKey> {
        match &self.body {
            WireShardMessage::Initial { key, .. } => Some(*key),
            WireShardMessage::ReShare { key, .. } => Some(*key),
            WireShardMessage::FetchPayload { .. } | WireShardMessage::PayloadResponse { .. } => {
                None
            }
        }
    }

    pub(crate) fn sender(&self) -> &PublicKey {
        &self.sender
    }

    pub(crate) fn to_wire(&self) -> WireShardMessage {
        self.body.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_coding::Scheme as CodingScheme;
    use commonware_consensus::types::{Epoch, View};
    use commonware_parallel::Sequential;

    fn sample_artifacts(
        payload: &[u8],
    ) -> (commonware_coding::Config, ZodaCommitment, Vec<ZodaShard>) {
        let config = coding_config(6);
        let (commitment, shards) = CodingImpl::encode(&config, payload, &Sequential).unwrap();
        (config, commitment, shards)
    }

    #[test_log::test]
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

    #[test_log::test]
    fn commitment_mismatch_is_rejected() {
        let (cfg_a, commitment_a, _) = sample_artifacts(b"payload-a");
        let (_, commitment_b, shards_b) = sample_artifacts(b"payload-b");
        assert_ne!(commitment_a, commitment_b);

        let result = CodingImpl::reshard(&cfg_a, &commitment_a, 0, shards_b[0].clone());
        assert!(result.is_err());
    }

    #[test_log::test]
    fn coding_config_boundary_values() {
        let zero = coding_config(0);
        assert_eq!(zero.minimum_shards, 1);
        assert_eq!(zero.extra_shards, 0);

        let one = coding_config(1);
        assert_eq!(one.minimum_shards, 1);
        assert_eq!(one.extra_shards, 0);

        let six = coding_config(6);
        assert_eq!(six.minimum_shards, 2);
        assert_eq!(six.extra_shards, 4);

        for validators in 1u16..=20u16 {
            let cfg = coding_config(validators);
            assert_eq!(
                cfg.minimum_shards.saturating_add(cfg.extra_shards),
                validators
            );
            assert!(cfg.minimum_shards >= 1);
        }
    }
}
