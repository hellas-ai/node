use bytes::BytesMut;
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_cryptography::{Hasher, Sha256, Signer, Verifier, sha256::Digest};
use hellas_types::{PrivateKey, PublicKey, Signature};

pub type ObjectId = Digest;

pub const TRANSFER_NAMESPACE: &[u8] = b"hellas-transfer-v1";
pub const MERGE_NAMESPACE: &[u8] = b"hellas-merge-v1";
pub const MAX_MERGE_INPUTS: usize = 32;
pub const MAX_TXS_PER_BLOCK: usize = 256;
pub const GENESIS_BALANCE: u64 = 1_000_000;

pub fn genesis_object_id(validator_index: u16) -> ObjectId {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(b"hellas-genesis");
    validator_index.write(&mut buf);
    Sha256::hash(&buf)
}

pub fn output_object_id(tx_digest: &Digest, output_index: u8) -> ObjectId {
    let mut buf = BytesMut::new();
    tx_digest.write(&mut buf);
    output_index.write(&mut buf);
    Sha256::hash(&buf)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub owner: PublicKey,
    pub value: u64,
}

impl EncodeSize for Coin {
    fn encode_size(&self) -> usize {
        self.owner.encode_size() + self.value.encode_size()
    }
}

impl Write for Coin {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.owner.write(buf);
        self.value.write(buf);
    }
}

impl Read for Coin {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            owner: PublicKey::read(buf)?,
            value: u64::read(buf)?,
        })
    }
}

// Keep transactions inline/stack-allocated to avoid per-transaction heap churn in hot paths.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum Transaction {
    Transfer {
        input: ObjectId,
        recipient: PublicKey,
        amount: u64,
        signature: Signature,
    },
    MergeCoin {
        inputs: Vec<ObjectId>,
        signature: Signature,
    },
}

pub(crate) fn transfer_signed_bytes(
    input: &ObjectId,
    recipient: &PublicKey,
    amount: u64,
) -> BytesMut {
    let mut buf = BytesMut::new();
    input.write(&mut buf);
    recipient.write(&mut buf);
    amount.write(&mut buf);
    buf
}

pub(crate) fn merge_signed_bytes(sorted_inputs: &[ObjectId]) -> BytesMut {
    let mut buf = BytesMut::new();
    sorted_inputs.write(&mut buf);
    buf
}

fn merge_inputs_are_strictly_sorted(inputs: &[ObjectId]) -> bool {
    inputs.windows(2).all(|pair| pair[0] < pair[1])
}

impl Transaction {
    pub fn transfer(key: &PrivateKey, input: ObjectId, recipient: PublicKey, amount: u64) -> Self {
        let message = transfer_signed_bytes(&input, &recipient, amount);
        let signature = key.sign(TRANSFER_NAMESPACE, &message);
        Self::Transfer {
            input,
            recipient,
            amount,
            signature,
        }
    }

    pub fn merge(key: &PrivateKey, mut inputs: Vec<ObjectId>) -> Self {
        inputs.sort();
        let message = merge_signed_bytes(&inputs);
        let signature = key.sign(MERGE_NAMESPACE, &message);
        Self::MergeCoin { inputs, signature }
    }

    pub fn verify_signature(&self, owner: &PublicKey) -> bool {
        match self {
            Self::Transfer {
                input,
                recipient,
                amount,
                signature,
            } => {
                let message = transfer_signed_bytes(input, recipient, *amount);
                owner.verify(TRANSFER_NAMESPACE, &message, signature)
            }
            Self::MergeCoin { inputs, signature } => {
                let message = merge_signed_bytes(inputs);
                owner.verify(MERGE_NAMESPACE, &message, signature)
            }
        }
    }

    pub fn merge_is_canonical(&self) -> bool {
        match self {
            Self::Transfer { .. } => true,
            Self::MergeCoin { inputs, .. } => merge_inputs_are_strictly_sorted(inputs),
        }
    }
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        match self {
            Self::Transfer {
                input,
                recipient,
                amount,
                signature,
            } => {
                u8::SIZE
                    + input.encode_size()
                    + recipient.encode_size()
                    + amount.encode_size()
                    + signature.encode_size()
            }
            Self::MergeCoin { inputs, signature } => {
                u8::SIZE + inputs.encode_size() + signature.encode_size()
            }
        }
    }
}

impl Write for Transaction {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Transfer {
                input,
                recipient,
                amount,
                signature,
            } => {
                0u8.write(buf);
                input.write(buf);
                recipient.write(buf);
                amount.write(buf);
                signature.write(buf);
            }
            Self::MergeCoin { inputs, signature } => {
                1u8.write(buf);
                inputs.write(buf);
                signature.write(buf);
            }
        }
    }
}

impl Read for Transaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Transfer {
                input: ObjectId::read(buf)?,
                recipient: PublicKey::read(buf)?,
                amount: u64::read(buf)?,
                signature: Signature::read(buf)?,
            }),
            1 => Ok(Self::MergeCoin {
                inputs: Vec::<ObjectId>::read_range(buf, 2..=MAX_MERGE_INPUTS)?,
                signature: Signature::read(buf)?,
            }),
            _ => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn coin_codec_roundtrip() {
        let owner = PrivateKey::from_seed(1).public_key();
        let coin = Coin { owner, value: 123 };
        let encoded = coin.encode();
        let decoded = Coin::decode(encoded).expect("coin decode");
        assert_eq!(decoded, coin);
    }

    #[test]
    fn transfer_codec_roundtrip() {
        let sender = PrivateKey::from_seed(1);
        let recipient = PrivateKey::from_seed(2).public_key();
        let tx = Transaction::transfer(&sender, Digest::from([9; 32]), recipient, 77);
        let encoded = tx.encode();
        let decoded = Transaction::decode(encoded).expect("tx decode");
        assert_eq!(decoded.encode(), tx.encode());
    }

    #[test]
    fn merge_codec_roundtrip() {
        let sender = PrivateKey::from_seed(1);
        let tx = Transaction::merge(
            &sender,
            vec![
                Digest::from([3; 32]),
                Digest::from([2; 32]),
                Digest::from([1; 32]),
            ],
        );
        let encoded = tx.encode();
        let decoded = Transaction::decode(encoded).expect("tx decode");
        assert_eq!(decoded.encode(), tx.encode());
    }

    #[test]
    fn signature_verification_succeeds_with_correct_key() {
        let sender = PrivateKey::from_seed(1);
        let sender_pk = sender.public_key();
        let recipient = PrivateKey::from_seed(2).public_key();
        let transfer = Transaction::transfer(&sender, Digest::from([7; 32]), recipient, 5);
        assert!(transfer.verify_signature(&sender_pk));

        let merge = Transaction::merge(
            &sender,
            vec![
                Digest::from([3; 32]),
                Digest::from([1; 32]),
                Digest::from([2; 32]),
            ],
        );
        assert!(merge.verify_signature(&sender_pk));
    }

    #[test]
    fn signature_verification_fails_with_wrong_key() {
        let sender = PrivateKey::from_seed(1);
        let wrong = PrivateKey::from_seed(2).public_key();
        let recipient = PrivateKey::from_seed(3).public_key();
        let transfer = Transaction::transfer(&sender, Digest::from([7; 32]), recipient, 5);
        assert!(!transfer.verify_signature(&wrong));
    }

    #[test]
    fn merge_inputs_are_canonicalized() {
        let sender = PrivateKey::from_seed(1);
        let tx = Transaction::merge(
            &sender,
            vec![
                Digest::from([3; 32]),
                Digest::from([1; 32]),
                Digest::from([2; 32]),
            ],
        );
        let Transaction::MergeCoin { inputs, .. } = tx else {
            panic!("expected merge tx");
        };
        assert!(inputs.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
