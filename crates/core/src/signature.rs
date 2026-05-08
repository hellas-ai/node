use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature as K256Signature, SigningKey, VerifyingKey};

use crate::digest::Digest;
use crate::{hash_tuple, tags};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SignatureKind {
    Secp256k1 = tags::SIGNATURE_SECP256K1,
}

impl SignatureKind {
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(byte: u8) -> Result<Self, SignatureError> {
        match byte {
            tags::SIGNATURE_SECP256K1 => Ok(Self::Secp256k1),
            _ => Err(SignatureError::UnknownSignatureKind(byte)),
        }
    }
}

impl Serialize for SignatureKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.to_byte())
    }
}

impl<'de> Deserialize<'de> for SignatureKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KindVisitor;

        impl Visitor<'_> for KindVisitor {
            type Value = SignatureKind;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a one-byte signature kind")
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                SignatureKind::from_byte(v).map_err(E::custom)
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                let byte = u8::try_from(v).map_err(E::custom)?;
                self.visit_u8(byte)
            }
        }

        deserializer.deserialize_u8(KindVisitor)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey {
    kind: SignatureKind,
    bytes: [u8; 33],
}

impl PublicKey {
    pub const LEN: usize = 33;

    pub const fn from_compressed_sec1(bytes: [u8; Self::LEN]) -> Self {
        Self {
            kind: SignatureKind::Secp256k1,
            bytes,
        }
    }

    pub const fn kind(&self) -> SignatureKind {
        self.kind
    }

    pub const fn bytes(&self) -> &[u8; Self::LEN] {
        &self.bytes
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, SignatureError> {
        match self.kind {
            SignatureKind::Secp256k1 => {
                VerifyingKey::from_sec1_bytes(&self.bytes).map_err(SignatureError::from)
            }
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("kind", &self.kind)
            .field("producer_id", &ProducerId::from_public_key(self))
            .finish()
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (&self.kind, serde_bytes::Bytes::new(&self.bytes)).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (kind, bytes): (SignatureKind, serde_bytes::ByteBuf) =
            Deserialize::deserialize(deserializer)?;
        if kind != SignatureKind::Secp256k1 {
            return Err(D::Error::custom("unsupported public key kind"));
        }
        let bytes: [u8; Self::LEN] = bytes.into_vec().try_into().map_err(|bytes: Vec<u8>| {
            D::Error::custom(format!("public key must be 33 bytes, got {}", bytes.len()))
        })?;
        Ok(Self { kind, bytes })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature {
    kind: SignatureKind,
    bytes: [u8; 64],
}

impl Signature {
    pub const LEN: usize = 64;

    pub const fn from_compact_secp256k1(bytes: [u8; Self::LEN]) -> Self {
        Self {
            kind: SignatureKind::Secp256k1,
            bytes,
        }
    }

    pub const fn kind(&self) -> SignatureKind {
        self.kind
    }

    pub const fn bytes(&self) -> &[u8; Self::LEN] {
        &self.bytes
    }

    fn as_k256(&self) -> Result<K256Signature, SignatureError> {
        match self.kind {
            SignatureKind::Secp256k1 => {
                let sig = K256Signature::from_slice(&self.bytes).map_err(SignatureError::from)?;
                if sig.normalize_s().is_some() {
                    return Err(SignatureError::HighS);
                }
                Ok(sig)
            }
        }
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (&self.kind, serde_bytes::Bytes::new(&self.bytes)).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (kind, bytes): (SignatureKind, serde_bytes::ByteBuf) =
            Deserialize::deserialize(deserializer)?;
        if kind != SignatureKind::Secp256k1 {
            return Err(D::Error::custom("unsupported signature kind"));
        }
        let bytes: [u8; Self::LEN] = bytes.into_vec().try_into().map_err(|bytes: Vec<u8>| {
            D::Error::custom(format!("signature must be 64 bytes, got {}", bytes.len()))
        })?;
        Ok(Self { kind, bytes })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProducerId(Digest);

impl ProducerId {
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let kind = [public_key.kind().to_byte()];
        Self(hash_tuple(
            tags::PRODUCER_ID_V1,
            &[&kind, public_key.bytes()],
        ))
    }

    pub const fn digest(&self) -> Digest {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Digest::LEN] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for ProducerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProducerId").field(&self.0).finish()
    }
}

pub struct ProducerSigningKey {
    inner: SigningKey,
}

impl ProducerSigningKey {
    pub fn generate() -> Self {
        let inner = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        Self { inner }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self, SignatureError> {
        let field_bytes = k256::FieldBytes::from(bytes);
        let inner = SigningKey::from_bytes(&field_bytes).map_err(SignatureError::from)?;
        Ok(Self { inner })
    }

    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }

    pub fn public_key(&self) -> PublicKey {
        let verifying_key = self.inner.verifying_key();
        let point = verifying_key.to_encoded_point(true);
        let bytes: [u8; PublicKey::LEN] = point
            .as_bytes()
            .try_into()
            .expect("compressed secp256k1 public key is 33 bytes");
        PublicKey::from_compressed_sec1(bytes)
    }

    pub fn producer_id(&self) -> ProducerId {
        ProducerId::from_public_key(&self.public_key())
    }

    pub fn sign_digest(&self, digest: Digest) -> Result<Signature, SignatureError> {
        let signature: K256Signature = self.inner.sign_prehash(digest.as_bytes())?;
        let signature = signature.normalize_s().unwrap_or(signature);
        Ok(Signature::from_compact_secp256k1(
            signature.to_bytes().into(),
        ))
    }

    #[cfg(test)]
    pub(crate) fn deterministic_for_tests() -> Self {
        Self::from_secret_bytes([1; 32]).expect("valid deterministic test key")
    }
}

pub fn verify_digest_signature(
    public_key: &PublicKey,
    signature: &Signature,
    digest: Digest,
) -> Result<(), SignatureError> {
    if public_key.kind() != signature.kind() {
        return Err(SignatureError::KindMismatch {
            public_key: public_key.kind(),
            signature: signature.kind(),
        });
    }

    let verifying_key = public_key.verifying_key()?;
    let signature = signature.as_k256()?;
    verifying_key.verify_prehash(digest.as_bytes(), &signature)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("unknown signature kind byte 0x{0:02x}")]
    UnknownSignatureKind(u8),
    #[error("public key kind {public_key:?} does not match signature kind {signature:?}")]
    KindMismatch {
        public_key: SignatureKind,
        signature: SignatureKind,
    },
    #[error("secp256k1 signature is not normalized to low-S form")]
    HighS,
    #[error("secp256k1 error: {0}")]
    Secp256k1(String),
}

impl From<k256::ecdsa::Error> for SignatureError {
    fn from(error: k256::ecdsa::Error) -> Self {
        Self::Secp256k1(error.to_string())
    }
}

impl From<k256::elliptic_curve::Error> for SignatureError {
    fn from(error: k256::elliptic_curve::Error) -> Self {
        Self::Secp256k1(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secp256k1_sign_verify_round_trip() {
        let key = ProducerSigningKey::deterministic_for_tests();
        let digest = hash_tuple("test.digest", &[b"payload"]);
        let signature = key.sign_digest(digest).unwrap();
        verify_digest_signature(&key.public_key(), &signature, digest).unwrap();
    }

    #[test]
    fn invalid_signature_fails() {
        let key = ProducerSigningKey::deterministic_for_tests();
        let digest = hash_tuple("test.digest", &[b"payload"]);
        let mut signature = key.sign_digest(digest).unwrap();
        signature.bytes[0] ^= 0x01;
        assert!(verify_digest_signature(&key.public_key(), &signature, digest).is_err());
    }

    #[test]
    fn producer_id_is_stable() {
        let key = ProducerSigningKey::deterministic_for_tests();
        assert_eq!(
            ProducerId::from_public_key(&key.public_key()),
            key.producer_id()
        );
    }
}
