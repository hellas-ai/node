use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use crate::tags;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const LEN: usize = 32;

    pub fn hash(bytes: &[u8]) -> Self {
        Self::from_bytes(*blake3::hash(bytes).as_bytes())
    }

    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; Self::LEN] {
        self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, DigestError> {
        let bytes: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| DigestError::WrongLength { len: bytes.len() })?;
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    #[error("digest must be 32 bytes, got {len}")]
    WrongLength { len: usize },
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DigestVisitor;

        impl Visitor<'_> for DigestVisitor {
            type Value = Digest;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 32-byte digest")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Digest::from_slice(v).map_err(E::custom)
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                self.visit_bytes(&v)
            }
        }

        deserializer.deserialize_bytes(DigestVisitor)
    }
}

pub fn hash_tuple(tag: &str, fields: &[&[u8]]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tags::HASH_TUPLE_V1.as_bytes());
    hasher.update(&(tag.len() as u32).to_be_bytes());
    hasher.update(tag.as_bytes());
    hasher.update(&(fields.len() as u32).to_be_bytes());
    for field in fields {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    Digest::from_bytes(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_tuple_is_length_delimited() {
        let a = hash_tuple("tag", &[b"ab", b"c"]);
        let b = hash_tuple("tag", &[b"a", b"bc"]);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_hash_is_blake3_of_exact_bytes() {
        assert_eq!(
            Digest::hash(b"abc").as_bytes(),
            blake3::hash(b"abc").as_bytes()
        );
    }

    #[test]
    fn digest_serializes_as_bytes() {
        let digest = Digest::from_bytes([7; 32]);
        let bytes = serde_ipld_dagcbor::to_vec(&digest).unwrap();
        assert_eq!(bytes, [&[0x58, 0x20][..], &[7; 32][..]].concat());
        let decoded: Digest = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        assert_eq!(decoded, digest);
    }
}
