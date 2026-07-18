use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use crate::digest::Digest;
use crate::tags;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SchemeId {
    Evaluate = tags::SCHEME_EVALUATE,
    Fetch = tags::SCHEME_FETCH,
}

impl SchemeId {
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(byte: u8) -> Result<Self, TagError> {
        match byte {
            tags::SCHEME_EVALUATE => Ok(Self::Evaluate),
            tags::SCHEME_FETCH => Ok(Self::Fetch),
            _ => Err(TagError::UnknownScheme(byte)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TagError {
    #[error("unknown scheme id byte 0x{0:02x}")]
    UnknownScheme(u8),
}

macro_rules! impl_u8_serde {
    ($ty:ty, $from:expr) => {
        impl Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_u8(self.to_byte())
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct ByteVisitor;

                impl Visitor<'_> for ByteVisitor {
                    type Value = $ty;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("a one-byte protocol tag")
                    }

                    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
                    where
                        E: DeError,
                    {
                        $from(v).map_err(E::custom)
                    }

                    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
                    where
                        E: DeError,
                    {
                        let byte = u8::try_from(v).map_err(E::custom)?;
                        self.visit_u8(byte)
                    }
                }

                deserializer.deserialize_u8(ByteVisitor)
            }
        }
    };
}

impl_u8_serde!(SchemeId, SchemeId::from_byte);

macro_rules! digest_commitment {
    ($ty:ident) => {
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $ty(pub Digest);

        impl $ty {
            pub fn from_canonical_bytes(canonical_bytes: &[u8]) -> Self {
                Self(Digest::hash(canonical_bytes))
            }

            pub const fn from_digest(digest: Digest) -> Self {
                Self(digest)
            }

            pub const fn digest(&self) -> Digest {
                self.0
            }

            pub const fn as_bytes(&self) -> &[u8; Digest::LEN] {
                self.0.as_bytes()
            }
        }
    };
}

digest_commitment!(RequestCommitment);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_newtypes_hash_exact_canonical_bytes() {
        let bytes = b"\x82x\x19hellas.example.object.v1Ddata";
        assert_eq!(
            RequestCommitment::from_canonical_bytes(bytes).as_bytes(),
            Digest::hash(bytes).as_bytes()
        );
    }
}
