//! Schema canonicalization for method ID derivation.
//!
//! `MethodSchema` captures *wire-relevant* shape only — field numbers
//! and structural types. Field names are intentionally excluded:
//! renaming a field does not change the wire form and must not change
//! the method ID.
//!
//! These types are owned (`String`/`Vec`) rather than borrowed: their
//! only producer is the `hellas-rpc` build script, which resolves them
//! out of protobuf descriptors and hashes them into the `METHOD_ID` /
//! `SERVICE_ID` constants baked into generated marker types. Nothing
//! constructs them at runtime, so const-buildability is not a goal.
//!
//! The encoded byte stream is a wire-compatibility surface: any change
//! to `encode_to` rotates every method and service ID and breaks
//! routing against already-deployed nodes. The golden tests at the
//! bottom of this file pin the current encoding.

use crate::canonical::{Encode, Writer};

pub const METHOD_DOMAIN: &[u8] = b"hellas.wire.method.v2";
pub const SERVICE_DOMAIN: &[u8] = b"hellas.wire.service.v2";

#[derive(Clone, Debug)]
pub struct MethodSchema {
    pub fqn: String,
    pub request: TypeSchema,
    pub response: TypeSchema,
    pub request_streaming: bool,
    pub response_streaming: bool,
}

#[derive(Clone, Debug)]
pub struct ServiceSchema {
    pub fqn: String,
    pub methods: Vec<MethodSchema>,
}

#[derive(Clone, Debug)]
pub enum TypeSchema {
    Primitive(PrimKind),
    Message(MessageSchema),
    EnumRef { name: String, variants: Vec<i32> },
    Repeated(Box<TypeSchema>),
    Map(Box<TypeSchema>, Box<TypeSchema>),
    Optional(Box<TypeSchema>),
}

#[derive(Clone, Debug)]
pub struct MessageSchema {
    pub name: String,
    pub fields: Vec<FieldSchema>,
}

#[derive(Clone, Debug)]
pub struct FieldSchema {
    pub number: u32,
    pub ty: TypeSchema,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum PrimKind {
    Bool = 0,
    I32 = 1,
    I64 = 2,
    U32 = 3,
    U64 = 4,
    Sint32 = 5,
    Sint64 = 6,
    Fixed32 = 7,
    Fixed64 = 8,
    Sfixed32 = 9,
    Sfixed64 = 10,
    Float = 11,
    Double = 12,
    String = 13,
    Bytes = 14,
}

// -- Encode impls ------------------------------------------------------------

impl Encode for PrimKind {
    const MAX_ENCODED_SIZE: usize = 1;
    fn encoded_size(&self) -> usize {
        1
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&[*self as u8]);
    }
}

impl Encode for TypeSchema {
    const MAX_ENCODED_SIZE: usize = usize::MAX;

    fn encoded_size(&self) -> usize {
        let body = match self {
            Self::Primitive(p) => p.encoded_size(),
            Self::Message(m) => m.encoded_size(),
            Self::EnumRef { name, variants } => {
                name.as_str().encoded_size()
                    + 4
                    + variants.iter().map(Encode::encoded_size).sum::<usize>()
            }
            Self::Repeated(inner) | Self::Optional(inner) => inner.encoded_size(),
            Self::Map(k, v) => k.encoded_size() + v.encoded_size(),
        };
        1 + body
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        match self {
            Self::Primitive(p) => {
                writer.write(&[0]);
                p.encode_to(writer);
            }
            Self::Message(m) => {
                writer.write(&[1]);
                m.encode_to(writer);
            }
            Self::EnumRef { name, variants } => {
                writer.write(&[2]);
                name.as_str().encode_to(writer);
                let len = u32::try_from(variants.len()).expect("enum variant count fits u32");
                writer.write(&len.to_be_bytes());
                for v in variants {
                    writer.write(&v.to_be_bytes());
                }
            }
            Self::Repeated(inner) => {
                writer.write(&[3]);
                inner.encode_to(writer);
            }
            Self::Map(k, v) => {
                writer.write(&[4]);
                k.encode_to(writer);
                v.encode_to(writer);
            }
            Self::Optional(inner) => {
                writer.write(&[5]);
                inner.encode_to(writer);
            }
        }
    }
}

impl Encode for i32 {
    const MAX_ENCODED_SIZE: usize = 4;
    fn encoded_size(&self) -> usize {
        4
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.to_be_bytes());
    }
}

impl Encode for FieldSchema {
    const MAX_ENCODED_SIZE: usize = usize::MAX;
    fn encoded_size(&self) -> usize {
        4 + self.ty.encoded_size()
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.number.to_be_bytes());
        self.ty.encode_to(writer);
    }
}

impl Encode for MessageSchema {
    const MAX_ENCODED_SIZE: usize = usize::MAX;
    fn encoded_size(&self) -> usize {
        // Name is part of the message identity (different names = different
        // types even if fields match). Fields encoded with explicit length.
        self.name.as_str().encoded_size() + self.fields.as_slice().encoded_size()
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.name.as_str().encode_to(writer);
        self.fields.as_slice().encode_to(writer);
    }
}

impl Encode for MethodSchema {
    const MAX_ENCODED_SIZE: usize = usize::MAX;
    fn encoded_size(&self) -> usize {
        self.fqn.as_str().encoded_size()
            + self.request.encoded_size()
            + self.response.encoded_size()
            + 2
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.fqn.as_str().encode_to(writer);
        self.request.encode_to(writer);
        self.response.encode_to(writer);
        writer.write(&[u8::from(self.request_streaming)]);
        writer.write(&[u8::from(self.response_streaming)]);
    }
}

impl Encode for ServiceSchema {
    const MAX_ENCODED_SIZE: usize = usize::MAX;
    fn encoded_size(&self) -> usize {
        self.fqn.as_str().encoded_size() + self.methods.as_slice().encoded_size()
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.fqn.as_str().encode_to(writer);
        self.methods.as_slice().encode_to(writer);
    }
}

impl MethodSchema {
    pub fn digest(&self) -> [u8; 32] {
        crate::canonical::hash(METHOD_DOMAIN, self)
    }

    /// Truncated 32-bit method ID (low 4 bytes, little-endian) for use
    /// in the OpenFrame.
    pub fn method_id(&self) -> u32 {
        let d = self.digest();
        u32::from_le_bytes([d[0], d[1], d[2], d[3]])
    }
}

impl ServiceSchema {
    pub fn digest(&self) -> [u8; 32] {
        crate::canonical::hash(SERVICE_DOMAIN, self)
    }

    pub fn service_id(&self) -> u32 {
        let d = self.digest();
        u32::from_le_bytes([d[0], d[1], d[2], d[3]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A schema exercising every construct that appears in a hellas
    /// .proto today: message nesting, primitives, repeated, enum refs,
    /// and streaming flags.
    fn sample_method() -> MethodSchema {
        MethodSchema {
            fqn: "hellas.test.v1.Echo/Ping".to_string(),
            request: TypeSchema::Message(MessageSchema {
                name: "PingRequest".to_string(),
                fields: vec![
                    FieldSchema {
                        number: 1,
                        ty: TypeSchema::Primitive(PrimKind::String),
                    },
                    FieldSchema {
                        number: 2,
                        ty: TypeSchema::Repeated(Box::new(TypeSchema::Primitive(PrimKind::U64))),
                    },
                    FieldSchema {
                        number: 3,
                        ty: TypeSchema::EnumRef {
                            name: "Mode".to_string(),
                            variants: vec![0, 1],
                        },
                    },
                    FieldSchema {
                        number: 4,
                        ty: TypeSchema::Message(MessageSchema {
                            name: "Inner".to_string(),
                            fields: vec![FieldSchema {
                                number: 1,
                                ty: TypeSchema::Primitive(PrimKind::Bytes),
                            }],
                        }),
                    },
                ],
            }),
            response: TypeSchema::Message(MessageSchema {
                name: "PingResponse".to_string(),
                fields: vec![],
            }),
            request_streaming: false,
            response_streaming: true,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Golden vector. If this test fails, the canonical schema encoding
    /// changed: every generated METHOD_ID rotates and deployed nodes
    /// will no longer route this build's calls. Only update the pinned
    /// value as part of a deliberate, coordinated protocol break.
    #[test]
    fn method_digest_is_pinned() {
        let m = sample_method();
        assert_eq!(
            hex(&m.digest()),
            "f871f1b997a9126e9091c64573f48c6d03da21195e0c3b3258c11865cc978fd7",
        );
        assert_eq!(m.method_id(), 0xb9f171f8);
    }

    /// Same contract as [`method_digest_is_pinned`], for SERVICE_ID.
    #[test]
    fn service_digest_is_pinned() {
        let s = ServiceSchema {
            fqn: "hellas.test.v1.Echo".to_string(),
            methods: vec![sample_method()],
        };
        assert_eq!(
            hex(&s.digest()),
            "b44b68e822aa2a26a1ce863a62809716ee58c1b110bc651c381dcf35984a243f",
        );
        assert_eq!(s.service_id(), 0xe8684bb4);
    }
}
