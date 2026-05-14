//! Schema canonicalization for method ID derivation.
//!
//! `MethodSchema` captures *wire-relevant* shape only — field numbers
//! and structural types. Field names are intentionally excluded:
//! renaming a field does not change the wire form and must not change
//! the method ID.

use crate::canonical::{Encode, Writer};

pub const METHOD_DOMAIN: &[u8] = b"hellas.wire.method.v1";
pub const SERVICE_DOMAIN: &[u8] = b"hellas.wire.service.v1";

#[derive(Clone, Copy, Debug)]
pub struct MethodSchema<'a> {
    pub fqn: &'a str,
    pub request: TypeSchema<'a>,
    pub response: TypeSchema<'a>,
    pub request_streaming: bool,
    pub response_streaming: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ServiceSchema<'a> {
    pub fqn: &'a str,
    pub methods: &'a [&'a MethodSchema<'a>],
}

#[derive(Clone, Copy, Debug)]
pub enum TypeSchema<'a> {
    Primitive(PrimKind),
    Message(MessageSchema<'a>),
    EnumRef { name: &'a str, variants: &'a [(&'a str, i32)] },
    Repeated(&'a TypeSchema<'a>),
    Map(&'a TypeSchema<'a>, &'a TypeSchema<'a>),
    Optional(&'a TypeSchema<'a>),
}

#[derive(Clone, Copy, Debug)]
pub struct MessageSchema<'a> {
    pub name: &'a str,
    pub fields: &'a [FieldSchema<'a>],
}

#[derive(Clone, Copy, Debug)]
pub struct FieldSchema<'a> {
    pub number: u32,
    pub ty: TypeSchema<'a>,
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

impl<'a> Encode for TypeSchema<'a> {
    const MAX_ENCODED_SIZE: usize = usize::MAX;

    fn encoded_size(&self) -> usize {
        let body = match self {
            Self::Primitive(p) => p.encoded_size(),
            Self::Message(m) => m.encoded_size(),
            Self::EnumRef { name, variants } => {
                name.encoded_size()
                    + 4
                    + variants
                        .iter()
                        .map(|(n, v)| n.encoded_size() + 4 + Encode::encoded_size(v))
                        .sum::<usize>()
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
                name.encode_to(writer);
                let len =
                    u32::try_from(variants.len()).expect("enum variant count fits u32");
                writer.write(&len.to_be_bytes());
                for (n, v) in *variants {
                    n.encode_to(writer);
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

impl<'a> Encode for FieldSchema<'a> {
    const MAX_ENCODED_SIZE: usize = usize::MAX;
    fn encoded_size(&self) -> usize {
        4 + self.ty.encoded_size()
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.number.to_be_bytes());
        self.ty.encode_to(writer);
    }
}

impl<'a> Encode for MessageSchema<'a> {
    const MAX_ENCODED_SIZE: usize = usize::MAX;
    fn encoded_size(&self) -> usize {
        // Name is part of the message identity (different names = different
        // types even if fields match). Fields encoded with explicit length.
        self.name.encoded_size() + self.fields.encoded_size()
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.name.encode_to(writer);
        self.fields.encode_to(writer);
    }
}

impl<'a> Encode for MethodSchema<'a> {
    const MAX_ENCODED_SIZE: usize = usize::MAX;
    fn encoded_size(&self) -> usize {
        self.fqn.encoded_size()
            + self.request.encoded_size()
            + self.response.encoded_size()
            + 2
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.fqn.encode_to(writer);
        self.request.encode_to(writer);
        self.response.encode_to(writer);
        writer.write(&[u8::from(self.request_streaming)]);
        writer.write(&[u8::from(self.response_streaming)]);
    }
}

impl<'a> Encode for ServiceSchema<'a> {
    const MAX_ENCODED_SIZE: usize = usize::MAX;
    fn encoded_size(&self) -> usize {
        self.fqn.encoded_size()
            + 4
            + self
                .methods
                .iter()
                .map(|m| m.encoded_size())
                .sum::<usize>()
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.fqn.encode_to(writer);
        let len = u32::try_from(self.methods.len()).expect("methods.len fits u32");
        writer.write(&len.to_be_bytes());
        for m in self.methods {
            m.encode_to(writer);
        }
    }
}

impl<'a> MethodSchema<'a> {
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

impl<'a> ServiceSchema<'a> {
    pub fn digest(&self) -> [u8; 32] {
        crate::canonical::hash(SERVICE_DOMAIN, self)
    }

    pub fn service_id(&self) -> u32 {
        let d = self.digest();
        u32::from_le_bytes([d[0], d[1], d[2], d[3]])
    }
}
