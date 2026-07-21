//! Canonical byte encoding for the wire schema.
//!
//! Mirrors `hellas-kernel::canonical` — same trait shape, separate copy.
//! When `hellas-kernel` moves into this workspace, this module is deleted
//! and `hellas-wire` depends on the kernel directly.
//!
//! The bytes emitted by `Encode::encode_to` are the canonical commitment
//! input. Hashes funnel through `hash(domain, value)` so commitments use the
//! Xet file hash of `domain ‖ value.encode_to(...)`.

/// Streaming destination for [`Encode`] output.
///
/// Implemented for raw byte buffers and `Vec<u8>` so the same `encode_to`
/// body drives serialization and hashing.
pub trait Writer {
    fn write(&mut self, bytes: &[u8]);
}

impl Writer for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

#[derive(Debug)]
pub struct BufferWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufferWriter<'a> {
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub const fn position(&self) -> usize {
        self.pos
    }
}

impl Writer for BufferWriter<'_> {
    /// Panics if `bytes.len()` exceeds remaining capacity — programming-
    /// error contract. Caller is expected to size buffers via
    /// `Encode::encoded_size()`.
    fn write(&mut self, bytes: &[u8]) {
        let end = self.pos + bytes.len();
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
    }
}

pub trait Encode {
    const MAX_ENCODED_SIZE: usize;
    fn encoded_size(&self) -> usize;
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W);

    fn write_to(&self, buf: &mut [u8]) -> usize {
        let mut writer = BufferWriter::new(buf);
        self.encode_to(&mut writer);
        writer.position()
    }
}

/// Xet file hash of `domain ‖ value.encode_to(...)`.
pub fn hash<T: Encode + ?Sized>(domain: &[u8], value: &T) -> hellas_xet::XetHash {
    let mut bytes = Vec::with_capacity(domain.len() + value.encoded_size());
    bytes.extend_from_slice(domain);
    value.encode_to(&mut bytes);
    hellas_xet::XetHash::hash(&bytes)
}

// -- Primitives --------------------------------------------------------------

impl Encode for u8 {
    const MAX_ENCODED_SIZE: usize = 1;
    fn encoded_size(&self) -> usize {
        1
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&[*self]);
    }
}

impl Encode for u16 {
    const MAX_ENCODED_SIZE: usize = 2;
    fn encoded_size(&self) -> usize {
        2
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.to_be_bytes());
    }
}

impl Encode for u32 {
    const MAX_ENCODED_SIZE: usize = 4;
    fn encoded_size(&self) -> usize {
        4
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.to_be_bytes());
    }
}

impl Encode for u64 {
    const MAX_ENCODED_SIZE: usize = 8;
    fn encoded_size(&self) -> usize {
        8
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.to_be_bytes());
    }
}

impl Encode for bool {
    const MAX_ENCODED_SIZE: usize = 1;
    fn encoded_size(&self) -> usize {
        1
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&[u8::from(*self)]);
    }
}

impl Encode for str {
    const MAX_ENCODED_SIZE: usize = usize::MAX;
    fn encoded_size(&self) -> usize {
        4 + self.len()
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        let len = u32::try_from(self.len()).expect("str length fits u32");
        writer.write(&len.to_be_bytes());
        writer.write(self.as_bytes());
    }
}

impl<T: Encode> Encode for &T {
    const MAX_ENCODED_SIZE: usize = T::MAX_ENCODED_SIZE;
    fn encoded_size(&self) -> usize {
        (*self).encoded_size()
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        (*self).encode_to(writer);
    }
}

/// Slice-of-Encode. Length-prefixed (u32 BE) then each item. For raw byte
/// blobs that should be treated as opaque bytes (not as `[u8]` items),
/// wrap in a dedicated type or call the prefix helpers directly.
impl<T: Encode> Encode for [T] {
    const MAX_ENCODED_SIZE: usize = usize::MAX;
    fn encoded_size(&self) -> usize {
        4 + self.iter().map(Encode::encoded_size).sum::<usize>()
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        let len = u32::try_from(self.len()).expect("slice length fits u32");
        writer.write(&len.to_be_bytes());
        for item in self {
            item.encode_to(writer);
        }
    }
}
