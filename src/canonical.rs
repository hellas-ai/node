//! Canonical byte encoding and hash binding for kernel types.
//!
//! Every kernel value that participates in a hash commitment or that
//! gets stored at the chain boundary implements [`Encode`]. Values that
//! can also be reconstructed from canonical bytes additionally implement
//! [`Decode`]. The split is deliberate: hash newtypes ([`crate::CoinId`],
//! [`crate::EdgeId`], [`crate::TermsHash`], [`crate::CloseHash`]) impl
//! `Encode` only — you can serialize a hash you already hold, you cannot
//! deserialize one in isolation. The hash discipline is enforced at the
//! type system level.
//!
//! Hash inputs and serialization inputs are unified. The bytes a value
//! emits via `encode_to` are *the* canonical bytes; commitments are
//! `BLAKE3(domain ‖ encode_to(value))`. Round-tripping through
//! `encode_to` / `decode` preserves hash by construction.
//!
//! The encoding is hand-rolled byte concatenation in a documented order
//! per type. No allocator. No format negotiation. `MAX_ENCODED_SIZE` is
//! a compile-time bound per type so callers can stack-allocate buffers.

#![allow(clippy::redundant_pub_crate)]

use crate::primitive::Party;

/// Streaming destination for [`Encode`] output.
///
/// Implemented for raw byte buffers (via [`BufferWriter`]) and for
/// `blake3::Hasher` so that the same `encode_to` body can drive both
/// serialization and hashing without an intermediate buffer.
pub trait Writer {
    /// Appends `bytes` to the destination.
    fn write(&mut self, bytes: &[u8]);
}

impl Writer for blake3::Hasher {
    fn write(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

/// Streaming write of canonical bytes into a `&mut [u8]`.
///
/// The buffer must be at least `value.encoded_size()` bytes for every
/// value the writer consumes; smaller buffers panic on the first
/// [`Writer::write`] that exceeds capacity. This is a programming-error
/// contract: every [`Encode`] type self-reports `encoded_size()`, so
/// callers can size the buffer exactly. The kernel does not offer a
/// fallible variant — undersized buffers indicate a caller bug, not a
/// runtime condition.
#[derive(Debug)]
pub struct BufferWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufferWriter<'a> {
    /// Wraps a byte slice for streaming writes starting at offset 0.
    ///
    /// The slice must be sized to hold the full encoding the caller
    /// intends to write. See the type-level documentation on
    /// [`BufferWriter`] for the precondition contract.
    #[must_use]
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns the number of bytes written so far.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }
}

impl Writer for BufferWriter<'_> {
    /// Appends `bytes` at the current write position.
    ///
    /// # Panics
    ///
    /// Panics if `bytes.len()` would exceed the remaining buffer
    /// capacity (`self.buf.len() - self.pos`). This indicates the
    /// caller sized the buffer below the value's `encoded_size()` —
    /// a programming error.
    fn write(&mut self, bytes: &[u8]) {
        let end = self.pos + bytes.len();
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
    }
}

/// Canonical byte encoding of a kernel value.
///
/// The bytes emitted by `encode_to` are the protocol commitment input.
/// `MAX_ENCODED_SIZE` is the compile-time upper bound (which equals
/// `encoded_size()` for fixed-shape types).
pub trait Encode {
    /// Maximum number of bytes any value of this type emits.
    const MAX_ENCODED_SIZE: usize;

    /// Actual number of bytes this value emits.
    fn encoded_size(&self) -> usize;

    /// Streams the canonical byte representation.
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W);

    /// Writes the canonical byte representation into a slice.
    ///
    /// Returns the number of bytes written. Default impl uses
    /// [`BufferWriter`].
    fn write_to(&self, buf: &mut [u8]) -> usize {
        let mut writer = BufferWriter::new(buf);
        self.encode_to(&mut writer);
        writer.position()
    }
}

/// Canonical byte decoding of a kernel value.
///
/// Returns the decoded value plus the number of bytes consumed. Nested
/// decoders advance `buf = &buf[consumed..]` for the next field.
pub trait Decode: Sized {
    /// Parses a canonical byte representation.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] when the input bytes are malformed (too
    /// short, invalid variant tag, list length exceeds the type bound).
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError>;
}

/// Reason a [`Decode`] attempt failed.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum DecodeError {
    /// Input ended before the decoder had enough bytes.
    InsufficientBytes {
        /// Bytes the decoder needed.
        needed: usize,
        /// Bytes the decoder saw.
        got: usize,
    },
    /// Variant tag byte does not match any defined variant.
    InvalidTag {
        /// Unrecognized tag byte.
        tag: u8,
    },
    /// List length prefix exceeded the type's compile-time capacity.
    InvalidLength {
        /// Length the input declared.
        got: usize,
        /// Maximum the type permits.
        max: usize,
    },
}

// -- BLAKE3 commitment over canonical bytes ----------------------------------

/// Computes the canonical BLAKE3 commitment over `value`'s bytes with
/// domain separation.
///
/// All kernel commitments funnel through this function. The protocol
/// hash binding is `BLAKE3(domain ‖ value.encode_to(...))`.
#[allow(dead_code)]
pub(crate) fn hash<T: Encode + ?Sized>(domain: &[u8], value: &T) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    value.encode_to(&mut hasher);
    *hasher.finalize().as_bytes()
}

// -- Primitive impls ---------------------------------------------------------

impl Encode for u8 {
    const MAX_ENCODED_SIZE: usize = 1;
    fn encoded_size(&self) -> usize {
        1
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&[*self]);
    }
}

impl Decode for u8 {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let byte = *buf.first().ok_or(DecodeError::InsufficientBytes {
            needed: 1,
            got: buf.len(),
        })?;
        Ok((byte, 1))
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

impl Decode for u32 {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::InsufficientBytes {
                needed: 4,
                got: buf.len(),
            });
        }
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(&buf[..4]);
        Ok((Self::from_be_bytes(bytes), 4))
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

impl Decode for u64 {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 8 {
            return Err(DecodeError::InsufficientBytes {
                needed: 8,
                got: buf.len(),
            });
        }
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&buf[..8]);
        Ok((Self::from_be_bytes(bytes), 8))
    }
}

// `usize` is encoded as `u64 big-endian`. The kernel's bounded lists
// fit easily in `u32`, but we use `u64` to keep cross-platform hashes
// stable and to match the historical `Digest::usize` encoding so the
// protocol commitment stays the same across this refactor.
impl Encode for usize {
    const MAX_ENCODED_SIZE: Self = 8;
    fn encoded_size(&self) -> Self {
        8
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        let as_u64 = u64::try_from(*self).unwrap_or(u64::MAX);
        writer.write(&as_u64.to_be_bytes());
    }
}

impl Decode for usize {
    fn decode(buf: &[u8]) -> Result<(Self, Self), DecodeError> {
        let (value, consumed) = u64::decode(buf)?;
        // On 64-bit platforms (the only ones we target) this fits.
        let as_usize = Self::try_from(value).unwrap_or(Self::MAX);
        Ok((as_usize, consumed))
    }
}

// -- Party (1-byte tag) ------------------------------------------------------

impl Encode for Party {
    const MAX_ENCODED_SIZE: usize = 1;
    fn encoded_size(&self) -> usize {
        1
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&[self.tag()]);
    }
}

impl Decode for Party {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (byte, consumed) = u8::decode(buf)?;
        Self::from_tag(byte)
            .map(|party| (party, consumed))
            .ok_or(DecodeError::InvalidTag { tag: byte })
    }
}

// -- List<T, N> blanket impls -------------------------------------------------
// List is encoded as `<len: usize big-endian> ‖ <entries...>` where each
// entry uses its own canonical encoding. `MAX_ENCODED_SIZE` reserves the
// max-length case; `encoded_size()` reports the actual size for the
// current live length.

impl<T: Encode, const N: usize> Encode for crate::List<T, N> {
    const MAX_ENCODED_SIZE: usize = <usize as Encode>::MAX_ENCODED_SIZE + N * T::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        let mut size = <usize as Encode>::MAX_ENCODED_SIZE;
        for item in self {
            size += item.encoded_size();
        }
        size
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.len().encode_to(writer);
        for item in self {
            item.encode_to(writer);
        }
    }
}

impl<T: Decode + Copy + Default, const N: usize> Decode for crate::List<T, N> {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (len, mut consumed) = usize::decode(buf)?;
        if len > N {
            return Err(DecodeError::InvalidLength { got: len, max: N });
        }
        let mut items = [T::default(); N];
        for slot in items.iter_mut().take(len) {
            let (item, n) = T::decode(&buf[consumed..])?;
            *slot = item;
            consumed += n;
        }
        // Type bound: `len <= N`, so `List::take` is exact.
        Ok((Self::take(items, len), consumed))
    }
}
