//! Xorb framing: turning downloaded bytes back into chunks.
//!
//! A xorb is a bare concatenation of framed chunks. No container header,
//! no index, no trailer — you find the second chunk by decoding the
//! first. Each chunk is an 8-byte header followed by exactly
//! `compressed_size` payload bytes:
//!
//! ```text
//! 0       version (u8, currently 0)
//! 1..4    compressed_size   (u24, little endian)
//! 4       compression scheme
//! 5..8    uncompressed_size (u24, little endian)
//! 8..     payload
//! ```
//!
//! # Two traps
//!
//! **Scheme 1 is the LZ4 *frame* format, not a raw block.** The spec
//! says "LZ4"; xet-core uses `lz4_flex::frame`. Decoding with the block
//! API fails outright, which is at least loud, but it is the kind of
//! detail that costs an afternoon.
//!
//! **Scheme 2 (byte grouping) is applied after decompression, not
//! instead of it.** The payload is LZ4-frame-decompressed whole, and the
//! result is then un-grouped: it was split into four near-equal groups
//! and concatenated, so recovering the original means interleaving them
//! back. Remainder bytes go one each to the first groups.
//!
//! # What verification this can and cannot do
//!
//! Each decoded chunk is hashed and checked against the chunk hash the
//! caller expects, so a xorb that decodes into the wrong bytes is
//! caught here. That check is only possible because *we* hold the chunk
//! list — a reconstruction response carries no chunk hashes, so a client
//! without an index cannot verify anything until it has reassembled a
//! whole file.

use hellas_xet::{Chunk, XetHash, chunk_hash};

/// Bytes of header before each chunk's payload.
const HEADER: usize = 8;
/// Groups the byte-grouping scheme splits a payload into.
const BG4_GROUPS: usize = 4;

/// How a chunk's payload was compressed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    /// Stored as-is.
    None,
    /// LZ4 frame format.
    Lz4,
    /// Byte-grouped, then LZ4 frame format.
    ByteGrouping4Lz4,
}

impl Scheme {
    fn from_tag(tag: u8) -> Result<Self, XorbError> {
        match tag {
            0 => Ok(Self::None),
            1 => Ok(Self::Lz4),
            2 => Ok(Self::ByteGrouping4Lz4),
            tag => Err(XorbError::UnknownScheme { tag }),
        }
    }
}

/// Why a xorb could not be decoded.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum XorbError {
    #[error("chunk header runs past the end of the xorb")]
    Truncated,
    #[error("unsupported chunk framing version {version}")]
    UnknownVersion { version: u8 },
    #[error("unknown compression scheme {tag}")]
    UnknownScheme { tag: u8 },
    #[error("chunk decompression failed")]
    Decompress,
    #[error("chunk decompressed to {actual} bytes, header declared {declared}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("chunk hashed to {actual}, expected {expected}")]
    HashMismatch { expected: XetHash, actual: XetHash },
}

/// One decoded chunk and how many bytes of the xorb it occupied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decoded {
    /// The chunk's uncompressed bytes.
    pub data: Vec<u8>,
    /// Bytes consumed from the xorb, header included.
    pub consumed: usize,
}

/// Decodes the chunk beginning at the start of `bytes`.
pub fn decode_chunk(bytes: &[u8]) -> Result<Decoded, XorbError> {
    let header = bytes.get(..HEADER).ok_or(XorbError::Truncated)?;
    let version = header[0];
    if version != 0 {
        return Err(XorbError::UnknownVersion { version });
    }
    let compressed_size = u24(&header[1..4]);
    let scheme = Scheme::from_tag(header[4])?;
    let uncompressed_size = u24(&header[5..8]);

    let payload = bytes
        .get(HEADER..HEADER + compressed_size)
        .ok_or(XorbError::Truncated)?;

    let data = match scheme {
        Scheme::None => payload.to_vec(),
        Scheme::Lz4 => lz4_frame(payload)?,
        Scheme::ByteGrouping4Lz4 => ungroup(&lz4_frame(payload)?),
    };
    if data.len() != uncompressed_size {
        return Err(XorbError::LengthMismatch {
            declared: uncompressed_size,
            actual: data.len(),
        });
    }
    Ok(Decoded {
        data,
        consumed: HEADER + compressed_size,
    })
}

/// Decodes a xorb range into chunks, checking each against `expected`.
///
/// `expected` is the slice of our own chunk list covering this range.
/// Checking here is what makes a partial fetch safe: without it the only
/// verification available is the file hash, which needs every byte.
pub fn decode_range(bytes: &[u8], expected: &[Chunk]) -> Result<Vec<Vec<u8>>, XorbError> {
    decode_chunks(bytes, expected.len(), Some(expected))
}

/// Decodes `count` consecutive chunks, verifying each against
/// `expected` when the caller has a chunk list to check against.
///
/// `None` is not laxity for its own sake: a client fetching content it
/// has never indexed genuinely has nothing to check against, because a
/// reconstruction response carries no chunk hashes. Such a fetch is
/// verified once, whole, against the file hash.
pub fn decode_chunks(
    bytes: &[u8],
    count: usize,
    expected: Option<&[Chunk]>,
) -> Result<Vec<Vec<u8>>, XorbError> {
    let mut decoded = Vec::with_capacity(count);
    let mut offset = 0;
    for index in 0..count {
        let next = decode_chunk(bytes.get(offset..).ok_or(XorbError::Truncated)?)?;
        if let Some(chunk) = expected.and_then(|chunks| chunks.get(index)) {
            let actual = chunk_hash(&next.data);
            if actual != chunk.hash {
                return Err(XorbError::HashMismatch {
                    expected: chunk.hash,
                    actual,
                });
            }
        }
        offset += next.consumed;
        decoded.push(next.data);
    }
    Ok(decoded)
}

fn u24(bytes: &[u8]) -> usize {
    usize::from(bytes[0]) | usize::from(bytes[1]) << 8 | usize::from(bytes[2]) << 16
}

fn lz4_frame(payload: &[u8]) -> Result<Vec<u8>, XorbError> {
    use std::io::Read as _;
    let mut out = Vec::new();
    lz4_flex::frame::FrameDecoder::new(payload)
        .read_to_end(&mut out)
        .map_err(|_| XorbError::Decompress)?;
    Ok(out)
}

/// Reverses byte grouping: the input is four concatenated groups that
/// were formed by dealing the original bytes round-robin.
///
/// Group sizes are `len / 4`, with the first `len % 4` groups taking one
/// extra byte — so for a length that is not a multiple of four the
/// groups are not all the same size, and assuming they are silently
/// corrupts the tail.
fn ungroup(grouped: &[u8]) -> Vec<u8> {
    let len = grouped.len();
    let base = len / BG4_GROUPS;
    let extra = len % BG4_GROUPS;

    let mut starts = [0_usize; BG4_GROUPS];
    let mut at = 0;
    for (index, start) in starts.iter_mut().enumerate() {
        *start = at;
        at += base + usize::from(index < extra);
    }

    let mut out = Vec::with_capacity(len);
    for position in 0..len {
        let group = position % BG4_GROUPS;
        let within = position / BG4_GROUPS;
        let size = base + usize::from(group < extra);
        if within < size {
            out.push(grouped[starts[group] + within]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deals bytes into four groups — the encoder this module reverses.
    fn group(bytes: &[u8]) -> Vec<u8> {
        let mut groups: [Vec<u8>; BG4_GROUPS] = Default::default();
        for (position, byte) in bytes.iter().enumerate() {
            groups[position % BG4_GROUPS].push(*byte);
        }
        groups.concat()
    }

    fn framed(data: &[u8], scheme: Scheme) -> Vec<u8> {
        let payload = match scheme {
            Scheme::None => data.to_vec(),
            Scheme::Lz4 => lz4_flex::frame::FrameEncoder::new(Vec::new())
                .tap_write(data)
                .expect("encode"),
            Scheme::ByteGrouping4Lz4 => lz4_flex::frame::FrameEncoder::new(Vec::new())
                .tap_write(&group(data))
                .expect("encode"),
        };
        let tag = match scheme {
            Scheme::None => 0,
            Scheme::Lz4 => 1,
            Scheme::ByteGrouping4Lz4 => 2,
        };
        let mut out = vec![0_u8];
        out.extend_from_slice(&payload.len().to_le_bytes()[..3]);
        out.push(tag);
        out.extend_from_slice(&data.len().to_le_bytes()[..3]);
        out.extend_from_slice(&payload);
        out
    }

    /// Helper so the test encoder reads tolerably.
    trait TapWrite {
        fn tap_write(self, bytes: &[u8]) -> std::io::Result<Vec<u8>>;
    }
    impl TapWrite for lz4_flex::frame::FrameEncoder<Vec<u8>> {
        fn tap_write(mut self, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
            use std::io::Write as _;
            self.write_all(bytes)?;
            self.finish().map_err(std::io::Error::other)
        }
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index * 31 % 251) as u8).collect()
    }

    #[test]
    fn every_scheme_round_trips() {
        for len in [0, 1, 3, 4, 5, 1000, 65_537] {
            let data = sample(len);
            for scheme in [Scheme::None, Scheme::Lz4, Scheme::ByteGrouping4Lz4] {
                let decoded = decode_chunk(&framed(&data, scheme))
                    .unwrap_or_else(|err| panic!("{scheme:?} len {len}: {err}"));
                assert_eq!(decoded.data, data, "{scheme:?} len {len}");
            }
        }
    }

    /// Lengths that are not multiples of four are where an ungrouper
    /// that assumes equal groups goes wrong.
    #[test]
    fn byte_grouping_survives_ragged_lengths() {
        for len in [1, 2, 3, 5, 6, 7, 9, 4095, 4097, 4098, 4099] {
            let data = sample(len);
            assert_eq!(ungroup(&group(&data)), data, "len {len}");
        }
    }

    #[test]
    fn a_truncated_xorb_is_refused_not_guessed() {
        let framed = framed(&sample(100), Scheme::Lz4);
        assert_eq!(decode_chunk(&framed[..4]), Err(XorbError::Truncated));
        assert_eq!(
            decode_chunk(&framed[..framed.len() - 1]),
            Err(XorbError::Truncated),
        );
    }

    #[test]
    fn an_unknown_version_or_scheme_is_refused() {
        let mut bad = framed(&sample(10), Scheme::None);
        bad[0] = 1;
        assert_eq!(
            decode_chunk(&bad),
            Err(XorbError::UnknownVersion { version: 1 })
        );

        let mut bad = framed(&sample(10), Scheme::None);
        bad[4] = 9;
        assert_eq!(decode_chunk(&bad), Err(XorbError::UnknownScheme { tag: 9 }));
    }

    /// The check that makes a partial fetch safe: bytes that decode
    /// cleanly but are not the bytes we asked for must be rejected.
    #[test]
    fn a_chunk_that_decodes_to_the_wrong_bytes_is_rejected() {
        let real = sample(5_000);
        let lie = sample(5_001);
        let expected = [Chunk::new(chunk_hash(&real), real.len() as u64)];

        assert!(decode_range(&framed(&real, Scheme::Lz4), &expected).is_ok());
        assert!(matches!(
            decode_range(&framed(&lie, Scheme::Lz4), &expected),
            Err(XorbError::HashMismatch { .. }),
        ));
    }

    #[test]
    fn a_range_decodes_consecutive_chunks_in_order() {
        let parts = [sample(1_000), sample(2_000), sample(3_000)];
        let mut xorb = Vec::new();
        let mut expected = Vec::new();
        for part in &parts {
            xorb.extend_from_slice(&framed(part, Scheme::ByteGrouping4Lz4));
            expected.push(Chunk::new(chunk_hash(part), part.len() as u64));
        }
        assert_eq!(decode_range(&xorb, &expected).expect("decode"), parts);
    }
}
