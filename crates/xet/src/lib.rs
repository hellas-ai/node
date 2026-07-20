#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::{fmt, str::FromStr};

/// Key used by Xet Protocol v1.1.0 for chunk (leaf) hashes.
pub const DATA_KEY: [u8; 32] = [
    102, 151, 245, 119, 91, 149, 80, 222, 49, 53, 203, 172, 165, 151, 24, 28, 157, 228, 33, 16,
    155, 235, 43, 88, 180, 208, 176, 75, 147, 173, 242, 41,
];

/// Key used by Xet Protocol v1.1.0 for Merkle internal-node hashes.
pub const INTERNAL_NODE_KEY: [u8; 32] = [
    1, 126, 197, 199, 165, 71, 41, 150, 253, 148, 102, 102, 180, 138, 2, 230, 93, 221, 83, 111, 55,
    199, 109, 210, 248, 99, 82, 230, 74, 83, 113, 63,
];

/// Target chunk size in bytes.
pub const TARGET_CHUNK_SIZE: usize = 64 * 1024;
/// Minimum non-final chunk size in bytes.
pub const MIN_CHUNK_SIZE: usize = 8 * 1024;
/// Maximum chunk size in bytes.
pub const MAX_CHUNK_SIZE: usize = 128 * 1024;
/// Boundary mask used with the Gear rolling hash.
pub const CHUNK_BOUNDARY_MASK: u64 = 0xffff_0000_0000_0000;

const TREE_BRANCHING_FACTOR: u64 = 4;
const MAX_GROUP_SIZE: usize = 2 * TREE_BRANCHING_FACTOR as usize + 1;
const MAX_ENTRY_SIZE: usize = 64 + 3 + 20 + 1;
const MAX_MERGE_BUFFER_SIZE: usize = MAX_GROUP_SIZE * MAX_ENTRY_SIZE;
const ZERO_KEY: [u8; 32] = [0; 32];

/// A raw 32-byte Xet hash.
///
/// The bytes are the BLAKE3 digest bytes. Its hexadecimal representation follows
/// Xet's convention: four little-endian `u64` limbs printed as 16 lowercase hex
/// digits each.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct XetHash([u8; 32]);

impl XetHash {
    /// The all-zero hash used by Xet for an empty chunk sequence.
    pub const ZERO: Self = Self([0; 32]);

    /// Wraps raw BLAKE3 digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw BLAKE3 digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the hash and returns its raw BLAKE3 digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    fn natural_cut_value(self) -> u64 {
        let mut limb = [0; 8];
        limb.copy_from_slice(&self.0[24..]);
        u64::from_le_bytes(limb)
    }
}

impl AsRef<[u8]> for XetHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for XetHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<XetHash> for [u8; 32] {
    fn from(hash: XetHash) -> Self {
        hash.into_bytes()
    }
}

impl fmt::LowerHex for XetHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for limb in self.0.chunks_exact(8) {
            for byte in limb.iter().rev() {
                write!(formatter, "{byte:02x}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for XetHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, formatter)
    }
}

impl fmt::Debug for XetHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, formatter)
    }
}

/// Error returned when parsing a non-canonical Xet hexadecimal hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseXetHashError;

impl fmt::Display for ParseXetHashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Xet hash: expected 64 hexadecimal characters")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseXetHashError {}

impl FromStr for XetHash {
    type Err = ParseXetHashError;

    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        if hex.len() != 64 {
            return Err(ParseXetHashError);
        }

        let mut raw = [0; 32];
        for (limb_index, limb) in hex.as_bytes().chunks_exact(16).enumerate() {
            for byte_index in 0..8 {
                let high = decode_hex(limb[byte_index * 2]).ok_or(ParseXetHashError)?;
                let low = decode_hex(limb[byte_index * 2 + 1]).ok_or(ParseXetHashError)?;
                raw[limb_index * 8 + 7 - byte_index] = (high << 4) | low;
            }
        }
        Ok(Self(raw))
    }
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A content chunk represented by its Xet hash and uncompressed length.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Chunk {
    /// Xet DATA-keyed BLAKE3 hash of the chunk bytes.
    pub hash: XetHash,
    /// Length of the chunk data in bytes.
    pub data_len: u64,
}

impl Chunk {
    /// Creates a chunk descriptor.
    #[must_use]
    pub const fn new(hash: XetHash, data_len: u64) -> Self {
        Self { hash, data_len }
    }
}

/// Computes the Xet chunk hash for `bytes`.
#[must_use]
pub fn chunk_hash(bytes: &[u8]) -> XetHash {
    XetHash::from(*blake3::keyed_hash(&DATA_KEY, bytes).as_bytes())
}

/// Splits `bytes` with Xet's GearHash CDC and returns its chunk descriptors.
#[cfg(feature = "chunking")]
#[must_use]
pub fn chunk(bytes: &[u8]) -> Vec<Chunk> {
    const HASH_WINDOW_SIZE: usize = 64;
    const INITIAL_SKIP: usize = MIN_CHUNK_SIZE - HASH_WINDOW_SIZE - 1;

    let mut chunks = Vec::new();
    let mut start = 0;

    while start < bytes.len() {
        let remaining = &bytes[start..];
        let search_end = remaining.len().min(MAX_CHUNK_SIZE);
        let mut cursor = INITIAL_SKIP.min(search_end);
        let mut hasher = gearhash::Hasher::default();
        let boundary = loop {
            let Some(consumed) =
                hasher.next_match(&remaining[cursor..search_end], CHUNK_BOUNDARY_MASK)
            else {
                break search_end;
            };
            cursor += consumed;
            if cursor >= MIN_CHUNK_SIZE {
                break cursor;
            }
        };

        let data = &remaining[..boundary];
        chunks.push(Chunk::new(chunk_hash(data), data.len() as u64));
        start += boundary;
    }

    chunks
}

/// Computes the Merkle root over ordered `(hash, length)` chunk descriptors.
///
/// At every level, Xet takes a natural cut after the third or later child whose
/// last hash limb is divisible by four. A group is capped at nine children, and
/// a final remainder of one or two children is merged as-is.
#[must_use]
pub fn merkle_root(chunks: &[Chunk]) -> XetHash {
    if chunks.is_empty() {
        return XetHash::ZERO;
    }

    let mut nodes = Vec::from(chunks);
    while nodes.len() > 1 {
        let mut read_index = 0;
        let mut write_index = 0;

        while read_index < nodes.len() {
            let cut = read_index + next_merge_cut(&nodes[read_index..]);
            nodes[write_index] = merge(&nodes[read_index..cut]);
            read_index = cut;
            write_index += 1;
        }

        nodes.truncate(write_index);
    }

    nodes[0].hash
}

/// Computes the Xet xorb hash: the unfinalized Merkle root of its chunks.
#[must_use]
pub fn xorb_hash(chunks: &[Chunk]) -> XetHash {
    merkle_root(chunks)
}

/// Computes the Xet file hash (xetHash/ContentId) from its chunks.
///
/// The Merkle root is finalized with BLAKE3 keyed by 32 zero bytes. As in the
/// reference implementation, an empty chunk sequence maps directly to zero.
#[must_use]
pub fn file_hash(chunks: &[Chunk]) -> XetHash {
    if chunks.is_empty() {
        return XetHash::ZERO;
    }

    XetHash::from(*blake3::keyed_hash(&ZERO_KEY, merkle_root(chunks).as_bytes()).as_bytes())
}

fn next_merge_cut(nodes: &[Chunk]) -> usize {
    if nodes.len() <= 2 {
        return nodes.len();
    }

    let end = nodes.len().min(MAX_GROUP_SIZE);
    for (index, node) in nodes.iter().enumerate().take(end).skip(2) {
        if node.hash.natural_cut_value() % TREE_BRANCHING_FACTOR == 0 {
            return index + 1;
        }
    }
    end
}

fn merge(nodes: &[Chunk]) -> Chunk {
    let mut buffer = [0; MAX_MERGE_BUFFER_SIZE];
    let mut position = 0;
    let mut total_len = 0;

    for node in nodes {
        write_hash(&mut buffer, &mut position, node.hash);
        buffer[position..position + 3].copy_from_slice(b" : ");
        position += 3;
        write_decimal(&mut buffer, &mut position, node.data_len);
        buffer[position] = b'\n';
        position += 1;
        total_len += node.data_len;
    }

    let hash = blake3::keyed_hash(&INTERNAL_NODE_KEY, &buffer[..position]);
    Chunk::new(XetHash::from(*hash.as_bytes()), total_len)
}

fn write_hash(buffer: &mut [u8], position: &mut usize, hash: XetHash) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for limb in hash.0.chunks_exact(8) {
        for byte in limb.iter().rev() {
            buffer[*position] = HEX[(byte >> 4) as usize];
            buffer[*position + 1] = HEX[(byte & 0x0f) as usize];
            *position += 2;
        }
    }
}

fn write_decimal(buffer: &mut [u8], position: &mut usize, value: u64) {
    if value == 0 {
        buffer[*position] = b'0';
        *position += 1;
        return;
    }

    let mut digits = [0; 20];
    let mut digit_start = digits.len();
    let mut remaining = value;
    while remaining > 0 {
        digit_start -= 1;
        digits[digit_start] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
    }

    let digits = &digits[digit_start..];
    buffer[*position..*position + digits.len()].copy_from_slice(digits);
    *position += digits.len();
}
