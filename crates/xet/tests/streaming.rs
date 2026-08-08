//! [`XetFileHasher`] must be exactly [`chunk`] / [`XetHash::hash`], for
//! every input and every split.
//!
//! Exactness is the whole point. The streaming hasher exists so a
//! multi-gigabyte file can be identified without being held in memory,
//! and that id is signed into an execution environment — an id that
//! differed from the slice path under some unlucky buffer size would be
//! a commitment to weights nobody can reproduce.
//!
//! So these tests do not check "streaming works". They check that no
//! split point, and no input length near a CDC constant, can make the
//! two disagree.

#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

use hellas_xet::{Chunk, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, XetFileHasher, XetHash, chunk, file_hash};

/// Deterministic pseudorandom bytes. Real content, not a constant run:
/// a constant never triggers a content-defined boundary, so it would
/// exercise only the MAX_CHUNK_SIZE cut.
fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

fn streamed(input: &[u8], split: usize) -> Vec<Chunk> {
    let mut hasher = XetFileHasher::new();
    for piece in input.chunks(split.max(1)) {
        hasher.update(piece);
    }
    hasher.finalize_chunks()
}

/// Every length that straddles a CDC constant, fed whole.
#[test]
fn matches_the_slice_chunker_at_every_boundary_length() {
    let lengths = [
        0,
        1,
        63,
        64,
        65,
        MIN_CHUNK_SIZE - 66,
        MIN_CHUNK_SIZE - 65,
        MIN_CHUNK_SIZE - 64,
        MIN_CHUNK_SIZE - 1,
        MIN_CHUNK_SIZE,
        MIN_CHUNK_SIZE + 1,
        MAX_CHUNK_SIZE - 1,
        MAX_CHUNK_SIZE,
        MAX_CHUNK_SIZE + 1,
        2 * MAX_CHUNK_SIZE,
        3 * MAX_CHUNK_SIZE + 7,
    ];

    for len in lengths {
        let input = bytes(len, len as u64);
        let expected = chunk(&input);
        assert_eq!(streamed(&input, len.max(1)), expected, "len {len} whole");
        let mut hasher = XetFileHasher::new();
        hasher.update(&input);
        assert_eq!(
            hasher.finalize(),
            XetHash::hash(&input),
            "len {len} file hash"
        );
    }
}

/// The property that matters: the split point must not be observable.
#[test]
fn no_split_point_changes_the_chunks() {
    // Large enough to contain several content-defined boundaries.
    let input = bytes(5 * MAX_CHUNK_SIZE + 1_234, 0xabcd);
    let expected = chunk(&input);
    assert!(
        expected.len() > 4,
        "fixture must produce several chunks, got {}",
        expected.len(),
    );

    let splits = [
        1,
        2,
        7,
        63,
        64,
        65,
        MIN_CHUNK_SIZE - 1,
        MIN_CHUNK_SIZE,
        MIN_CHUNK_SIZE + 1,
        MAX_CHUNK_SIZE - 1,
        MAX_CHUNK_SIZE,
        MAX_CHUNK_SIZE + 1,
        1_048_576,
        input.len(),
    ];

    for split in splits {
        assert_eq!(streamed(&input, split), expected, "split {split}");
        assert_eq!(
            file_hash(&streamed(&input, split)),
            XetHash::hash(&input),
            "split {split} file hash",
        );
    }
}

/// Uneven, adversarial splits — not just a fixed stride.
#[test]
fn ragged_splits_agree_too() {
    let input = bytes(3 * MAX_CHUNK_SIZE + 999, 7);
    let expected = chunk(&input);

    let mut hasher = XetFileHasher::new();
    let mut offset = 0;
    let mut step = 1;
    while offset < input.len() {
        let end = (offset + step).min(input.len());
        hasher.update(&input[offset..end]);
        offset = end;
        // 1, 3, 9, 27 … then wrap, so pieces land at every alignment.
        step = if step > MAX_CHUNK_SIZE { 1 } else { step * 3 };
    }
    assert_eq!(hasher.finalize_chunks(), expected);
}

/// Empty input, and updates that carry no bytes, must not invent a chunk.
#[test]
fn empty_input_hashes_to_zero() {
    assert_eq!(XetFileHasher::new().finalize_chunks(), Vec::new());
    assert_eq!(XetFileHasher::new().finalize(), XetHash::ZERO);
    assert_eq!(XetHash::hash(&[]), XetHash::ZERO);

    let mut hasher = XetFileHasher::new();
    hasher.update(&[]);
    hasher.update(&[]);
    assert_eq!(hasher.finalize(), XetHash::ZERO);
}

/// The published reference file, re-fed one byte at a time, must still
/// produce the id HuggingFace publishes.
#[test]
fn the_published_vectors_survive_byte_at_a_time_streaming() {
    const CHUNK_LIST: &str =
        include_str!("vectors/Electric_Vehicle_Population_Data_20250917.csv.chunks");

    let reference: Vec<Chunk> = CHUNK_LIST
        .lines()
        .map(|line| {
            let (hash, len) = line.split_once(' ').expect("vector line is `hash len`");
            Chunk::new(
                hash.parse::<XetHash>().expect("vector hash parses"),
                len.parse().expect("vector length parses"),
            )
        })
        .collect();
    assert_eq!(reference.len(), 796);

    // The vectors give chunk descriptors, not the original bytes, so
    // reconstruct the three published chunks and stream those.
    let published: Vec<&[u8]> = vec![
        include_bytes!(
            "vectors/b10aa1dc71c61661de92280c41a188aabc47981739b785724a099945d8dc5ce4.chunk"
        ),
        include_bytes!(
            "vectors/26255591fa803b6baf25d88c315b8a6f5153d5bcfdf18ec5ef526264e0ccc907.chunk"
        ),
        include_bytes!(
            "vectors/099cb228194fe640e36a6c7d274ee5ed3a714ccd557a0951d9b6b43a7292b5d1.chunk"
        ),
    ];
    let joined: Vec<u8> = published.concat();
    let expected = chunk(&joined);

    for split in [1, 2, 3, 7, 4096, MIN_CHUNK_SIZE, joined.len()] {
        assert_eq!(streamed(&joined, split), expected, "split {split}");
    }
    // And the first three chunks are the published ones, which pins the
    // streaming path to real HuggingFace output rather than to our own
    // slice implementation alone.
    for (produced, published) in expected.iter().zip(&reference) {
        assert_eq!(produced, published);
    }
}
