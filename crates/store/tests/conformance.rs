//! Decoding bytes HuggingFace actually served.
//!
//! The unit tests in `xorb` round-trip against this crate's own test
//! encoder, which proves the decoder is self-consistent and nothing
//! more. This one decodes a range downloaded from HuggingFace's CAS and
//! checks the chunks against hashes published in the Xet spec's
//! reference dataset. If our framing, our LZ4 handling or our byte
//! ungrouping drifted from theirs, this is what would notice.
//!
//! The fixture is the first two chunks of
//! `xet-team/xet-spec-reference-files`'s reference CSV, fetched from
//! `/v2/reconstructions/118a5332…` and then its signed xorb URL with
//! `Range: bytes=0-50468`.
//!
//! # What this does NOT cover
//!
//! Both chunks in the fixture use scheme 1 (LZ4 frame). **Scheme 2,
//! byte-grouping, is not exercised against production here** — only
//! against this crate's own encoder in the `xorb` unit tests. If our
//! ungrouping disagrees with xet-core's on the ragged-tail case, these
//! tests would still pass. Replacing this fixture with a range that
//! contains a BG4 chunk would close that, and is worth doing before
//! anything depends on BG4 content.

use hellas_store::xorb::{decode_chunk, decode_range};
use hellas_xet::{Chunk, XetHash, chunk_hash};

/// Bytes as served: a xorb range covering chunk indices [0, 2).
const RANGE: &[u8] = include_bytes!("vectors/reference-xorb-chunks-0-2.bin");

/// Published in the reference dataset, and independently the values our
/// own `spec_vectors` test asserts for the same file.
const PUBLISHED: [(&str, u64); 2] = [
    (
        "b10aa1dc71c61661de92280c41a188aabc47981739b785724a099945d8dc5ce4",
        131_072,
    ),
    (
        "26255591fa803b6baf25d88c315b8a6f5153d5bcfdf18ec5ef526264e0ccc907",
        106_099,
    ),
];

fn published() -> Vec<Chunk> {
    PUBLISHED
        .iter()
        .map(|(hash, len)| Chunk::new(hash.parse::<XetHash>().expect("vector hash"), *len))
        .collect()
}

#[test]
fn a_real_xorb_range_decodes_to_the_published_chunks() {
    let decoded = decode_range(RANGE, &published()).expect("real xorb decodes");

    assert_eq!(decoded.len(), 2);
    for (data, (hash, len)) in decoded.iter().zip(PUBLISHED) {
        assert_eq!(data.len() as u64, len);
        assert_eq!(chunk_hash(data).to_string(), hash);
    }
}

/// The framing must locate the second chunk purely by decoding the
/// first — a xorb carries no index.
#[test]
fn chunk_boundaries_are_found_by_decoding_not_by_an_index() {
    let first = decode_chunk(RANGE).expect("first chunk");
    assert_eq!(first.data.len(), 131_072);

    let second = decode_chunk(&RANGE[first.consumed..]).expect("second chunk");
    assert_eq!(second.data.len(), 106_099);
    assert_eq!(
        first.consumed + second.consumed,
        RANGE.len(),
        "the two chunks must account for the whole served range",
    );
}
