//! Decoding bytes HuggingFace actually served.
//!
//! The unit tests in `xorb` round-trip against this crate's own test
//! encoder, which proves the decoder is self-consistent and nothing
//! more. This one decodes a range downloaded from HuggingFace's CAS and
//! checks the chunks against hashes published in the Xet spec's
//! reference dataset. If our framing, our LZ4 handling or our byte
//! ungrouping drifted from theirs, this is what would notice.
//!
//! The scheme-1 fixture is the first two chunks of
//! `xet-team/xet-spec-reference-files`'s reference CSV, fetched from
//! `/v2/reconstructions/118a5332…` and then its signed xorb URL with
//! `Range: bytes=0-50468`.
//!
//! # Scheme 2, and how it is checked without arguing in a circle
//!
//! The reference CSV compresses with scheme 1 throughout, so a second
//! fixture covers byte grouping: two scheme-2 chunks out of the middle
//! of a safetensors shard, where uploaders' clients actually pick BG4.
//! See [`bg4`] for its provenance.
//!
//! A xorb range carries no chunk hashes, so the expected hashes for that
//! fixture cannot simply be looked up. Deriving them by decoding the
//! fixture with this crate would prove nothing: the decoder would be
//! grading its own homework. The way out is a second, independent
//! rendering of the same bytes — HuggingFace's `resolve` endpoint serves
//! a file's *plaintext*, reconstructed by their implementation, and it
//! honours `Range`. So the second fixture ships with the plaintext of
//! exactly the byte span its two chunks cover, fetched that way, and the
//! test asserts our decoded chunks concatenate to it. Everything else —
//! the chunk hashes, the boundary between the two chunks — is then
//! derived from bytes xet-core produced, not from bytes we produced.
//!
//! # What this does NOT cover
//!
//! All three compression schemes now have a production fixture (0 is
//! trivial; 1 and 2 are here), and both scheme-2 chunks have an
//! uncompressed length that is not a multiple of four, so the ragged
//! tail — the case an ungrouper that assumes equal groups gets wrong —
//! is exercised against real xet-core output. Still outside this file:
//! multi-term and multi-xorb reconstructions, ranges whose first chunk
//! is preceded by a non-zero `offset_into_first_range` (the fixtures are
//! whole chunks), and the HTTP layer itself, which no fixture can test.

use hellas_store::xorb::{decode_chunk, decode_chunks, decode_range};
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

/// Byte grouping (scheme 2) against bytes xet-core produced.
///
/// # Provenance
///
/// `HuggingFaceTB/SmolLM2-135M` at commit `93efa2f0`, `model.safetensors`
/// (Apache-2.0). Asking `/v2/reconstructions/8595fbb3…` for
/// `Range: bytes=200000000-200060000` yields a single term over xorb
/// `ee90c1fe…`, chunk indices [1100, 1102), served from its signed URL
/// with `Range: bytes=56832488-56928801`. Both chunk headers carry
/// scheme tag 2.
///
/// The plaintext oracle is
/// `GET huggingface.co/HuggingFaceTB/SmolLM2-135M/resolve/93efa2f0…/model.safetensors`
/// with `Range: bytes=199964592-200075831` — that is the requested start
/// less the response's `offset_into_first_range` of 35408, spanning the
/// term's `unpacked_length` of 111240. It is the same content by a
/// different code path, which is the whole point.
mod bg4 {
    use super::{Chunk, XetHash, chunk_hash, decode_chunk, decode_chunks, decode_range};

    /// Bytes as served: a xorb range covering chunk indices [1100, 1102).
    const RANGE: &[u8] = include_bytes!("vectors/bg4-xorb-chunks-1100-1102.bin");

    /// The same span of the file, served decoded by HuggingFace.
    const PLAIN: &[u8] = include_bytes!("vectors/bg4-plaintext-chunks-1100-1102.bin");

    /// Uncompressed lengths from the two chunk headers. Neither is a
    /// multiple of four, so both go through the remainder branch of the
    /// ungrouper.
    const LENGTHS: [usize; 2] = [62_290, 48_950];

    /// Scheme tags from the two chunk headers, as a reminder of what
    /// this fixture is for. A fixture that quietly became all-scheme-1
    /// would still pass every other assertion here.
    #[test]
    fn the_fixture_really_is_byte_grouped() {
        assert_eq!(RANGE[4], 2, "first chunk header must say scheme 2");
        let first = decode_chunk(RANGE).expect("first chunk");
        assert_eq!(
            RANGE[first.consumed + 4],
            2,
            "second chunk header must say scheme 2",
        );
        assert!(LENGTHS.iter().all(|len| len % 4 != 0), "ragged tails");
    }

    /// The external oracle: our ungrouping must land on the bytes
    /// HuggingFace's own reconstruction serves for the same span.
    #[test]
    fn ungrouped_chunks_match_the_plaintext_huggingface_serves() {
        let decoded = decode_chunks(RANGE, 2, None).expect("bg4 xorb decodes");
        assert_eq!(
            decoded.iter().map(Vec::len).collect::<Vec<_>>(),
            LENGTHS.to_vec(),
        );
        assert_eq!(
            decoded.concat(),
            PLAIN,
            "decoded bytes differ from the file"
        );
    }

    /// With the chunk list derived from the oracle rather than from our
    /// own decoding, the verifying path must accept the fixture.
    #[test]
    fn per_chunk_verification_accepts_the_real_range() {
        let mut expected = Vec::new();
        let mut at = 0;
        for len in LENGTHS {
            let data = &PLAIN[at..at + len];
            expected.push(Chunk::new(chunk_hash(data), len as u64));
            at += len;
        }
        assert_eq!(at, PLAIN.len(), "lengths must account for the oracle");

        let decoded = decode_range(RANGE, &expected).expect("bg4 range verifies");
        assert_eq!(decoded.concat(), PLAIN);
    }

    /// Hashes pinned so a change in `chunk_hash` itself is caught, not
    /// only a change in the decoder. Computed from the oracle bytes.
    #[test]
    fn the_chunk_hashes_are_the_pinned_ones() {
        const PINNED: [&str; 2] = [
            "82e7e9e4e603ea809e8dcf6595a878e7bf3abc33cb52f7421cae7949c9b2084c",
            "4b69d94163af2b10a87d79f2f860a3ddb68c685aa10e3e548ef45c1e3a2729e2",
        ];
        let mut at = 0;
        for (len, pin) in LENGTHS.into_iter().zip(PINNED) {
            let from_oracle = chunk_hash(&PLAIN[at..at + len]);
            assert_eq!(from_oracle.to_string(), pin);
            assert_eq!(pin.parse::<XetHash>().expect("pin parses"), from_oracle);
            at += len;
        }
    }
}
