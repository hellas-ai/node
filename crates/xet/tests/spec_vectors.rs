use std::str::FromStr;

use hellas_xet::{Chunk, XetHash, file_hash, xorb_hash};
#[cfg(feature = "chunking")]
use hellas_xet::{chunk, chunk_hash};

// Published by xet-team/xet-spec-reference-files at
// c4aa3a3f15b1395fff5ce934784bf6c8f2d62de8.
const CHUNK_LIST: &str =
    include_str!("vectors/Electric_Vehicle_Population_Data_20250917.csv.chunks");

#[test]
#[cfg(feature = "chunking")]
fn published_chunk_data_and_boundaries_match() {
    let reference_chunks = [
        (
            include_bytes!(
                "vectors/b10aa1dc71c61661de92280c41a188aabc47981739b785724a099945d8dc5ce4.chunk"
            )
            .as_slice(),
            "b10aa1dc71c61661de92280c41a188aabc47981739b785724a099945d8dc5ce4",
        ),
        (
            include_bytes!(
                "vectors/26255591fa803b6baf25d88c315b8a6f5153d5bcfdf18ec5ef526264e0ccc907.chunk"
            )
            .as_slice(),
            "26255591fa803b6baf25d88c315b8a6f5153d5bcfdf18ec5ef526264e0ccc907",
        ),
        (
            include_bytes!(
                "vectors/099cb228194fe640e36a6c7d274ee5ed3a714ccd557a0951d9b6b43a7292b5d1.chunk"
            )
            .as_slice(),
            "099cb228194fe640e36a6c7d274ee5ed3a714ccd557a0951d9b6b43a7292b5d1",
        ),
    ];

    let mut joined = Vec::new();
    let expected: Vec<_> = reference_chunks
        .iter()
        .map(|(data, hash)| {
            let hash = XetHash::from_str(hash).unwrap();
            assert_eq!(chunk_hash(data), hash);
            joined.extend_from_slice(data);
            Chunk::new(hash, data.len() as u64)
        })
        .collect();

    assert_eq!(chunk(&joined), expected);
}

#[test]
fn published_file_and_xorb_hashes_match() {
    let chunks: Vec<_> = CHUNK_LIST
        .lines()
        .map(|line| {
            let (hash, data_len) = line.split_once(' ').unwrap();
            Chunk::new(XetHash::from_str(hash).unwrap(), data_len.parse().unwrap())
        })
        .collect();

    assert_eq!(chunks.len(), 796);
    assert_eq!(
        xorb_hash(&chunks).to_string(),
        "eea25d6ee393ccae385820daed127b96ef0ea034dfb7cf6da3a950ce334b7632"
    );
    assert_eq!(
        file_hash(&chunks).to_string(),
        "118a53328412787fee04011dcf82fdc4acf3a4a1eddec341c910d30a306aaf97"
    );
}

#[test]
fn reference_limb_endianness_matches() {
    let raw = [
        22, 175, 58, 132, 4, 75, 131, 214, 190, 153, 138, 66, 226, 3, 153, 242, 204, 86, 80, 234,
        249, 153, 80, 99, 159, 80, 65, 138, 236, 231, 149, 78,
    ];
    let expected = "d6834b04843aaf16f29903e2428a99be635099f9ea5056cc4e95e7ec8a41509f";

    let hash = XetHash::from_bytes(raw);
    assert_eq!(hash.to_string(), expected);
    assert_eq!(XetHash::from_str(expected).unwrap(), hash);
}
