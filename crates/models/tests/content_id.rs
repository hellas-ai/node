//! The streamed content id must equal the one a full read produced, and
//! remembering a file must never change the answer.
//!
//! `program_manifest` used to be `ContentId::hash(&fs::read(path))`. It
//! now streams, and caches by file identity. Both changes are invisible
//! only if the id is bit-identical — that id is signed into an
//! `execution_environment`, so "close enough" is a losable claim rather
//! than a rounding error.

use std::io::Write as _;

use hellas_rpc::ContentId;
use hellas_store::fastresume;

/// Deterministic pseudorandom bytes; a constant run would never trigger
/// a content-defined chunk boundary.
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

fn write_temp(name: &str, content: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("hellas-content-id-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).expect("create");
    file.write_all(content).expect("write");
    file.sync_all().expect("sync");
    path
}

/// Sizes that straddle the chunker's constants, including several
/// multiples of the 1 MiB streaming buffer so a boundary lands mid-read.
#[test]
fn streamed_ids_match_a_whole_file_read() {
    let sizes = [
        0,
        1,
        8_191,
        8_192,
        131_072,
        131_073,
        1024 * 1024 - 1,
        1024 * 1024,
        1024 * 1024 + 1,
        3 * 1024 * 1024 + 12_345,
    ];

    for size in sizes {
        let content = bytes(size, size as u64);
        let path = write_temp(&format!("size-{size}"), &content);

        // What the old implementation computed.
        let expected = ContentId::hash(&content);
        // What the manifest path computes now, via a real file.
        let actual = hellas_models::content_id_of(&path).expect("hash file");

        assert_eq!(actual, expected, "size {size}");
        let _ = std::fs::remove_file(&path);
    }
}

/// A remembered file must give the same id as an unremembered one, and
/// force_recheck must genuinely make it hash again.
#[test]
fn remembering_a_file_does_not_change_its_id() {
    let content = bytes(2 * 1024 * 1024 + 7, 99);
    let path = write_temp("remembered", &content);

    fastresume::force_recheck();
    let cold = hellas_models::content_id_of(&path).expect("cold hash");
    let warm = hellas_models::content_id_of(&path).expect("warm hash");
    assert_eq!(cold, warm);
    assert_eq!(cold, ContentId::hash(&content));
    assert!(fastresume::remembered() >= 1);

    fastresume::force_recheck();
    assert_eq!(fastresume::remembered(), 0, "force_recheck must forget");
    let rechecked = hellas_models::content_id_of(&path).expect("rechecked");
    assert_eq!(rechecked, cold);

    let _ = std::fs::remove_file(&path);
}

/// The hazard the identity key exists for: a file replaced in place must
/// not keep its old id.
#[test]
fn replacing_a_file_invalidates_its_record() {
    let first = bytes(200_000, 1);
    let second = bytes(200_000, 2);
    assert_ne!(first, second);

    let path = write_temp("replaced", &first);
    let before = hellas_models::content_id_of(&path).expect("hash first");
    assert_eq!(before, ContentId::hash(&first));

    // Same path, same length — only the bytes and the stat differ.
    let mut file = std::fs::File::create(&path).expect("recreate");
    file.write_all(&second).expect("write");
    file.sync_all().expect("sync");
    drop(file);

    let after = hellas_models::content_id_of(&path).expect("hash second");
    assert_eq!(
        after,
        ContentId::hash(&second),
        "a replaced file must be re-hashed, not served from the record",
    );
    assert_ne!(before, after);

    let _ = std::fs::remove_file(&path);
}
