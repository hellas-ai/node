//! A running node must use what `adopt` learned.
//!
//! `hellas store adopt` persists what it hashed, and until now nothing
//! in the serving path read it back: the node re-hashed every weight
//! shard on its first quote. Measured at 647 ms cold against 549 µs warm
//! on a 29-blob cache — all of it accruing to a CLI process that exited
//! immediately afterwards.
//!
//! Two claims, and the second one is the hard one:
//!
//! 1. What `adopt` hashed comes back into the process that serves.
//! 2. It is *used* — the node does not hash an adopted file again.
//!
//! Proving (2) needs an observation, not a stopwatch. So the record
//! handed to the node deliberately disagrees with the file: it names an
//! id the bytes do not have. If the node answers with that id it read
//! the record and did not hash; if it answers with the real id it
//! hashed. There is no third possibility, and no timing to be flaky
//! about.
//!
//! That record is a lie, which is the point. It is also why loading is
//! never trusting — see `a_changed_file_is_hashed_again_despite_its_record`,
//! which is the same lie told about a file that has since moved on.

use std::path::PathBuf;

use hellas_rpc::ContentId;
use hellas_store::fastresume::Records;
use hellas_store::{ContentStore, Indexed};
use hellas_xet::XetHash;

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hellas-node-fastresume-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");
    root
}

/// Bytes that actually chunk, so the id is not a degenerate one.
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

/// A hash no file will ever have, so seeing it back is unambiguous.
fn impossible_id() -> XetHash {
    XetHash::from_bytes([0xAB; 32])
}

/// Writes a record file claiming `path` hashes to `id`.
///
/// The only way to observe "did not hash" from outside: a truthful
/// record is indistinguishable from a re-hash.
fn record_claiming(path: &std::path::Path, id: XetHash, at: &std::path::Path) {
    let metadata = std::fs::metadata(path).expect("stat the file");
    let records = Records::default();
    records.put(
        &metadata,
        &Indexed {
            id,
            chunks: Vec::new(),
            len: metadata.len(),
        },
    );
    assert_eq!(records.save(at).expect("save the record"), 1);
}

#[test]
fn a_node_started_after_adopt_does_not_hash_an_adopted_file() {
    let root = scratch("no-rehash");
    let file = root.join("model.safetensors");
    let content = bytes(300_000, 5);
    std::fs::write(&file, &content).expect("write");
    let real_id = ContentId::hash(&content);

    let records = root.join("fastresume.bin");
    record_claiming(&file, impossible_id(), &records);

    // What the node does at startup.
    assert_eq!(
        hellas_models::load_store_records(&records),
        1,
        "the node must read what an earlier process hashed",
    );

    assert_eq!(
        hellas_models::content_id_of(&file).expect("id"),
        ContentId::from_bytes(impossible_id().into_bytes()),
        "the node hashed a file it had a record for",
    );
    assert_ne!(
        real_id,
        ContentId::from_bytes(impossible_id().into_bytes()),
        "the control: hashing would have given a different answer",
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Loading is not trusting. A record whose file has since changed is
/// discarded, and the node hashes — which is what keeps the file a cache
/// of work rather than a source of truth.
#[test]
fn a_changed_file_is_hashed_again_despite_its_record() {
    let root = scratch("changed");
    let file = root.join("model.safetensors");
    std::fs::write(&file, bytes(200_000, 6)).expect("write");

    let records = root.join("fastresume.bin");
    record_claiming(&file, impossible_id(), &records);

    // The file moves on after the record was written.
    let replacement = bytes(200_000, 7);
    std::fs::write(&file, &replacement).expect("rewrite");

    assert_eq!(hellas_models::load_store_records(&records), 1);
    assert_eq!(
        hellas_models::content_id_of(&file).expect("id"),
        ContentId::hash(&replacement),
        "a record for a file that has changed must not be believed",
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The other direction: what this process hashed must be there for the
/// next one, at the path the node was told to use.
#[test]
fn what_the_node_hashed_is_there_for_the_next_start() {
    let root = scratch("round-trip");
    let file = root.join("model.safetensors");
    let content = bytes(150_000, 8);
    std::fs::write(&file, &content).expect("write");

    let id = hellas_models::content_id_of(&file).expect("hash it");
    assert_eq!(id, ContentId::hash(&content));

    let records = root.join("state/fastresume.bin");
    let saved = hellas_models::save_store_records(&records).expect("save");
    assert!(saved >= 1, "the file this test hashed must be in there");
    assert!(records.exists(), "written where the node was told to");

    // A fresh store — a next start — gets the work back.
    let next = ContentStore::new();
    assert_eq!(next.records().remembered(), 0);
    assert_eq!(next.records().load(&records), saved);
    assert_eq!(
        next.index(&file).expect("index").id,
        XetHash::from_bytes(id.as_bytes().to_owned()),
    );

    let _ = std::fs::remove_dir_all(&root);
}
