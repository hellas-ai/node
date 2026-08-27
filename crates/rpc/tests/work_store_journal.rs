//! The journal envelope, pinned as bytes.
//!
//! Every other test of these files writes with this code and reads with
//! this code, so all of them stay green when the magic, the version
//! byte, or either digest domain is changed — writer and reader move
//! together and agree with each other about a format nobody else would
//! recognise. What that hides is the only failure these constants have:
//! an endpoint that no longer opens the journal it wrote yesterday, and
//! reports its own file as somebody else's.
//!
//! So this is a file, from outside: fifty-seven header bytes and one
//! frame, written once and pinned as hex. It fails if the magic moves,
//! if the version moves, if the header domain moves — the header digest
//! is in every frame's preimage — or if the frame domain moves.

#![cfg(feature = "work")]

use hellas_rpc::work_store::Role;
use hellas_rpc::work_store::journal::{Journal, JournalId, JournalKind};

/// Bytes before the first frame: magic, version, kind, role, key.
const HEADER_BYTES: usize = 57;

/// `hellas.work-journal.v1`, then `02` version, `02` channel, `02`
/// provider, then the 32-byte key.
const GOLDEN_HEADER: &str = concat!(
    "68656c6c61732e776f726b2d6a6f75726e616c2e7631",
    "02",
    "02",
    "02",
    "1111111111111111111111111111111111111111111111111111111111111111",
);

/// A four-byte big-endian length, the record, and the frame digest over
/// the frame domain, the header digest, the sequence, and the length.
const GOLDEN_FRAME: &str = concat!(
    "0000000a",
    "6f6e65207265636f7264",
    "33ad92cc54b8abb64f09aa5592917a3020dada20dc23f00ecefdc33c4039eb1c",
);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Version 1 files are pre-deployment casualties: they have no recovery
/// arming records and cannot be upgraded without inventing the observation
/// floor they failed to retain.
#[test]
fn a_v1_journal_is_refused() {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let path = dir.path().join("old.journal");
    let id = JournalId {
        kind: JournalKind::Channel,
        role: Role::Provider,
        key: [0x11; 32],
    };
    {
        let Ok((journal, _)) = Journal::open(&path, id) else {
            panic!("the current journal opens");
        };
        drop(journal);
    }
    let Ok(mut bytes) = std::fs::read(&path) else {
        panic!("the current journal reads");
    };
    bytes[b"hellas.work-journal.v1".len()] = 1;
    if let Err(error) = std::fs::write(&path, bytes) {
        panic!("the old header writes: {error}");
    }
    let error = Journal::open(&path, id).expect_err("v1 lacks recovery arming state");
    assert!(
        matches!(
            error,
            hellas_rpc::work_store::JournalError::OldVersion {
                found: 1,
                expected: 2,
                ..
            }
        ),
        "unexpected error: {error}",
    );
}

/// One journal holding one record is these exact bytes.
#[test]
fn a_journal_of_one_record_is_these_bytes() {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let path = dir.path().join("golden.journal");
    let id = JournalId {
        kind: JournalKind::Channel,
        role: Role::Provider,
        key: [0x11; 32],
    };
    {
        let (mut journal, replay) = match Journal::open(&path, id) {
            Ok(opened) => opened,
            Err(error) => panic!("the journal opens: {error}"),
        };
        assert!(replay.records.is_empty(), "a new file holds nothing");
        if let Err(error) = journal.append(b"one record") {
            panic!("the record appends: {error}");
        }
    }

    let Ok(bytes) = std::fs::read(&path) else {
        panic!("the journal reads");
    };
    assert!(
        bytes.len() > HEADER_BYTES,
        "a header and a frame, not {} bytes",
        bytes.len()
    );
    let (header, frame) = bytes.split_at(HEADER_BYTES);
    assert_eq!(hex(header), GOLDEN_HEADER, "the header this endpoint reads");
    assert_eq!(hex(frame), GOLDEN_FRAME, "the frame it binds");
}
