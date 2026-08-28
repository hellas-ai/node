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

/// Bytes before the first frame: magic, version, kind, role,
/// generation, key.
const HEADER_BYTES: usize = 65;

/// `hellas.work-journal.v1`, then `05` version, `02` channel, `02`
/// provider, the eight-byte generation, then the 32-byte key.
const GOLDEN_HEADER: &str = concat!(
    "68656c6c61732e776f726b2d6a6f75726e616c2e7631",
    "05",
    "02",
    "02",
    "0000000000000000",
    "1111111111111111111111111111111111111111111111111111111111111111",
);

/// A four-byte big-endian length, the record, and the frame digest over
/// the frame domain, the header digest, the sequence, and the length.
const GOLDEN_FRAME: &str = concat!(
    "0000000a",
    "6f6e65207265636f7264",
    "4607087f3e8fbd8481bde856d457cd51c4110826e0a2ecb8b61085f91ffac1a4",
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
    let path = dir.path().join("old.0000000000000000.journal");
    let id = JournalId {
        kind: JournalKind::Channel,
        role: Role::Provider,
        key: [0x11; 32],
        generation: 0,
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
                expected: 5,
                ..
            }
        ),
        "unexpected error: {error}",
    );
}

/// Version 2 files are refused before a single frame is decoded.
///
/// Between v2 and v3 the channel-record tags were reassigned: 7–11 meant
/// admitted-payment, ending, and the three close records, and the same
/// tag bytes now mean the terminal and shifted close records. The file
/// below is a genuine v2 file — its one frame's digest verifies under
/// the v2 header — and its payload is the old `ResultVerified` record,
/// whose single byte decodes *cleanly* today as a different record. The
/// version byte is the only thing standing between such a file and a
/// silent misread, which is why an old file must fail on it rather than
/// reach the decoder.
#[test]
fn a_v2_channel_journal_is_refused_not_misread() {
    use hellas_rpc::protocol::Digest;
    use hellas_rpc::work_store::ChannelRecord;

    // The old encoding under the new decoder: the v2 tag 6 meant the
    // oracle-verified record, and the same byte decodes today, without
    // error, as the re-execution match. Nothing in the record layer can
    // tell the two apart, which is what makes the refusal the journal
    // header's job.
    assert!(
        matches!(
            ChannelRecord::decode(&[0x06]),
            Ok(ChannelRecord::ResultMatched)
        ),
        "an old v2 record body still decodes under the new tags",
    );

    // A genuine v2 file, written byte by byte: the v2 header, then one
    // frame whose digest verifies under that header, carrying the old
    // record above. The digests are recomputed here from the pinned
    // domains rather than taken from the writer, which no longer writes
    // this version.
    let mut header = Vec::new();
    header.extend_from_slice(b"hellas.work-journal.v1");
    header.push(2); // the retired FORMAT_VERSION
    header.push(2); // JournalKind::Channel
    header.push(2); // Role::Provider
    header.extend_from_slice(&[0x11; 32]);
    // A v2 header carried no generation: thirty-two key bytes followed
    // the role byte, and nothing else did.
    let mut header_preimage = b"hellas.work.journal-header.v1".to_vec();
    header_preimage.extend_from_slice(&header);
    let header_digest = Digest::hash(&header_preimage);

    let payload = [0x06_u8];
    let mut frame_preimage = b"hellas.work.journal-frame.v1".to_vec();
    frame_preimage.extend_from_slice(header_digest.as_bytes());
    frame_preimage.extend_from_slice(&0_u64.to_be_bytes());
    frame_preimage.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    frame_preimage.extend_from_slice(&payload);
    let frame_digest = Digest::hash(&frame_preimage);

    let mut bytes = header;
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(frame_digest.as_bytes());

    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let path = dir.path().join("v2.0000000000000000.journal");
    if let Err(error) = std::fs::write(&path, bytes) {
        panic!("the v2 fixture writes: {error}");
    }
    let id = JournalId {
        kind: JournalKind::Channel,
        role: Role::Provider,
        key: [0x11; 32],
        generation: 0,
    };
    let error =
        Journal::open(&path, id).expect_err("v2 channel records mis-replay under the v3 tags");
    assert!(
        matches!(
            error,
            hellas_rpc::work_store::JournalError::OldVersion {
                found: 2,
                expected: 5,
                ..
            }
        ),
        "unexpected error: {error}",
    );
}

/// Version 3 files are refused for a different reason, and the version
/// byte is the only thing that can refuse them.
///
/// Nothing moved between v3 and v4: the tags did not shift, they ran
/// out. The frame below carries a `CloseOpened` — a contest, which is a
/// duty — and it decodes today into exactly the record it was written
/// as, so no reader downstream of the header has any grounds to object.
/// What that file cannot express is the twelfth tag: the answer this
/// endpoint fixed for that contest. Replayed, a channel whose answer was
/// decided reads as one that decided nothing and is free to decide
/// differently, which is why the header refuses it rather than the
/// records.
#[test]
fn a_v3_channel_journal_is_refused_for_the_answer_it_cannot_hold() {
    use hellas_rpc::protocol::Digest;
    use hellas_rpc::work_store::ChannelRecord;

    // The v3 record set is today's minus the answer, and every tag it
    // does use means today what it meant then.
    let contest = ChannelRecord::CloseOpened {
        start_id: hellas_kernel::StartId::from_bytes([0x7c; 32]),
        opener: hellas_kernel::Party::Maker,
        response_deadline: 166,
        claimed: 0,
    };
    let payload = contest.encode();
    assert_eq!(
        ChannelRecord::decode(&payload),
        Ok(contest),
        "a v3 record body still decodes as itself under the v4 tags",
    );

    let mut header = Vec::new();
    header.extend_from_slice(b"hellas.work-journal.v1");
    header.push(3); // the retired FORMAT_VERSION
    header.push(2); // JournalKind::Channel
    header.push(2); // Role::Provider
    header.extend_from_slice(&[0x11; 32]);
    let mut header_preimage = b"hellas.work.journal-header.v1".to_vec();
    header_preimage.extend_from_slice(&header);
    let header_digest = Digest::hash(&header_preimage);

    let mut frame_preimage = b"hellas.work.journal-frame.v1".to_vec();
    frame_preimage.extend_from_slice(header_digest.as_bytes());
    frame_preimage.extend_from_slice(&0_u64.to_be_bytes());
    frame_preimage.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    frame_preimage.extend_from_slice(&payload);
    let frame_digest = Digest::hash(&frame_preimage);

    let mut bytes = header;
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(frame_digest.as_bytes());

    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let path = dir.path().join("v3.0000000000000000.journal");
    if let Err(error) = std::fs::write(&path, bytes) {
        panic!("the v3 fixture writes: {error}");
    }
    let id = JournalId {
        kind: JournalKind::Channel,
        role: Role::Provider,
        key: [0x11; 32],
        generation: 0,
    };
    let error = Journal::open(&path, id).expect_err("v3 cannot record an answered contest");
    let hellas_rpc::work_store::JournalError::OldVersion {
        found,
        expected,
        retirement,
    } = error
    else {
        panic!("unexpected error: {error}");
    };
    assert_eq!((found, expected), (3, 5));
    assert!(
        retirement.contains("answered contest"),
        "the reason given is v3's own, not v2's: {retirement}",
    );
}

/// One journal holding one record is these exact bytes.
#[test]
fn a_journal_of_one_record_is_these_bytes() {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let path = dir.path().join("golden.0000000000000000.journal");
    let id = JournalId {
        kind: JournalKind::Channel,
        role: Role::Provider,
        key: [0x11; 32],
        generation: 0,
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
