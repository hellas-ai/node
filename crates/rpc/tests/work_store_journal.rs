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

use hellas_rpc::observe::Samples;
use hellas_rpc::work_store::Role;
use hellas_rpc::work_store::journal::{Journal, JournalId, JournalKind};

/// Bytes before the first frame: magic, version, kind, role,
/// generation, key.
const HEADER_BYTES: usize = 65;

/// `hellas.work-journal.v1`, then `06` version, `02` channel, `02`
/// provider, the eight-byte generation, then the 32-byte key.
const GOLDEN_HEADER: &str = concat!(
    "68656c6c61732e776f726b2d6a6f75726e616c2e7631",
    "06",
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
    "c954ab65afded981062cd1f8f0cbee864c20ae9c01104104ee7a9081c743b5bd",
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
                expected: 6,
                ..
            }
        ),
        "unexpected error: {error}",
    );
}

/// Version 5 journals encode one implicit job and therefore cannot be
/// replayed as the version 6 format, where every follow-on record names
/// its job.
#[test]
fn a_v5_single_job_journal_is_refused() {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let path = dir.path().join("v5.0000000000000000.journal");
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
    bytes[b"hellas.work-journal.v1".len()] = 5;
    if let Err(error) = std::fs::write(&path, bytes) {
        panic!("the old header writes: {error}");
    }
    let error = Journal::open(&path, id).expect_err("v5 has no per-record work IDs");
    let hellas_rpc::work_store::JournalError::OldVersion {
        found,
        expected,
        retirement,
    } = error
    else {
        panic!("unexpected error: {error}");
    };
    assert_eq!((found, expected), (5, 6));
    assert!(
        retirement.contains("single-job"),
        "the reason given is v5's own: {retirement}",
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
        ChannelRecord::decode(&[0x06]).is_err(),
        "a v4 job marker requires its work id",
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
                expected: 6,
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
    assert_eq!((found, expected), (3, 6));
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

// ── The measurement seams §4's budgets are made of ────────────────────

/// The records a measured fixture writes, and the state a rotation
/// carries forward.
const MEASURED: [&[u8]; 3] = [b"one", b"two", b"three"];
const MEASURED_CHECKPOINT: &[u8] = b"the state the predecessor reached";

/// Writes `MEASURED` into a fresh journal under `dir` and rotates it.
///
/// The one sequence both measurement tests below run, so "the same work
/// with an observer and without one" is the same call and not two
/// hand-copied ones.
fn measured_run(dir: &std::path::Path) {
    let (mut journal, _) = match Journal::open_latest(dir, "duty", measured_id()) {
        Ok(opened) => opened,
        Err(error) => panic!("the journal opens: {error}"),
    };
    for record in MEASURED {
        if let Err(error) = journal.append(record) {
            panic!("the record appends: {error}");
        }
    }
    if let Err(error) = journal.rotate(MEASURED_CHECKPOINT) {
        panic!("the rotation completes: {error}");
    }
    if let Err(error) = journal.append(b"after") {
        panic!("the successor takes a record: {error}");
    }
}

const fn measured_id() -> JournalId {
    JournalId {
        kind: JournalKind::Setup,
        role: Role::Provider,
        key: [0x5a; 32],
        generation: 0,
    }
}

/// Every append is one `fsync_tail_ms`, every rotation is one
/// `rotation_tail_ms`, and neither is ever a summary of the other.
///
/// §4 divides a lower tail by a block time, and a lower tail cannot be
/// recovered from a mean — so what this pins is not that a number was
/// emitted but that *each piece of work* emitted its own, distinguishable
/// from the others by the sequence it occupied. Four appends and one
/// rotation are four samples and one, never one of each carrying a count.
#[test]
fn each_append_and_each_rotation_is_its_own_sample() {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let samples = std::sync::Arc::new(Samples::new());
    tracing::subscriber::with_default(samples.clone(), || measured_run(dir.path()));

    let fsyncs = samples.of("fsync_tail_ms");
    assert_eq!(
        fsyncs.len(),
        4,
        "three predecessor appends and one successor append",
    );
    let seqs: Vec<Option<&str>> = fsyncs.iter().map(|sample| sample.field("seq")).collect();
    assert_eq!(
        seqs,
        vec![Some("0"), Some("1"), Some("2"), Some("1")],
        "each sample says which append it was, so none of them is a total",
    );
    assert_eq!(fsyncs[0].field("kind"), Some("Setup"));
    assert_eq!(fsyncs[0].field("role"), Some("Provider"));
    assert_eq!(fsyncs[0].field("key"), Some("5a".repeat(32).as_str()));
    assert_eq!(fsyncs[0].field("generation"), Some("0"));
    assert_eq!(
        fsyncs[3].field("generation"),
        Some("1"),
        "an append after a rotation is the successor's",
    );

    let rotations = samples.of("rotation_tail_ms");
    assert_eq!(rotations.len(), 1, "one rotation, one sample");
    assert_eq!(rotations[0].field("generation"), Some("1"));
    assert_eq!(
        rotations[0].field("frames"),
        Some("3"),
        "the predecessor's frames, which is what the successor no longer holds",
    );
    assert_eq!(
        rotations[0].field("checkpoint_bytes"),
        Some(MEASURED_CHECKPOINT.len().to_string().as_str()),
    );
    assert!(
        fsyncs
            .iter()
            .chain(&rotations)
            .all(|sample| sample.ms >= 0.0),
        "every sample carries the duration it is a sample of",
    );
}

/// Nothing that did not happen is sampled.
///
/// A journal that is opened and never written emits no `fsync_tail_ms`
/// — the header's own sync is not an append — and a rotation refused
/// before it writes anything emits no `rotation_tail_ms`, because no
/// generation moved.
#[test]
fn work_that_was_not_done_is_not_sampled() {
    use hellas_rpc::work_store::journal::MAX_CHECKPOINT_BYTES;

    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let samples = std::sync::Arc::new(Samples::new());
    tracing::subscriber::with_default(samples.clone(), || {
        let (mut journal, _) = match Journal::open_latest(dir.path(), "idle", measured_id()) {
            Ok(opened) => opened,
            Err(error) => panic!("the journal opens: {error}"),
        };
        assert!(
            samples.all().is_empty(),
            "opening an empty journal is not an append and not a rotation",
        );
        if journal
            .rotate(&vec![0_u8; MAX_CHECKPOINT_BYTES + 1])
            .is_ok()
        {
            panic!("a state wider than a frame cannot rotate");
        }
    });
    assert!(
        samples.of("fsync_tail_ms").is_empty(),
        "no record was appended",
    );
    assert!(
        samples.of("rotation_tail_ms").is_empty(),
        "a rotation that wrote nothing is not a rotation that happened",
    );
}

/// A journal nobody is measuring writes exactly the file a measured one
/// writes.
///
/// This is the hottest path in the tree, and the one place where an
/// observation that had become a decision would be invisible: the seam
/// sits around `sync_all` and around the three-step install, so a branch
/// taken on whether anyone is listening would change an order, a byte,
/// or a generation. Two runs of the identical sequence — one under a
/// collector, one under nothing at all — are compared as bytes.
#[test]
fn an_unobserved_journal_writes_the_same_file_as_an_observed_one() {
    let Ok(watched) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let Ok(unwatched) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };

    let samples = std::sync::Arc::new(Samples::new());
    tracing::subscriber::with_default(samples.clone(), || measured_run(watched.path()));
    measured_run(unwatched.path());

    assert!(
        !samples.all().is_empty(),
        "the observed run is observed, or this proves nothing",
    );

    let listing = |dir: &std::path::Path| {
        let Ok(entries) = std::fs::read_dir(dir) else {
            panic!("the journal directory reads");
        };
        let mut names: Vec<String> = entries
            .map(|entry| match entry {
                Ok(entry) => entry.file_name().to_string_lossy().into_owned(),
                Err(error) => panic!("the directory entry reads: {error}"),
            })
            .collect();
        names.sort();
        names
    };
    let names = listing(watched.path());
    assert_eq!(
        names,
        listing(unwatched.path()),
        "the same generation is live and the same predecessor is gone",
    );
    for name in names {
        let Ok(observed) = std::fs::read(watched.path().join(&name)) else {
            panic!("the observed journal reads");
        };
        let Ok(plain) = std::fs::read(unwatched.path().join(&name)) else {
            panic!("the unobserved journal reads");
        };
        assert_eq!(
            hex(&observed),
            hex(&plain),
            "{name} is byte-identical whether or not it was measured",
        );
    }
}
