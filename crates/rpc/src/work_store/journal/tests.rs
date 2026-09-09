use super::{
    DUTY_RESERVE_FRAMES, Digest, Journal, JournalError, JournalId, JournalKind, MAX_ACTIVE_FRAMES,
    MAX_CHECKPOINT_BYTES, OpenOptions, Role, candidate_path, generation_path, install, retire,
    write_candidate,
};

/// The identity every fixture below is written under.
const fn id() -> JournalId {
    JournalId {
        kind: JournalKind::Setup,
        role: Role::Client,
        key: [0x5a; 32],
        generation: 0,
    }
}

/// The three records a predecessor holds before it is rotated.
const PREDECESSOR: [&[u8]; 3] = [b"one", b"two", b"three"];

/// The bytes a rotation carries forward.
const CHECKPOINT: &[u8] = b"the state the predecessor reached";

/// How far the install got before the crash.
#[derive(Clone, Copy, Debug)]
enum Stop {
    /// The candidate was being written when the process died: some
    /// prefix of it is on the disk and its `fsync` never returned.
    PartialCandidate,
    /// The candidate is whole and fsynced, and not yet renamed.
    Candidate,
    /// The rename happened and the predecessor is still there.
    Renamed,
    /// The predecessor is unlinked. The install is over.
    Retired,
}

/// Builds a directory holding exactly what a crash at `stop` leaves.
///
/// The three steps are the module's own — [`write_candidate`],
/// [`install`], [`retire`] — run in the order [`Journal::rotate`]
/// runs them and stopped after one of them. What each case asserts
/// is therefore about this implementation's order, not about four
/// shapes a test invented.
fn crashed_at(stop: Stop) -> tempfile::TempDir {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    {
        let (mut journal, _) = match Journal::open_latest(dir.path(), "duty", id()) {
            Ok(opened) => opened,
            Err(error) => panic!("the predecessor opens: {error}"),
        };
        for record in PREDECESSOR {
            if let Err(error) = journal.append(record) {
                panic!("the record appends: {error}");
            }
        }
    }
    let candidate = candidate_path(dir.path(), "duty", 1);
    let installed = generation_path(dir.path(), "duty", 1);
    let (file, _) = match write_candidate(&candidate, id().at(1), CHECKPOINT) {
        Ok(written) => written,
        Err(error) => panic!("the candidate writes: {error}"),
    };
    drop(file);
    match stop {
        Stop::PartialCandidate => {
            let Ok(whole) = std::fs::read(&candidate) else {
                panic!("the candidate reads");
            };
            if let Err(error) = std::fs::write(&candidate, &whole[..whole.len() / 2]) {
                panic!("the candidate truncates: {error}");
            }
        }
        Stop::Candidate => {}
        Stop::Renamed | Stop::Retired => {
            if let Err(error) = install(&candidate, &installed, dir.path()) {
                panic!("the candidate installs: {error}");
            }
            if matches!(stop, Stop::Retired)
                && let Err(error) = retire(&generation_path(dir.path(), "duty", 0), dir.path())
            {
                panic!("the predecessor retires: {error}");
            }
        }
    }
    dir
}

/// A crash at any point of the install leaves a journal that opens,
/// and every one of them opens to the same state.
///
/// Before the rename the state is in the predecessor's frames, and
/// after it the state is the successor's first frame — and those are
/// the same state, which is the whole of what the checkpoint is for.
/// The candidate is never the answer: it is a file whose writer was
/// never told it existed, and recovery does not look at it.
#[test]
fn an_install_recovers_at_every_step() {
    for stop in [
        Stop::PartialCandidate,
        Stop::Candidate,
        Stop::Renamed,
        Stop::Retired,
    ] {
        let dir = crashed_at(stop);
        let (journal, replay) = match Journal::open_latest(dir.path(), "duty", id()) {
            Ok(opened) => opened,
            Err(error) => panic!("{stop:?}: the journal opens: {error}"),
        };
        match stop {
            Stop::PartialCandidate | Stop::Candidate => {
                assert_eq!(
                    journal.generation(),
                    0,
                    "{stop:?}: no successor is installed"
                );
                assert_eq!(replay.checkpoint, None, "{stop:?}");
                assert_eq!(replay.records, PREDECESSOR.map(<[u8]>::to_vec), "{stop:?}");
            }
            Stop::Renamed | Stop::Retired => {
                assert_eq!(journal.generation(), 1, "{stop:?}: the successor is live");
                assert_eq!(
                    replay.checkpoint.as_deref(),
                    Some(CHECKPOINT),
                    "{stop:?}: replay starts from the state, not from a frame",
                );
                assert!(replay.records.is_empty(), "{stop:?}");
                assert!(
                    !generation_path(dir.path(), "duty", 0).exists(),
                    "{stop:?}: opening finishes the retirement the crash interrupted",
                );
            }
        }
        assert!(!replay.truncated_tail, "{stop:?}: no frame was torn");
    }
}

/// A whole rotation leaves one file, and the predecessor's bytes are
/// gone while its state is not.
#[test]
fn a_rotation_leaves_only_its_successor() {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let (mut journal, _) = match Journal::open_latest(dir.path(), "duty", id()) {
        Ok(opened) => opened,
        Err(error) => panic!("the journal opens: {error}"),
    };
    for record in PREDECESSOR {
        if let Err(error) = journal.append(record) {
            panic!("the record appends: {error}");
        }
    }
    if let Err(error) = journal.rotate(CHECKPOINT) {
        panic!("the rotation completes: {error}");
    }
    assert_eq!(journal.generation(), 1);
    if let Err(error) = journal.append(b"after") {
        panic!("the successor takes a record: {error}");
    }
    assert!(!generation_path(dir.path(), "duty", 0).exists());
    assert!(!candidate_path(dir.path(), "duty", 1).exists());
    drop(journal);

    let (reopened, replay) = match Journal::open_latest(dir.path(), "duty", id()) {
        Ok(opened) => opened,
        Err(error) => panic!("the successor reopens: {error}"),
    };
    assert_eq!(reopened.generation(), 1);
    assert_eq!(replay.checkpoint.as_deref(), Some(CHECKPOINT));
    assert_eq!(replay.records, vec![b"after".to_vec()]);
}

/// A rotation that cannot install its successor leaves the
/// predecessor whole, and still writable.
///
/// This is the order test. The successor's name is occupied by a
/// directory that cannot be renamed over, so the rename fails after
/// the candidate is written and fsynced — which is exactly the
/// window in which unlinking the predecessor first would destroy the
/// journal. A rotation that retired before it installed would leave
/// nothing here at all; this one leaves three records and takes a
/// fourth.
#[test]
fn a_rotation_that_cannot_install_leaves_its_predecessor() {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let (mut journal, _) = match Journal::open_latest(dir.path(), "duty", id()) {
        Ok(opened) => opened,
        Err(error) => panic!("the journal opens: {error}"),
    };
    for record in PREDECESSOR {
        if let Err(error) = journal.append(record) {
            panic!("the record appends: {error}");
        }
    }

    let blocked = generation_path(dir.path(), "duty", 1);
    if let Err(error) = std::fs::create_dir(&blocked) {
        panic!("the obstruction is created: {error}");
    }
    if let Err(error) = std::fs::write(blocked.join("occupied"), b"in the way") {
        panic!("the obstruction is non-empty: {error}");
    }

    match journal.rotate(CHECKPOINT) {
        Err(JournalError::Io(_)) => {}
        other => panic!("a name that cannot be renamed over: {other:?}"),
    }
    assert_eq!(
        journal.generation(),
        0,
        "this handle is still the predecessor's"
    );
    if let Err(error) = journal.append(b"four") {
        panic!("and the predecessor still takes records: {error}");
    }
    drop(journal);

    // The obstruction is the fixture's, not the journal's, so it
    // goes before the reopen that asks what survived.
    if let Err(error) = std::fs::remove_dir_all(&blocked) {
        panic!("the obstruction is removable: {error}");
    }
    let (reopened, replay) = match Journal::open_latest(dir.path(), "duty", id()) {
        Ok(opened) => opened,
        Err(error) => panic!("the predecessor reopens: {error}"),
    };
    assert_eq!(reopened.generation(), 0);
    assert_eq!(replay.checkpoint, None);
    assert_eq!(replay.records.len(), 4, "nothing was retired");
}

/// The reserve above the soft limit is for a duty, and the hard cap
/// is where even that ends.
///
/// The rotation is made to fail for the one reason a state can cause
/// — a checkpoint wider than one frame — so what is exercised is the
/// case the spec names: rotation cannot complete, and the frames
/// held back are still there for whatever was already under way.
#[test]
fn the_reserve_outlives_a_rotation_that_cannot_complete() {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let (mut journal, _) = match Journal::open_latest(dir.path(), "duty", id()) {
        Ok(opened) => opened,
        Err(error) => panic!("the journal opens: {error}"),
    };
    for _ in 0..MAX_ACTIVE_FRAMES - DUTY_RESERVE_FRAMES {
        if let Err(error) = journal.append(b"x") {
            panic!("the record appends: {error}");
        }
    }
    assert!(journal.at_soft_limit(), "the soft limit is reached");

    let oversized = vec![0_u8; MAX_CHECKPOINT_BYTES + 1];
    match journal.rotate(&oversized) {
        Err(JournalError::CheckpointTooLarge { .. }) => {}
        other => panic!("a state wider than a frame cannot rotate: {other:?}"),
    }
    assert_eq!(journal.generation(), 0, "nothing was installed");

    for _ in 0..DUTY_RESERVE_FRAMES {
        if let Err(error) = journal.append(b"x") {
            panic!("the reserve is still writable: {error}");
        }
    }
    match journal.append(b"x") {
        Err(JournalError::Full { frames, .. }) => assert_eq!(frames, MAX_ACTIVE_FRAMES),
        other => panic!("the hard cap is the end of it: {other:?}"),
    }

    // And a rotation that *can* complete is what moves it on, which
    // is why the refusal above is not the end of the journal.
    if let Err(error) = journal.rotate(CHECKPOINT) {
        panic!("the rotation completes: {error}");
    }
    if let Err(error) = journal.append(b"x") {
        panic!("the successor takes a record: {error}");
    }
}

/// A successor's tail tears like any other tail, and a complete
/// frame that does not verify refuses the file wherever it is.
#[test]
fn a_successor_tears_and_refuses_like_its_predecessor() {
    for (label, damage) in [("torn", 0_usize), ("corrupt", 1)] {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("a temporary directory");
        };
        {
            let (mut journal, _) = match Journal::open_latest(dir.path(), "duty", id()) {
                Ok(opened) => opened,
                Err(error) => panic!("{label}: the journal opens: {error}"),
            };
            if let Err(error) = journal.rotate(CHECKPOINT) {
                panic!("{label}: the rotation completes: {error}");
            }
            if let Err(error) = journal.append(b"after the checkpoint") {
                panic!("{label}: the record appends: {error}");
            }
        }
        let path = generation_path(dir.path(), "duty", 1);
        let Ok(mut bytes) = std::fs::read(&path) else {
            panic!("{label}: the successor reads");
        };
        if damage == 0 {
            bytes.truncate(bytes.len() - 4);
        } else {
            let last = bytes.len() - 1;
            bytes[last] ^= 0xff;
        }
        if let Err(error) = std::fs::write(&path, bytes) {
            panic!("{label}: the damage writes: {error}");
        }
        let opened = Journal::open_latest(dir.path(), "duty", id());
        if damage == 0 {
            let Ok((journal, replay)) = opened else {
                panic!("{label}: a torn tail is not a refusal");
            };
            assert_eq!(journal.generation(), 1);
            assert_eq!(replay.checkpoint.as_deref(), Some(CHECKPOINT));
            assert!(replay.records.is_empty(), "{label}: the tear is gone");
            assert!(replay.truncated_tail, "{label}: and it is reported");
        } else {
            match opened {
                Err(JournalError::Corrupt { seq }) => assert_eq!(seq, 1),
                other => panic!("{label}: a complete frame must verify: {other:?}"),
            }
        }
    }
}

/// An append that fails takes the journal with it.
///
/// The failure is real rather than simulated: the handle is a
/// read-only descriptor, so `write_all` returns the operating
/// system's own refusal. What the second call proves is that the
/// refusal is remembered — a writer that answered an i/o error by
/// offering the next record would be writing a frame at a sequence
/// it cannot know is free, over bytes it cannot know are there.
#[test]
fn a_failed_append_poisons_the_journal() {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let path = dir.path().join("unwritable.0000000000000000.journal");
    if let Err(error) = std::fs::write(&path, b"") {
        panic!("the file is created: {error}");
    }
    let file = match OpenOptions::new().read(true).open(&path) {
        Ok(file) => file,
        Err(error) => panic!("the file opens for reading: {error}"),
    };
    let mut journal = Journal {
        file,
        path,
        directory: dir.path().to_path_buf(),
        stem: "unwritable".to_owned(),
        id: JournalId {
            kind: JournalKind::Channel,
            role: Role::Provider,
            key: [0_u8; 32],
            generation: 0,
        },
        header: Digest::from_bytes([0_u8; 32]),
        next_seq: 0,
        bytes: 0,
        poisoned: false,
    };
    match journal.append(b"one record") {
        Err(JournalError::Io(_)) => {}
        other => panic!("a read-only handle cannot be appended to: {other:?}"),
    }
    match journal.append(b"another record") {
        Err(JournalError::Poisoned) => {}
        other => panic!("the second append is refused without a write: {other:?}"),
    }
}

/// A record refused for its size leaves the journal usable.
///
/// Nothing was written, so nothing about the file is unknown, and
/// poisoning it would turn one caller's oversized record into a
/// channel that cannot be written again.
#[test]
fn an_oversized_record_does_not_poison_the_journal() {
    use super::MAX_RECORD_BYTES;

    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let (mut journal, _) = match Journal::open_latest(
        dir.path(),
        "sized",
        JournalId {
            kind: JournalKind::Channel,
            role: Role::Provider,
            key: [0x22; 32],
            generation: 0,
        },
    ) {
        Ok(opened) => opened,
        Err(error) => panic!("the journal opens: {error}"),
    };
    match journal.append(&vec![0_u8; MAX_RECORD_BYTES + 1]) {
        Err(JournalError::RecordTooLarge { .. }) => {}
        other => panic!("an oversized record is refused: {other:?}"),
    }
    if let Err(error) = journal.append(b"one record") {
        panic!("the journal still takes a record: {error}");
    }
    assert_eq!(journal.len(), 1);
}
