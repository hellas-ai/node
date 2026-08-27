//! The one durable thing under a paid endpoint: an append-only file
//! that is fsynced before the bytes it records are released.
//!
//! # What a journal is for
//!
//! Every rule in this module family is a rule about *order*. A
//! signature exported before the state that authorises it is durable is
//! a signature the endpoint cannot account for after a crash: the peer
//! holds it, and the endpoint has never heard of it. So the only thing
//! this file offers is "these bytes are on the disk, and they were
//! there before you were told so" — [`Journal::append`] returns after
//! `fsync`, and callers release nothing before it returns.
//!
//! # Crash story
//!
//! Before an append: `n` frames on disk. After it: `n + 1`. Interrupt
//! it and the caller was never told it succeeded, so recovery's job is
//! to get back to `n`.
//!
//! What the interruption leaves depends on what died. A dead *process*
//! leaves a short prefix of the frame: the kernel either took the whole
//! `write_all` or took a prefix of it. A dead *machine* is not so
//! orderly. The frame is not on the disk until `sync_all` returns, and
//! until then it is pages in a cache that reach the platter in whatever
//! order they like — while the file's length may already have grown.
//!
//! So the rule is about *extent*, and only about extent. A frame whose
//! bytes are not all in the file is an append the file ends inside:
//! nothing was written after it, its writer was never given an `Ok`,
//! and recovery truncates it. A frame whose bytes are all there and
//! whose digest does not verify is a different thing — it is
//! indistinguishable from a record this endpoint was told it had
//! written and may already have acted on. Recovery refuses the file
//! rather than reconstructing a state behind one: it is
//! [`JournalError::Corrupt`], deliberately terminal, wherever in the
//! file it is.
//!
//! That is the fail-closed half of the trade, and it is chosen over the
//! other one. Truncating a complete-length frame silently drops a
//! record whose signature may already be in a peer's hands, and the
//! endpoint would then contradict what it has promised — which is the
//! one failure this whole module family exists to stop. A channel that
//! will not open is loud and an operator can act on it; an endpoint
//! quietly behind its own signature is neither.
//!
//! # A failed append is terminal for the writer
//!
//! [`Journal::append`] either returns after `fsync` or poisons the
//! journal. A write or a sync that fails leaves the file in a state
//! this process cannot describe: a prefix may be on the platter, the
//! length may have grown, and the sequence this frame would occupy may
//! or may not be free. So no further append is admitted through that
//! handle — [`JournalError::Poisoned`] — and the only way on is to
//! reopen, which is the one path that reads the file and finds out what
//! is actually there.
//!
//! # What it is not
//!
//! It is not a defence against an adversary with write access to the
//! file. The frame digests bind position and header, so a frame cannot
//! be moved, duplicated, reordered, or lifted from another channel's
//! journal — but anyone who can write the file can also write a whole
//! consistent journal, and this module makes no claim otherwise. Its
//! threat is a crash, not a forger.
//!
//! It is not a filesystem. Recovery finds the frames by following the
//! length fields, so a length that is not a length says the file ends
//! inside that frame, and nothing after it can be found to say
//! otherwise. Such a frame is truncated as the tear it almost always
//! is — and if it were instead damage in the middle of the file, the
//! records after it go with it. That is the one place this module can
//! lose a write it acknowledged, and it is named rather than papered
//! over.
//!
//! It is not a database. There is one writer, holding an exclusive
//! `flock` taken before anything is replayed, and a second process
//! fails to open rather than waiting for the first.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use hellas_xet::XetFileHasher;

use crate::protocol::Digest;

/// First bytes of every journal file.
const MAGIC: &[u8] = b"hellas.work-journal.v1";
/// Envelope version of the header and framing below.
///
/// Version 1 journals are intentionally refused. They predate `ScanArmed`
/// and `ArmedBundle`, so replay cannot prove that every authorization which
/// escaped still has a recoverable observation floor and close descriptor.
/// This is a pre-deployment reset, not a migratable format change.
const FORMAT_VERSION: u8 = 2;
/// Domain of the header digest every frame is bound to.
const HEADER_DOMAIN: &[u8] = b"hellas.work.journal-header.v1";
/// Domain of one frame's digest.
const FRAME_DOMAIN: &[u8] = b"hellas.work.journal-frame.v1";

/// Bytes the fixed header occupies.
const HEADER_SIZE: usize = MAGIC.len() + 3 + 32;

/// Bytes a frame spends on its length prefix and trailing digest.
const FRAME_OVERHEAD: usize = 4 + Digest::LEN;

/// Largest record this journal will write or read back.
///
/// The widest record is one job proposal: an authorization, a
/// signature, and the whole prepared-input bundle the provider must
/// still be able to execute after a restart. The demonstration profile
/// bounds that bundle at a megabyte through
/// `max_encoded_quote_response`, and that bound is checked where the
/// profile is known. This is the coarser bound of the two: the length
/// past which a length field is more likely to be corruption than a
/// record.
pub const MAX_RECORD_BYTES: usize = 4 << 20;

/// Which of the three journals a file is.
///
/// In the header, so a channel journal handed to the setup reader — or
/// to the counterparty ledger — fails to open rather than replaying as
/// an empty state of the wrong kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalKind {
    /// The two-Open handshake and its recovery state.
    Setup,
    /// One channel's jobs, credit, and certificates.
    Channel,
    /// One counterparty's unresolved compute and delivery loss.
    CounterpartyLoss,
}

impl JournalKind {
    const fn code(self) -> u8 {
        match self {
            Self::Setup => 1,
            Self::Channel => 2,
            Self::CounterpartyLoss => 3,
        }
    }
}

/// Which side of the channel this endpoint is.
///
/// The two endpoints share these transition rules and share nothing
/// else. It is in the header because the rules differ by role — only a
/// provider submits the opens, only a client consumes proposal nonces —
/// and a store replayed under the wrong role would apply the wrong ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The party that funds the payment edge and signs certificates.
    Client,
    /// The party that stakes the bond, executes, and is paid.
    Provider,
}

impl Role {
    const fn code(self) -> u8 {
        match self {
            Self::Client => 1,
            Self::Provider => 2,
        }
    }
}

/// What a journal file is about: its kind, its role, and the 32-byte key
/// of the thing it records.
///
/// The key is a commitment supplied by the caller — a channel id, or a
/// hash over the network and an edge or a counterparty key. Every frame
/// digest binds it, so a journal cannot be opened as, or grafted onto,
/// another one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalId {
    /// Which journal this is.
    pub kind: JournalKind,
    /// Which side of the channel wrote it.
    pub role: Role,
    /// What it is about.
    pub key: [u8; 32],
}

impl JournalId {
    fn header_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(self.kind.code());
        out.push(self.role.code());
        out.extend_from_slice(&self.key);
        debug_assert_eq!(out.len(), HEADER_SIZE);
        out
    }

    fn digest(&self) -> Digest {
        let mut hasher = XetFileHasher::new();
        hasher.update(HEADER_DOMAIN);
        hasher.update(&self.header_bytes());
        hasher.finalize()
    }
}

/// Why a journal is not usable.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The file could not be created, read, written, or synced.
    #[error("journal i/o failed: {0}")]
    Io(#[from] std::io::Error),
    /// Another process holds this journal.
    #[error("another process holds the journal at {path}")]
    Locked {
        /// File that is already locked.
        path: PathBuf,
    },
    /// The file is a recognized journal envelope whose recovery contract has
    /// been retired.
    #[error("journal format {found} is retired; expected {expected}: {retirement}")]
    OldVersion {
        /// Version byte found after the journal magic.
        found: u8,
        /// Version this binary writes and reads.
        expected: u8,
        /// Operator-facing reason this version cannot be migrated safely.
        retirement: &'static str,
    },
    /// The file exists and is not a journal of this kind, role, and key.
    #[error("the file at {path} is not this endpoint's {kind:?} journal")]
    HeaderMismatch {
        /// File that was opened.
        path: PathBuf,
        /// Kind that was expected.
        kind: JournalKind,
    },
    /// A complete frame did not verify. The file is not the file this
    /// endpoint wrote, and no earlier state is reconstructed from it.
    #[error("journal frame {seq} does not verify; the journal is corrupt")]
    Corrupt {
        /// Position of the first frame that failed.
        seq: u64,
    },
    /// A record was larger than [`MAX_RECORD_BYTES`].
    #[error("journal record of {len} bytes exceeds the {MAX_RECORD_BYTES}-byte maximum")]
    RecordTooLarge {
        /// Length the record claimed.
        len: usize,
    },
    /// An earlier append failed, so what this file holds is unknown to
    /// this handle. Reopening is the only way to find out.
    #[error("an earlier append failed; this journal must be reopened before it is written again")]
    Poisoned,
}

/// What opening a journal found.
#[derive(Debug)]
pub struct Replay {
    /// Every complete frame, in the order it was appended.
    pub records: Vec<Vec<u8>>,
    /// Whether an interrupted write was removed to get here.
    ///
    /// True means the file ended inside an append — or inside the
    /// header — whose caller was never told it succeeded, and those
    /// bytes are gone. A clean shutdown does not produce it, which is
    /// why the stores carry it out to their callers rather than
    /// swallowing it.
    pub truncated_tail: bool,
}

/// One append-only fsynced file, exclusively held.
#[derive(Debug)]
pub struct Journal {
    file: File,
    path: PathBuf,
    header: Digest,
    next_seq: u64,
    poisoned: bool,
}

impl Journal {
    /// Opens or creates the journal at `path`, taking its exclusive
    /// lock and replaying it.
    ///
    /// The lock is taken before a single byte is interpreted, so two
    /// processes cannot both replay and then both act. It is
    /// non-blocking: a second opener is told the journal is held rather
    /// than waiting for a holder that may never let go.
    ///
    /// # Errors
    ///
    /// [`JournalError::Locked`] when another process holds it,
    /// [`JournalError::HeaderMismatch`] when the file is some other
    /// journal, [`JournalError::Corrupt`] when a complete frame does
    /// not verify, and [`JournalError::Io`] for the filesystem.
    pub fn open(path: impl Into<PathBuf>, id: JournalId) -> Result<(Self, Replay), JournalError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(JournalError::Locked { path }),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }

        let mut bytes = Vec::new();
        (&file).read_to_end(&mut bytes)?;
        let header = id.digest();
        let mut journal = Self {
            file,
            path,
            header,
            next_seq: 0,
            poisoned: false,
        };

        if bytes.is_empty() {
            journal.write_header(&id)?;
            return Ok((
                journal,
                Replay {
                    records: Vec::new(),
                    truncated_tail: false,
                },
            ));
        }

        let expected = id.header_bytes();
        if !bytes.starts_with(&expected) {
            if bytes.starts_with(MAGIC)
                && bytes
                    .get(MAGIC.len())
                    .is_some_and(|found| *found < FORMAT_VERSION)
            {
                return Err(JournalError::OldVersion {
                    found: bytes[MAGIC.len()],
                    expected: FORMAT_VERSION,
                    retirement: "pre-arming journals have no recoverable scan floor or close descriptor",
                });
            }
            // A file that is a strict prefix of the header this journal
            // would write is the creation that was interrupted. No frame
            // can have been recorded under it — there is not even a
            // whole header yet — so it is written again rather than
            // refused as somebody else's file.
            if expected.starts_with(&bytes) {
                journal.file.set_len(0)?;
                journal.write_header(&id)?;
                return Ok((
                    journal,
                    Replay {
                        records: Vec::new(),
                        truncated_tail: true,
                    },
                ));
            }
            return Err(JournalError::HeaderMismatch {
                path: journal.path,
                kind: id.kind,
            });
        }

        let replay = journal.replay(&bytes)?;
        Ok((journal, replay))
    }

    fn write_header(&mut self, id: &JournalId) -> Result<(), JournalError> {
        self.file.write_all(&id.header_bytes())?;
        self.file.sync_all()?;
        // The file's own bytes are durable above; this is what makes the
        // directory entry durable, so a crash cannot leave a channel
        // with a signature exported and no file to find it in.
        if let Some(parent) = self.path.parent() {
            sync_directory(parent)?;
        }
        Ok(())
    }

    /// Walks every frame, truncating one partial tail and refusing any
    /// complete frame that does not verify.
    fn replay(&mut self, bytes: &[u8]) -> Result<Replay, JournalError> {
        let mut offset = HEADER_SIZE;
        let mut records = Vec::new();
        let mut truncated_tail = false;
        while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
            let Some(prefix) = rest.get(..4) else {
                truncated_tail = true;
                break;
            };
            let mut len_bytes = [0_u8; 4];
            len_bytes.copy_from_slice(prefix);
            let len = u32::from_be_bytes(len_bytes) as usize;
            // The extent first, and the length's plausibility second: a
            // frame that runs past the end of the file is an append the
            // file ends inside, whether its length field is a hundred
            // bytes too many or four gigabytes too many. Only a length
            // that fits inside the file could be a complete frame, and
            // only there is an oversized one evidence of corruption
            // rather than of a tear.
            let Some(frame) = FRAME_OVERHEAD
                .checked_add(len)
                .and_then(|end| rest.get(..end))
            else {
                truncated_tail = true;
                break;
            };
            if len > MAX_RECORD_BYTES {
                return Err(JournalError::RecordTooLarge { len });
            }
            let (Some(payload), Some(stored)) = (frame.get(4..4 + len), frame.get(4 + len..))
            else {
                truncated_tail = true;
                break;
            };
            if stored != frame_digest(self.header, self.next_seq, payload).as_bytes() {
                // Every byte this frame claims is in the file, so it was
                // long enough to be a complete append — and a complete
                // append is one whose caller may have been given an
                // `Ok`. Nothing here can tell that from a machine that
                // died mid-flush, so the file is refused rather than
                // read back one record short of what a peer may hold.
                return Err(JournalError::Corrupt { seq: self.next_seq });
            }
            records.push(payload.to_vec());
            self.next_seq = self.next_seq.saturating_add(1);
            offset += FRAME_OVERHEAD + len;
        }

        if truncated_tail {
            // The interrupted bytes are removed rather than left in
            // place: the next append must land where the next frame's
            // digest says it does, and a reader that skipped a partial
            // frame once would have to skip it identically forever.
            self.file.set_len(offset as u64)?;
            self.file.sync_all()?;
        }
        Ok(Replay {
            records,
            truncated_tail,
        })
    }

    /// Appends one record and returns only once it is on the disk.
    ///
    /// A write or a sync that fails poisons this handle: what the file
    /// holds afterwards is not something this process can describe, and
    /// a second append would be a guess about where the next frame
    /// starts and which sequence is free. Every later call is refused
    /// until the journal is reopened and the file is read again.
    ///
    /// A record refused for its *size* is not one of those. Nothing was
    /// written, so nothing is unknown, and the journal stays usable.
    ///
    /// # Errors
    ///
    /// [`JournalError::RecordTooLarge`] above [`MAX_RECORD_BYTES`],
    /// [`JournalError::Poisoned`] after any earlier append failed, and
    /// [`JournalError::Io`] when this write or its sync fails.
    pub fn append(&mut self, payload: &[u8]) -> Result<(), JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        if payload.len() > MAX_RECORD_BYTES {
            return Err(JournalError::RecordTooLarge { len: payload.len() });
        }
        let Ok(len) = u32::try_from(payload.len()) else {
            return Err(JournalError::RecordTooLarge { len: payload.len() });
        };
        let digest = frame_digest(self.header, self.next_seq, payload);
        let mut frame = Vec::with_capacity(FRAME_OVERHEAD + payload.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(digest.as_bytes());
        // One `write_all` of the whole frame: the most an interrupted
        // *process* can leave behind is a short prefix of it, rather
        // than a length and a payload from two different calls.
        //
        // Poisoned before the failure is reported, so a caller cannot
        // answer an i/o error by offering the next record.
        self.write_frame(&frame).inspect_err(|_| {
            self.poisoned = true;
        })?;
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(())
    }

    fn write_frame(&mut self, frame: &[u8]) -> Result<(), JournalError> {
        self.file.write_all(frame)?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Returns how many records this journal holds.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.next_seq
    }

    /// Returns whether this journal holds no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.next_seq == 0
    }
}

/// Returns the digest that binds one frame to its journal and position.
///
/// The header digest is in the preimage, so a frame lifted from another
/// channel's file does not verify here; the sequence is in it, so a
/// frame replayed at another position does not either; and the length
/// is, so a frame cannot be reinterpreted as a shorter one followed by
/// something else.
fn frame_digest(header: Digest, seq: u64, payload: &[u8]) -> Digest {
    let mut hasher = XetFileHasher::new();
    hasher.update(FRAME_DOMAIN);
    hasher.update(header.as_bytes());
    hasher.update(&seq.to_be_bytes());
    hasher.update(&(payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize()
}

/// Fsyncs a directory, so a file created in it survives a crash.
///
/// Not every platform can open a directory as a file. Where it cannot,
/// the file's own `fsync` is what survives, and the directory entry is
/// the platform's business; the failure is not reported as this
/// endpoint's, because there is nothing it could do differently.
fn sync_directory(path: &Path) -> Result<(), JournalError> {
    match File::open(path) {
        Ok(directory) => match directory.sync_all() {
            Ok(()) => Ok(()),
            Err(_) if cfg!(not(unix)) => Ok(()),
            Err(error) => Err(error.into()),
        },
        Err(_) if cfg!(not(unix)) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{Digest, Journal, JournalError, OpenOptions};

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
        let path = dir.path().join("unwritable.journal");
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
            header: Digest::from_bytes([0_u8; 32]),
            next_seq: 0,
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
        use super::{JournalId, JournalKind, MAX_RECORD_BYTES, Role};

        let Ok(dir) = tempfile::tempdir() else {
            panic!("a temporary directory");
        };
        let (mut journal, _) = match Journal::open(
            dir.path().join("sized.journal"),
            JournalId {
                kind: JournalKind::Channel,
                role: Role::Provider,
                key: [0x22; 32],
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
}
