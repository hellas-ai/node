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
//! A record here runs to [`MAX_RECORD_BYTES`], hundreds of pages, so
//! the last frame can come back full-length with a hole in it, or with
//! a length field that is not a length at all.
//!
//! So the rule is about *position*, not about shape: a frame that does
//! not verify and has nothing after it is the interrupted append, in
//! whichever of those shapes, and recovery truncates it. A frame that
//! does not verify with bytes after it is not an interrupted append —
//! those bytes were written later, so this one was complete once. That
//! is a file that is not the file this endpoint wrote, and recovery
//! refuses it rather than reconstructing an earlier state the endpoint
//! may already have acted past: [`JournalError::Corrupt`], deliberately
//! terminal.
//!
//! The cost of that rule is named: media rot in the *last* frame is
//! silently truncated rather than refused. It is the trade this file
//! chooses, because the alternative wedges a channel permanently on the
//! failure it is most likely to meet, and because the record it drops
//! is one whose writer was never given an `Ok`.
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
const FORMAT_VERSION: u8 = 1;
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
                // Nothing after it: the interrupted append, arrived out
                // of order or short, and never acknowledged. Bytes after
                // it: this frame was whole when they were written, so
                // what changed it was not a crash.
                if frame.len() == rest.len() {
                    truncated_tail = true;
                    break;
                }
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
    /// # Errors
    ///
    /// [`JournalError::RecordTooLarge`] above [`MAX_RECORD_BYTES`], and
    /// [`JournalError::Io`] when the write or the sync fails.
    pub fn append(&mut self, payload: &[u8]) -> Result<(), JournalError> {
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
        // than a length and a payload from two different calls. It says
        // nothing about an interrupted machine, whose pages land in
        // their own order; that case is recovery's, above.
        self.file.write_all(&frame)?;
        self.file.sync_all()?;
        self.next_seq = self.next_seq.saturating_add(1);
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
