//! Durable endpoint state: what an endpoint may still do after it has
//! crashed, and what it may not.
//!
//! # The one rule
//!
//! **The state that authorises a signature is on the disk before the
//! signature leaves the process.** Everything here is an instance of
//! that. A setup revision is fsynced before its signature is exported.
//! A nonce is fsynced before the authorization carrying it is built. A
//! result is fsynced before the plaintext goes out. An allocation is
//! fsynced before the certificate that pays for it is sent — and the
//! provider's copy is fsynced before it acknowledges payment or lets
//! any credit go.
//!
//! Reversing any one of those pairs is the same defect: the peer holds
//! a signature the endpoint has no record of, and after the crash the
//! endpoint's own state contradicts what it has already promised.
//!
//! What these types enforce is the half of that rule they can see. A
//! commit returns only after `fsync`; a record the rules refuse writes
//! nothing at all; and the records themselves are ordered, so a result
//! cannot be journaled before the marker that says the backend was
//! called, nor a certificate before the invoice it pays. What they
//! cannot see is a caller that sends first and commits afterwards.
//! Nothing in a store can catch that, and no doc sentence here should
//! be read as claiming it does.
//!
//! # Three files, one primitive
//!
//! - [`setup::SetupStore`] — the two-Open handshake, its retained
//!   revisions, and the recovery decision that resumes it. Keyed by
//!   `(network, bond edge)`, because the bond edge is the first thing
//!   both parties can name.
//! - [`channel::ChannelStore`] — one channel's nonces, its one job, its
//!   credit ledgers, and its certificates. Keyed by the channel id,
//!   which binds the network, both edges, and both terms bodies.
//! - [`channel::CounterpartyLoss`] — what one client owes across every
//!   channel it has had. Keyed by `(network, client key)`, so a fresh
//!   payment edge inherits it and a deleted channel does not clear it.
//!
//! All three are the same append-only fsynced [`journal::Journal`],
//! with one exclusive lock each and one replay each.
//!
//! # Why here
//!
//! The provider and the client share every transition rule and share no
//! database. Writing the rules twice — once under `crates/executor` and
//! once under `crates/client`, as an earlier plan had it — is two
//! implementations of "has this job been paid for", which is the defect
//! this phase exists to prevent. They live beside the records they are
//! about, in the neutral protocol crate both endpoints already depend
//! on, and the two databases are two *files*.
//!
//! # What none of it claims
//!
//! Not rollback resistance. An exclusive lock stops two processes on
//! one live path; it does nothing about a storage snapshot restored
//! behind a signer's back. This milestone has no externally retained
//! monotone store generation, so a restored older journal is an
//! accepted operational residual and is named as one here rather than
//! being quietly counted as covered.
//!
//! Not that a backend was invoked exactly once. A running marker says
//! an invocation may have happened; after a crash between the marker
//! and the result, recovery reports indeterminate and refuses to
//! resolve it, because nothing local can tell the two cases apart.

pub mod channel;
pub mod journal;
pub mod setup;

mod cursor;

pub use channel::{
    ChannelRecord, ChannelState, ChannelStateError, ChannelStore, CounterpartyLoss, JobEnd,
    JobPhase, JobState, LossTotals, PaidCertificate,
};
pub use journal::{Journal, JournalError, JournalId, JournalKind, Role};
pub use setup::{
    ObservedSetup, SetupAbort, SetupDecision, SetupEnd, SetupFault, SetupOrigin, SetupRecord,
    SetupState, SetupStateError, SetupStore,
};

/// Why a durable step could not be taken.
#[derive(Debug, thiserror::Error)]
pub enum WorkStoreError {
    /// The file could not be opened, replayed, or appended to.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The setup step is not one this handshake may take.
    #[error(transparent)]
    Setup(#[from] SetupStateError),
    /// The channel step is not one this state may take.
    #[error(transparent)]
    Channel(#[from] ChannelStateError),
}

/// Whether applying a record changed anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Applied {
    /// The state moved, so the record must be journaled.
    Changed,
    /// The state already held exactly this. Nothing is written, and the
    /// retry returns what the first call did.
    Redundant,
}

pub(crate) fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
