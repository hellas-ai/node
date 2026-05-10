//! Witness verification boundary.
//!
//! The kernel implements no cryptography. A [`Verifier`] decides whether a
//! signature or dispute seal should be accepted as a valid witness for a
//! resolve. Production callers wire in a real verifier — typically a
//! preverified-cache lookup populated off the apply critical path
//! (PERF.md §4) — so the kernel stays a pure transition function and parallel
//! signature verification does not have to retrofit the apply path.
//!
//! Tests provide their own [`Verifier`] that accepts the deterministic
//! placeholder shapes built by [`crate::Sig::placeholder`] and
//! [`crate::Seal::placeholder`].

use crate::op::{ResolveKind, Seal};
use crate::primitive::{Key, ProtocolCode, ResolveHash, Sig};

/// Decides whether a witness is accepted by the kernel for one resolve.
pub trait Verifier {
    /// Returns true when `sig` is a valid witness from `key` over `hash`.
    #[must_use]
    fn verify_sig(&self, sig: Sig, key: Key, hash: ResolveHash) -> bool;

    /// Returns true when `seal` is a valid dispute outcome for `protocol`,
    /// witness `kind`, and `hash`.
    #[must_use]
    fn verify_seal(
        &self,
        seal: Seal,
        protocol: ProtocolCode,
        kind: ResolveKind,
        hash: ResolveHash,
    ) -> bool;
}
