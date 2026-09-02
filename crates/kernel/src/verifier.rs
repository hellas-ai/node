//! Witness verification boundary.
//!
//! The transition core delegates cryptography through one narrow trait.
//! [`SigVerifier`] decides whether a party-key [`Auth`] witness is valid
//! over a canonical payload hash. Used for [`crate::Tx::Open`],
//! [`Proof::Mutual`], and the work-payment `Freeze`.
//!
//! [`Proof::Timeout`] and the adjudicated work-payment close need no
//! cryptography — their admissibility is structural (terms-hash
//! binding, height guard, payout shape, staged registry state) and the
//! kernel handles both inline. No close consults an external verifier;
//! there is no seal trait, and adding one is a protocol decision, not
//! an extension point.
//!
//! Production callers wire a real implementation — typically a
//! preverified-cache lookup populated off the apply critical path — so
//! the kernel stays a pure transition function and parallel signature
//! verification does not have to retrofit the apply path. Tests provide
//! forgeable verifiers that accept the deterministic shapes built by
//! `Sig::placeholder` (gated behind the `placeholders` feature).
//!
//! Abstract counterpart: `models/verifier.qnt`. The Quint module's
//! `sigOk` predicate is pure — the abstract model takes the verifier on
//! faith.
//!
//! [`Proof::Mutual`]: crate::Proof::Mutual
//! [`Proof::Timeout`]: crate::Proof::Timeout

use crate::primitive::{Key, PayloadHash, Sig};
use crate::tx::Auth;

/// Decides whether one party-key authorization is admissible over a
/// canonical payload hash.
///
/// Used by the kernel for [`crate::Tx::Open`] (both parties authorize the
/// open hash) and [`Proof::Mutual`] (both parties authorize the canonical
/// [`crate::Tx::payload_hash`] of the close).
///
/// [`Proof::Mutual`]: crate::Proof::Mutual
pub trait SigVerifier {
    /// Returns true when `sig` is a valid witness from `party_key` over
    /// `hash`.
    #[must_use]
    fn verify_sig(&self, sig: Sig, party_key: Key, hash: PayloadHash) -> bool;

    /// Returns true when `auth` is a valid authorization from `party_key`
    /// over `hash`.
    ///
    /// Native authorizations reuse [`Self::verify_sig`]. `WebAuthn` is
    /// rejected by default so existing native-only verifiers do not
    /// accidentally start accepting a new signature scheme.
    #[must_use]
    fn verify_auth(&self, auth: &Auth, party_key: Key, hash: PayloadHash) -> bool {
        match auth {
            Auth::Native(sig) => self.verify_sig(*sig, party_key, hash),
            Auth::WebAuthn(_) => false,
        }
    }
}
