//! Witness verification boundary.
//!
//! The transition core delegates cryptography through two narrow traits:
//!
//!   - [`SigVerifier`] decides whether a settlement signature or open
//!     authorization is valid over a canonical payload hash. Used for
//!     [`Proof::Mutual`] and [`crate::Tx::Open`].
//!   - [`SealVerifier`] decides whether a protocol-specific dispute
//!     seal is admissible over the canonical close public inputs.
//!     Used for [`Proof::Violation`].
//!
//! [`Proof::Timeout`] needs neither — its admissibility is purely
//! structural (terms-hash binding, height guard, payout shape) and the
//! kernel handles it inline.
//!
//! Production callers wire real implementations of both — typically a
//! preverified-cache lookup populated off the apply critical path
//! (PERF.md §4) — so the kernel stays a pure transition function and
//! parallel signature verification does not have to retrofit the apply
//! path. Tests provide forgeable verifiers that accept the deterministic
//! shapes built by [`crate::Sig::placeholder`] and
//! [`crate::Seal::placeholder`].
//!
//! Abstract counterpart: `models/verifier.qnt`. The Quint module's
//! `sigOk` / `sealOk` predicates are pure — the abstract model takes the
//! verifiers on faith. The corresponding determinism and soundness
//! assumptions are documented in `models/deps/assumptions.qnt`.
//!
//! [`Proof::Mutual`]: crate::Proof::Mutual
//! [`Proof::Timeout`]: crate::Proof::Timeout
//! [`Proof::Violation`]: crate::Proof::Violation

use crate::consts::MAX_EDGE_OUTPUTS;
use crate::list::List;
use crate::primitive::{EdgeId, Key, PayloadHash, ProtocolCode, Sig, TermsHash};
use crate::tx::{OpenAuth, Payout, Seal};

/// Decides whether one settlement signature is admissible over a close
/// payload hash.
///
/// Used by the kernel for [`Proof::Mutual`]: both maker and taker
/// signatures are checked through this trait against the canonical
/// [`crate::Tx::payload_hash`] of the close payload.
///
/// [`Proof::Mutual`]: crate::Proof::Mutual
pub trait SigVerifier {
    /// Returns true when `sig` is a valid witness from `party_key` over
    /// `hash`.
    #[must_use]
    fn verify_sig(&self, sig: Sig, party_key: Key, hash: PayloadHash) -> bool;

    /// Returns true when `auth` is a valid open authorization from
    /// `party_key` over `hash`.
    ///
    /// Native open authorizations reuse [`Self::verify_sig`]. `WebAuthn` is
    /// rejected by default so existing native-only verifiers do not
    /// accidentally start accepting a new signature scheme.
    #[must_use]
    fn verify_open_auth(&self, auth: &OpenAuth, party_key: Key, hash: PayloadHash) -> bool {
        match auth {
            OpenAuth::Native(sig) => self.verify_sig(*sig, party_key, hash),
            OpenAuth::WebAuthn(_) => false,
        }
    }
}

/// Canonical public inputs that a dispute seal commits to.
///
/// Bundled and passed by value-reference into [`SealVerifier::verify_seal`]
/// so concrete protocol-specific verifiers see a stable input shape
/// regardless of the underlying ZK system. The kernel populates every
/// field from the close transaction and the live edge state.
#[derive(Debug, Clone, Copy)]
pub struct SealPublicInputs<'a> {
    /// Id of the edge being closed.
    pub edge_id: EdgeId,
    /// Protocol code committed by the closed edge's terms. Verifiers use
    /// this to dispatch to the right protocol-specific seal circuit /
    /// verifying key.
    pub protocol: ProtocolCode,
    /// Commitment to the closed edge's terms. The seal's circuit binds
    /// to this to prevent cross-edge replay.
    pub terms_hash: TermsHash,
    /// Payouts the close materialises. The seal commits to this exact
    /// payout shape, so a verifying circuit can attest "this outcome
    /// justifies these payouts".
    pub payouts: &'a List<Payout, MAX_EDGE_OUTPUTS>,
}

/// Decides whether a protocol-specific dispute seal is admissible.
///
/// Used by the kernel for [`Proof::Violation`]: the seal's
/// 32 admissibility bytes are checked through this trait against the
/// canonical [`SealPublicInputs`]. Concrete implementations are
/// protocol-specific and ZK-system-specific; the kernel is oblivious to
/// both.
///
/// [`Proof::Violation`]: crate::Proof::Violation
pub trait SealVerifier {
    /// Returns true when `seal` is admissible under `public`.
    #[must_use]
    fn verify_seal(&self, seal: Seal, public: &SealPublicInputs<'_>) -> bool;
}
