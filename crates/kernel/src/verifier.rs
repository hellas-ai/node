//! Witness verification boundary.
//!
//! The transition core delegates cryptography through two narrow traits:
//!
//!   - [`SigVerifier`] decides whether a party-key [`Auth`] witness is
//!     valid over a canonical payload hash. Used for [`crate::Tx::Open`]
//!     and [`Proof::Mutual`].
//!   - [`SealVerifier`] decides whether a protocol-specific dispute
//!     seal is admissible over the canonical close public inputs.
//!     Used for [`Proof::Violation`].
//!
//! [`Proof::Timeout`] needs neither — its admissibility is purely
//! structural (terms-hash binding, height guard, payout shape) and the
//! kernel handles it inline.
//!
//! Production callers wire real implementations of both — typically a
//! preverified-cache lookup populated off the apply critical path — so
//! the kernel stays a pure transition function and
//! parallel signature verification does not have to retrofit the apply
//! path. Tests provide forgeable verifiers that accept the deterministic
//! shapes built by `Sig::placeholder` and `Seal::placeholder` (gated
//! behind the `placeholders` feature).
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
use crate::network::NetworkId;
use crate::primitive::{EdgeId, Key, PayloadHash, ProtocolCode, Sig, TermsHash};
use crate::terms::Terms;
use crate::tx::{Auth, Payout, Seal};

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

/// Canonical public inputs that a dispute seal commits to.
///
/// Bundled and passed by value-reference into [`SealVerifier::verify_seal`]
/// so concrete protocol-specific verifiers see a stable input shape
/// regardless of the underlying ZK system. The kernel populates every
/// field from the close transaction and the live edge state; a
/// `Violation` proof reveals the full terms body (already checked
/// against the edge's committed hash), so verifiers read committed
/// policy — protocol code, stake-bond parameters, parties — directly
/// from `terms` instead of resolving it from a bare hash.
#[derive(Debug, Clone, Copy)]
pub struct SealPublicInputs<'a> {
    /// The network this close settles on. A fraud proof is evidence
    /// about one deployment's execution, so the network is one of its
    /// public inputs: without it, a seal proving misbehaviour on a dev
    /// chain would be admissible evidence against the identical edge on
    /// any other.
    pub network: NetworkId,
    /// Id of the edge being closed.
    pub edge_id: EdgeId,
    /// The closed edge's revealed terms. Hash-checked by the kernel
    /// against the edge before the verifier runs.
    pub terms: &'a Terms,
    /// Payouts the close materialises. The seal commits to this exact
    /// payout shape, so a verifying circuit can attest "this outcome
    /// justifies these payouts".
    pub payouts: &'a List<Payout, MAX_EDGE_OUTPUTS>,
}

impl SealPublicInputs<'_> {
    /// Protocol code committed by the closed edge's terms. Verifiers use
    /// this to dispatch to the right protocol-specific seal circuit /
    /// verifying key.
    #[must_use]
    pub const fn protocol(&self) -> ProtocolCode {
        self.terms.protocol()
    }

    /// Commitment to the closed edge's terms. The seal's circuit binds
    /// to this to prevent cross-edge replay.
    #[must_use]
    pub const fn terms_hash(&self) -> TermsHash {
        self.terms.hash()
    }
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
