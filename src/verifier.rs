//! Witness verification boundary.
//!
//! The kernel implements no cryptography and no protocol-level close
//! policy beyond bookkeeping (value conservation, slot collisions, fee
//! arithmetic). A [`Verifier`] decides, for one close, whether the
//! supplied [`Proof`] is admissible against the edge being closed at
//! the active context and produced payouts. Production callers wire in
//! a real verifier — typically a preverified-cache lookup populated
//! off the apply critical path (PERF.md §4) — so the kernel stays a
//! pure transition function and parallel signature verification does
//! not have to retrofit the apply path.
//!
//! Tests provide their own [`Verifier`] that accepts the deterministic
//! placeholder shapes built by [`crate::Sig::placeholder`] and
//! [`crate::Seal::placeholder`] and otherwise mirrors production's
//! close-validity rules (terms-hash binding, timeout height, timeout
//! payout shape).
//!
//! Abstract counterpart: `models/verifier.qnt`. The Quint module's
//! `proofOk` / `payoutsBound` predicates are pure — the abstract model
//! takes the verifier on faith. The corresponding determinism and
//! soundness assumptions are documented in `models/deps/assumptions.qnt`.

use crate::context::Context;
use crate::error::InvalidProofReason;
use crate::list::List;
use crate::object::Edge;
use crate::primitive::EdgeId;
use crate::tx::{Payout, Proof};
use crate::consts::MAX_EDGE_OUTPUTS;

/// Decides whether a [`Proof`] is a valid close witness for one edge.
pub trait Verifier {
    /// Returns `Ok` iff `proof` admits closing `edge` (id `edge_id`) into
    /// `payouts` under `context`. Implementations own the full
    /// close-validity policy: terms-hash binding, timeout height, timeout
    /// payout shape, mutual-close signatures, dispute seals, etc.
    ///
    /// # Errors
    ///
    /// Returns the [`InvalidProofReason`] selected by the implementation
    /// when the proof does not admit the close. The kernel forwards this
    /// reason verbatim through [`crate::ApplyError::InvalidProof`].
    fn verify_close(
        &self,
        edge_id: EdgeId,
        edge: &Edge,
        payouts: &List<Payout, MAX_EDGE_OUTPUTS>,
        proof: &Proof,
        context: &Context,
    ) -> Result<(), InvalidProofReason>;
}
