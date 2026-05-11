// -*- mode: Bluespec; -*-
//
// Verification policy for close witnesses.
//
// Mirrors src/verifier.rs and src/tx/proof.rs. The Rust kernel itself
// implements no cryptography and no close-validity policy beyond
// bookkeeping; every admissibility decision is delegated to the caller's
// [`Verifier`]. This module defines the *abstract* policy any conforming
// verifier is assumed to enforce — `proofOk` for "this witness shape is
// admissible at this height" and `payoutsBound` for "this proof kind
// constrains the (m, t) split to the canonical canonical-pair split".
//
// Pure: no state vars, no actions. Importing it gives any module access to
// the verification rules without touching the model's live state.

module verifier {
  import types.* from "./types"

  // Whether a proof witness is admissible at the current height. Mutual
  // and Violation are unconditionally admissible — the abstract model
  // trusts the verifier to have already validated their cryptographic
  // content. Timeout is gated by the height guard.
  pure def proofOk(p: Proof, height: int): bool =
    match p {
      | Mutual => true
      | Timeout => height >= TimeoutHeight
      | Violation => true
    }

  // Per-proof payout binding. Every close witness binds the canonical
  // (MakerPayout, TakerPayout) split: Mutual via the signed payload,
  // Timeout via `terms.timeout_outputs`, Violation via the dispute seal.
  // There is no proof kind that admits an unbound split — that is the
  // whole point of collapsing Basic out of the protocol.
  pure def payoutsBound(p: Proof, makerPay: int, takerPay: int): bool =
    match p {
      | Mutual => makerPay == MakerPayout and takerPay == TakerPayout
      | Timeout => makerPay == MakerPayout and takerPay == TakerPayout
      | Violation => makerPay == MakerPayout and takerPay == TakerPayout
    }
}
