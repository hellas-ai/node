// -*- mode: Bluespec; -*-
//
// Verification policy for close witnesses.
//
// Mirrors src/verifier.rs: the kernel implements no cryptography and
// owns no protocol-level admissibility policy beyond Timeout structural
// checks. Two narrow verifier interfaces draw the kernel/crypto seam:
//
//   sigOk(...)  ↔ SigVerifier::verify_sig
//   sealOk(...) ↔ SealVerifier::verify_seal
//
// Timeout closes need neither — their admissibility is purely
// structural (terms-hash binding, height guard, payout shape) and lives
// in the kernel's apply path, not behind a verifier. This module pins
// the *abstract* policy any conforming verifier is assumed to enforce.
//
// Pure: no state vars, no actions. Importing it gives any module access
// to the verification rules without touching the model's live state.

module verifier {
  import types.* from "./types"

  // Whether a proof witness is admissible at the current height.
  //
  // The Mutual case folds the abstract `sigOk` predicate inline:
  // every conforming signature verifier admits a witness *only when*
  // both maker and taker signed the canonical payload — which at this
  // abstraction layer is just "the protocol's bound (MakerPayout,
  // TakerPayout) split was committed to". The Violation case folds
  // `sealOk` similarly. Timeout has no verifier: the kernel itself
  // enforces the height guard.
  pure def proofOk(p: Proof, height: int): bool =
    match p {
      | Mutual => true
      | Timeout => height >= TimeoutHeight
      | Violation => true
    }

  // Per-proof payout binding. Every close witness binds the canonical
  // (MakerPayout, TakerPayout) split: Mutual via signed payload,
  // Timeout via `terms.timeout_outputs` (kernel-enforced), Violation
  // via the dispute seal's public inputs. There is no proof kind that
  // admits an unbound split.
  pure def payoutsBound(p: Proof, makerPay: int, takerPay: int): bool =
    match p {
      | Mutual => makerPay == MakerPayout and takerPay == TakerPayout
      | Timeout => makerPay == MakerPayout and takerPay == TakerPayout
      | Violation => makerPay == MakerPayout and takerPay == TakerPayout
    }
}
