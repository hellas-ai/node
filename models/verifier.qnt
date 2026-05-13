// -*- mode: Bluespec; -*-
//
// Verification policy for close witnesses.
//
// Mirrors src/verifier.rs at the abstract close-proof level. The Rust
// verifier trait also covers typed open authorization; the L1 model
// represents that separately as `openAuth` in l1.qnt because the concrete
// signature envelope (native vs WebAuthn) is irrelevant to the state
// invariants once it establishes "this party authorized the open".
// Two narrow verifier interfaces draw the kernel/crypto seam:
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
  // `sealOk` similarly. Mutual and Violation are pre-expiry paths; Timeout
  // is the deterministic fallback once the paid lifetime has expired.
  pure def proofOk(p: Proof, height: int): bool =
    match p {
      | Mutual => height < TimeoutHeight
      | Timeout => height >= TimeoutHeight
      | Violation => height < TimeoutHeight
    }

  // Per-proof payout binding. Every close witness binds the canonical
  // (MakerPayout, TakerPayout) split: Mutual via signed payload,
  // Timeout via `terms.timeout_outputs` (kernel-enforced), Violation
  // via the dispute seal's public inputs. There is no proof kind that
  // admits an unbound split.
  pure def payoutsBound(p: Proof, makerPay: int, takerPay: int): bool =
    match p {
      | Mutual => payoutSplitOk(makerPay, takerPay)
      | Timeout => payoutSplitOk(makerPay, takerPay)
      | Violation => payoutSplitOk(makerPay, takerPay)
    }
}
