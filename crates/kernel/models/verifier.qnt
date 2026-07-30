// -*- mode: Bluespec; -*-
//
// Verification policy for close witnesses.
//
// Mirrors src/verifier.rs at the abstract close-proof level. The Rust
// verifier trait also covers typed open authorization; the L1 model
// represents that separately as `openAuth` in l1.qnt because native vs
// WebAuthn changes only the witness encoding. The invariant cares that the
// same party key used for funds/terms authorized the open, with no separate
// open-auth key namespace.
// The kernel/crypto seam (`SigVerifier::verify_sig`,
// `SealVerifier::verify_seal`) is ABSTRACTED AWAY here, not modelled:
// this module has no `sigOk`/`sealOk` predicate, and `proofOk` below is
// a height guard only. The model therefore cannot distinguish a valid
// signature from a forged one — witness validity is an assumption
// (`deps/assumptions.qnt`), and real signature behaviour is pinned by
// the Rust tests (`tests/secp256k1.rs`, `tests/webauthn.rs`) instead.
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
