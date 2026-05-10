// -*- mode: Bluespec; -*-
//
// Verification policy for resolve witnesses.
//
// Mirrors src/verifier.rs and the policy embedded in src/op/proof.rs:
// the kernel itself implements no cryptography; verification is policy
// supplied by the caller. This module defines the *abstract* policy the
// caller is assumed to enforce — `proofOk` for "this witness shape is
// admissible at this height under the active feature config", and
// `payoutsBound` for "this proof kind constrains the (m, t) split to the
// canonical canonical-pair-or-better".
//
// Pure: no state vars, no actions. Importing it gives any module access to
// the verification rules without touching the model's live state.

module verifier {
  import types.* from "./types"

  // FakeCrypto mirrors the Rust `cfg(feature = "fake-crypto")` gate. Set
  // true to model the modelling/test build (Basic accepted; Sig/Seal
  // placeholders verifiable). Set false to model production semantics
  // (Basic rejected by policy regardless of payouts).
  pure val FakeCrypto = false

  // Whether a proof witness is *admissible at all* under the current
  // height and feature config. Production verifiers reject Basic; Timeout
  // is gated by the height guard; the rest are unconditionally admissible
  // here because the abstract model trusts the verifier to have already
  // validated their cryptographic content.
  pure def proofOk(p: Proof, height: int): bool =
    match p {
      | Basic => FakeCrypto
      | Agreement => true
      | Timeout => height >= TimeoutHeight
      | ClaimantWins => true
      | ChallengerWins => true
    }

  // Per-proof payout binding. Agreement is bound by signature; Timeout is
  // bound by `terms.timeout_outputs`; ClaimantWins/ChallengerWins are
  // bound by the dispute seal. Basic carries no binding — it is the
  // adversary surface gated by FakeCrypto via `proofOk`.
  pure def payoutsBound(p: Proof, makerPay: int, takerPay: int): bool =
    match p {
      | Basic => true
      | Agreement => makerPay == MakerPayout and takerPay == TakerPayout
      | Timeout => makerPay == MakerPayout and takerPay == TakerPayout
      | ClaimantWins => makerPay == MakerPayout and takerPay == TakerPayout
      | ChallengerWins => makerPay == MakerPayout and takerPay == TakerPayout
    }
}
