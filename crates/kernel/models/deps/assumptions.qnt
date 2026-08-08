// -*- mode: Bluespec; -*-
//
// Assumed invariants — what the L1 model takes on faith from layers below
// and beside it.
//
// These are not properties the kernel establishes. They are properties the
// kernel *requires* of its callers and dependencies. If a dependency
// violates an assumption listed here, the kernel's correctness arguments
// stop applying.
//
// Layer correspondence:
//   consensus → src/state.rs::apply_block (kernel applies whatever it gets)
//   verifier  → src/verifier.rs::Verifier
//   store     → src/store.rs::Store, src/store.rs::Batch
//   genesis   → src/object.rs::Genesis::insert
//
// Each assumption is a `pure def` predicate over abstract state and a
// short doc comment naming the dependency, the property, and the
// consequence of violation.

module assumptions {
  import types.* from "../types"

  // ---------------------------------------------------------------------
  // Consensus
  // ---------------------------------------------------------------------

  // Block height advances monotonically across the trace. Consensus
  // guarantees this; the kernel reads height from `Context` and trusts the
  // monotonicity. Violation: timeout proofs could fire at the wrong block.
  pure def heightMonotonic(prev: int, current: int): bool = current >= prev

  // Finalized blocks arrive in a single deterministic order. The kernel's
  // `apply_block` applies operations in their listed order; consensus is
  // assumed to have committed that order. Modelled implicitly by
  // sequential `step` execution.

  // ---------------------------------------------------------------------
  // Verifier
  // ---------------------------------------------------------------------

  // The verifier never accepts a witness it should not. If `proofOk(p, h)
  // = true` and `payoutsBound(p, mPay, tPay) = true`, the kernel treats
  // the close proof as valid; if the verifier admits an invalid signature,
  // seal, or non-canonical payout split, an unauthorized close can drain an
  // edge. For opens, `openAuth` in `l1.qnt` abstracts both native and
  // WebAuthn authorization as "the named party authorized this edge".
  // Modelled by the `proofOk` / `payoutsBound` predicates in
  // `verifier.qnt` and the `fundingAuthorized` invariant in `l1.qnt`.

  // Verification is deterministic — same proof, same answer every call.
  // The kernel relies on this to avoid double-checking; the abstract
  // `proofOk` is a pure predicate so determinism holds by construction.

  // ---------------------------------------------------------------------
  // Network
  // ---------------------------------------------------------------------

  // Every trace is a SINGLE-NETWORK trace, and the model has no notion of
  // a network at all. The real `Tx::open_hash` and `Tx::payload_hash`
  // commit to the `NetworkId` in `Context`, so a witness made for one
  // deployment is not admissible on another; `openAuth` and `proofOk`
  // abstract that away and say only "the named party authorized this",
  // never "...here".
  //
  // Deliberate. Cross-network replay is not a temporal property — no
  // reachable sequence of actions on one network exhibits it — so a
  // two-network model would multiply the state space without making any
  // new property expressible. It is a hash-domain property, and it is
  // pinned in Rust by `tests/network.rs`, which replays an identical
  // transaction under two networks and requires the second to be
  // rejected.
  //
  // Consequence of violation: if the signature domains were NOT network
  // separated, every proof in this model would still hold, and would
  // still be about a chain whose witnesses another chain could spend.

  // ---------------------------------------------------------------------
  // Store
  // ---------------------------------------------------------------------

  // Store transactions are atomic: all writes commit together or none
  // commit at all. The kernel relies on this to roll back on rejection;
  // the abstract model captures it by only updating state inside an
  // `action` (all assignments primed at once).

  // Slot reads observe the working transaction state, not concurrent
  // modifications from elsewhere. The kernel's two-phase validate/fold
  // depends on this. The abstract model has no concurrency, so this holds
  // trivially.

  // ---------------------------------------------------------------------
  // Genesis
  // ---------------------------------------------------------------------

  // Genesis is operator-trusted: caller-supplied coin ids are accepted
  // without authentication. The model bakes this in by initializing
  // `MakerCoin` / `TakerCoin` with fixed values. Production deployments
  // must control the genesis-seeding path.
  pure def genesisFunded(coins: Coin -> int): bool =
    coins.get(MakerCoin) == MakerValue and coins.get(TakerCoin) == TakerValue
}
