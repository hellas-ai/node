// -*- mode: Bluespec; -*-
//
// Top-level L1 transition model. Owns the state vars; composes the
// vocabulary and verification policy from sibling modules; lifts the
// established-invariant rules from `rules/` into model-state predicates;
// pins lifecycle paths as deterministic `run` traces that get exported as
// ITF fixtures and replayed by `tests/itf.rs`.
//
// Module map:
//   types.qnt              — ADTs, closed-universe constants, wiring
//   verifier.qnt           — proofOk, payoutsBound (verification policy)
//   deps/assumptions.qnt   — what we assume of consensus / verifier / store
//   rules/invariants.qnt   — what this model establishes
//
// New trace tests added here are picked up automatically by the
// itf::Runner-based replay in tests/itf.rs (no Rust changes).

module l1 {
  import types.* from "./types"
  import verifier.* from "./verifier"
  import invariants as inv from "./rules/invariants"

  // ---------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------

  var coins: Coin -> int
  var edges: Edge -> int
  var liveCoins: Set[Coin]
  var liveEdges: Set[Edge]
  var height: int

  // Per-edge open authorization. For every edge that goes live, the
  // open action records the (asMaker, asTaker) parties the submitter
  // claimed when calling `openEdge`. The `fundingAuthorized` invariant
  // checks these against `coinOwner(makerInput(e))` / `coinOwner(takerInput(e))`
  // — i.e. that the claimed parties actually own the consumed coins.
  // Dead-edge entries are meaningless; the invariant only ranges over
  // `liveEdges`.
  var openAuth: Edge -> OpenAuth

  // Recording vars: the action that produced the current state and the
  // abstract event it emitted. The Rust ITF runner reads these to drive
  // the kernel and assert event/state correspondence at each step.
  var lastInput: Input
  var lastEvent: Event

  // ---------------------------------------------------------------------
  // Derived state projections (used by inline invariants)
  // ---------------------------------------------------------------------

  def totalCoins: int =
    liveCoins.fold(0, (sum, id) => sum + coins.get(id))

  def totalEdges: int =
    liveEdges.fold(0, (sum, id) => sum + edges.get(id))

  def liveEdgeCount: int =
    liveEdges.size()

  // ---------------------------------------------------------------------
  // Preconditions (combine verifier/auth policy + state shape)
  // ---------------------------------------------------------------------

  def canOpen(e: Edge, asMaker: Party, asTaker: Party): bool =
    not(liveEdges.contains(e))
      and edges.get(e) == 0
      and height < TimeoutHeight
      and liveCoins.contains(makerInput(e))
      and liveCoins.contains(takerInput(e))
      and openAuthOk(e, { maker: asMaker, taker: asTaker })

  def canClose(e: Edge, p: Proof, makerPay: int, takerPay: int): bool =
    liveEdges.contains(e)
      and edges.get(e) == EdgeValue
      and proofOk(p, height)
      and makerPay >= 0
      and takerPay >= 0
      and makerPay + takerPay == EdgeValue
      and payoutsBound(p, makerPay, takerPay)
      and not(liveCoins.contains(makerOutput(e)))
      and not(liveCoins.contains(takerOutput(e)))

  // ---------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------

  // Genesis. Two live coins, zero edges, height 1.
  action init = all {
    coins' = AllCoins.mapBy(id =>
      if (id == MakerCoin) {
        MakerValue
      } else if (id == TakerCoin) {
        TakerValue
      } else {
        0
      }
    ),
    edges' = AllEdges.mapBy(_ => 0),
    liveCoins' = Set(MakerCoin, TakerCoin),
    liveEdges' = Set(),
    height' = 1,
    openAuth' = AllEdges.mapBy(_ => NoOpenAuth),
    lastInput' = NoInput,
    lastEvent' = NoEvent,
  }

  // Open consumes the canonical input coins for an edge and creates the
  // edge with their summed value, recording the parties the submitter
  // claimed (`asMaker`, `asTaker`). Fees/reserves are abstracted away
  // here and modelled in `l1_fees.qnt`.
  //
  // The action requires the claimed parties to actually own the coins
  // being consumed: `asMaker == coinOwner(makerInput(e))` and likewise
  // for the taker. This mirrors the kernel's owner-match + dual-
  // signature check on `apply_open`. Adversarial calls (with
  // `Adversary` as a claimed party) are then disabled rather than
  // landing in live state, and `fundingAuthorized` holds in every
  // reachable state.
  action openEdge(e, asMaker, asTaker) = all {
    canOpen(e, asMaker, asTaker),
    coins' = coins
      .set(makerInput(e), 0)
      .set(takerInput(e), 0),
    edges' = edges.set(e, coins.get(makerInput(e)) + coins.get(takerInput(e))),
    liveCoins' = liveCoins.exclude(Set(makerInput(e), takerInput(e))),
    liveEdges' = liveEdges.union(Set(e)),
    height' = height,
    openAuth' = openAuth.set(e, { maker: asMaker, taker: asTaker }),
    lastInput' = OpenInput(e),
    lastEvent' = EdgeOpenedEvent(e),
  }

  // Close consumes one live edge and materializes payout coins. Payouts
  // are explicit so the model can explore non-canonical splits and
  // confirm the verifier rejects everything but the canonical split.
  action closeEdge(e, p, makerPay, takerPay) = all {
    canClose(e, p, makerPay, takerPay),
    coins' = coins
      .set(makerOutput(e), makerPay)
      .set(takerOutput(e), takerPay),
    edges' = edges.set(e, 0),
    liveCoins' = liveCoins.union(Set(makerOutput(e), takerOutput(e))),
    liveEdges' = liveEdges.exclude(Set(e)),
    height' = height,
    openAuth' = openAuth,
    lastInput' = CloseInput({ edge: e, proof: p, makerPay: makerPay, takerPay: takerPay }),
    lastEvent' = EdgeClosedEvent(e),
  }

  // Advance height. Required for Timeout proofs to become admissible.
  action tick = all {
    coins' = coins,
    edges' = edges,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    height' = height + 1,
    openAuth' = openAuth,
    lastInput' = TickInput,
    lastEvent' = NoEvent,
  }

  // Stutter. Preserves every invariant; useful for temporal exploration.
  action idle = all {
    coins' = coins,
    edges' = edges,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    height' = height,
    openAuth' = openAuth,
    lastInput' = IdleInput,
    lastEvent' = NoEvent,
  }

  // ---------------------------------------------------------------------
  // Transition relation
  // ---------------------------------------------------------------------

  // Each proof kind appears with the canonical (MakerPayout, TakerPayout)
  // split. Non-canonical splits under bound proofs are also listed so the
  // spec makes the rejection surface explicit; `canClose` rejects them
  // through `payoutsBound`, and Apalache confirms they remain unreachable.
  action step = any {
    // Canonical (authorized) opens.
    openEdge(Edge1, Maker, Taker),
    openEdge(Edge2, Maker, Taker),
    // Adversarial (unauthorized) opens. Each names a party identity
    // that doesn't own the corresponding funding coin. `openEdge`'s
    // owner-match precondition disables every one of them; Apalache
    // confirms they remain unreachable. Listing them in `step`
    // surfaces the rejection in the spec rather than hiding it inside
    // the precondition.
    openEdge(Edge1, Adversary, Adversary),
    openEdge(Edge1, Adversary, Taker),
    openEdge(Edge1, Maker, Adversary),
    openEdge(Edge2, Adversary, Adversary),
    openEdge(Edge2, Adversary, Taker),
    openEdge(Edge2, Maker, Adversary),
    // Canonical-split closes under each proof kind.
    closeEdge(Edge1, Mutual, MakerPayout, TakerPayout),
    closeEdge(Edge1, Timeout, MakerPayout, TakerPayout),
    closeEdge(Edge1, Violation, MakerPayout, TakerPayout),
    closeEdge(Edge2, Mutual, MakerPayout, TakerPayout),
    closeEdge(Edge2, Timeout, MakerPayout, TakerPayout),
    closeEdge(Edge2, Violation, MakerPayout, TakerPayout),
    // Non-canonical splits. Each is rejected by `canClose` via
    // `payoutsBound`; Apalache symbolically confirms these remain
    // unreachable, making the rejection surface explicit in the spec
    // rather than implicit in `payoutsBound`.
    closeEdge(Edge1, Mutual, EdgeValue, 0),
    closeEdge(Edge1, Timeout, EdgeValue, 0),
    closeEdge(Edge1, Violation, EdgeValue, 0),
    closeEdge(Edge2, Mutual, EdgeValue, 0),
    closeEdge(Edge2, Timeout, EdgeValue, 0),
    closeEdge(Edge2, Violation, EdgeValue, 0),
    tick,
    idle,
  }

  // ---------------------------------------------------------------------
  // Invariants (lifted from rules/invariants.qnt over this model's state)
  // ---------------------------------------------------------------------

  val valueConserved = inv::valueConserved(coins, edges, liveCoins, liveEdges)
  val noNegativeValue = inv::noNegativeValue(coins, edges)
  val atMostOneLiveEdge = inv::atMostOneLiveEdge(liveEdges)
  val liveCoinsAreKnown = inv::liveCoinsAreKnown(liveCoins)
  val liveEdgesAreKnown = inv::liveEdgesAreKnown(liveEdges)
  val wiringIsExpected = inv::wiringIsExpected
  val liveCoinsHaveCanonicalValue = inv::liveCoinsHaveCanonicalValue(coins, liveCoins)
  val payoutsHonorBindings = inv::payoutsHonorBindings(coins, liveCoins)
  val payoutOutputsPaired = inv::payoutOutputsPaired(liveCoins)
  val deadSlotsAreZero = inv::deadSlotsAreZero(coins, edges, liveCoins, liveEdges)
  val liveEdgesHaveCanonicalValue = inv::liveEdgesHaveCanonicalValue(edges, liveEdges)
  val fundingInputsConsumed = inv::fundingInputsConsumed(liveCoins, liveEdges)
  val heightAtLeastGenesis = inv::heightAtLeastGenesis(height)

  // Every live edge's (asMaker, asTaker) authorization must match the
  // canonical owners of the coins that funded it. A correct kernel
  // enforces this on open; reaching a state where it fails means an
  // unauthorized open went through. The Rust kernel enforces this through
  // owner-match plus typed open authorization (`OpenAuth::Native` or
  // `OpenAuth::WebAuthn`), both abstracted here as "the named party
  // authorized this edge".
  val fundingAuthorized = inv::fundingAuthorized(liveEdges, openAuth)

  // ---------------------------------------------------------------------
  // Trace tests — exported as ITF fixtures via `npm run quint:fixtures`
  // ---------------------------------------------------------------------

  // Smoke: open the canonical edge, cooperatively close.
  run basicTraceTest =
    init
      .then(openEdge(Edge1, Maker, Taker))
      .then(closeEdge(Edge1, Mutual, MakerPayout, TakerPayout))
      .expect(valueConserved
        and atMostOneLiveEdge
        and noNegativeValue
        and fundingAuthorized
        and deadSlotsAreZero)


  // Multi-edge: mutual close on Edge1, then handoff to Edge2 funded by
  // Edge1's payout coins, then timeout-close Edge2.
  run mutualTimeoutTraceTest =
    init
      .then(openEdge(Edge1, Maker, Taker))
      .then(closeEdge(Edge1, Mutual, MakerPayout, TakerPayout))
      .then(openEdge(Edge2, Maker, Taker))
      .then(tick)
      .then(closeEdge(Edge2, Timeout, MakerPayout, TakerPayout))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue and deadSlotsAreZero)

  // Violation closes on both edges.
  run violationTraceTest =
    init
      .then(openEdge(Edge1, Maker, Taker))
      .then(closeEdge(Edge1, Violation, MakerPayout, TakerPayout))
      .then(openEdge(Edge2, Maker, Taker))
      .then(closeEdge(Edge2, Violation, MakerPayout, TakerPayout))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue and deadSlotsAreZero)

  // Negative trace: an open without a tick cannot Timeout.
  run earlyTimeoutRejectedTest =
    init
      .then(openEdge(Edge1, Maker, Taker))
      .expect(not(canClose(Edge1, Timeout, MakerPayout, TakerPayout)))

  // Negative trace: each unauthorized open shape is disabled from genesis.
  run unauthorizedOpenRejectedTest =
    init
      .expect(not(canOpen(Edge1, Adversary, Adversary))
        and not(canOpen(Edge1, Adversary, Taker))
        and not(canOpen(Edge1, Maker, Adversary)))

  // Negative trace: authorization is checked again for Edge2 after its
  // funding coins exist, so this is not just a missing-input rejection.
  run edge2UnauthorizedOpenRejectedTest =
    init
      .then(openEdge(Edge1, Maker, Taker))
      .then(closeEdge(Edge1, Mutual, MakerPayout, TakerPayout))
      .expect(canOpen(Edge2, Maker, Taker)
        and not(canOpen(Edge2, Adversary, Adversary))
        and not(canOpen(Edge2, Adversary, Taker))
        and not(canOpen(Edge2, Maker, Adversary)))

  // Negative trace: Edge2 cannot open until Edge1's payout coins exist.
  run edge2BeforeFundingRejectedTest =
    init
      .expect(not(canOpen(Edge2, Maker, Taker)))

  // Negative trace: a value-conserving but non-canonical payout split is
  // rejected for close proof kinds that are enabled without height advance.
  run nonCanonicalCloseRejectedTest =
    init
      .then(openEdge(Edge1, Maker, Taker))
      .expect(not(canClose(Edge1, Mutual, EdgeValue, 0))
        and not(canClose(Edge1, Violation, EdgeValue, 0)))

  // Negative trace: timeout close rejects the same non-canonical split even
  // after the height guard is satisfied.
  run nonCanonicalTimeoutRejectedTest =
    init
      .then(openEdge(Edge1, Maker, Taker))
      .then(tick)
      .expect(height >= TimeoutHeight
        and not(canClose(Edge1, Timeout, EdgeValue, 0)))

  // Negative trace: once Edge1 has closed, its consumed genesis funding
  // cannot be reused to reopen it.
  run consumedFundingCannotReopenTest =
    init
      .then(openEdge(Edge1, Maker, Taker))
      .then(closeEdge(Edge1, Mutual, MakerPayout, TakerPayout))
      .expect(not(canOpen(Edge1, Maker, Taker)))

  // Timeout closes the edge after paid lifetime expires. With this small model's
  // single absolute timeout height, a later handoff open is rejected unless a
  // richer per-edge timeout is introduced.
  run timeoutExpiryTraceTest =
    init
      .then(openEdge(Edge1, Maker, Taker))
      .then(tick)
      .then(closeEdge(Edge1, Timeout, MakerPayout, TakerPayout))
      .expect(valueConserved
        and atMostOneLiveEdge
        and noNegativeValue
        and deadSlotsAreZero
        and not(canOpen(Edge2, Maker, Taker)))

  // Negative trace: pre-expiry proof paths are not accepted once timeout is
  // available.
  run expiredMutualAndViolationRejectedTest =
    init
      .then(openEdge(Edge1, Maker, Taker))
      .then(tick)
      .expect(height >= TimeoutHeight
        and not(canClose(Edge1, Mutual, MakerPayout, TakerPayout))
        and not(canClose(Edge1, Violation, MakerPayout, TakerPayout)))

  // Mixed proof kinds across edges: violation close on the first,
  // mutual on the second. Catches kernel paths that assume the
  // same proof kind across an entire trace.
  run mixedProofsTraceTest =
    init
      .then(openEdge(Edge1, Maker, Taker))
      .then(closeEdge(Edge1, Violation, MakerPayout, TakerPayout))
      .then(openEdge(Edge2, Maker, Taker))
      .then(closeEdge(Edge2, Mutual, MakerPayout, TakerPayout))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue and deadSlotsAreZero)

  // Height accumulates across multiple ticks; idle stutter does not
  // disturb live state. Once the single model timeout is reached, new opens
  // are disabled until a richer per-edge timeout vocabulary exists.
  run heightAccumulationTraceTest =
    init
      .then(tick)
      .then(idle)
      .then(tick)
      .expect(valueConserved
        and noNegativeValue
        and height == 3
        and heightAtLeastGenesis
        and not(canOpen(Edge1, Maker, Taker)))
}
