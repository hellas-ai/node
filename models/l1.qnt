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
  // Close precondition (combines verifier policy + state shape)
  // ---------------------------------------------------------------------

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
    lastInput' = NoInput,
    lastEvent' = NoEvent,
  }

  // Open consumes the canonical input coins for an edge and creates the
  // edge with their summed value. Fees/reserves are abstracted away here
  // and modelled separately in `fees.qnt`.
  action openEdge(e) = all {
    not(liveEdges.contains(e)),
    liveCoins.contains(makerInput(e)),
    liveCoins.contains(takerInput(e)),
    coins' = coins
      .set(makerInput(e), 0)
      .set(takerInput(e), 0),
    edges' = edges.set(e, coins.get(makerInput(e)) + coins.get(takerInput(e))),
    liveCoins' = liveCoins.exclude(Set(makerInput(e), takerInput(e))),
    liveEdges' = liveEdges.union(Set(e)),
    height' = height,
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
    openEdge(Edge1),
    openEdge(Edge2),
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
  val payoutsHonorBindings = inv::payoutsHonorBindings(coins, liveCoins)

  // ---------------------------------------------------------------------
  // Trace tests — exported as ITF fixtures via `npm run quint:fixtures`
  // ---------------------------------------------------------------------

  // Smoke: open the canonical edge, cooperatively close.
  run basicTraceTest =
    init
      .then(openEdge(Edge1))
      .then(closeEdge(Edge1, Mutual, MakerPayout, TakerPayout))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue)

  // Multi-edge: mutual close on Edge1, then handoff to Edge2 funded by
  // Edge1's payout coins, then timeout-close Edge2.
  run mutualTimeoutTraceTest =
    init
      .then(openEdge(Edge1))
      .then(closeEdge(Edge1, Mutual, MakerPayout, TakerPayout))
      .then(openEdge(Edge2))
      .then(tick)
      .then(closeEdge(Edge2, Timeout, MakerPayout, TakerPayout))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue)

  // Violation closes on both edges.
  run violationTraceTest =
    init
      .then(openEdge(Edge1))
      .then(closeEdge(Edge1, Violation, MakerPayout, TakerPayout))
      .then(openEdge(Edge2))
      .then(closeEdge(Edge2, Violation, MakerPayout, TakerPayout))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue)

  // Negative trace: an open without a tick cannot Timeout.
  run earlyTimeoutRejectedTest =
    init
      .then(openEdge(Edge1))
      .expect(not(canClose(Edge1, Timeout, MakerPayout, TakerPayout)))

  // Both edges closed by Timeout. Demonstrates the timeout-only path
  // without any cooperative or dispute witness — production Rust uses
  // exactly this path when no one signed and no one disputed.
  run bothEdgesTimeoutTraceTest =
    init
      .then(openEdge(Edge1))
      .then(tick)
      .then(closeEdge(Edge1, Timeout, MakerPayout, TakerPayout))
      .then(openEdge(Edge2))
      .then(closeEdge(Edge2, Timeout, MakerPayout, TakerPayout))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue)

  // Mixed proof kinds across edges: violation close on the first,
  // mutual on the second. Catches kernel paths that assume the
  // same proof kind across an entire trace.
  run mixedProofsTraceTest =
    init
      .then(openEdge(Edge1))
      .then(closeEdge(Edge1, Violation, MakerPayout, TakerPayout))
      .then(openEdge(Edge2))
      .then(closeEdge(Edge2, Mutual, MakerPayout, TakerPayout))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue)

  // Height accumulates across multiple ticks; idle stutter does not
  // disturb live state. The Rust runner advances its tracked height on
  // tick and asserts the model's height matches at every step.
  run heightAccumulationTraceTest =
    init
      .then(tick)
      .then(idle)
      .then(tick)
      .then(openEdge(Edge1))
      .then(closeEdge(Edge1, Timeout, MakerPayout, TakerPayout))
      .expect(valueConserved and noNegativeValue and height == 3)
}
