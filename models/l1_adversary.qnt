// -*- mode: Bluespec; -*-
//
// Adversary configuration of the L1 model: `FakeCrypto = true`. Models
// the Rust kernel built with the `fake-crypto` feature, under which
// `Proof::basic` is admitted by the verifier policy regardless of
// payouts and signatures/seals carry no cryptographic force.
//
// Module body is otherwise byte-for-byte identical to `l1.qnt`. Any
// edit there must be mirrored here; CI runs `scripts/check-adversary-sync.sh`
// to enforce this. The split exists only because Quint's current
// flattener cannot propagate parameterized imports through a wrapper
// module (see history of `models/configs/` in git), so the two
// configurations are siblings rather than one wrapping the other.
//
// Under this configuration:
//
//   - the five safety invariants (valueConserved, noNegativeValue,
//     atMostOneLiveEdge, liveCoinsAreKnown, liveEdgesAreKnown) still
//     hold — burning principal and edge accounting are independent of
//     the witness shape, so Apalache verifies them just like under
//     production.
//   - `payoutsHonorBindings` is reachably *violated*: a Basic adversary
//     path can resolve an edge with any value-conserving split,
//     including `(EdgeValue, 0)`. Apalache produces the concrete attack
//     trace via `npm run quint:verify:adversary:attack`.

module l1_adversary {
  import types.* from "./types"
  // Adversary semantics: Basic is admitted unconditionally. See header
  // for the sync contract with `l1.qnt`.
  import verifier(FakeCrypto = true).* from "./verifier"
  import invariants as inv from "./rules/invariants"

  // ---------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------

  var coins: Coin -> int
  var edges: Edge -> int
  var liveCoins: Set[Coin]
  var liveEdges: Set[Edge]
  var height: int

  var lastInput: Input
  var lastEvent: Event

  // ---------------------------------------------------------------------
  // Derived state projections
  // ---------------------------------------------------------------------

  def totalCoins: int =
    liveCoins.fold(0, (sum, id) => sum + coins.get(id))

  def totalEdges: int =
    liveEdges.fold(0, (sum, id) => sum + edges.get(id))

  def liveEdgeCount: int =
    liveEdges.size()

  // ---------------------------------------------------------------------
  // Resolve precondition
  // ---------------------------------------------------------------------

  def canResolve(e: Edge, p: Proof, makerPay: int, takerPay: int): bool =
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

  action resolveEdge(e, p, makerPay, takerPay) = all {
    canResolve(e, p, makerPay, takerPay),
    coins' = coins
      .set(makerOutput(e), makerPay)
      .set(takerOutput(e), takerPay),
    edges' = edges.set(e, 0),
    liveCoins' = liveCoins.union(Set(makerOutput(e), takerOutput(e))),
    liveEdges' = liveEdges.exclude(Set(e)),
    height' = height,
    lastInput' = ResolveInput({ edge: e, proof: p, makerPay: makerPay, takerPay: takerPay }),
    lastEvent' = EdgeResolvedEvent(e),
  }

  action tick = all {
    coins' = coins,
    edges' = edges,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    height' = height + 1,
    lastInput' = TickInput,
    lastEvent' = NoEvent,
  }

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

  action step = any {
    openEdge(Edge1),
    openEdge(Edge2),
    resolveEdge(Edge1, Basic, MakerPayout, TakerPayout),
    resolveEdge(Edge1, Agreement, MakerPayout, TakerPayout),
    resolveEdge(Edge1, Timeout, MakerPayout, TakerPayout),
    resolveEdge(Edge1, ClaimantWins, MakerPayout, TakerPayout),
    resolveEdge(Edge1, ChallengerWins, MakerPayout, TakerPayout),
    resolveEdge(Edge2, Basic, MakerPayout, TakerPayout),
    resolveEdge(Edge2, Agreement, MakerPayout, TakerPayout),
    resolveEdge(Edge2, Timeout, MakerPayout, TakerPayout),
    resolveEdge(Edge2, ClaimantWins, MakerPayout, TakerPayout),
    resolveEdge(Edge2, ChallengerWins, MakerPayout, TakerPayout),
    resolveEdge(Edge1, Basic, EdgeValue, 0),
    resolveEdge(Edge1, Basic, 0, EdgeValue),
    resolveEdge(Edge2, Basic, EdgeValue, 0),
    resolveEdge(Edge2, Basic, 0, EdgeValue),
    tick,
    idle,
  }

  // ---------------------------------------------------------------------
  // Invariants
  // ---------------------------------------------------------------------

  val valueConserved = inv::valueConserved(coins, edges, liveCoins, liveEdges)
  val noNegativeValue = inv::noNegativeValue(coins, edges)
  val atMostOneLiveEdge = inv::atMostOneLiveEdge(liveEdges)
  val liveCoinsAreKnown = inv::liveCoinsAreKnown(liveCoins)
  val liveEdgesAreKnown = inv::liveEdgesAreKnown(liveEdges)
  val payoutsHonorBindings = inv::payoutsHonorBindings(coins, liveCoins)
}
