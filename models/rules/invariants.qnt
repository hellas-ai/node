// -*- mode: Bluespec; -*-
//
// Established invariants — properties the L1 model *guarantees* hold in
// every reachable state, given that the assumed invariants in
// `deps/assumptions.qnt` are satisfied.
//
// Each rule is a `pure def` predicate that takes the relevant state
// projection and returns a bool. The top-level `l1.qnt` lifts these to
// `val` declarations against its own state vars and feeds them to
// `quint run --invariants=...`.
//
// Layer correspondence — these are the properties the Rust kernel must
// preserve under every transition. ITF-replay tests in `tests/itf.rs`
// check them at every step against the abstract trace; stateright /
// proptest tests run them as inline assertions.

module invariants {
  import types.* from "../types"
  import verifier.* from "../verifier"

  // ---------------------------------------------------------------------
  // Conservation
  // ---------------------------------------------------------------------

  // Sum of live coin values plus live edge values equals genesis funding.
  // Open burns funding into edge value; resolve mints payout coins from
  // edge value. Either way, principal is conserved. (The fee model in
  // `fees.qnt` extends this with a `paid` accumulator for protocol fee
  // collection.)
  pure def valueConserved(
    coins: Coin -> int,
    edges: Edge -> int,
    liveCoins: Set[Coin],
    liveEdges: Set[Edge],
  ): bool =
    val coinTotal = liveCoins.fold(0, (sum, id) => sum + coins.get(id))
    val edgeTotal = liveEdges.fold(0, (sum, id) => sum + edges.get(id))
    coinTotal + edgeTotal == Total

  // No state value goes negative. Catches accidental subtraction from
  // unfunded slots or sign confusion in the fees model.
  pure def noNegativeValue(coins: Coin -> int, edges: Edge -> int): bool =
    AllCoins.forall(id => coins.get(id) >= 0)
      and AllEdges.forall(id => edges.get(id) >= 0)

  // ---------------------------------------------------------------------
  // Shape
  // ---------------------------------------------------------------------

  // At most one live edge in this small model. Edge2 is funded from
  // Edge1's resolve outputs, so they cannot coexist.
  pure def atMostOneLiveEdge(liveEdges: Set[Edge]): bool =
    liveEdges.size() <= 1

  // Live ids belong to the closed universe — catches accidental id
  // leakage (the abstract model has no id allocator, so this is a
  // sanity guard rather than a load-bearing invariant).
  pure def liveCoinsAreKnown(liveCoins: Set[Coin]): bool =
    liveCoins.subseteq(AllCoins)

  pure def liveEdgesAreKnown(liveEdges: Set[Edge]): bool =
    liveEdges.subseteq(AllEdges)

  // ---------------------------------------------------------------------
  // Binding
  // ---------------------------------------------------------------------

  // Every live payout coin carries the canonical (MakerPayout,
  // TakerPayout) split. Holds in every reachable state: every close
  // witness binds payouts (Mutual via signature, Timeout via
  // `terms.timeout_outputs`, Violation via dispute seal), and `canClose`
  // enforces the binding through `payoutsBound`.
  pure def payoutsHonorBindings(
    coins: Coin -> int,
    liveCoins: Set[Coin],
  ): bool =
    AllEdges.forall(e =>
      not(liveCoins.contains(makerOutput(e)))
        or (coins.get(makerOutput(e)) == MakerPayout
              and coins.get(takerOutput(e)) == TakerPayout))
}
