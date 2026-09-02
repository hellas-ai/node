// -*- mode: Bluespec; -*-
//
// Established invariants — properties the L1 model *guarantees* hold in
// every reachable state, given that the premises the kernel takes on
// faith are satisfied. Those premises are not modelled: they live with
// the code that relies on them (`src/context.rs`, `src/block.rs`,
// `src/store.rs`, `src/object.rs`) and at the top of `verifier.qnt`.
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
  // edge value. Either way, principal is conserved. `l1_fees.qnt` extends
  // this with protocol fee and reserve accounting.
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

  // Static sanity check on the closed universe wiring. This catches accidental
  // edits that make the two party lanes alias, or break the intended handoff
  // where Edge1's close outputs fund Edge2.
  pure val wiringIsExpected =
    AllEdges.forall(e =>
      makerInput(e) != takerInput(e)
        and makerOutput(e) != takerOutput(e)
        and makerInput(e) != makerOutput(e)
        and takerInput(e) != takerOutput(e))
      and makerOutput(Edge1) == makerInput(Edge2)
      and takerOutput(Edge1) == takerInput(Edge2)

  pure def liveCoinsHaveCanonicalValue(
    coins: Coin -> int,
    liveCoins: Set[Coin],
  ): bool =
    liveCoins.forall(id => coins.get(id) == canonicalCoinValue(id))

  // Dead map slots must contain zero. The live sets are the source of truth,
  // but keeping dead slots zero catches transitions that forget to clear a
  // consumed coin/edge and would otherwise be masked by the live-set filter in
  // `valueConserved`.
  pure def deadSlotsAreZero(
    coins: Coin -> int,
    edges: Edge -> int,
    liveCoins: Set[Coin],
    liveEdges: Set[Edge],
  ): bool =
    AllCoins.forall(id => liveCoins.contains(id) or coins.get(id) == 0)
      and AllEdges.forall(id => liveEdges.contains(id) or edges.get(id) == 0)

  // In this reduced L1 model every edge is funded by the full maker+taker
  // principal. A live edge with any other value means open accounting drifted.
  pure def liveEdgesHaveCanonicalValue(
    edges: Edge -> int,
    liveEdges: Set[Edge],
  ): bool =
    liveEdges.forall(id => edges.get(id) == EdgeValue)

  // Opening an edge consumes both funding coins. This is intentionally
  // separate from value conservation: a buggy transition could leave a
  // consumed coin live and compensate elsewhere.
  pure def fundingInputsConsumed(
    liveCoins: Set[Coin],
    liveEdges: Set[Edge],
  ): bool =
    liveEdges.forall(e =>
      not(liveCoins.contains(makerInput(e)))
        and not(liveCoins.contains(takerInput(e))))

  pure def heightAtLeastGenesis(height: int): bool =
    height >= 1

  // ---------------------------------------------------------------------
  // Binding
  // ---------------------------------------------------------------------

  // Every live payout coin carries the canonical (MakerPayout,
  // TakerPayout) split. Holds in every reachable state: every close
  // witness binds payouts (Mutual via signature, Timeout via
  // `terms.timeout_outputs`), and `canClose`
  // enforces the binding through `payoutsBound`.
  pure def payoutsHonorBindings(
    coins: Coin -> int,
    liveCoins: Set[Coin],
  ): bool =
    AllEdges.forall(e =>
      not(liveCoins.contains(makerOutput(e)))
        or (coins.get(makerOutput(e)) == MakerPayout
              and coins.get(takerOutput(e)) == TakerPayout))

  // Close outputs are created as a maker/taker pair. `payoutsHonorBindings`
  // checks values; this checks shape, including the case where a bug creates
  // only the taker output.
  pure def payoutOutputsPaired(liveCoins: Set[Coin]): bool =
    AllEdges.forall(e =>
      liveCoins.contains(makerOutput(e)) == liveCoins.contains(takerOutput(e)))

  // Every live edge's recorded open authorization must match the canonical
  // party keys for the funding lineage consumed by that edge. This abstracts
  // over native/WebAuthn witness encoding without introducing a second
  // authorization identity.
  pure def fundingAuthorized(
    liveEdges: Set[Edge],
    openAuth: Edge -> OpenAuth,
  ): bool =
    AllEdges.forall(e =>
      not(liveEdges.contains(e)) or openAuthOk(e, openAuth.get(e)))
}
