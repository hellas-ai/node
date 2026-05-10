module l1 {
  // Small L1 transition model for live coins and live edges.
  //
  // This is not a serialization model. It uses a fixed finite universe of coin
  // and edge ids so the checker can explore operation orderings without
  // allocation or unbounded maps. The `coins` and `edges` maps store values for
  // every known id, while `liveCoins` and `liveEdges` say which ids are actually
  // occupied. A non-live id may still have an old or zero map value; only the
  // live sets define state.

  // The two input coins are genesis. The four output coins are deterministic
  // resolve outputs for Edge1 and Edge2. Edge2 is funded from Edge1's outputs,
  // which gives traces enough shape to check open -> resolve -> open -> resolve
  // without introducing an unbounded id generator.
  type Coin =
    | MakerCoin
    | TakerCoin
    | MakerOut1
    | TakerOut1
    | MakerOut2
    | TakerOut2

  type Edge =
    | Edge1
    | Edge2

  // Basic is a modelling/fake-crypto witness. Production Rust accepts it only
  // under the fake-crypto feature; Timeout is the proof-free production path in
  // this small model, and Agreement/Claimant/Challenger stand in for preverified
  // evidence.
  type Proof =
    | Basic
    | Agreement
    | Timeout
    | ClaimantWins
    | ChallengerWins

  var coins: Coin -> int
  var edges: Edge -> int
  var liveCoins: Set[Coin]
  var liveEdges: Set[Edge]
  var height: int

  // Closed universes used by the invariants below. If an operation introduces a
  // new id family, it should appear here and in the known-id invariants.
  pure val AllCoins = Set(
    MakerCoin,
    TakerCoin,
    MakerOut1,
    TakerOut1,
    MakerOut2,
    TakerOut2,
  )
  pure val AllEdges = Set(Edge1, Edge2)
  pure val AllProofs = Set(Basic, Agreement, Timeout, ClaimantWins, ChallengerWins)
  pure val TimeoutHeight = 2
  pure val MakerValue = 10
  pure val TakerValue = 5
  pure val EdgeValue = MakerValue + TakerValue
  pure val MakerPayout = 7
  pure val TakerPayout = 8
  pure val Total = EdgeValue

  // Canonical input/output wiring for each edge. This mirrors Rust's derived
  // ids: callers do not choose output ids, they are fixed by the operation.
  pure def makerInput(e: Edge): Coin =
    match e {
      | Edge1 => MakerCoin
      | Edge2 => MakerOut1
    }

  pure def takerInput(e: Edge): Coin =
    match e {
      | Edge1 => TakerCoin
      | Edge2 => TakerOut1
    }

  pure def makerOutput(e: Edge): Coin =
    match e {
      | Edge1 => MakerOut1
      | Edge2 => MakerOut2
    }

  pure def takerOutput(e: Edge): Coin =
    match e {
      | Edge1 => TakerOut1
      | Edge2 => TakerOut2
    }

  def totalCoins: int =
    liveCoins.fold(0, (sum, id) => sum + coins.get(id))

  def totalEdges: int =
    liveEdges.fold(0, (sum, id) => sum + edges.get(id))

  def liveEdgeCount: int =
    liveEdges.size()

  // Genesis starts with two live coins and no live edge. Values for non-live ids
  // are initialized to zero to keep value accounting simple.
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
  }

  // Open consumes the two canonical input coins for an edge and creates that
  // edge with exactly the consumed value. This model ignores fees/reserves; the
  // fees.qnt model covers protocol payment accounting separately.
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
  }

  // FakeCrypto toggles the modelling/fake-crypto witness path. Set true to
  // explore the adversary surface that exists when the fake-crypto feature is
  // built in; set false to model production semantics where the kernel rejects
  // Basic. The `payoutsHonorBindings` invariant holds iff FakeCrypto is false.
  pure val FakeCrypto = false

  // Proof validity. Timeout has a height guard. Basic is the modelling witness
  // and is enabled only under FakeCrypto, mirroring the Rust kernel's
  // cfg(feature = "fake-crypto") gate on Proof::Basic.
  def proofOk(p: Proof): bool =
    match p {
      | Basic => FakeCrypto
      | Agreement => true
      | Timeout => height >= TimeoutHeight
      | ClaimantWins => true
      | ChallengerWins => true
    }

  // Per-proof payout binding. Agreement is bound by signature; Timeout is
  // bound by terms.timeout_outputs; ClaimantWins/ChallengerWins are bound by
  // the dispute seal. Basic carries no binding — it is the adversary surface
  // gated by FakeCrypto via proofOk.
  def payoutsBound(p: Proof, makerPay: int, takerPay: int): bool =
    match p {
      | Basic => true
      | Agreement => makerPay == MakerPayout and takerPay == TakerPayout
      | Timeout => makerPay == MakerPayout and takerPay == TakerPayout
      | ClaimantWins => makerPay == MakerPayout and takerPay == TakerPayout
      | ChallengerWins => makerPay == MakerPayout and takerPay == TakerPayout
    }

  def canResolve(e: Edge, p: Proof, makerPay: int, takerPay: int): bool =
    liveEdges.contains(e)
      and edges.get(e) == EdgeValue
      and proofOk(p)
      and makerPay >= 0
      and takerPay >= 0
      and makerPay + takerPay == EdgeValue
      and payoutsBound(p, makerPay, takerPay)
      and not(liveCoins.contains(makerOutput(e)))
      and not(liveCoins.contains(takerOutput(e)))

  // Resolve consumes one live edge and materializes payout coins. Payouts are
  // explicit so the model can explore adversarial choices under Basic and
  // confirm bound proofs reject anything but the canonical split.
  action resolveEdge(e, p, makerPay, takerPay) = all {
    canResolve(e, p, makerPay, takerPay),
    coins' = coins
      .set(makerOutput(e), makerPay)
      .set(takerOutput(e), takerPay),
    edges' = edges.set(e, 0),
    liveCoins' = liveCoins.union(Set(makerOutput(e), takerOutput(e))),
    liveEdges' = liveEdges.exclude(Set(e)),
    height' = height,
  }

  // Advance block height without changing live objects. This is how timeout
  // guards become enabled.
  action tick = all {
    coins' = coins,
    edges' = edges,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    height' = height + 1,
  }

  // Stutter step for temporal exploration. It should preserve every invariant.
  action idle = all {
    coins' = coins,
    edges' = edges,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    height' = height,
  }

  // The nondeterministic transition relation checked by `quint run`. Each
  // proof kind appears with the canonical (MakerPayout, TakerPayout) split,
  // and Basic also appears with adversarial splits. Adversarial splits under
  // bound proofs are listed below to document that they are rejected by
  // payoutsBound; canResolve will never enable them.
  action step = any {
    openEdge(Edge1),
    openEdge(Edge2),
    // Canonical-split resolves under each proof kind.
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
    // Adversarial Basic splits. Reachable iff FakeCrypto is true; this is the
    // surface that the production kernel closes by gating Basic. Adversarial
    // splits under bound proofs are not listed because canResolve rejects them
    // through payoutsBound — Quint's exploration covers this by never
    // enabling those actions, regardless of whether they appear here.
    resolveEdge(Edge1, Basic, EdgeValue, 0),
    resolveEdge(Edge1, Basic, 0, EdgeValue),
    resolveEdge(Edge2, Basic, EdgeValue, 0),
    resolveEdge(Edge2, Basic, 0, EdgeValue),
    tick,
    idle,
  }

  // Conservation over live principal. Reserve/fee accounting is intentionally
  // absent from this model and appears in fees.qnt.
  val valueConserved = totalCoins + totalEdges == Total

  // V1 traces should never have two simultaneously live channel edges in this
  // bounded scenario: Edge2 can only open from Edge1's resolved outputs.
  val atMostOneLiveEdge = liveEdgeCount <= 1

  // Sanity checks that catch accidental negative arithmetic or id leakage.
  val noNegativeValue =
    AllCoins.forall(id => coins.get(id) >= 0)
      and AllEdges.forall(id => edges.get(id) >= 0)
  val liveEdgesAreKnown = liveEdges.subseteq(AllEdges)
  val liveCoinsAreKnown = liveCoins.subseteq(AllCoins)

  // Every live payout coin carries the canonical (MakerPayout, TakerPayout)
  // split. Holds when FakeCrypto is false because the only enabled resolves
  // are bound proofs. Becomes reachable-violation when FakeCrypto is true and
  // a Basic adversary path resolves with a non-canonical split. This is the
  // invariant that catches the original "timeout payouts unconstrained" class
  // of bug: any binding that fails to fix the (m, t) shape will trip this.
  val payoutsHonorBindings =
    AllEdges.forall(e =>
      not(liveCoins.contains(makerOutput(e)))
        or (coins.get(makerOutput(e)) == MakerPayout
              and coins.get(takerOutput(e)) == TakerPayout))

  // Deterministic smoke traces used to generate ITF fixtures and pin obvious
  // lifecycle paths. All resolve steps use the canonical split; the Rust
  // kernel checks Agreement/Timeout/Dispute payouts are bound. The state
  // sequence in each fixture is what matters, not the proof kind — Rust
  // replays may use any kernel-accepted proof that produces the same state
  // transitions.
  run basicTraceTest =
    init
      .then(openEdge(Edge1))
      .then(resolveEdge(Edge1, Agreement, MakerPayout, TakerPayout))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue)

  run agreementTimeoutTraceTest =
    init
      .then(openEdge(Edge1))
      .then(resolveEdge(Edge1, Agreement, MakerPayout, TakerPayout))
      .then(openEdge(Edge2))
      .then(tick)
      .then(resolveEdge(Edge2, Timeout, MakerPayout, TakerPayout))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue)

  run disputeTraceTest =
    init
      .then(openEdge(Edge1))
      .then(resolveEdge(Edge1, ClaimantWins, MakerPayout, TakerPayout))
      .then(openEdge(Edge2))
      .then(resolveEdge(Edge2, ChallengerWins, MakerPayout, TakerPayout))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue)

  run earlyTimeoutRejectedTest =
    init
      .then(openEdge(Edge1))
      .expect(not(canResolve(Edge1, Timeout, MakerPayout, TakerPayout)))
}
