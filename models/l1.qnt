module l1 {
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

  type Proof =
    | Basic
    | Agreement
    | Timeout
    | ClaimantWins
    | ChallengerWins

  var coins: Coin -> int
  var edges: Edge -> int
  var liveEdges: Set[Edge]
  var height: int

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
    AllCoins.fold(0, (sum, id) => sum + coins.get(id))

  def totalEdges: int =
    liveEdges.fold(0, (sum, id) => sum + edges.get(id))

  def liveEdgeCount: int =
    liveEdges.size()

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
    liveEdges' = Set(),
    height' = 1,
  }

  action openEdge(e) = all {
    not(liveEdges.contains(e)),
    coins.get(makerInput(e)) > 0,
    coins.get(takerInput(e)) > 0,
    coins' = coins
      .set(makerInput(e), 0)
      .set(takerInput(e), 0),
    edges' = edges.set(e, coins.get(makerInput(e)) + coins.get(takerInput(e))),
    liveEdges' = liveEdges.union(Set(e)),
    height' = height,
  }

  def proofOk(p: Proof): bool =
    match p {
      | Basic => true
      | Agreement => true
      | Timeout => height >= TimeoutHeight
      | ClaimantWins => true
      | ChallengerWins => true
    }

  def canResolve(e: Edge, p: Proof): bool =
    liveEdges.contains(e)
      and edges.get(e) == EdgeValue
      and proofOk(p)
      and coins.get(makerOutput(e)) == 0
      and coins.get(takerOutput(e)) == 0

  action resolveEdge(e, p) = all {
    canResolve(e, p),
    coins' = coins
      .set(makerOutput(e), MakerPayout)
      .set(takerOutput(e), TakerPayout),
    edges' = edges.set(e, 0),
    liveEdges' = liveEdges.exclude(Set(e)),
    height' = height,
  }

  action tick = all {
    coins' = coins,
    edges' = edges,
    liveEdges' = liveEdges,
    height' = height + 1,
  }

  action idle = all {
    coins' = coins,
    edges' = edges,
    liveEdges' = liveEdges,
    height' = height,
  }

  action step = any {
    openEdge(Edge1),
    openEdge(Edge2),
    resolveEdge(Edge1, Basic),
    resolveEdge(Edge1, Agreement),
    resolveEdge(Edge1, Timeout),
    resolveEdge(Edge1, ClaimantWins),
    resolveEdge(Edge1, ChallengerWins),
    resolveEdge(Edge2, Basic),
    resolveEdge(Edge2, Agreement),
    resolveEdge(Edge2, Timeout),
    resolveEdge(Edge2, ClaimantWins),
    resolveEdge(Edge2, ChallengerWins),
    tick,
    idle,
  }

  val valueConserved = totalCoins + totalEdges == Total
  val atMostOneLiveEdge = liveEdgeCount <= 1
  val noNegativeValue =
    AllCoins.forall(id => coins.get(id) >= 0)
      and AllEdges.forall(id => edges.get(id) >= 0)
  val liveEdgesAreKnown = liveEdges.subseteq(AllEdges)

  run basicTraceTest =
    init
      .then(openEdge(Edge1))
      .then(resolveEdge(Edge1, Basic))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue)

  run agreementTimeoutTraceTest =
    init
      .then(openEdge(Edge1))
      .then(resolveEdge(Edge1, Agreement))
      .then(openEdge(Edge2))
      .then(tick)
      .then(resolveEdge(Edge2, Timeout))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue)

  run disputeTraceTest =
    init
      .then(openEdge(Edge1))
      .then(resolveEdge(Edge1, ClaimantWins))
      .then(openEdge(Edge2))
      .then(resolveEdge(Edge2, ChallengerWins))
      .expect(valueConserved and atMostOneLiveEdge and noNegativeValue)

  run earlyTimeoutRejectedTest =
    init
      .then(openEdge(Edge1))
      .expect(not(canResolve(Edge1, Timeout)))
}
