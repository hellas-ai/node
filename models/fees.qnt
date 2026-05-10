module fees {
  type Coin =
    | MakerCoin
    | TakerCoin
    | MakerOut
    | TakerOut

  type Edge =
    | Channel

  type Proof =
    | Basic
    | Timeout

  var coins: Coin -> int
  var edges: Edge -> int
  var reserves: Edge -> int
  var liveEdges: Set[Edge]
  var paid: int
  var height: int

  pure val AllCoins = Set(MakerCoin, TakerCoin, MakerOut, TakerOut)
  pure val AllEdges = Set(Channel)
  pure val TimeoutHeight = 2
  pure val MakerValue = 30
  pure val TakerValue = 20
  pure val Total = MakerValue + TakerValue
  pure val OpenFee = 10
  pure val ResolveReserve = 16
  pure val ResolveFee = 10
  pure val MakerPayout = 12
  pure val TakerPayout = 12
  pure val Principal = MakerPayout + TakerPayout

  def coinTotal: int =
    AllCoins.fold(0, (sum, id) => sum + coins.get(id))

  def edgeTotal: int =
    liveEdges.fold(0, (sum, id) => sum + edges.get(id))

  def reserveTotal: int =
    liveEdges.fold(0, (sum, id) => sum + reserves.get(id))

  def liveEdgeCount: int =
    liveEdges.size()

  def funding: int =
    coins.get(MakerCoin) + coins.get(TakerCoin)

  def canOpen: bool =
    not(liveEdges.contains(Channel))
      and coins.get(MakerOut) == 0
      and coins.get(TakerOut) == 0
      and funding >= OpenFee + ResolveReserve

  def proofOk(p: Proof): bool =
    match p {
      | Basic => true
      | Timeout => height >= TimeoutHeight
    }

  def canResolve(p: Proof): bool =
    liveEdges.contains(Channel)
      and proofOk(p)
      and reserves.get(Channel) >= ResolveFee
      and edges.get(Channel) == Principal
      and coins.get(MakerOut) == 0
      and coins.get(TakerOut) == 0

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
    reserves' = AllEdges.mapBy(_ => 0),
    liveEdges' = Set(),
    paid' = 0,
    height' = 1,
  }

  action initUnderfunded = all {
    coins' = AllCoins.mapBy(id =>
      if (id == MakerCoin) {
        20
      } else if (id == TakerCoin) {
        5
      } else {
        0
      }
    ),
    edges' = AllEdges.mapBy(_ => 0),
    reserves' = AllEdges.mapBy(_ => 0),
    liveEdges' = Set(),
    paid' = 0,
    height' = 1,
  }

  action openEdge = all {
    canOpen,
    coins' = coins
      .set(MakerCoin, 0)
      .set(TakerCoin, 0),
    edges' = edges.set(Channel, funding - OpenFee - ResolveReserve),
    reserves' = reserves.set(Channel, ResolveReserve),
    liveEdges' = liveEdges.union(Set(Channel)),
    paid' = paid + OpenFee,
    height' = height,
  }

  action resolveEdge(p) = all {
    canResolve(p),
    coins' = coins
      .set(MakerOut, MakerPayout)
      .set(TakerOut, TakerPayout),
    edges' = edges.set(Channel, 0),
    reserves' = reserves.set(Channel, 0),
    liveEdges' = liveEdges.exclude(Set(Channel)),
    paid' = paid + reserves.get(Channel),
    height' = height,
  }

  action tick = all {
    coins' = coins,
    edges' = edges,
    reserves' = reserves,
    liveEdges' = liveEdges,
    paid' = paid,
    height' = height + 1,
  }

  action idle = all {
    coins' = coins,
    edges' = edges,
    reserves' = reserves,
    liveEdges' = liveEdges,
    paid' = paid,
    height' = height,
  }

  action step = any {
    openEdge,
    resolveEdge(Basic),
    resolveEdge(Timeout),
    tick,
    idle,
  }

  val valueAccounted =
    coinTotal + edgeTotal + reserveTotal + paid == Total

  val reserveCoversResolve =
    liveEdges.forall(id => reserves.get(id) >= ResolveFee)

  val paidWithinBounds =
    paid >= 0 and paid <= OpenFee + ResolveReserve

  val atMostOneLiveEdge =
    liveEdgeCount <= 1

  val noNegativeValue =
    AllCoins.forall(id => coins.get(id) >= 0)
      and AllEdges.forall(id => edges.get(id) >= 0)
      and AllEdges.forall(id => reserves.get(id) >= 0)
      and paid >= 0

  run feeTraceTest =
    init
      .then(openEdge)
      .then(resolveEdge(Basic))
      .expect(valueAccounted and paid == OpenFee + ResolveReserve)

  run timeoutFeeTraceTest =
    init
      .then(openEdge)
      .then(tick)
      .then(resolveEdge(Timeout))
      .expect(valueAccounted and paid == OpenFee + ResolveReserve)

  run underfundedOpenRejectedTest =
    initUnderfunded
      .expect(not(canOpen))
}
