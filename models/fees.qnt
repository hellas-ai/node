module fees {
  // Fee/reserve accounting model for one open channel.
  //
  // The l1.qnt model focuses on live coin/edge shape. This model adds the
  // protocol payment bucket (`paid`) and an explicit edge reserve so we can
  // check the v1 rule that the protocol is paid pessimistically: open burns the
  // open fee and locks the worst-case resolve reserve; resolve consumes the
  // whole reserve rather than refunding unused reserve into payout coins.
  //
  // The model also exercises the deliberate fee-schedule asymmetry: an edge's
  // reserve is locked at open under the schedule active at that block, but a
  // resolve is priced under the schedule active at *its* block. A protocol
  // fee raise can therefore push the resolve cost above the locked reserve,
  // which stalls the edge. Principal stays conserved; it just cannot be paid
  // out under the new schedule. This is the v1 stale-edge collection knob.

  // Fixed universe of ids. As in l1.qnt, map values are meaningful only when an
  // id is present in the corresponding live set.
  type Coin =
    | MakerCoin
    | TakerCoin
    | MakerOut
    | TakerOut

  type Edge =
    | Channel

  // Basic is the modelling/fake-crypto witness. Timeout is the proof-free
  // production path in this reduced fee model.
  type Proof =
    | Basic
    | Timeout

  var coins: Coin -> int
  var edges: Edge -> int
  var reserves: Edge -> int
  var liveCoins: Set[Coin]
  var liveEdges: Set[Edge]
  var paid: int
  var height: int
  // Currently active resolve fee. Initialised to BaseResolveFee at genesis;
  // a raiseFee step lifts it to RaisedResolveFee, modelling the protocol
  // bumping fees mid-lifecycle.
  var resolveFee: int

  // Concrete values chosen to mirror the Rust resource-fee tests:
  // 30 + 20 funding, 10 open fee, 16 prepaid reserve, 24 principal.
  pure val AllCoins = Set(MakerCoin, TakerCoin, MakerOut, TakerOut)
  pure val AllEdges = Set(Channel)
  pure val TimeoutHeight = 2
  pure val MakerValue = 30
  pure val TakerValue = 20
  pure val Total = MakerValue + TakerValue
  pure val OpenFee = 10
  pure val ResolveReserve = 16
  // Resolve fee under the schedule active at open. Locked reserve is sized
  // to cover this exactly.
  pure val BaseResolveFee = 10
  // Resolve fee after a protocol fee raise. Chosen to exceed ResolveReserve so
  // the model can witness an edge becoming unresolvable.
  pure val RaisedResolveFee = ResolveReserve + 2
  pure val MakerPayout = 12
  pure val TakerPayout = 12
  pure val Principal = MakerPayout + TakerPayout

  def coinTotal: int =
    liveCoins.fold(0, (sum, id) => sum + coins.get(id))

  def edgeTotal: int =
    liveEdges.fold(0, (sum, id) => sum + edges.get(id))

  def reserveTotal: int =
    liveEdges.fold(0, (sum, id) => sum + reserves.get(id))

  def liveEdgeCount: int =
    liveEdges.size()

  def funding: int =
    coins.get(MakerCoin) + coins.get(TakerCoin)

  // Open is admitted only when funding can cover both immediate open fee and
  // the pessimistic reserve. This is the "protocol always gets paid" invariant
  // in guard form.
  def canOpen: bool =
    not(liveEdges.contains(Channel))
      and liveCoins.contains(MakerCoin)
      and liveCoins.contains(TakerCoin)
      and not(liveCoins.contains(MakerOut))
      and not(liveCoins.contains(TakerOut))
      and funding >= OpenFee + ResolveReserve

  def proofOk(p: Proof): bool =
    match p {
      | Basic => true
      | Timeout => height >= TimeoutHeight
    }

  // Resolve is admitted only when the edge's locked reserve covers the
  // *current* resolve fee — not the fee active at open. Under a fee raise,
  // an existing edge's reserve may no longer cover the new fee, leaving the
  // edge unresolvable.
  def canResolve(p: Proof): bool =
    liveEdges.contains(Channel)
      and proofOk(p)
      and reserves.get(Channel) >= resolveFee
      and edges.get(Channel) == Principal
      and not(liveCoins.contains(MakerOut))
      and not(liveCoins.contains(TakerOut))

  // Normal genesis: enough funding to pay open fee and reserve. Resolve fee
  // starts at the base schedule.
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
    liveCoins' = Set(MakerCoin, TakerCoin),
    liveEdges' = Set(),
    paid' = 0,
    height' = 1,
    resolveFee' = BaseResolveFee,
  }

  // Underfunded genesis proves that an open with insufficient protocol payment
  // is rejected before any state mutation.
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
    liveCoins' = Set(MakerCoin, TakerCoin),
    liveEdges' = Set(),
    paid' = 0,
    height' = 1,
    resolveFee' = BaseResolveFee,
  }

  // Open consumes both funding coins, pays the open fee immediately, locks the
  // fixed reserve on the edge, and stores only remaining principal as edge
  // value.
  action openEdge = all {
    canOpen,
    coins' = coins
      .set(MakerCoin, 0)
      .set(TakerCoin, 0),
    edges' = edges.set(Channel, funding - OpenFee - ResolveReserve),
    reserves' = reserves.set(Channel, ResolveReserve),
    liveCoins' = liveCoins.exclude(Set(MakerCoin, TakerCoin)),
    liveEdges' = liveEdges.union(Set(Channel)),
    paid' = paid + OpenFee,
    height' = height,
    resolveFee' = resolveFee,
  }

  // Resolve materializes principal payouts and pays the entire locked reserve to
  // the protocol bucket. Deliberately no reserve surplus is refunded.
  action resolveEdge(p) = all {
    canResolve(p),
    coins' = coins
      .set(MakerOut, MakerPayout)
      .set(TakerOut, TakerPayout),
    edges' = edges.set(Channel, 0),
    reserves' = reserves.set(Channel, 0),
    liveCoins' = liveCoins.union(Set(MakerOut, TakerOut)),
    liveEdges' = liveEdges.exclude(Set(Channel)),
    paid' = paid + reserves.get(Channel),
    height' = height,
    resolveFee' = resolveFee,
  }

  // Protocol bumps the active resolve fee. Edges already opened keep their
  // locked reserve; if the raised fee exceeds that reserve, those edges
  // become unresolvable. This is the deliberate stale-edge collection knob
  // and the production semantics this model exists to pin.
  action raiseFee = all {
    resolveFee == BaseResolveFee,
    coins' = coins,
    edges' = edges,
    reserves' = reserves,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    paid' = paid,
    height' = height,
    resolveFee' = RaisedResolveFee,
  }

  // Height advance enables timeout without changing money accounting.
  action tick = all {
    coins' = coins,
    edges' = edges,
    reserves' = reserves,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    paid' = paid,
    height' = height + 1,
    resolveFee' = resolveFee,
  }

  // Stutter step for invariant exploration.
  action idle = all {
    coins' = coins,
    edges' = edges,
    reserves' = reserves,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    paid' = paid,
    height' = height,
    resolveFee' = resolveFee,
  }

  // Nondeterministic transition relation for random exploration.
  action step = any {
    openEdge,
    resolveEdge(Basic),
    resolveEdge(Timeout),
    raiseFee,
    tick,
    idle,
  }

  // Full value accounting includes live payout/edge principal, still-locked
  // reserve, and value already paid to the protocol. Holds across every step,
  // including across a fee raise — the raise reorganises which transitions
  // are enabled, not where money lives.
  val valueAccounted =
    coinTotal + edgeTotal + reserveTotal + paid == Total

  // Reserves are sized to the schedule active at open. Any live edge therefore
  // covers BaseResolveFee even after a subsequent raise; what changes is
  // whether the *current* fee fits, captured in canResolve.
  val reserveAtLeastBaseFee =
    liveEdges.forall(id => reserves.get(id) >= BaseResolveFee)

  // Paid can only be zero, open fee, or open fee plus consumed reserve.
  val paidWithinBounds =
    paid >= 0 and paid <= OpenFee + ResolveReserve

  val atMostOneLiveEdge =
    liveEdgeCount <= 1

  val liveCoinsAreKnown =
    liveCoins.subseteq(AllCoins)

  val noNegativeValue =
    AllCoins.forall(id => coins.get(id) >= 0)
      and AllEdges.forall(id => edges.get(id) >= 0)
      and AllEdges.forall(id => reserves.get(id) >= 0)
      and paid >= 0

  // Deterministic traces for fee accounting and underfunded rejection.
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

  // Stale-edge collection: an edge opened under the base schedule cannot
  // resolve once the protocol raises the fee above the locked reserve.
  // Principal stays inside the live edge (valueAccounted continues to hold),
  // it just cannot be paid out under the new schedule.
  run staleEdgeAfterFeeRaiseTest =
    init
      .then(openEdge)
      .then(raiseFee)
      .expect(valueAccounted and liveEdges.contains(Channel) and not(canResolve(Basic)) and not(canResolve(Timeout)) and reserves.get(Channel) == ResolveReserve and edges.get(Channel) == Principal)

  // Even after height advances past the timeout, a raised fee keeps the
  // edge stuck. Timeout is no escape hatch from a deliberate fee raise.
  run timeoutDoesNotRescueAfterFeeRaiseTest =
    init
      .then(openEdge)
      .then(raiseFee)
      .then(tick)
      .expect(height >= TimeoutHeight and not(canResolve(Timeout)))
}
