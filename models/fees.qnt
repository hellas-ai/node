module fees {
  // Fee/reserve accounting model for one open channel.
  //
  // The l1.qnt model focuses on live coin/edge shape. This model adds the
  // protocol payment bucket (`paid`) and an explicit edge reserve so we can
  // check the v1 rule that the protocol is paid pessimistically: open burns the
  // open fee and locks the worst-case close reserve; close consumes the
  // whole reserve rather than refunding unused reserve into payout coins.
  //
  // The model also exercises the deliberate fee-schedule asymmetry: an edge's
  // reserve is locked at open under the schedule active at that block, but a
  // close is priced under the schedule active at *its* block. A protocol
  // fee raise can therefore push the close cost above the locked reserve,
  // which stalls the edge. Principal stays conserved; it just cannot be paid
  // out under the new schedule. This is the v1 stale-edge collection knob.

  // Fixed universe of ids. As in l1.qnt, map values are meaningful only when an
  // id is present in the corresponding live set.
  type Coin =
    | MakerCoin
    | TakerCoin
    | MakerOut
    | TakerOut

  // `UnusedEdge` is a workaround for an Apalache/Quint-IR bug: when a
  // sum type has a single variant, the FUN_APP type inference produces
  // a row-polymorphic argument type that Apalache rejects ("FUN_APP
  // cannot be applied to arguments of types ((Channel({tag:Str}) -> Int),
  // Channel({tag:Str}) | c)"). Adding a second variant collapses the row
  // to a closed sum and unblocks verification. `UnusedEdge` is never
  // a member of `AllEdges`, never live, and never appears in any
  // reachable state; the trace and invariant semantics are unchanged.
  type Edge =
    | Channel
    | UnusedEdge

  // Mutual is the unconditionally-admitted cooperative close. Timeout is
  // the height-gated production path in this reduced fee model.
  type Proof =
    | Mutual
    | Timeout

  var coins: Coin -> int
  var edges: Edge -> int
  var reserves: Edge -> int
  var liveCoins: Set[Coin]
  var liveEdges: Set[Edge]
  var paid: int
  var height: int
  // Currently active close fee. Initialised to BaseCloseFee at genesis;
  // a raiseFee step lifts it to RaisedCloseFee, modelling the protocol
  // bumping fees mid-lifecycle.
  var closeFee: int

  // Concrete values chosen to mirror the Rust resource-fee tests:
  // 30 + 20 funding, 10 open fee, 16 prepaid reserve, 24 principal.
  pure val AllCoins = Set(MakerCoin, TakerCoin, MakerOut, TakerOut)
  pure val AllEdges = Set(Channel)
  pure val TimeoutHeight = 2
  pure val MakerValue = 30
  pure val TakerValue = 20
  pure val Total = MakerValue + TakerValue
  pure val OpenFee = 10
  pure val CloseReserve = 16
  // Close fee under the schedule active at open. Locked reserve is sized
  // to cover this exactly.
  pure val BaseCloseFee = 10
  // Close fee after a protocol fee raise. Chosen to exceed CloseReserve so
  // the model can witness an edge becoming unclosable.
  pure val RaisedCloseFee = CloseReserve + 2
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
      and funding >= OpenFee + CloseReserve

  def proofOk(p: Proof): bool =
    match p {
      | Mutual => true
      | Timeout => height >= TimeoutHeight
    }

  // Close is admitted only when the edge's locked reserve covers the
  // *current* close fee — not the fee active at open. Under a fee raise,
  // an existing edge's reserve may no longer cover the new fee, leaving the
  // edge unclosable.
  def canClose(p: Proof): bool =
    liveEdges.contains(Channel)
      and proofOk(p)
      and reserves.get(Channel) >= closeFee
      and edges.get(Channel) == Principal
      and not(liveCoins.contains(MakerOut))
      and not(liveCoins.contains(TakerOut))

  // Normal genesis: enough funding to pay open fee and reserve. Close fee
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
    closeFee' = BaseCloseFee,
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
    closeFee' = BaseCloseFee,
  }

  // Open consumes both funding coins, pays the open fee immediately, locks the
  // fixed reserve on the edge, and stores only remaining principal as edge
  // value.
  action openEdge = all {
    canOpen,
    coins' = coins
      .set(MakerCoin, 0)
      .set(TakerCoin, 0),
    edges' = edges.set(Channel, funding - OpenFee - CloseReserve),
    reserves' = reserves.set(Channel, CloseReserve),
    liveCoins' = liveCoins.exclude(Set(MakerCoin, TakerCoin)),
    liveEdges' = liveEdges.union(Set(Channel)),
    paid' = paid + OpenFee,
    height' = height,
    closeFee' = closeFee,
  }

  // Close materializes principal payouts and pays the entire locked reserve to
  // the protocol bucket. Deliberately no reserve surplus is refunded.
  action closeEdge(p) = all {
    canClose(p),
    coins' = coins
      .set(MakerOut, MakerPayout)
      .set(TakerOut, TakerPayout),
    edges' = edges.set(Channel, 0),
    reserves' = reserves.set(Channel, 0),
    liveCoins' = liveCoins.union(Set(MakerOut, TakerOut)),
    liveEdges' = liveEdges.exclude(Set(Channel)),
    paid' = paid + reserves.get(Channel),
    height' = height,
    closeFee' = closeFee,
  }

  // Protocol bumps the active close fee. Edges already opened keep their
  // locked reserve; if the raised fee exceeds that reserve, those edges
  // become unclosable. This is the deliberate stale-edge collection knob
  // and the production semantics this model exists to pin.
  action raiseFee = all {
    closeFee == BaseCloseFee,
    coins' = coins,
    edges' = edges,
    reserves' = reserves,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    paid' = paid,
    height' = height,
    closeFee' = RaisedCloseFee,
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
    closeFee' = closeFee,
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
    closeFee' = closeFee,
  }

  // Nondeterministic transition relation for random exploration.
  action step = any {
    openEdge,
    closeEdge(Mutual),
    closeEdge(Timeout),
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
  // covers BaseCloseFee even after a subsequent raise; what changes is
  // whether the *current* fee fits, captured in canClose.
  val reserveAtLeastBaseFee =
    liveEdges.forall(id => reserves.get(id) >= BaseCloseFee)

  // Paid can only be zero, open fee, or open fee plus consumed reserve.
  val paidWithinBounds =
    paid >= 0 and paid <= OpenFee + CloseReserve

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
      .then(closeEdge(Mutual))
      .expect(valueAccounted and paid == OpenFee + CloseReserve)

  run timeoutFeeTraceTest =
    init
      .then(openEdge)
      .then(tick)
      .then(closeEdge(Timeout))
      .expect(valueAccounted and paid == OpenFee + CloseReserve)

  run underfundedOpenRejectedTest =
    initUnderfunded
      .expect(not(canOpen))

  // Stale-edge collection: an edge opened under the base schedule cannot
  // close once the protocol raises the fee above the locked reserve.
  // Principal stays inside the live edge (valueAccounted continues to hold),
  // it just cannot be paid out under the new schedule.
  run staleEdgeAfterFeeRaiseTest =
    init
      .then(openEdge)
      .then(raiseFee)
      .expect(valueAccounted and liveEdges.contains(Channel) and not(canClose(Mutual)) and not(canClose(Timeout)) and reserves.get(Channel) == CloseReserve and edges.get(Channel) == Principal)

  // Even after height advances past the timeout, a raised fee keeps the
  // edge stuck. Timeout is no escape hatch from a deliberate fee raise.
  run timeoutDoesNotRescueAfterFeeRaiseTest =
    init
      .then(openEdge)
      .then(raiseFee)
      .then(tick)
      .expect(height >= TimeoutHeight and not(canClose(Timeout)))
}
