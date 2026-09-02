module l1_fees {
  import accounting.* from "./accounting"
  import terms.* from "./terms"
  import bounds.* from "./bounds"

  // Unified accepted-transition model for one L1 edge. This composes the
  // object lifecycle shape from `l1.qnt` with the fee, reserve, and
  // prepaid-lifetime buckets, and it is now the only model of them: the
  // focused `lifetime.qnt` and `proof_lifetime.qnt` were deleted because
  // their subjects — budgeted/bonded lifetime policies, a self-contained
  // latest-state proof, violation proofs, stale receipts — are things
  // the kernel does not have and never had. Every assertion of theirs
  // that was about the real kernel is here, and unlike theirs it is
  // replayed against the kernel by `tests/itf.rs`.
  //
  // The edge modelled here is a Basic edge, with the two close kinds a
  // Basic edge admits. Stake and work-payment edges are NOT modelled
  // anywhere; `models/registry.md` says exactly what that leaves
  // unproven.
  //
  // This model intentionally does not try to cover invalid-transaction network
  // spam. It models accepted L1 state transitions plus disabled invalid kernel
  // shapes; admission-layer pricing for rejected transactions remains a
  // separate open question.

  type Coin =
    | MakerCoin
    | TakerCoin
    | MakerOut
    | TakerOut

  // `UnusedEdge` keeps Apalache/Quint row inference closed when maps are keyed
  // by an edge sum type. It is never live.
  type Edge =
    | Channel
    | UnusedEdge

  type Proof =
    | Mutual
    | Timeout

  type FundingShape =
    | FullFunding
    | MakerOnlyFunding
    | TakerOnlyFunding
    | EmptyFunding
    | SelfFunding

  // Parties named by the channel terms and open authorization. Native and
  // WebAuthn are concrete witness encodings for these same party keys; the
  // fee model does not introduce an extra open-auth key namespace. One-sided
  // and empty funding can still require both parties to consent, while a
  // self-edge intentionally names the same party key twice.
  type OpenParties = { maker: Party, taker: Party }

  type CloseOutcome =
    | NoClose
    | ClosedMutual
    | ClosedTimeout

  type Input =
    | NoInput
    | OpenInput(FundingShape)
    | CloseInput(Proof)
    | RejectedOpenInput(FundingShape)
    | RejectedCloseInput(Proof)
    | RaiseFeeInput
    | TickInput
    | IdleInput

  type Event =
    | NoEvent
    | EdgeOpenedEvent
    | EdgeClosedEvent

  var coins: Coin -> int
  var edges: Edge -> int
  var reserves: Edge -> int
  var closeFees: Edge -> int
  var edgeShape: Edge -> FundingShape
  var edgeParties: Edge -> OpenParties
  var liveCoins: Set[Coin]
  var liveEdges: Set[Edge]
  var paid: int
  var height: int
  var currentCloseFee: int
  var closeOutcome: CloseOutcome
  var lastInput: Input
  var lastEvent: Event

  pure val AllCoins = Set(MakerCoin, TakerCoin, MakerOut, TakerOut)
  pure val AllEdges = Set(Channel)
  pure val AllFundingShapes = Set(
    FullFunding,
    MakerOnlyFunding,
    TakerOnlyFunding,
    EmptyFunding,
    SelfFunding,
  )

  pure val TimeoutHeight = 2
  pure val MakerValue = 40
  pure val TakerValue = 40
  pure val OpenFee = 10
  pure val OneInputOpenFee = 7
  pure val LifetimePricePerBlock = 3
  pure val PaidLifetimeBlocks = TimeoutHeight - 1
  pure val LifetimeFee = LifetimePricePerBlock * PaidLifetimeBlocks
  pure val CloseReserve = 16
  pure val BaseCloseFee = 10
  pure val RaisedCloseFee = CloseReserve + 2
  pure val ReserveSurplus = CloseReserve - BaseCloseFee
  pure val TotalPrincipal = MakerValue + TakerValue
  pure val GenesisTotal = TotalPrincipal

  pure val EmptyParties: OpenParties = { maker: Adversary, taker: Adversary }

  pure def coinOwner(id: Coin): Party =
    match id {
      | MakerCoin => Maker
      | MakerOut => Maker
      | TakerCoin => Taker
      | TakerOut => Taker
    }

  pure def makerInputs(shape: FundingShape): Set[Coin] =
    match shape {
      | FullFunding => Set(MakerCoin)
      | MakerOnlyFunding => Set(MakerCoin)
      | TakerOnlyFunding => Set()
      | EmptyFunding => Set()
      | SelfFunding => Set(MakerCoin)
    }

  pure def takerInputs(shape: FundingShape): Set[Coin] =
    match shape {
      | FullFunding => Set(TakerCoin)
      | MakerOnlyFunding => Set()
      | TakerOnlyFunding => Set(TakerCoin)
      | EmptyFunding => Set()
      | SelfFunding => Set()
    }

  pure def fundingInputs(shape: FundingShape): Set[Coin] =
    makerInputs(shape).union(takerInputs(shape))

  pure def openPartiesFor(shape: FundingShape): OpenParties =
    match shape {
      | FullFunding => { maker: Maker, taker: Taker }
      | MakerOnlyFunding => { maker: Maker, taker: Taker }
      | TakerOnlyFunding => { maker: Maker, taker: Taker }
      | EmptyFunding => { maker: Maker, taker: Taker }
      | SelfFunding => { maker: Maker, taker: Maker }
    }

  pure def fundingInputsOwnedByOpenParties(
    shape: FundingShape,
    parties: OpenParties,
  ): bool =
    makerInputs(shape).forall(id => coinOwner(id) == parties.maker)
      and takerInputs(shape).forall(id => coinOwner(id) == parties.taker)

  pure def openAuthorizationOk(shape: FundingShape, parties: OpenParties): bool =
    parties == openPartiesFor(shape)
      and parties.maker != Adversary
      and parties.taker != Adversary
      and fundingInputsOwnedByOpenParties(shape, parties)

  pure def fundingTotalFor(shape: FundingShape): int =
    match shape {
      | FullFunding => MakerValue + TakerValue
      | MakerOnlyFunding => MakerValue
      | TakerOnlyFunding => TakerValue
      | EmptyFunding => 0
      | SelfFunding => MakerValue
    }

  pure def openFeeFor(shape: FundingShape): int =
    match shape {
      | EmptyFunding => 0
      | FullFunding => OpenFee
      | MakerOnlyFunding => OneInputOpenFee
      | TakerOnlyFunding => OneInputOpenFee
      | SelfFunding => OneInputOpenFee
    }

  pure def lifetimeFeeFor(shape: FundingShape): int =
    match shape {
      | EmptyFunding => 0
      | FullFunding => LifetimeFee
      | MakerOnlyFunding => LifetimeFee
      | TakerOnlyFunding => LifetimeFee
      | SelfFunding => LifetimeFee
    }

  pure def closeReserveFor(shape: FundingShape): int =
    match shape {
      | EmptyFunding => 0
      | FullFunding => CloseReserve
      | MakerOnlyFunding => CloseReserve
      | TakerOnlyFunding => CloseReserve
      | SelfFunding => CloseReserve
    }

  pure def committedCloseFeeFor(shape: FundingShape): int =
    match shape {
      | EmptyFunding => 0
      | FullFunding => BaseCloseFee
      | MakerOnlyFunding => BaseCloseFee
      | TakerOnlyFunding => BaseCloseFee
      | SelfFunding => BaseCloseFee
    }

  pure def openDebitFor(shape: FundingShape): int =
    openFeeFor(shape) + lifetimeFeeFor(shape) + closeReserveFor(shape)

  pure def principalFor(shape: FundingShape): int =
    fundingTotalFor(shape) - openDebitFor(shape)

  pure def reserveSurplusFor(shape: FundingShape): int =
    closeReserveFor(shape) - committedCloseFeeFor(shape)

  pure def makerPrincipalFor(shape: FundingShape): int =
    match shape {
      | FullFunding => 26
      | MakerOnlyFunding => principalFor(shape)
      | TakerOnlyFunding => 0
      | EmptyFunding => 0
      | SelfFunding => principalFor(shape)
    }

  pure def takerPrincipalFor(shape: FundingShape): int =
    principalFor(shape) - makerPrincipalFor(shape)

  pure def makerReserveSurplusFor(shape: FundingShape): int =
    match shape {
      | FullFunding => 3
      | MakerOnlyFunding => reserveSurplusFor(shape)
      | TakerOnlyFunding => 0
      | EmptyFunding => 0
      | SelfFunding => reserveSurplusFor(shape)
    }

  pure def takerReserveSurplusFor(shape: FundingShape): int =
    reserveSurplusFor(shape) - makerReserveSurplusFor(shape)

  pure def makerPayoutFor(shape: FundingShape): int =
    makerPrincipalFor(shape) + makerReserveSurplusFor(shape)

  pure def takerPayoutFor(shape: FundingShape): int =
    takerPrincipalFor(shape) + takerReserveSurplusFor(shape)

  pure def termsFor(shape: FundingShape): EconomicTerms =
    basicTerms(
      makerPrincipalFor(shape),
      takerPrincipalFor(shape),
      makerReserveSurplusFor(shape),
      takerReserveSurplusFor(shape),
    )

  def liveShape: FundingShape =
    edgeShape.get(Channel)

  def coinTotal: int =
    liveCoins.fold(0, (sum, id) => sum + coins.get(id))

  def edgeTotal: int =
    liveEdges.fold(0, (sum, id) => sum + edges.get(id))

  def reserveTotal: int =
    liveEdges.fold(0, (sum, id) => sum + reserves.get(id))

  def liveEdgeCount: int =
    liveEdges.size()

  def partyLiquid: Party -> int =
    AllParties.mapBy(party =>
      AllCoins.fold(0, (sum, id) =>
        if (liveCoins.contains(id) and coinOwner(id) == party) {
          sum + coins.get(id)
        } else {
          sum
        }
      )
    )

  def fundingValue(shape: FundingShape): int =
    fundingInputs(shape).fold(0, (sum, id) => sum + coins.get(id))

  def reserveSurplusLive: int =
    if (liveEdges.contains(Channel)) {
      reserves.get(Channel) - closeFees.get(Channel)
    } else {
      0
    }

  def currentTerms: EconomicTerms =
    if (liveEdges.contains(Channel)) {
      termsFor(liveShape)
    } else {
      EmptyTerms
    }

  def proofOk(p: Proof): bool =
    match p {
      | Mutual => height < TimeoutHeight
      | Timeout => height >= TimeoutHeight
    }

  def canOpen(shape: FundingShape): bool =
    not(liveEdges.contains(Channel))
      and liveEdges.size() == 0
      and edges.get(Channel) == 0
      and reserves.get(Channel) == 0
      and closeFees.get(Channel) == 0
      and height < TimeoutHeight
      and openAuthorizationOk(shape, openPartiesFor(shape))
      and fundingInputs(shape).forall(id => liveCoins.contains(id))
      and fundingValue(shape) == fundingTotalFor(shape)
      and fundingValue(shape) >= openDebitFor(shape)
      and not(liveCoins.contains(MakerOut))
      and not(liveCoins.contains(TakerOut))

  def canClose(p: Proof): bool =
    liveEdges.contains(Channel)
      and edges.get(Channel) == principalFor(liveShape)
      and reserves.get(Channel) == closeReserveFor(liveShape)
      and closeFees.get(Channel) == committedCloseFeeFor(liveShape)
      and reserves.get(Channel) >= closeFees.get(Channel)
      and proofOk(p)
      and not(liveCoins.contains(MakerOut))
      and not(liveCoins.contains(TakerOut))

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
    closeFees' = AllEdges.mapBy(_ => 0),
    edgeShape' = AllEdges.mapBy(_ => FullFunding),
    edgeParties' = AllEdges.mapBy(_ => EmptyParties),
    liveCoins' = Set(MakerCoin, TakerCoin),
    liveEdges' = Set(),
    paid' = 0,
    height' = 1,
    currentCloseFee' = BaseCloseFee,
    closeOutcome' = NoClose,
    lastInput' = NoInput,
    lastEvent' = NoEvent,
  }

  action initUnderfunded = all {
    coins' = AllCoins.mapBy(id =>
      if (id == MakerCoin) {
        20
      } else if (id == TakerCoin) {
        TakerValue
      } else {
        0
      }
    ),
    edges' = AllEdges.mapBy(_ => 0),
    reserves' = AllEdges.mapBy(_ => 0),
    closeFees' = AllEdges.mapBy(_ => 0),
    edgeShape' = AllEdges.mapBy(_ => FullFunding),
    edgeParties' = AllEdges.mapBy(_ => EmptyParties),
    liveCoins' = Set(MakerCoin, TakerCoin),
    liveEdges' = Set(),
    paid' = 0,
    height' = 1,
    currentCloseFee' = BaseCloseFee,
    closeOutcome' = NoClose,
    lastInput' = NoInput,
    lastEvent' = NoEvent,
  }

  action openBy(s) = all {
    canOpen(s),
    coins' = AllCoins.mapBy(id =>
      if (fundingInputs(s).contains(id)) {
        0
      } else {
        coins.get(id)
      }
    ),
    edges' = edges.set(Channel, principalFor(s)),
    reserves' = reserves.set(Channel, closeReserveFor(s)),
    closeFees' = closeFees.set(Channel, committedCloseFeeFor(s)),
    edgeShape' = edgeShape.set(Channel, s),
    edgeParties' = edgeParties.set(Channel, openPartiesFor(s)),
    liveCoins' = liveCoins.exclude(fundingInputs(s)),
    liveEdges' = liveEdges.union(Set(Channel)),
    paid' = paid + openFeeFor(s) + lifetimeFeeFor(s),
    height' = height,
    currentCloseFee' = currentCloseFee,
    closeOutcome' = NoClose,
    lastInput' = OpenInput(s),
    lastEvent' = EdgeOpenedEvent,
  }

  action closeMutual = all {
    canClose(Mutual),
    coins' = coins
      .set(MakerOut, makerPayoutFor(liveShape))
      .set(TakerOut, takerPayoutFor(liveShape)),
    edges' = edges.set(Channel, 0),
    reserves' = reserves.set(Channel, 0),
    closeFees' = closeFees.set(Channel, 0),
    edgeShape' = edgeShape,
    edgeParties' = edgeParties,
    liveCoins' = liveCoins.union(Set(MakerOut, TakerOut)),
    liveEdges' = liveEdges.exclude(Set(Channel)),
    paid' = paid + committedCloseFeeFor(liveShape),
    height' = height,
    currentCloseFee' = currentCloseFee,
    closeOutcome' = ClosedMutual,
    lastInput' = CloseInput(Mutual),
    lastEvent' = EdgeClosedEvent,
  }

  action closeTimeout = all {
    canClose(Timeout),
    coins' = coins
      .set(MakerOut, makerPayoutFor(liveShape))
      .set(TakerOut, takerPayoutFor(liveShape)),
    edges' = edges.set(Channel, 0),
    reserves' = reserves.set(Channel, 0),
    closeFees' = closeFees.set(Channel, 0),
    edgeShape' = edgeShape,
    edgeParties' = edgeParties,
    liveCoins' = liveCoins.union(Set(MakerOut, TakerOut)),
    liveEdges' = liveEdges.exclude(Set(Channel)),
    paid' = paid + committedCloseFeeFor(liveShape),
    height' = height,
    currentCloseFee' = currentCloseFee,
    closeOutcome' = ClosedTimeout,
    lastInput' = CloseInput(Timeout),
    lastEvent' = EdgeClosedEvent,
  }

  action raiseFee = all {
    liveEdges.contains(Channel),
    currentCloseFee == BaseCloseFee,
    coins' = coins,
    edges' = edges,
    reserves' = reserves,
    closeFees' = closeFees,
    edgeShape' = edgeShape,
    edgeParties' = edgeParties,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    paid' = paid,
    height' = height,
    currentCloseFee' = RaisedCloseFee,
    closeOutcome' = closeOutcome,
    lastInput' = RaiseFeeInput,
    lastEvent' = NoEvent,
  }

  // A rejected open attempt: `openBy`'s precondition fails, state is
  // untouched, and the attempt is recorded so the Rust ITF runner can
  // replay it against the kernel and assert it is rejected with the
  // store unchanged (no specific error is asserted; the model records
  // no rejection reason).
  action rejectOpen(s) = all {
    not(canOpen(s)),
    coins' = coins,
    edges' = edges,
    reserves' = reserves,
    closeFees' = closeFees,
    edgeShape' = edgeShape,
    edgeParties' = edgeParties,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    paid' = paid,
    height' = height,
    currentCloseFee' = currentCloseFee,
    closeOutcome' = closeOutcome,
    lastInput' = RejectedOpenInput(s),
    lastEvent' = NoEvent,
  }

  // A rejected close attempt: the dual of `rejectOpen` for the close
  // actions. The recorded proof kind tells the Rust runner which close
  // shape to replay.
  action rejectClose(p) = all {
    not(canClose(p)),
    coins' = coins,
    edges' = edges,
    reserves' = reserves,
    closeFees' = closeFees,
    edgeShape' = edgeShape,
    edgeParties' = edgeParties,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    paid' = paid,
    height' = height,
    currentCloseFee' = currentCloseFee,
    closeOutcome' = closeOutcome,
    lastInput' = RejectedCloseInput(p),
    lastEvent' = NoEvent,
  }

  action tick = all {
    height < TimeoutHeight,
    coins' = coins,
    edges' = edges,
    reserves' = reserves,
    closeFees' = closeFees,
    edgeShape' = edgeShape,
    edgeParties' = edgeParties,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    paid' = paid,
    height' = height + 1,
    currentCloseFee' = currentCloseFee,
    closeOutcome' = closeOutcome,
    lastInput' = TickInput,
    lastEvent' = NoEvent,
  }

  action idle = all {
    coins' = coins,
    edges' = edges,
    reserves' = reserves,
    closeFees' = closeFees,
    edgeShape' = edgeShape,
    edgeParties' = edgeParties,
    liveCoins' = liveCoins,
    liveEdges' = liveEdges,
    paid' = paid,
    height' = height,
    currentCloseFee' = currentCloseFee,
    closeOutcome' = closeOutcome,
    lastInput' = IdleInput,
    lastEvent' = NoEvent,
  }

  action step = any {
    openBy(FullFunding),
    openBy(MakerOnlyFunding),
    openBy(TakerOnlyFunding),
    openBy(EmptyFunding),
    openBy(SelfFunding),
    closeMutual,
    closeTimeout,
    raiseFee,
    tick,
  }

  val valueAccounted =
    coinTotal + edgeTotal + reserveTotal + paid == GenesisTotal

  val partyValueAccounted =
    partyTotal(partyLiquid) + edgeTotal + reserveTotal + paid == GenesisTotal

  val constantsBalanced =
    PaidLifetimeBlocks == TimeoutHeight - 1
      and LifetimeFee == LifetimePricePerBlock * PaidLifetimeBlocks
      and ReserveSurplus == CloseReserve - BaseCloseFee
      and AllFundingShapes.forall(shape =>
        principalFor(shape) + openDebitFor(shape) == fundingTotalFor(shape)
          and reserveSurplusFor(shape) == closeReserveFor(shape) - committedCloseFeeFor(shape)
          and principalTotal(termsFor(shape)) == principalFor(shape)
          and reserveSurplusTotal(termsFor(shape)) == reserveSurplusFor(shape)
      )

  val noNegativeBucket =
    AllCoins.forall(id => coins.get(id) >= 0)
      and AllEdges.forall(id => edges.get(id) >= 0)
      and AllEdges.forall(id => reserves.get(id) >= 0)
      and AllEdges.forall(id => closeFees.get(id) >= 0)
      and paid >= 0

  val reserveAtLeastCommittedFee =
    liveEdges.forall(id => reserves.get(id) >= closeFees.get(id))

  val paidIsLifecycleAmount =
    paid == 0
      or AllFundingShapes.exists(shape =>
        paid == openFeeFor(shape) + lifetimeFeeFor(shape)
          or paid == openFeeFor(shape) + lifetimeFeeFor(shape) + committedCloseFeeFor(shape))

  val currentCloseFeeKnown =
    currentCloseFee == BaseCloseFee or currentCloseFee == RaisedCloseFee

  val heightAtLeastGenesis =
    height >= 1

  val atMostOneLiveEdge =
    liveEdgeCount <= 1

  val liveCoinsAreKnown =
    liveCoins.subseteq(AllCoins)

  val liveEdgesAreKnown =
    liveEdges.subseteq(AllEdges)

  val deadSlotsAreZero =
    AllCoins.forall(id => liveCoins.contains(id) or coins.get(id) == 0)
      and AllEdges.forall(id =>
        liveEdges.contains(id)
          or all {
            edges.get(id) == 0,
            reserves.get(id) == 0,
            closeFees.get(id) == 0,
          })

  val liveEdgesCarryPrincipalAndReserve =
    liveEdges.forall(id =>
      edges.get(id) == principalFor(edgeShape.get(id))
        and reserves.get(id) == closeReserveFor(edgeShape.get(id))
        and closeFees.get(id) == committedCloseFeeFor(edgeShape.get(id)))

  val reserveLivesWithEdge =
    AllEdges.forall(id =>
      if (liveEdges.contains(id)) {
        reserves.get(id) == closeReserveFor(edgeShape.get(id))
      } else {
        reserves.get(id) == 0
      })

  val closeFeeLivesWithEdge =
    AllEdges.forall(id =>
      if (liveEdges.contains(id)) {
        closeFees.get(id) == committedCloseFeeFor(edgeShape.get(id))
      } else {
        closeFees.get(id) == 0
      })

  val termsCoherentForClose =
    termsCoherent(currentTerms, edgeTotal, reserveSurplusLive)

  val escapeHatchBoundsNonNegative =
    allEscapeHatchBoundsNonNegative(partyLiquid, currentTerms)

  val escapeHatchTotalMatchesRecoverableValue =
    totalEscapeHatchLowerBound(partyLiquid, currentTerms)
      == partyTotal(partyLiquid) + edgeTotal + reserveSurplusLive

  val fundingShapeDecisionsCoherent =
    openDebitFor(EmptyFunding) == 0
      and fundingTotalFor(EmptyFunding) == 0
      and openPartiesFor(SelfFunding).maker == openPartiesFor(SelfFunding).taker
      and openPartiesFor(FullFunding).maker != openPartiesFor(FullFunding).taker
      and (canOpen(EmptyFunding) implies fundingValue(EmptyFunding) == 0)
      and AllFundingShapes.forall(shape => openAuthorizationOk(shape, openPartiesFor(shape)))

  val fundingAuthorized =
    liveEdges.forall(id =>
      openAuthorizationOk(edgeShape.get(id), edgeParties.get(id)))

  val expiredLiveHasTimeoutPath =
    not(liveEdges.contains(Channel)) or height < TimeoutHeight or canClose(Timeout)

  val nonTimeoutProofsExpire =
    height < TimeoutHeight or not(canClose(Mutual))







  run fullFundingMutualTraceTest =
    init
      .then(openBy(FullFunding))
      .then(closeMutual)
      .expect(valueAccounted
        and partyValueAccounted
        and paid == openFeeFor(FullFunding) + lifetimeFeeFor(FullFunding) + committedCloseFeeFor(FullFunding)
        and termsCoherentForClose
        and deadSlotsAreZero)

  run makerOnlyFundingTraceTest =
    init
      .then(openBy(MakerOnlyFunding))
      .then(closeMutual)
      .expect(valueAccounted
        and partyValueAccounted
        and coins.get(TakerCoin) == TakerValue
        and coins.get(MakerOut) == principalFor(MakerOnlyFunding) + reserveSurplusFor(MakerOnlyFunding)
        and paid == openFeeFor(MakerOnlyFunding) + lifetimeFeeFor(MakerOnlyFunding) + committedCloseFeeFor(MakerOnlyFunding)
        and termsCoherentForClose)

  run takerOnlyFundingTraceTest =
    init
      .then(openBy(TakerOnlyFunding))
      .then(closeMutual)
      .expect(valueAccounted
        and partyValueAccounted
        and coins.get(MakerCoin) == MakerValue
        and coins.get(TakerOut) == principalFor(TakerOnlyFunding) + reserveSurplusFor(TakerOnlyFunding)
        and paid == openFeeFor(TakerOnlyFunding) + lifetimeFeeFor(TakerOnlyFunding) + committedCloseFeeFor(TakerOnlyFunding)
        and termsCoherentForClose)

  run emptyFundingTraceTest =
    init
      .then(openBy(EmptyFunding))
      .then(closeMutual)
      .expect(valueAccounted
        and partyValueAccounted
        and paid == 0
        and coins.get(MakerCoin) == MakerValue
        and coins.get(TakerCoin) == TakerValue
        and openDebitFor(EmptyFunding) == 0
        and termsCoherentForClose)

  run selfEdgeTraceTest =
    init
      .then(openBy(SelfFunding))
      .then(closeMutual)
      .expect(valueAccounted
        and partyValueAccounted
        and openPartiesFor(SelfFunding).maker == openPartiesFor(SelfFunding).taker
        and coins.get(TakerCoin) == TakerValue
        and coins.get(MakerOut) == principalFor(SelfFunding) + reserveSurplusFor(SelfFunding))

  run underfundedOneSidedOpenRejectedTest =
    initUnderfunded
      .then(rejectOpen(MakerOnlyFunding))
      .expect(not(canOpen(MakerOnlyFunding)))

  // The fee-raise property, and the only assertion `lifetime.qnt` and
  // `proof_lifetime.qnt` held that this model did not already hold when
  // they were deleted. Both spelled it as an invariant
  // (`feeRaiseCannotStrandClose`) of the form `A or B or C` where `A or
  // C` was another invariant, so `currentCloseFee` never did any work
  // and the property held precisely *because* close pricing ignores the
  // raised fee — it could not have caught a regression that honoured it.
  //
  // Here it is a reachability witness with the stranding shape stated
  // outright: after the raise the current fee genuinely exceeds the
  // whole reserve, and the close is STILL available, because it is
  // priced at the schedule committed on the edge at open. The Rust side
  // is not a restatement — `tests/itf.rs` replays this trace's sibling
  // `feeRaiseThenCloseTraceTest` against the kernel under the RAISED
  // schedule, so a kernel that priced the close from `Context::fees`
  // fails it with `ReserveTooSmall`.
  run feeRaiseDoesNotStrandCloseTest =
    init
      .then(openBy(FullFunding))
      .then(raiseFee)
      .expect(valueAccounted
        and partyValueAccounted
        and currentCloseFee == RaisedCloseFee
        and currentCloseFee > reserves.get(Channel)
        and closeFees.get(Channel) == BaseCloseFee
        and canClose(Mutual)
        and reserveAtLeastCommittedFee
        and liveEdgesCarryPrincipalAndReserve)

  run feeRaiseThenCloseTraceTest =
    init
      .then(openBy(FullFunding))
      .then(raiseFee)
      .then(closeMutual)
      .expect(valueAccounted
        and partyValueAccounted
        and currentCloseFee == RaisedCloseFee
        and closeOutcome == ClosedMutual
        and paid == openFeeFor(FullFunding) + lifetimeFeeFor(FullFunding) + committedCloseFeeFor(FullFunding)
        and deadSlotsAreZero)

  run timeoutCloseTraceTest =
    init
      .then(openBy(FullFunding))
      .then(tick)
      .then(closeTimeout)
      .expect(valueAccounted
        and partyValueAccounted
        and paid == openFeeFor(FullFunding) + lifetimeFeeFor(FullFunding) + committedCloseFeeFor(FullFunding)
        and closeOutcome == ClosedTimeout
        and nonTimeoutProofsExpire)

  run expiredMutualRejectedTest =
    init
      .then(openBy(FullFunding))
      .then(tick)
      .then(rejectClose(Mutual))
      .expect(height >= TimeoutHeight
        and canClose(Timeout)
        and not(canClose(Mutual)))

  // A cooperative close of a Basic edge pays principal and charges the
  // committed close fee.
  run mutualClosePaysPrincipalTraceTest =
    init
      .then(openBy(FullFunding))
      .then(closeMutual)
      .expect(valueAccounted
        and partyValueAccounted
        and closeOutcome == ClosedMutual)
}
