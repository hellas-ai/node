module lifetime {
  import accounting.* from "./accounting"
  import terms.* from "./terms"
  import bounds.* from "./bounds"

  // Focused model for active channel lifetime pricing.
  //
  // The model compares policy mechanisms while using the shared economic
  // vocabulary: party-indexed liquid/reward buckets, terms-separated value
  // domains, and an explicit escape-hatch lower-bound function.

  type LifetimePolicy =
    | NoPolicy
    | PermanentLifetime
    | BudgetedLifetime
    | BondedLifetime

  var liquid: Party -> int
  var edgePrincipal: int
  var closeReserve: int
  var stateBudget: int
  var stateBond: int
  var feesPaid: int
  var rewards: Party -> int
  var height: int
  var currentCloseFee: int
  var live: bool
  var expired: bool
  var opened: bool
  var policy: LifetimePolicy
  var edgeTerms: EconomicTerms

  pure val MakerFunding = 36
  pure val TakerFunding = 24
  pure val Funding = MakerFunding + TakerFunding
  pure val OpenFee = 5
  pure val CloseReserve = 12
  pure val PrepaidCloseFee = 8
  pure val ReserveSurplus = CloseReserve - PrepaidCloseFee
  pure val MakerReserveSurplus = 2
  pure val TakerReserveSurplus = 2
  pure val PermanentSlotFee = 9
  pure val StateBudgetInitial = 4
  pure val StateBondInitial = 4
  pure val RentPerTick = 2
  pure val GenesisHeight = 1
  pure val ExpiryHeight = 3
  pure val BaseCloseFee = 8
  pure val RaisedCloseFee = 20

  pure val PermanentPrincipal =
    Funding - OpenFee - PermanentSlotFee - CloseReserve

  pure val BudgetedPrincipal =
    Funding - OpenFee - StateBudgetInitial - CloseReserve

  pure val BondedPrincipal =
    Funding - OpenFee - StateBondInitial - CloseReserve

  pure val PermanentMakerPrincipal = 17
  pure val PermanentTakerPrincipal = 17
  pure val BudgetedMakerPrincipal = 20
  pure val BudgetedTakerPrincipal = 19
  pure val BondedMakerPrincipal = 20
  pure val BondedTakerPrincipal = 19
  pure val MakerStateBudgetRefund = 2
  pure val TakerStateBudgetRefund = 2
  pure val MakerStateBondRefund = 2
  pure val TakerStateBondRefund = 2

  def canOpenPermanent: bool =
    not(opened)
      and not(live)
      and partyTotal(liquid) >= OpenFee + PermanentSlotFee + CloseReserve

  def canOpenBudgeted: bool =
    not(opened)
      and not(live)
      and partyTotal(liquid) >= OpenFee + StateBudgetInitial + CloseReserve

  def canOpenBonded: bool =
    not(opened)
      and not(live)
      and partyTotal(liquid) >= OpenFee + StateBondInitial + CloseReserve

  def canClose: bool =
    live
      and closeReserve >= PrepaidCloseFee

  def canCollect: bool =
    live
      and expired
      and closeReserve >= PrepaidCloseFee

  def closeSurplus: int =
    if (live) {
      closeReserve - PrepaidCloseFee
    } else {
      0
    }

  pure def budgetTermsAfterRent(t: EconomicTerms): EconomicTerms = {
    principal: t.principal,
    reserveSurplus: t.reserveSurplus,
    stateBudgetRefund: t.stateBudgetRefund
      .set(Maker, t.stateBudgetRefund.get(Maker) - 1)
      .set(Taker, t.stateBudgetRefund.get(Taker) - 1),
    stateBondRefund: t.stateBondRefund,
    slashExposure: t.slashExposure,
  }

  action init = all {
    liquid' = makerTakerValues(MakerFunding, TakerFunding),
    edgePrincipal' = 0,
    closeReserve' = 0,
    stateBudget' = 0,
    stateBond' = 0,
    feesPaid' = 0,
    rewards' = zeroPartyValues,
    height' = GenesisHeight,
    currentCloseFee' = BaseCloseFee,
    live' = false,
    expired' = false,
    opened' = false,
    policy' = NoPolicy,
    edgeTerms' = EmptyTerms,
  }

  action openPermanent = all {
    canOpenPermanent,
    liquid' = zeroPartyValues,
    edgePrincipal' = PermanentPrincipal,
    closeReserve' = CloseReserve,
    stateBudget' = 0,
    stateBond' = 0,
    feesPaid' = feesPaid + OpenFee + PermanentSlotFee,
    rewards' = rewards,
    height' = height,
    currentCloseFee' = currentCloseFee,
    live' = true,
    expired' = false,
    opened' = true,
    policy' = PermanentLifetime,
    edgeTerms' = basicTerms(
      PermanentMakerPrincipal,
      PermanentTakerPrincipal,
      MakerReserveSurplus,
      TakerReserveSurplus,
      0,
      0,
      0,
      0,
    ),
  }

  action openBudgeted = all {
    canOpenBudgeted,
    liquid' = zeroPartyValues,
    edgePrincipal' = BudgetedPrincipal,
    closeReserve' = CloseReserve,
    stateBudget' = StateBudgetInitial,
    stateBond' = 0,
    feesPaid' = feesPaid + OpenFee,
    rewards' = rewards,
    height' = height,
    currentCloseFee' = currentCloseFee,
    live' = true,
    expired' = false,
    opened' = true,
    policy' = BudgetedLifetime,
    edgeTerms' = basicTerms(
      BudgetedMakerPrincipal,
      BudgetedTakerPrincipal,
      MakerReserveSurplus,
      TakerReserveSurplus,
      MakerStateBudgetRefund,
      TakerStateBudgetRefund,
      0,
      0,
    ),
  }

  action openBonded = all {
    canOpenBonded,
    liquid' = zeroPartyValues,
    edgePrincipal' = BondedPrincipal,
    closeReserve' = CloseReserve,
    stateBudget' = 0,
    stateBond' = StateBondInitial,
    feesPaid' = feesPaid + OpenFee,
    rewards' = rewards,
    height' = height,
    currentCloseFee' = currentCloseFee,
    live' = true,
    expired' = false,
    opened' = true,
    policy' = BondedLifetime,
    edgeTerms' = basicTerms(
      BondedMakerPrincipal,
      BondedTakerPrincipal,
      MakerReserveSurplus,
      TakerReserveSurplus,
      0,
      0,
      MakerStateBondRefund,
      TakerStateBondRefund,
    ),
  }

  action closeEdge = all {
    canClose,
    liquid' = AllParties.mapBy(party =>
      liquid.get(party)
        + edgeTerms.principal.get(party)
        + edgeTerms.reserveSurplus.get(party)
        + edgeTerms.stateBudgetRefund.get(party)
        + edgeTerms.stateBondRefund.get(party)
    ),
    edgePrincipal' = 0,
    closeReserve' = 0,
    stateBudget' = 0,
    stateBond' = 0,
    feesPaid' = feesPaid + PrepaidCloseFee,
    rewards' = rewards,
    height' = height,
    currentCloseFee' = currentCloseFee,
    live' = false,
    expired' = false,
    opened' = opened,
    policy' = NoPolicy,
    edgeTerms' = EmptyTerms,
  }

  action collectExpired = all {
    canCollect,
    liquid' = AllParties.mapBy(party =>
      liquid.get(party)
        + edgeTerms.principal.get(party)
        + edgeTerms.reserveSurplus.get(party)
    ),
    edgePrincipal' = 0,
    closeReserve' = 0,
    stateBudget' = 0,
    stateBond' = 0,
    feesPaid' = feesPaid + PrepaidCloseFee,
    rewards' = rewards.set(Adversary, rewards.get(Adversary) + stateBudget + stateBond),
    height' = height,
    currentCloseFee' = currentCloseFee,
    live' = false,
    expired' = false,
    opened' = opened,
    policy' = NoPolicy,
    edgeTerms' = EmptyTerms,
  }

  action tickNoLive = all {
    not(live),
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    stateBudget' = stateBudget,
    stateBond' = stateBond,
    feesPaid' = feesPaid,
    rewards' = rewards,
    height' = height + 1,
    currentCloseFee' = currentCloseFee,
    live' = live,
    expired' = expired,
    opened' = opened,
    policy' = policy,
    edgeTerms' = edgeTerms,
  }

  action tickPermanent = all {
    live,
    policy == PermanentLifetime,
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    stateBudget' = stateBudget,
    stateBond' = stateBond,
    feesPaid' = feesPaid,
    rewards' = rewards,
    height' = height + 1,
    currentCloseFee' = currentCloseFee,
    live' = live,
    expired' = false,
    opened' = opened,
    policy' = policy,
    edgeTerms' = edgeTerms,
  }

  action tickBudgeted = all {
    live,
    policy == BudgetedLifetime,
    not(expired),
    stateBudget >= RentPerTick,
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    stateBudget' = stateBudget - RentPerTick,
    stateBond' = stateBond,
    feesPaid' = feesPaid + RentPerTick,
    rewards' = rewards,
    height' = height + 1,
    currentCloseFee' = currentCloseFee,
    live' = live,
    expired' = stateBudget == RentPerTick,
    opened' = opened,
    policy' = policy,
    edgeTerms' = budgetTermsAfterRent(edgeTerms),
  }

  action tickBonded = all {
    live,
    policy == BondedLifetime,
    not(expired),
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    stateBudget' = stateBudget,
    stateBond' = stateBond,
    feesPaid' = feesPaid,
    rewards' = rewards,
    height' = height + 1,
    currentCloseFee' = currentCloseFee,
    live' = live,
    expired' = height + 1 >= ExpiryHeight,
    opened' = opened,
    policy' = policy,
    edgeTerms' = edgeTerms,
  }

  action raiseFee = all {
    currentCloseFee == BaseCloseFee,
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    stateBudget' = stateBudget,
    stateBond' = stateBond,
    feesPaid' = feesPaid,
    rewards' = rewards,
    height' = height,
    currentCloseFee' = RaisedCloseFee,
    live' = live,
    expired' = expired,
    opened' = opened,
    policy' = policy,
    edgeTerms' = edgeTerms,
  }

  action step = any {
    openPermanent,
    openBudgeted,
    openBonded,
    closeEdge,
    collectExpired,
    tickNoLive,
    tickPermanent,
    tickBudgeted,
    tickBonded,
    raiseFee,
  }

  val valueAccounted =
    partyTotal(liquid)
      + edgePrincipal
      + closeReserve
      + stateBudget
      + stateBond
      + feesPaid
      + partyTotal(rewards) == Funding

  val noNegativeBucket =
    partyNonNegative(liquid)
      and edgePrincipal >= 0
      and closeReserve >= 0
      and stateBudget >= 0
      and stateBond >= 0
      and feesPaid >= 0
      and partyNonNegative(rewards)

  val closeReserveCoversCommittedFee =
    not(live) or closeReserve >= PrepaidCloseFee

  val closeAlwaysAvailableWhenLive =
    not(live) or canClose

  val feeRaiseCannotStrandClose =
    not(live) or currentCloseFee <= closeReserve or canClose

  val liveCloseReserveIsNotRent =
    not(live) or closeReserve == CloseReserve

  val expiredLiveHasCleanup =
    not(live) or not(expired) or (canClose and canCollect)

  val termsCoherentForLiveState =
    termsCoherent(edgeTerms, edgePrincipal, closeSurplus, stateBudget, stateBond)

  val escapeHatchBoundsNonNegative =
    allEscapeHatchBoundsNonNegative(liquid, edgeTerms)

  val escapeHatchTotalMatchesRecoverableValue =
    totalEscapeHatchLowerBound(liquid, edgeTerms)
      == partyTotal(liquid) + edgePrincipal + closeSurplus + stateBudget + stateBond

  val collectorRewardsOnlySlotValue =
    rewards.get(Maker) == 0
      and rewards.get(Taker) == 0
      and rewards.get(Adversary) <= StateBudgetInitial + StateBondInitial

  val policyBucketsConsistent =
    if (live) {
      if (policy == PermanentLifetime) {
        edgePrincipal == PermanentPrincipal
          and stateBudget == 0
          and stateBond == 0
          and not(expired)
      } else if (policy == BudgetedLifetime) {
        edgePrincipal == BudgetedPrincipal and stateBond == 0
      } else if (policy == BondedLifetime) {
        edgePrincipal == BondedPrincipal and stateBudget == 0
      } else {
        false
      }
    } else {
      edgePrincipal == 0
        and closeReserve == 0
        and stateBudget == 0
        and stateBond == 0
        and not(expired)
        and edgeTerms == EmptyTerms
    }

  val currentCloseFeeKnown =
    currentCloseFee == BaseCloseFee or currentCloseFee == RaisedCloseFee

  val heightAtLeastGenesis =
    height >= GenesisHeight

  run permanentCloseAfterFeeRaiseTest =
    init
      .then(openPermanent)
      .then(raiseFee)
      .then(tickPermanent)
      .then(closeEdge)
      .expect(not(live)
        and valueAccounted
        and termsCoherentForLiveState
        and escapeHatchBoundsNonNegative
        and currentCloseFee == RaisedCloseFee
        and feesPaid == OpenFee + PermanentSlotFee + PrepaidCloseFee
        and partyTotal(liquid) == PermanentPrincipal + ReserveSurplus)

  run budgetedRentConsumesBudgetOnlyTest =
    init
      .then(openBudgeted)
      .then(tickBudgeted)
      .expect(live
        and valueAccounted
        and canClose
        and termsCoherentForLiveState
        and escapeHatchBoundsNonNegative
        and escapeHatchLowerBound(Maker, liquid, edgeTerms) == 23
        and closeReserve == CloseReserve
        and stateBudget == StateBudgetInitial - RentPerTick
        and feesPaid == OpenFee + RentPerTick)

  run budgetedExpiredStillClosableTest =
    init
      .then(openBudgeted)
      .then(tickBudgeted)
      .then(tickBudgeted)
      .then(raiseFee)
      .expect(live
        and expired
        and currentCloseFee == RaisedCloseFee
        and canClose
        and canCollect
        and termsCoherentForLiveState
        and escapeHatchBoundsNonNegative
        and closeReserve == CloseReserve)

  run bondedExpiryCollectsOnlyBondTest =
    init
      .then(openBonded)
      .then(tickBonded)
      .then(tickBonded)
      .then(collectExpired)
      .expect(not(live)
        and valueAccounted
        and termsCoherentForLiveState
        and escapeHatchBoundsNonNegative
        and collectorRewardsOnlySlotValue
        and rewards.get(Adversary) == StateBondInitial
        and feesPaid == OpenFee + PrepaidCloseFee
        and partyTotal(liquid) == BondedPrincipal + ReserveSurplus)

  run closeReturnsUnspentBudgetTest =
    init
      .then(openBudgeted)
      .then(tickBudgeted)
      .then(closeEdge)
      .expect(not(live)
        and valueAccounted
        and termsCoherentForLiveState
        and escapeHatchBoundsNonNegative
        and partyTotal(rewards) == 0
        and feesPaid == OpenFee + RentPerTick + PrepaidCloseFee
        and partyTotal(liquid) == BudgetedPrincipal
          + ReserveSurplus
          + StateBudgetInitial
          - RentPerTick)
}
