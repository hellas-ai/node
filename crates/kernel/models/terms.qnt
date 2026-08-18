module terms {
  import accounting.* from "./accounting"

  // Economic terms, separated by value domain. A terms instance can describe
  // principal, reserve surplus, state-slot budget refund, state-slot bond
  // refund, and slash exposure without merging those concepts into one total.
  type EconomicTerms = {
    principal: Party -> int,
    reserveSurplus: Party -> int,
    stateBudgetRefund: Party -> int,
    stateBondRefund: Party -> int,
    slashExposure: Party -> int,
  }

  pure val EmptyTerms: EconomicTerms = {
    principal: zeroPartyValues,
    reserveSurplus: zeroPartyValues,
    stateBudgetRefund: zeroPartyValues,
    stateBondRefund: zeroPartyValues,
    slashExposure: zeroPartyValues,
  }

  pure def basicTerms(
    makerPrincipal: int,
    takerPrincipal: int,
    makerReserveSurplus: int,
    takerReserveSurplus: int,
    makerStateBudgetRefund: int,
    takerStateBudgetRefund: int,
    makerStateBondRefund: int,
    takerStateBondRefund: int,
  ): EconomicTerms = {
    principal: makerTakerValues(makerPrincipal, takerPrincipal),
    reserveSurplus: makerTakerValues(makerReserveSurplus, takerReserveSurplus),
    stateBudgetRefund: makerTakerValues(makerStateBudgetRefund, takerStateBudgetRefund),
    stateBondRefund: makerTakerValues(makerStateBondRefund, takerStateBondRefund),
    slashExposure: zeroPartyValues,
  }

  pure def principalTotal(t: EconomicTerms): int =
    partyTotal(t.principal)

  pure def reserveSurplusTotal(t: EconomicTerms): int =
    partyTotal(t.reserveSurplus)

  pure def stateBudgetRefundTotal(t: EconomicTerms): int =
    partyTotal(t.stateBudgetRefund)

  pure def stateBondRefundTotal(t: EconomicTerms): int =
    partyTotal(t.stateBondRefund)

  pure def termsNonNegative(t: EconomicTerms): bool =
    partyNonNegative(t.principal)
      and partyNonNegative(t.reserveSurplus)
      and partyNonNegative(t.stateBudgetRefund)
      and partyNonNegative(t.stateBondRefund)
      and partyNonNegative(t.slashExposure)

  pure def termsCoherent(
    t: EconomicTerms,
    principal: int,
    reserveSurplus: int,
    stateBudgetRefund: int,
    stateBondRefund: int,
  ): bool =
    termsNonNegative(t)
      and principalTotal(t) == principal
      and reserveSurplusTotal(t) == reserveSurplus
      and stateBudgetRefundTotal(t) == stateBudgetRefund
      and stateBondRefundTotal(t) == stateBondRefund
}
