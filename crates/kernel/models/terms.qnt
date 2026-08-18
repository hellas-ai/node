module terms {
  import accounting.* from "./accounting"

  // Economic terms, separated by value domain. A terms instance describes
  // the two domains a close of a real edge distributes: the principal the
  // edge locked at open, and the part of the close reserve this close does
  // not spend.
  //
  // There were three more — a state-budget refund, a state-bond refund,
  // and a slash exposure. They were the vocabulary of `lifetime.qnt`'s
  // budgeted/bonded policy alternatives and of the deleted seal
  // apparatus, and the kernel has none of them: it charges one prepaid
  // lifetime fee at open, holds one close reserve, and slashes nothing.
  // They are deleted rather than pinned to zero, because a value domain
  // every caller passes zero for is a domain a reader will believe the
  // kernel has.
  type EconomicTerms = {
    principal: Party -> int,
    reserveSurplus: Party -> int,
  }

  pure val EmptyTerms: EconomicTerms = {
    principal: zeroPartyValues,
    reserveSurplus: zeroPartyValues,
  }

  pure def basicTerms(
    makerPrincipal: int,
    takerPrincipal: int,
    makerReserveSurplus: int,
    takerReserveSurplus: int,
  ): EconomicTerms = {
    principal: makerTakerValues(makerPrincipal, takerPrincipal),
    reserveSurplus: makerTakerValues(makerReserveSurplus, takerReserveSurplus),
  }

  pure def principalTotal(t: EconomicTerms): int =
    partyTotal(t.principal)

  pure def reserveSurplusTotal(t: EconomicTerms): int =
    partyTotal(t.reserveSurplus)

  pure def termsNonNegative(t: EconomicTerms): bool =
    partyNonNegative(t.principal)
      and partyNonNegative(t.reserveSurplus)

  pure def termsCoherent(
    t: EconomicTerms,
    principal: int,
    reserveSurplus: int,
  ): bool =
    termsNonNegative(t)
      and principalTotal(t) == principal
      and reserveSurplusTotal(t) == reserveSurplus
}
