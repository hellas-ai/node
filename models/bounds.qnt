module bounds {
  import accounting.* from "./accounting"
  import terms.* from "./terms"

  // Current immediate escape-hatch recovery for one party. This is not yet a
  // temporal liveness claim; it is the amount the party can recover from the
  // current state if it exercises the enabled close path under the current
  // terms and witness assumptions.
  pure def escapeHatchLowerBound(
    party: Party,
    liquid: Party -> int,
    t: EconomicTerms,
  ): int =
    liquid.get(party)
      + t.principal.get(party)
      + t.reserveSurplus.get(party)
      + t.stateBudgetRefund.get(party)
      + t.stateBondRefund.get(party)
      - t.slashExposure.get(party)

  pure def allEscapeHatchBoundsNonNegative(
    liquid: Party -> int,
    t: EconomicTerms,
  ): bool =
    AllParties.forall(party => escapeHatchLowerBound(party, liquid, t) >= 0)

  pure def totalEscapeHatchLowerBound(
    liquid: Party -> int,
    t: EconomicTerms,
  ): int =
    AllParties.fold(0, (sum, party) =>
      sum + escapeHatchLowerBound(party, liquid, t)
    )

  pure def liquidOnlyBounds(
    liquid: Party -> int,
    t: EconomicTerms,
  ): bool =
    t == EmptyTerms and totalEscapeHatchLowerBound(liquid, t) == partyTotal(liquid)
}
