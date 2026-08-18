module bounds {
  import accounting.* from "./accounting"
  import terms.* from "./terms"

  // Current immediate escape-hatch recovery for one party. This is not yet a
  // temporal liveness claim; it is the amount the party can recover from the
  // current state if it exercises the enabled close path under the current
  // terms and witness assumptions.
  //
  // Two domains, because the kernel distributes two: the principal an edge
  // locked at open, and the part of its close reserve the close does not
  // spend. The state-budget refund and state-bond refund this used to add,
  // and the slash exposure it used to subtract, went with `lifetime.qnt`
  // and the seal apparatus — the kernel has no such buckets.
  pure def escapeHatchLowerBound(
    party: Party,
    liquid: Party -> int,
    t: EconomicTerms,
  ): int =
    liquid.get(party)
      + t.principal.get(party)
      + t.reserveSurplus.get(party)

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
}
