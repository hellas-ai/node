module accounting {
  // Shared arithmetic helpers over party-indexed economic buckets. Focused
  // models can keep their own object universes while still using the same
  // party/value algebra.

  type Party =
    | Maker
    | Taker
    | Adversary

  pure val AllParties = Set(Maker, Taker, Adversary)

  pure def partyTotal(values: Party -> int): int =
    AllParties.fold(0, (sum, party) => sum + values.get(party))

  pure def partyNonNegative(values: Party -> int): bool =
    AllParties.forall(party => values.get(party) >= 0)

  pure val zeroPartyValues: Party -> int =
    AllParties.mapBy(_ => 0)

  pure def makerTakerValues(makerValue: int, takerValue: int): Party -> int =
    AllParties.mapBy(party =>
      if (party == Maker) {
        makerValue
      } else if (party == Taker) {
        takerValue
      } else {
        0
      }
    )
}
