module terms {
  import accounting.* from "./accounting"
  import proofs.* from "./proofs"

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

  // Payoff-relevant terms for rational incentive checks. These are separate
  // from `EconomicTerms`: `EconomicTerms` describes value movement accepted by
  // L1, while `IncentiveTerms` describes the off-chain payoff comparison that
  // should make cooperation preferable to rational deviation.
  type DeviationKind =
    | ProofObligationBreachDeviation
    | StaleReceiptDeviation
    | BadComputeDeviation

  type PenaltySource =
    | NoPenaltySource
    | PostedStakeSource

  pure val AllDeviationKinds = Set(
    ProofObligationBreachDeviation,
    StaleReceiptDeviation,
    BadComputeDeviation,
  )

  type IncentiveTerms = {
    latest: Party -> int,
    timeout: Party -> int,
    staleReceipt: Party -> int,
    proofCost: int,
    rejectedReceiptCost: int,
    deviationFriction: int,
    postedStake: int,
    proofObligationBreachPenalty: int,
    staleReceiptPenalty: int,
    badComputeGain: int,
    badComputePenalty: int,
    proofObligation: ProofSubmissionObligation,
    evidence: DeviationKind -> EvidenceKind,
    proof: DeviationKind -> ProofKind,
    penaltySource: DeviationKind -> PenaltySource,
    penaltyBudget: DeviationKind -> int,
  }

  pure def economicParty(p: Party): bool =
    p == Maker or p == Taker

  pure def positivePart(x: int): int =
    if (x > 0) {
      x
    } else {
      0
    }

  pure def max2(a: int, b: int): int =
    if (a >= b) {
      a
    } else {
      b
    }

  pure def incentiveTermsNonNegative(t: IncentiveTerms): bool =
    partyNonNegative(t.latest)
      and partyNonNegative(t.timeout)
      and partyNonNegative(t.staleReceipt)
      and t.proofCost >= 0
      and t.rejectedReceiptCost >= 0
      and t.deviationFriction >= 0
      and t.postedStake >= 0
      and t.proofObligationBreachPenalty >= 0
      and t.staleReceiptPenalty >= 0
      and t.badComputeGain >= 0
      and t.badComputePenalty >= 0
      and AllDeviationKinds.forall(kind => t.penaltyBudget.get(kind) >= 0)

  pure def incentiveTermsCoherent(t: IncentiveTerms): bool =
    incentiveTermsNonNegative(t)
      and partyTotal(t.latest) == partyTotal(t.timeout)
      and partyTotal(t.latest) == partyTotal(t.staleReceipt)

  pure def requiredProofObligationBreachPenalty(t: IncentiveTerms, p: Party): int =
    positivePart(t.timeout.get(p) - t.latest.get(p) - t.deviationFriction + 1)

  pure def requiredStaleReceiptPenalty(t: IncentiveTerms, p: Party): int =
    positivePart(t.staleReceipt.get(p) - t.latest.get(p) - t.rejectedReceiptCost + 1)

  pure def requiredBadComputePenalty(t: IncentiveTerms, _p: Party): int =
    positivePart(t.badComputeGain - t.deviationFriction + 1)

  pure def proofCostCeilingFor(t: IncentiveTerms, p: Party): int =
    positivePart(t.latest.get(p) - t.timeout.get(p) - 1)

  pure def requiredStake(t: IncentiveTerms): int =
    max2(
      enforceablePenalty(t, ProofObligationBreachDeviation),
      max2(
        enforceablePenalty(t, StaleReceiptDeviation),
        enforceablePenalty(t, BadComputeDeviation),
      ),
    )

  pure def configuredPenalty(t: IncentiveTerms, kind: DeviationKind): int =
    match kind {
      | ProofObligationBreachDeviation => t.proofObligationBreachPenalty
      | StaleReceiptDeviation => t.staleReceiptPenalty
      | BadComputeDeviation => t.badComputePenalty
    }

  pure def evidenceMatchesDeviation(kind: DeviationKind, evidence: EvidenceKind): bool =
    match kind {
      | ProofObligationBreachDeviation => evidence == ProofObligationBreachEvidence
      | StaleReceiptDeviation => evidence == SignedStaleReceiptEvidence
      | BadComputeDeviation => evidence == BadComputeEvidence
    }

  pure def proofMatchesEvidence(evidence: EvidenceKind, proof: ProofKind): bool =
    match evidence {
      | NoEvidence => false
      | ExpiryEvidence => proof == TimeoutFallbackProof
      | ProofObligationBreachEvidence => proof == ProofObligationBreachSealProof
      | SignedStaleReceiptEvidence => proof == StaleReceiptSealProof
      | BadComputeEvidence => proof == BadComputeSealProof
    }

  pure def proofObligationBacksPenalty(t: IncentiveTerms): bool =
    proofSubmissionObligationWellFormed(t.proofObligation, t.postedStake)
      and t.proofObligation.penalty == t.proofObligationBreachPenalty
      and t.proofObligation.penaltyBudget
        == t.penaltyBudget.get(ProofObligationBreachDeviation)

  pure def deviationHasPublicObligation(t: IncentiveTerms, kind: DeviationKind): bool =
    match kind {
      | ProofObligationBreachDeviation => proofObligationBacksPenalty(t)
      | StaleReceiptDeviation => true
      | BadComputeDeviation => true
    }

  pure def proofObligationSatisfied(t: IncentiveTerms, kind: DeviationKind): bool =
    evidenceMatchesDeviation(kind, t.evidence.get(kind))
      and deviationHasPublicObligation(t, kind)
      and evidenceCanProveViolation(t.evidence.get(kind))
      and proofMatchesEvidence(t.evidence.get(kind), t.proof.get(kind))
      and proofKindAdmissible(t.proof.get(kind))
      and proofCanSlash(t.proof.get(kind))

  pure def penaltyBacked(t: IncentiveTerms, kind: DeviationKind): bool =
    proofObligationSatisfied(t, kind)
      and t.penaltySource.get(kind) != NoPenaltySource
      and t.penaltyBudget.get(kind) >= configuredPenalty(t, kind)

  pure def enforceablePenalty(t: IncentiveTerms, kind: DeviationKind): int =
    if (penaltyBacked(t, kind)) {
      configuredPenalty(t, kind)
    } else {
      0
    }

  pure def incentivePenaltyRequirementsMet(t: IncentiveTerms): bool =
    AllParties.forall(party =>
      not(economicParty(party))
        or all {
          enforceablePenalty(t, ProofObligationBreachDeviation)
            >= requiredProofObligationBreachPenalty(t, party),
          enforceablePenalty(t, StaleReceiptDeviation) >= requiredStaleReceiptPenalty(t, party),
          enforceablePenalty(t, BadComputeDeviation) >= requiredBadComputePenalty(t, party),
        }
    )

  pure def incentiveProofCostBoundMet(t: IncentiveTerms): bool =
    AllParties.forall(party =>
      not(economicParty(party))
        or t.latest.get(party) <= t.timeout.get(party)
        or t.proofCost <= proofCostCeilingFor(t, party)
    )

  pure def incentiveStakeRequirementMet(t: IncentiveTerms): bool =
    requiredStake(t) <= t.postedStake
      and AllDeviationKinds.forall(kind =>
        t.penaltySource.get(kind) != PostedStakeSource
          or t.penaltyBudget.get(kind) <= t.postedStake
      )

  pure def incentiveRequirementsMet(t: IncentiveTerms): bool =
    incentiveTermsCoherent(t)
      and incentivePenaltyRequirementsMet(t)
      and incentiveProofCostBoundMet(t)
      and incentiveStakeRequirementMet(t)
}
