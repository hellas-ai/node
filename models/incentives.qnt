module incentives {
  import accounting.* from "./accounting"
  import proofs.* from "./proofs"
  import terms.* from "./terms"

  // Focused payoff model for cryptoeconomic incentives.
  //
  // Safety models say which L1 transitions are accepted. This model asks a
  // different question: under explicit expected payoff parameters, is
  // cooperation at least as good as the rational deviations we care about?
  //
  // Values are in abstract payoff units. Expected penalties may encode
  // probability-weighted stake loss, reputation loss, proof-generation cost,
  // or any other economic cost that is outside the L1 transition relation.

  type Strategy =
    | Cooperate
    | PostSelfContainedLatestProof
    | AcceptTimeoutFallback
    | BreachProofObligation
    | SubmitStaleReceipt
    | ForceCounterpartyProof
    | SubmitBadCompute

  var actor: Party
  var strategy: Strategy
  var payoffValue: int
  var counterexample: bool

  pure val GenesisHeight = 1
  pure val ProofDeadline = 3
  pure val ExpiryHeight = 5
  pure val InclusionMargin = 1
  pure val ProofObligationBreachPenalty = 9
  pure val PostedStake = 12

  pure val ScenarioProofObligation: ProofSubmissionObligation = {
    kind: SignedProofDeadlineObligation,
    obligor: Taker,
    beneficiary: Maker,
    requiredProof: RequiredSelfContainedLatestProof,
    createdAt: GenesisHeight,
    proofDeadline: ProofDeadline,
    expiryHeight: ExpiryHeight,
    inclusionMargin: InclusionMargin,
    penalty: ProofObligationBreachPenalty,
    penaltyBudget: PostedStake,
  }

  pure val UnbackedProofObligation: ProofSubmissionObligation = {
    kind: NoProofObligation,
    obligor: Taker,
    beneficiary: Maker,
    requiredProof: RequiredSelfContainedLatestProof,
    createdAt: GenesisHeight,
    proofDeadline: ProofDeadline,
    expiryHeight: ExpiryHeight,
    inclusionMargin: InclusionMargin,
    penalty: ProofObligationBreachPenalty,
    penaltyBudget: PostedStake,
  }

  pure val UnsafeLateProofObligation: ProofSubmissionObligation = {
    kind: SignedProofDeadlineObligation,
    obligor: Taker,
    beneficiary: Maker,
    requiredProof: RequiredSelfContainedLatestProof,
    createdAt: GenesisHeight,
    proofDeadline: ExpiryHeight,
    expiryHeight: ExpiryHeight,
    inclusionMargin: InclusionMargin,
    penalty: ProofObligationBreachPenalty,
    penaltyBudget: PostedStake,
  }

  pure val ScenarioTerms: IncentiveTerms = {
    latest: makerTakerValues(27, 14),
    timeout: makerTakerValues(20, 21),
    staleReceipt: makerTakerValues(18, 23),
    proofCost: 2,
    rejectedReceiptCost: 1,
    deviationFriction: 1,
    postedStake: PostedStake,
    proofObligationBreachPenalty: ProofObligationBreachPenalty,
    staleReceiptPenalty: 10,
    badComputeGain: 4,
    badComputePenalty: 8,
    proofObligation: ScenarioProofObligation,
    evidence: AllDeviationKinds.mapBy(kind =>
      match kind {
        | ProofObligationBreachDeviation => ProofObligationBreachEvidence
        | StaleReceiptDeviation => SignedStaleReceiptEvidence
        | BadComputeDeviation => BadComputeEvidence
      }
    ),
    proof: AllDeviationKinds.mapBy(kind =>
      match kind {
        | ProofObligationBreachDeviation => ProofObligationBreachSealProof
        | StaleReceiptDeviation => StaleReceiptSealProof
        | BadComputeDeviation => BadComputeSealProof
      }
    ),
    penaltySource: AllDeviationKinds.mapBy(_ => PostedStakeSource),
    penaltyBudget: AllDeviationKinds.mapBy(_ => PostedStake),
  }

  pure val UnbackedProofObligationTerms: IncentiveTerms = {
    latest: ScenarioTerms.latest,
    timeout: ScenarioTerms.timeout,
    staleReceipt: ScenarioTerms.staleReceipt,
    proofCost: ScenarioTerms.proofCost,
    rejectedReceiptCost: ScenarioTerms.rejectedReceiptCost,
    deviationFriction: ScenarioTerms.deviationFriction,
    postedStake: ScenarioTerms.postedStake,
    proofObligationBreachPenalty: ScenarioTerms.proofObligationBreachPenalty,
    staleReceiptPenalty: ScenarioTerms.staleReceiptPenalty,
    badComputeGain: ScenarioTerms.badComputeGain,
    badComputePenalty: ScenarioTerms.badComputePenalty,
    proofObligation: UnbackedProofObligation,
    evidence: ScenarioTerms.evidence.set(ProofObligationBreachDeviation, NoEvidence),
    proof: ScenarioTerms.proof.set(ProofObligationBreachDeviation, NoProof),
    penaltySource: ScenarioTerms.penaltySource,
    penaltyBudget: ScenarioTerms.penaltyBudget,
  }

  pure val UnsafeLateProofObligationTerms: IncentiveTerms = {
    latest: ScenarioTerms.latest,
    timeout: ScenarioTerms.timeout,
    staleReceipt: ScenarioTerms.staleReceipt,
    proofCost: ScenarioTerms.proofCost,
    rejectedReceiptCost: ScenarioTerms.rejectedReceiptCost,
    deviationFriction: ScenarioTerms.deviationFriction,
    postedStake: ScenarioTerms.postedStake,
    proofObligationBreachPenalty: ScenarioTerms.proofObligationBreachPenalty,
    staleReceiptPenalty: ScenarioTerms.staleReceiptPenalty,
    badComputeGain: ScenarioTerms.badComputeGain,
    badComputePenalty: ScenarioTerms.badComputePenalty,
    proofObligation: UnsafeLateProofObligation,
    evidence: ScenarioTerms.evidence,
    proof: ScenarioTerms.proof,
    penaltySource: ScenarioTerms.penaltySource,
    penaltyBudget: ScenarioTerms.penaltyBudget,
  }

  pure def cooperatePayoff(p: Party): int =
    cooperatePayoffUnder(ScenarioTerms, p)

  pure def postSelfContainedLatestProofPayoff(p: Party): int =
    ScenarioTerms.latest.get(p) - ScenarioTerms.proofCost

  pure def proofObligationBreachPayoff(p: Party): int =
    proofObligationBreachPayoffUnder(ScenarioTerms, p)

  pure def timeoutFallbackPayoff(p: Party): int =
    ScenarioTerms.timeout.get(p)

  pure def staleReceiptDeviationPayoff(p: Party): int =
    ScenarioTerms.staleReceipt.get(p)
      - ScenarioTerms.rejectedReceiptCost
      - enforceablePenalty(ScenarioTerms, StaleReceiptDeviation)

  pure def forceCounterpartyProofPayoff(p: Party): int =
    ScenarioTerms.latest.get(p) - ScenarioTerms.deviationFriction

  pure def badComputeDeviationPayoff(p: Party): int =
    ScenarioTerms.latest.get(p)
      + ScenarioTerms.badComputeGain
      - enforceablePenalty(ScenarioTerms, BadComputeDeviation)
      - ScenarioTerms.deviationFriction

  pure def cooperatePayoffUnder(t: IncentiveTerms, p: Party): int =
    t.latest.get(p)

  pure def proofObligationBreachPayoffUnder(t: IncentiveTerms, p: Party): int =
    t.timeout.get(p)
      - enforceablePenalty(t, ProofObligationBreachDeviation)
      - t.deviationFriction

  pure def payoff(p: Party, s: Strategy): int =
    match s {
      | Cooperate => cooperatePayoff(p)
      | PostSelfContainedLatestProof => postSelfContainedLatestProofPayoff(p)
      | AcceptTimeoutFallback => timeoutFallbackPayoff(p)
      | BreachProofObligation => proofObligationBreachPayoff(p)
      | SubmitStaleReceipt => staleReceiptDeviationPayoff(p)
      | ForceCounterpartyProof => forceCounterpartyProofPayoff(p)
      | SubmitBadCompute => badComputeDeviationPayoff(p)
    }

  pure def isDeviation(s: Strategy): bool =
    match s {
      | Cooperate => false
      | PostSelfContainedLatestProof => false
      | AcceptTimeoutFallback => false
      | BreachProofObligation => true
      | SubmitStaleReceipt => true
      | ForceCounterpartyProof => true
      | SubmitBadCompute => true
    }

  action chooseStrategy(p, s) = all {
    economicParty(p),
    actor' = p,
    strategy' = s,
    payoffValue' = payoff(p, s),
    counterexample' = false,
  }

  action chooseTimeoutFallback(p) = all {
    economicParty(p),
    actor' = p,
    strategy' = AcceptTimeoutFallback,
    payoffValue' = timeoutFallbackPayoff(p),
    counterexample' = true,
  }

  action chooseUnbackedProofObligationBreach(p) = all {
    economicParty(p),
    actor' = p,
    strategy' = BreachProofObligation,
    payoffValue' = proofObligationBreachPayoffUnder(UnbackedProofObligationTerms, p),
    counterexample' = true,
  }

  action chooseUnsafeLateProofObligationBreach(p) = all {
    economicParty(p),
    actor' = p,
    strategy' = BreachProofObligation,
    payoffValue' = proofObligationBreachPayoffUnder(UnsafeLateProofObligationTerms, p),
    counterexample' = true,
  }

  action init = chooseStrategy(Maker, Cooperate)

  action step = any {
    chooseStrategy(Maker, Cooperate),
    chooseStrategy(Maker, PostSelfContainedLatestProof),
    chooseStrategy(Maker, AcceptTimeoutFallback),
    chooseStrategy(Maker, BreachProofObligation),
    chooseStrategy(Maker, SubmitStaleReceipt),
    chooseStrategy(Maker, ForceCounterpartyProof),
    chooseStrategy(Maker, SubmitBadCompute),
    chooseStrategy(Taker, Cooperate),
    chooseStrategy(Taker, PostSelfContainedLatestProof),
    chooseStrategy(Taker, AcceptTimeoutFallback),
    chooseStrategy(Taker, BreachProofObligation),
    chooseStrategy(Taker, SubmitStaleReceipt),
    chooseStrategy(Taker, ForceCounterpartyProof),
    chooseStrategy(Taker, SubmitBadCompute),
  }

  val chosenPayoffMatchesStrategy =
    if (counterexample) {
      any {
        strategy == AcceptTimeoutFallback and payoffValue == timeoutFallbackPayoff(actor),
        strategy == BreachProofObligation
          and any {
            payoffValue == proofObligationBreachPayoffUnder(UnbackedProofObligationTerms, actor),
            payoffValue == proofObligationBreachPayoffUnder(
              UnsafeLateProofObligationTerms,
              actor,
            ),
          },
      }
    } else {
      payoffValue == payoff(actor, strategy)
    }

  val cooperationWeaklyDominatesChosen =
    counterexample
      or cooperatePayoff(actor) >= payoffValue

  val cooperationStrictlyDominatesChosenDeviation =
    counterexample
      or not(isDeviation(strategy))
      or cooperatePayoff(actor) > payoffValue

  val proofObligationBreachPenaltyCoversTimeoutAdvantage =
    AllParties.forall(party =>
      not(economicParty(party))
        or ScenarioTerms.proofObligationBreachPenalty + ScenarioTerms.deviationFriction
          > positivePart(ScenarioTerms.timeout.get(party) - ScenarioTerms.latest.get(party))
    )

  val staleReceiptIsCostly =
    AllParties.forall(party =>
      not(economicParty(party))
        or staleReceiptDeviationPayoff(party) < cooperatePayoff(party)
    )

  val forcedProofIsCostly =
    AllParties.forall(party =>
      not(economicParty(party))
        or forceCounterpartyProofPayoff(party) < cooperatePayoff(party)
    )

  val selfContainedProofPostingRationalForLatestBeneficiary =
    AllParties.forall(party =>
      not(economicParty(party))
        or ScenarioTerms.latest.get(party) <= ScenarioTerms.timeout.get(party)
        or postSelfContainedLatestProofPayoff(party) > ScenarioTerms.timeout.get(party)
    )

  val badComputeIsCostly =
    AllParties.forall(party =>
      not(economicParty(party))
        or badComputeDeviationPayoff(party) < cooperatePayoff(party)
    )

  val termsCoherentForPayoffs =
    incentiveTermsCoherent(ScenarioTerms)

  val penaltiesFundedByStake =
    incentiveStakeRequirementMet(ScenarioTerms)

  val configuredPenaltiesBacked =
    AllDeviationKinds.forall(kind => penaltyBacked(ScenarioTerms, kind))

  val configuredProofObligationBacksPenalty =
    proofObligationBacksPenalty(ScenarioTerms)
      and proofObligationDeadlineHasMargin(ScenarioTerms.proofObligation)
      and ScenarioTerms.proofObligation.proofDeadline
        + ScenarioTerms.proofObligation.inclusionMargin
          <= ScenarioTerms.proofObligation.expiryHeight

  val configuredProofsMapToL1Boundary =
    AllDeviationKinds.forall(kind =>
      proofKindAdmissible(ScenarioTerms.proof.get(kind))
        and proofCanSlash(ScenarioTerms.proof.get(kind))
        and evidenceCanProveViolation(ScenarioTerms.evidence.get(kind))
        and l1ProofKind(ScenarioTerms.proof.get(kind)) == ViolationClose
    )
      and l1ProofKind(TimeoutFallbackProof) == TimeoutClose
      and proofKindAdmissible(TimeoutFallbackProof)
      and not(proofCanSlash(TimeoutFallbackProof))
      and l1ProofKind(SelfContainedLatestStateProof) == LatestProofClose
      and proofKindAdmissible(SelfContainedLatestStateProof)
      and not(proofCanSlash(SelfContainedLatestStateProof))
      and l1ProofKind(FreshMutualLatestCloseProof) == MutualClose
      and proofKindAdmissible(FreshMutualLatestCloseProof)
      and not(proofCanSlash(FreshMutualLatestCloseProof))
      and l1ProofKind(BareSignedReceiptProof) == NoL1Proof
      and not(proofKindAdmissible(BareSignedReceiptProof))
      and l1ProofKind(NoProof) == NoL1Proof
      and not(proofKindAdmissible(NoProof))

  val penaltyRequirementsDerived =
    incentivePenaltyRequirementsMet(ScenarioTerms)

  val proofCostBoundDerived =
    incentiveProofCostBoundMet(ScenarioTerms)

  val requiredStakeDerived =
    requiredStake(ScenarioTerms) == ScenarioTerms.staleReceiptPenalty
      and incentiveStakeRequirementMet(ScenarioTerms)
      and configuredPenaltiesBacked
      and configuredProofObligationBacksPenalty
      and configuredProofsMapToL1Boundary

  val proofCostCoveredWhenProofImproves =
    selfContainedProofPostingRationalForLatestBeneficiary and proofCostBoundDerived

  val timeoutFallbackNotSlashable =
    l1ProofKind(TimeoutFallbackProof) == TimeoutClose
      and proofKindAdmissible(TimeoutFallbackProof)
      and not(proofCanSlash(TimeoutFallbackProof))

  val proofObligationBreachDeviationUnprofitable =
    proofObligationBreachPenaltyCoversTimeoutAdvantage and penaltyRequirementsDerived

  val proofObligationBreachUnprofitable =
    AllParties.forall(party =>
      not(economicParty(party))
        or proofObligationBreachPayoff(party) < cooperatePayoff(party)
    )

  val staleReceiptUnprofitable =
    staleReceiptIsCostly

  val badComputeUnprofitable =
    badComputeIsCostly

  val allModeledDeviationsUnprofitable =
    proofObligationBreachUnprofitable
      and staleReceiptUnprofitable
      and forcedProofIsCostly
      and badComputeUnprofitable

  val chosenDeviationUnprofitable =
    cooperationStrictlyDominatesChosenDeviation

  val currentMarginsKnown =
    ScenarioTerms.proofCost > 0
      and ScenarioTerms.rejectedReceiptCost > 0
      and ScenarioTerms.deviationFriction > 0
      and ScenarioTerms.postedStake > 0
      and timeoutFallbackProfitableForTaker
      and requiredProofObligationBreachPenalty(ScenarioTerms, Taker) == 7
      and requiredStaleReceiptPenalty(ScenarioTerms, Taker) == 9
      and proofCostCeilingFor(ScenarioTerms, Maker) == 6
      and requiredBadComputePenalty(ScenarioTerms, Taker) == 4
      and requiredStake(ScenarioTerms) == 10
      and enforceablePenalty(ScenarioTerms, ProofObligationBreachDeviation) == 9
      and enforceablePenalty(UnbackedProofObligationTerms, ProofObligationBreachDeviation) == 0
      and enforceablePenalty(UnsafeLateProofObligationTerms, ProofObligationBreachDeviation) == 0
      and proofObligationSatisfied(ScenarioTerms, ProofObligationBreachDeviation)
      and not(proofObligationSatisfied(UnbackedProofObligationTerms, ProofObligationBreachDeviation))
      and not(proofObligationSatisfied(
        UnsafeLateProofObligationTerms,
        ProofObligationBreachDeviation,
      ))
      and proofObligationBacksPenalty(ScenarioTerms)
      and not(proofObligationBacksPenalty(UnbackedProofObligationTerms))
      and not(proofObligationBacksPenalty(UnsafeLateProofObligationTerms))
      and proofObligationPublic(ScenarioTerms.proofObligation.kind)
      and not(proofObligationPublic(UnbackedProofObligationTerms.proofObligation.kind))
      and proofObligationPublic(UnsafeLateProofObligationTerms.proofObligation.kind)
      and not(proofObligationDeadlineHasMargin(UnsafeLateProofObligationTerms.proofObligation))
      and l1ProofKind(ScenarioTerms.proof.get(ProofObligationBreachDeviation)) == ViolationClose
      and proofKindAdmissible(ScenarioTerms.proof.get(ProofObligationBreachDeviation))
      and proofCanSlash(ScenarioTerms.proof.get(ProofObligationBreachDeviation))
      and timeoutFallbackNotSlashable

  val timeoutFallbackProfitableForTaker =
    timeoutFallbackPayoff(Taker) > cooperatePayoff(Taker)

  val unbackedProofObligationBreachProfitableForTaker =
    proofObligationBreachPayoffUnder(UnbackedProofObligationTerms, Taker)
      > cooperatePayoffUnder(UnbackedProofObligationTerms, Taker)

  val unsafeLateProofObligationBreachProfitableForTaker =
    proofObligationBreachPayoffUnder(UnsafeLateProofObligationTerms, Taker)
      > cooperatePayoffUnder(UnsafeLateProofObligationTerms, Taker)

  run cooperateTraceTest =
    init
      .expect(actor == Maker
        and strategy == Cooperate
        and payoffValue == cooperatePayoff(Maker)
        and cooperationWeaklyDominatesChosen)

  run proofObligationBreachPenalizedTest =
    init
      .then(chooseStrategy(Taker, BreachProofObligation))
      .expect(actor == Taker
        and strategy == BreachProofObligation
        and proofObligationBreachPayoff(Taker) < cooperatePayoff(Taker)
        and cooperationStrictlyDominatesChosenDeviation)

  run staleReceiptDeviationPenalizedTest =
    init
      .then(chooseStrategy(Taker, SubmitStaleReceipt))
      .expect(actor == Taker
        and strategy == SubmitStaleReceipt
        and staleReceiptDeviationPayoff(Taker) < cooperatePayoff(Taker)
        and cooperationStrictlyDominatesChosenDeviation)

  run selfContainedProofPostingBeneficiaryTest =
    init
      .then(chooseStrategy(Maker, PostSelfContainedLatestProof))
      .expect(actor == Maker
        and strategy == PostSelfContainedLatestProof
        and postSelfContainedLatestProofPayoff(Maker) > ScenarioTerms.timeout.get(Maker)
        and cooperationWeaklyDominatesChosen)

  run timeoutFallbackCanFavorTakerTest =
    init
      .then(chooseTimeoutFallback(Taker))
      .expect(counterexample
        and actor == Taker
        and strategy == AcceptTimeoutFallback
        and payoffValue == timeoutFallbackPayoff(Taker)
        and timeoutFallbackProfitableForTaker
        and timeoutFallbackNotSlashable)

  run unbackedProofObligationCounterexampleTest =
    init
      .then(chooseUnbackedProofObligationBreach(Taker))
      .expect(counterexample
        and actor == Taker
        and payoffValue == proofObligationBreachPayoffUnder(UnbackedProofObligationTerms, Taker)
        and not(proofObligationSatisfied(UnbackedProofObligationTerms, ProofObligationBreachDeviation))
        and not(penaltyBacked(UnbackedProofObligationTerms, ProofObligationBreachDeviation))
        and enforceablePenalty(UnbackedProofObligationTerms, ProofObligationBreachDeviation) == 0
        and unbackedProofObligationBreachProfitableForTaker)

  run unsafeLateProofObligationCounterexampleTest =
    init
      .then(chooseUnsafeLateProofObligationBreach(Taker))
      .expect(counterexample
        and actor == Taker
        and payoffValue == proofObligationBreachPayoffUnder(
          UnsafeLateProofObligationTerms,
          Taker,
        )
        and not(proofObligationBacksPenalty(UnsafeLateProofObligationTerms))
        and not(proofObligationDeadlineHasMargin(UnsafeLateProofObligationTerms.proofObligation))
        and not(penaltyBacked(UnsafeLateProofObligationTerms, ProofObligationBreachDeviation))
        and enforceablePenalty(UnsafeLateProofObligationTerms, ProofObligationBreachDeviation) == 0
        and unsafeLateProofObligationBreachProfitableForTaker)

  run badComputeDeviationPenalizedTest =
    init
      .then(chooseStrategy(Taker, SubmitBadCompute))
      .expect(actor == Taker
        and strategy == SubmitBadCompute
        and badComputeDeviationPayoff(Taker) < cooperatePayoff(Taker)
        and cooperationStrictlyDominatesChosenDeviation)

  run derivedRequirementTraceTest =
    init
      .expect(requiredProofObligationBreachPenalty(ScenarioTerms, Taker) == 7
        and ScenarioTerms.proofObligationBreachPenalty == 9
        and requiredStaleReceiptPenalty(ScenarioTerms, Taker) == 9
        and ScenarioTerms.staleReceiptPenalty == 10
        and requiredBadComputePenalty(ScenarioTerms, Taker) == 4
        and ScenarioTerms.badComputePenalty == 8
        and proofCostCeilingFor(ScenarioTerms, Maker) == 6
        and ScenarioTerms.proofCost == 2
        and requiredStake(ScenarioTerms) == 10
        and ScenarioTerms.postedStake == 12
        and configuredProofObligationBacksPenalty
        and proofObligationSatisfied(ScenarioTerms, ProofObligationBreachDeviation)
        and proofObligationSatisfied(ScenarioTerms, StaleReceiptDeviation)
        and proofObligationSatisfied(ScenarioTerms, BadComputeDeviation)
        and configuredProofsMapToL1Boundary
        and configuredPenaltiesBacked
        and incentiveRequirementsMet(ScenarioTerms)
        and penaltyRequirementsDerived
        and proofCostBoundDerived
        and requiredStakeDerived)
}
