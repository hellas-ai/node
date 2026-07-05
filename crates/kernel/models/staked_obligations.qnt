module staked_obligations {
  import accounting.* from "./accounting"
  import proofs.* from "./proofs"
  import terms.* from "./terms"

  // Focused accounting model for stake-backed violation closes.
  //
  // Fraud-game internals stay off-chain. The L1 boundary sees a bounded final
  // violation seal. When that seal is valid under the signed terms/job config,
  // the configured penalty moves from the violator's posted stake to the
  // violated party. Edge principal and stake remain separate value domains.

  type Phase =
    | Live
    | Closed

  type ObligationStatus =
    | NoObligationStatus
    | ObligationOpen
    | ObligationBreached

  type ClosePath =
    | NoClose
    | SelfContainedLatestProofClose
    | TimeoutFallbackClose
    | ViolationStakeClose

  var phase: Phase
  var height: int
  var liquid: Party -> int
  var edgePrincipal: int
  var closeReserve: int
  var feesPaid: int
  var stake: Party -> int
  var stakeAward: Party -> int
  var obligation: ProofSubmissionObligation
  var status: ObligationStatus
  var finalPath: ClosePath
  var closedAt: int

  pure val MakerFunding = 36
  pure val TakerFunding = 24
  pure val Funding = MakerFunding + TakerFunding
  pure val OpenFee = 5
  pure val CloseReserve = 12
  pure val PrepaidCloseFee = 8
  pure val ReserveSurplus = CloseReserve - PrepaidCloseFee
  pure val LifetimeFee = 6
  pure val EdgePrincipal = Funding - OpenFee - CloseReserve - LifetimeFee

  pure val GenesisHeight = 1
  pure val ProofDeadline = 3
  pure val ExpiryHeight = 5
  pure val InclusionMargin = 1
  pure val PostedStake = 12
  pure val ViolationPenalty = 9
  pure val TotalValue = Funding + PostedStake

  pure val InitialStake = makerTakerValues(0, PostedStake)

  pure val LatestTerms = basicTerms(
    25,
    12,
    2,
    2,
    0,
    0,
    0,
    0,
  )

  pure val TimeoutTerms = basicTerms(
    18,
    19,
    2,
    2,
    0,
    0,
    0,
    0,
  )

  pure val ViolationTerms = basicTerms(
    20,
    17,
    2,
    2,
    0,
    0,
    0,
    0,
  )

  pure val EmptyObligation: ProofSubmissionObligation = {
    kind: NoProofObligation,
    obligor: Adversary,
    beneficiary: Adversary,
    requiredProof: NoRequiredProof,
    createdAt: GenesisHeight,
    proofDeadline: ExpiryHeight,
    expiryHeight: ExpiryHeight,
    inclusionMargin: InclusionMargin,
    penalty: 0,
    penaltyBudget: 0,
  }

  pure val MakerProtectedObligation: ProofSubmissionObligation = {
    kind: SignedProofDeadlineObligation,
    obligor: Taker,
    beneficiary: Maker,
    requiredProof: RequiredSelfContainedLatestProof,
    createdAt: GenesisHeight,
    proofDeadline: ProofDeadline,
    expiryHeight: ExpiryHeight,
    inclusionMargin: InclusionMargin,
    penalty: ViolationPenalty,
    penaltyBudget: PostedStake,
  }

  pure val UnbackedObligation: ProofSubmissionObligation = {
    kind: NoProofObligation,
    obligor: Taker,
    beneficiary: Maker,
    requiredProof: RequiredSelfContainedLatestProof,
    createdAt: GenesisHeight,
    proofDeadline: ProofDeadline,
    expiryHeight: ExpiryHeight,
    inclusionMargin: InclusionMargin,
    penalty: ViolationPenalty,
    penaltyBudget: PostedStake,
  }

  pure val UnsafeLateObligation: ProofSubmissionObligation = {
    kind: SignedProofDeadlineObligation,
    obligor: Taker,
    beneficiary: Maker,
    requiredProof: RequiredSelfContainedLatestProof,
    createdAt: GenesisHeight,
    proofDeadline: ExpiryHeight,
    expiryHeight: ExpiryHeight,
    inclusionMargin: InclusionMargin,
    penalty: ViolationPenalty,
    penaltyBudget: PostedStake,
  }

  pure def obligationWellFormed(o: ProofSubmissionObligation): bool =
    proofSubmissionObligationWellFormed(o, PostedStake)
      and o.penalty == ViolationPenalty

  pure def recoveryFromTerms(t: EconomicTerms): Party -> int =
    AllParties.mapBy(party =>
      t.principal.get(party) + t.reserveSurplus.get(party)
    )

  def totalRecoveryFor(party: Party): int =
    liquid.get(party) + stakeAward.get(party)

  pure def termsFor(path: ClosePath): EconomicTerms =
    match path {
      | NoClose => EmptyTerms
      | SelfContainedLatestProofClose => LatestTerms
      | TimeoutFallbackClose => TimeoutTerms
      | ViolationStakeClose => ViolationTerms
    }

  pure def pathProofKind(path: ClosePath): ProofKind =
    match path {
      | NoClose => NoProof
      | SelfContainedLatestProofClose => SelfContainedLatestStateProof
      | TimeoutFallbackClose => TimeoutFallbackProof
      | ViolationStakeClose => ProofObligationBreachSealProof
    }

  def activeExpiryHeight: int =
    if (proofObligationPublic(obligation.kind)) {
      obligation.expiryHeight
    } else {
      ExpiryHeight
    }

  def canCreateObligation(o: ProofSubmissionObligation): bool =
    phase == Live
      and status == NoObligationStatus
      and height == o.createdAt
      and obligationWellFormed(o)
      and stake.get(o.obligor) >= o.penalty

  def canForceInvalidObligation(o: ProofSubmissionObligation): bool =
    phase == Live
      and status == NoObligationStatus
      and height == o.createdAt
      and not(obligationWellFormed(o))

  def canSubmitSelfContainedLatestProof: bool =
    phase == Live
      and status == ObligationOpen
      and obligation.requiredProof == RequiredSelfContainedLatestProof
      and l1ProofKind(SelfContainedLatestStateProof) == LatestProofClose
      and proofKindAdmissible(SelfContainedLatestStateProof)
      and not(proofCanSlash(SelfContainedLatestStateProof))
      and height < obligation.proofDeadline
      and closeReserve >= PrepaidCloseFee
      and termsCoherent(LatestTerms, edgePrincipal, ReserveSurplus, 0, 0)

  def canMarkBreach: bool =
    phase == Live
      and status == ObligationOpen
      and obligationWellFormed(obligation)
      and height >= obligation.proofDeadline
      and height < obligation.expiryHeight

  def canCloseByViolation: bool =
    phase == Live
      and status == ObligationBreached
      and obligationWellFormed(obligation)
      and evidenceCanProveViolation(ProofObligationBreachEvidence)
      and l1ProofKind(ProofObligationBreachSealProof) == ViolationClose
      and proofCanSlash(ProofObligationBreachSealProof)
      and height < obligation.expiryHeight
      and stake.get(obligation.obligor) >= obligation.penalty
      and closeReserve >= PrepaidCloseFee
      and termsCoherent(ViolationTerms, edgePrincipal, ReserveSurplus, 0, 0)

  def canCloseByTimeout: bool =
    phase == Live
      and height >= activeExpiryHeight
      and l1ProofKind(TimeoutFallbackProof) == TimeoutClose
      and not(proofCanSlash(TimeoutFallbackProof))
      and closeReserve >= PrepaidCloseFee
      and termsCoherent(TimeoutTerms, edgePrincipal, ReserveSurplus, 0, 0)

  action init = all {
    phase' = Live,
    height' = GenesisHeight,
    liquid' = zeroPartyValues,
    edgePrincipal' = EdgePrincipal,
    closeReserve' = CloseReserve,
    feesPaid' = OpenFee + LifetimeFee,
    stake' = InitialStake,
    stakeAward' = zeroPartyValues,
    obligation' = EmptyObligation,
    status' = NoObligationStatus,
    finalPath' = NoClose,
    closedAt' = 0,
  }

  action createObligation(o) = all {
    canCreateObligation(o),
    phase' = phase,
    height' = height,
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    feesPaid' = feesPaid,
    stake' = stake,
    stakeAward' = stakeAward,
    obligation' = o,
    status' = ObligationOpen,
    finalPath' = finalPath,
    closedAt' = closedAt,
  }

  action forceInvalidObligation(o) = all {
    canForceInvalidObligation(o),
    phase' = phase,
    height' = height,
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    feesPaid' = feesPaid,
    stake' = stake,
    stakeAward' = stakeAward,
    obligation' = o,
    status' = ObligationOpen,
    finalPath' = finalPath,
    closedAt' = closedAt,
  }

  action submitSelfContainedLatestProof = all {
    canSubmitSelfContainedLatestProof,
    phase' = Closed,
    height' = height,
    liquid' = recoveryFromTerms(LatestTerms),
    edgePrincipal' = 0,
    closeReserve' = 0,
    feesPaid' = feesPaid + PrepaidCloseFee,
    stake' = stake,
    stakeAward' = stakeAward,
    obligation' = obligation,
    status' = ObligationOpen,
    finalPath' = SelfContainedLatestProofClose,
    closedAt' = height,
  }

  action markBreach = all {
    canMarkBreach,
    phase' = phase,
    height' = height,
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    feesPaid' = feesPaid,
    stake' = stake,
    stakeAward' = stakeAward,
    obligation' = obligation,
    status' = ObligationBreached,
    finalPath' = finalPath,
    closedAt' = closedAt,
  }

  action closeByViolation = all {
    canCloseByViolation,
    phase' = Closed,
    height' = height,
    liquid' = recoveryFromTerms(ViolationTerms),
    edgePrincipal' = 0,
    closeReserve' = 0,
    feesPaid' = feesPaid + PrepaidCloseFee,
    stake' = stake.set(obligation.obligor, stake.get(obligation.obligor) - obligation.penalty),
    stakeAward' = stakeAward.set(
      obligation.beneficiary,
      stakeAward.get(obligation.beneficiary) + obligation.penalty
    ),
    obligation' = obligation,
    status' = ObligationBreached,
    finalPath' = ViolationStakeClose,
    closedAt' = height,
  }

  action closeByTimeout = all {
    canCloseByTimeout,
    phase' = Closed,
    height' = height,
    liquid' = recoveryFromTerms(TimeoutTerms),
    edgePrincipal' = 0,
    closeReserve' = 0,
    feesPaid' = feesPaid + PrepaidCloseFee,
    stake' = stake,
    stakeAward' = stakeAward,
    obligation' = obligation,
    status' = status,
    finalPath' = TimeoutFallbackClose,
    closedAt' = height,
  }

  action tickLive = all {
    phase == Live,
    height < activeExpiryHeight,
    phase' = phase,
    height' = height + 1,
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    feesPaid' = feesPaid,
    stake' = stake,
    stakeAward' = stakeAward,
    obligation' = obligation,
    status' = status,
    finalPath' = finalPath,
    closedAt' = closedAt,
  }

  action tickClosed = all {
    phase == Closed,
    phase' = phase,
    height' = height + 1,
    liquid' = liquid,
    edgePrincipal' = edgePrincipal,
    closeReserve' = closeReserve,
    feesPaid' = feesPaid,
    stake' = stake,
    stakeAward' = stakeAward,
    obligation' = obligation,
    status' = status,
    finalPath' = finalPath,
    closedAt' = closedAt,
  }

  action step = any {
    createObligation(MakerProtectedObligation),
    forceInvalidObligation(UnbackedObligation),
    forceInvalidObligation(UnsafeLateObligation),
    submitSelfContainedLatestProof,
    markBreach,
    closeByViolation,
    closeByTimeout,
    tickLive,
    tickClosed,
  }

  val valueAccounted =
    partyTotal(liquid)
      + edgePrincipal
      + closeReserve
      + feesPaid
      + partyTotal(stake)
      + partyTotal(stakeAward)
      == TotalValue

  val noNegativeBucket =
    height >= GenesisHeight
      and closedAt >= 0
      and partyNonNegative(liquid)
      and edgePrincipal >= 0
      and closeReserve >= 0
      and feesPaid >= 0
      and partyNonNegative(stake)
      and partyNonNegative(stakeAward)

  val termsCoherentForClose =
    termsCoherent(LatestTerms, EdgePrincipal, ReserveSurplus, 0, 0)
      and termsCoherent(TimeoutTerms, EdgePrincipal, ReserveSurplus, 0, 0)
      and termsCoherent(ViolationTerms, EdgePrincipal, ReserveSurplus, 0, 0)

  val stakeDomainConserved =
    partyTotal(stake) + partyTotal(stakeAward) == PostedStake

  val stakeAwardBackedOnlyByStakeDebits =
    partyTotal(stakeAward) == PostedStake - partyTotal(stake)

  val stakeAwardNeverExceedsPostedStake =
    partyTotal(stakeAward) <= PostedStake

  val stakeAwardOnlyThroughViolation =
    partyTotal(stakeAward) == 0
      or all {
        finalPath == ViolationStakeClose,
        l1ProofKind(pathProofKind(finalPath)) == ViolationClose,
        proofCanSlash(pathProofKind(finalPath)),
      }

  val timeoutDoesNotAwardStake =
    finalPath != TimeoutFallbackClose
      or all {
        stake == InitialStake,
        stakeAward == zeroPartyValues,
        l1ProofKind(TimeoutFallbackProof) == TimeoutClose,
        not(proofCanSlash(TimeoutFallbackProof)),
      }

  val selfContainedLatestProofDoesNotAwardStake =
    finalPath != SelfContainedLatestProofClose
      or all {
        stake == InitialStake,
        stakeAward == zeroPartyValues,
        l1ProofKind(SelfContainedLatestStateProof) == LatestProofClose,
        proofKindAdmissible(SelfContainedLatestStateProof),
        not(proofCanSlash(SelfContainedLatestStateProof)),
      }

  val violationRequiresWellFormedObligation =
    finalPath != ViolationStakeClose
      or all {
        obligationWellFormed(obligation),
        status == ObligationBreached,
        closedAt >= obligation.proofDeadline,
        closedAt < obligation.expiryHeight,
      }

  val violationAwardsStakeToViolatedParty =
    finalPath != ViolationStakeClose
      or all {
        stakeAward.get(obligation.beneficiary) == obligation.penalty,
        stake.get(obligation.obligor) == PostedStake - obligation.penalty,
        partyTotal(stakeAward) == obligation.penalty,
      }

  val violationRecoveryProtectsBeneficiary =
    finalPath != ViolationStakeClose
      or all {
        totalRecoveryFor(obligation.beneficiary)
          >= recoveryFromTerms(TimeoutTerms).get(obligation.beneficiary),
        totalRecoveryFor(obligation.beneficiary)
          >= recoveryFromTerms(LatestTerms).get(obligation.beneficiary),
      }

  val closedPathHasExpectedPrincipal =
    phase != Closed
      or all {
        edgePrincipal == 0,
        closeReserve == 0,
        liquid == recoveryFromTerms(termsFor(finalPath)),
      }

  val closePaysCommittedFee =
    phase != Closed or feesPaid == OpenFee + LifetimeFee + PrepaidCloseFee

  val unbackedOrLateObligationCannotAwardStake =
    not(obligation == UnbackedObligation or obligation == UnsafeLateObligation)
      or all {
        stakeAward == zeroPartyValues,
        not(canMarkBreach),
        not(canCloseByViolation),
      }

  run selfContainedLatestProofNoSlashTest =
    init
      .then(createObligation(MakerProtectedObligation))
      .then(tickLive)
      .then(submitSelfContainedLatestProof)
      .expect(finalPath == SelfContainedLatestProofClose
        and liquid == recoveryFromTerms(LatestTerms)
        and stake == InitialStake
        and stakeAward == zeroPartyValues
        and selfContainedLatestProofDoesNotAwardStake
        and valueAccounted)

  run violationAwardsStakeTest =
    init
      .then(createObligation(MakerProtectedObligation))
      .then(tickLive)
      .then(tickLive)
      .then(markBreach)
      .then(closeByViolation)
      .expect(finalPath == ViolationStakeClose
        and liquid == recoveryFromTerms(ViolationTerms)
        and stakeAward.get(Maker) == ViolationPenalty
        and stake.get(Taker) == PostedStake - ViolationPenalty
        and violationAwardsStakeToViolatedParty
        and violationRecoveryProtectsBeneficiary
        and valueAccounted)

  run timeoutNoStakeAwardTest =
    init
      .then(createObligation(MakerProtectedObligation))
      .then(tickLive)
      .then(tickLive)
      .then(tickLive)
      .then(tickLive)
      .then(closeByTimeout)
      .expect(finalPath == TimeoutFallbackClose
        and liquid == recoveryFromTerms(TimeoutTerms)
        and stake == InitialStake
        and stakeAward == zeroPartyValues
        and timeoutDoesNotAwardStake
        and valueAccounted)

  run unbackedObligationCannotAwardStakeTest =
    init
      .then(forceInvalidObligation(UnbackedObligation))
      .then(tickLive)
      .then(tickLive)
      .expect(obligation == UnbackedObligation
        and unbackedOrLateObligationCannotAwardStake
        and stakeAward == zeroPartyValues
        and valueAccounted)

  run unsafeLateObligationCannotAwardStakeTest =
    init
      .then(forceInvalidObligation(UnsafeLateObligation))
      .then(tickLive)
      .then(tickLive)
      .expect(obligation == UnsafeLateObligation
        and unbackedOrLateObligationCannotAwardStake
        and stakeAward == zeroPartyValues
        and valueAccounted)
}
