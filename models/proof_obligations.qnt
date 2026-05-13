module proof_obligations {
  import accounting.* from "./accounting"
  import proofs.* from "./proofs"

  // Focused model for signed proof-submission obligations.
  //
  // The core distinction is observability. L1 cannot slash private silence:
  // a party "having a proof and not sending it" is not public evidence. A
  // proof-related penalty is enforceable only when the terms or a later signed
  // state create a public obligation with a deadline, and a violation seal can
  // prove that the deadline passed without the required proof closing the edge.

  type Phase =
    | Live
    | Closed

  type ObligationStatus =
    | NoObligationStatus
    | ObligationOpen
    | ObligationDischarged
    | ObligationBreached

  type ClosePath =
    | NoClose
    | SelfContainedLatestProofClose
    | TimeoutFallbackClose
    | BreachSealClose

  var phase: Phase
  var height: int
  var obligation: ProofSubmissionObligation
  var status: ObligationStatus
  var finalPath: ClosePath
  var recovery: Party -> int
  var slashed: int
  var closedAt: int

  pure val GenesisHeight = 1
  pure val ProofDeadline = 3
  pure val ExpiryHeight = 5
  pure val InclusionMargin = 1
  pure val ProofBreachPenalty = 9
  pure val PostedStake = 12

  pure val LatestRecovery = makerTakerValues(27, 14)
  pure val TimeoutRecovery = makerTakerValues(20, 21)
  pure val BreachSealRecovery = makerTakerValues(29, 12)

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
    penalty: ProofBreachPenalty,
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
    penalty: ProofBreachPenalty,
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
    penalty: ProofBreachPenalty,
    penaltyBudget: PostedStake,
  }

  pure def obligationDeadlineHasMargin(o: ProofSubmissionObligation): bool =
    proofObligationDeadlineHasMargin(o)

  pure def obligationPenaltyBacked(o: ProofSubmissionObligation): bool =
    proofObligationPenaltyBacked(o, PostedStake)

  pure def obligationWellFormed(o: ProofSubmissionObligation): bool =
    proofSubmissionObligationWellFormed(o, PostedStake)

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

  def canSubmitRequiredProof: bool =
    phase == Live
      and status == ObligationOpen
      and proofObligationPublic(obligation.kind)
      and obligation.requiredProof == RequiredSelfContainedLatestProof
      and l1ProofKind(SelfContainedLatestStateProof) == LatestProofClose
      and proofKindAdmissible(SelfContainedLatestStateProof)
      and not(proofCanSlash(SelfContainedLatestStateProof))
      and height < obligation.proofDeadline

  def canMarkBreach: bool =
    phase == Live
      and status == ObligationOpen
      and proofObligationPublic(obligation.kind)
      and height >= obligation.proofDeadline
      and height < obligation.expiryHeight

  def canCloseByBreachSeal: bool =
    phase == Live
      and status == ObligationBreached
      and proofObligationPublic(obligation.kind)
      and evidenceCanProveViolation(ProofObligationBreachEvidence)
      and l1ProofKind(ProofObligationBreachSealProof) == ViolationClose
      and proofCanSlash(ProofObligationBreachSealProof)
      and height < obligation.expiryHeight
      and obligationPenaltyBacked(obligation)

  def canCloseByTimeout: bool =
    phase == Live
      and height >= activeExpiryHeight
      and l1ProofKind(TimeoutFallbackProof) == TimeoutClose
      and not(proofCanSlash(TimeoutFallbackProof))

  action init = all {
    phase' = Live,
    height' = GenesisHeight,
    obligation' = EmptyObligation,
    status' = NoObligationStatus,
    finalPath' = NoClose,
    recovery' = zeroPartyValues,
    slashed' = 0,
    closedAt' = 0,
  }

  action createObligation(o) = all {
    canCreateObligation(o),
    phase' = phase,
    height' = height,
    obligation' = o,
    status' = ObligationOpen,
    finalPath' = finalPath,
    recovery' = recovery,
    slashed' = slashed,
    closedAt' = closedAt,
  }

  action createUnbackedObligation = all {
    phase == Live,
    status == NoObligationStatus,
    height == GenesisHeight,
    phase' = phase,
    height' = height,
    obligation' = UnbackedObligation,
    status' = ObligationOpen,
    finalPath' = finalPath,
    recovery' = recovery,
    slashed' = slashed,
    closedAt' = closedAt,
  }

  action submitRequiredProof = all {
    canSubmitRequiredProof,
    phase' = Closed,
    height' = height,
    obligation' = obligation,
    status' = ObligationDischarged,
    finalPath' = SelfContainedLatestProofClose,
    recovery' = LatestRecovery,
    slashed' = 0,
    closedAt' = height,
  }

  action markBreach = all {
    canMarkBreach,
    phase' = phase,
    height' = height,
    obligation' = obligation,
    status' = ObligationBreached,
    finalPath' = finalPath,
    recovery' = recovery,
    slashed' = slashed,
    closedAt' = closedAt,
  }

  action closeByBreachSeal = all {
    canCloseByBreachSeal,
    phase' = Closed,
    height' = height,
    obligation' = obligation,
    status' = ObligationBreached,
    finalPath' = BreachSealClose,
    recovery' = BreachSealRecovery,
    slashed' = obligation.penalty,
    closedAt' = height,
  }

  action closeByTimeout = all {
    canCloseByTimeout,
    phase' = Closed,
    height' = height,
    obligation' = obligation,
    status' = status,
    finalPath' = TimeoutFallbackClose,
    recovery' = TimeoutRecovery,
    slashed' = 0,
    closedAt' = height,
  }

  action tickLive = all {
    phase == Live,
    height < activeExpiryHeight,
    phase' = phase,
    height' = height + 1,
    obligation' = obligation,
    status' = status,
    finalPath' = finalPath,
    recovery' = recovery,
    slashed' = slashed,
    closedAt' = closedAt,
  }

  action tickClosed = all {
    phase == Closed,
    phase' = phase,
    height' = height + 1,
    obligation' = obligation,
    status' = status,
    finalPath' = finalPath,
    recovery' = recovery,
    slashed' = slashed,
    closedAt' = closedAt,
  }

  action step = any {
    createObligation(MakerProtectedObligation),
    submitRequiredProof,
    markBreach,
    closeByBreachSeal,
    closeByTimeout,
    tickLive,
    tickClosed,
  }

  val noNegativeValue =
    height >= GenesisHeight
      and closedAt >= 0
      and partyNonNegative(recovery)
      and slashed >= 0
      and slashed <= PostedStake

  val publicObligationHasSafeDeadline =
    not(proofObligationPublic(obligation.kind))
      or obligationDeadlineHasMargin(obligation)

  val noSlashWithoutPublicObligation =
    slashed == 0 or proofObligationPublic(obligation.kind)

  val slashOnlyThroughViolationSeal =
    slashed == 0
      or all {
        finalPath == BreachSealClose,
        l1ProofKind(ProofObligationBreachSealProof) == ViolationClose,
        proofCanSlash(ProofObligationBreachSealProof),
      }

  val slashOnlyAfterDeadline =
    slashed == 0 or height >= obligation.proofDeadline

  val timeoutFallbackIsNotSlashable =
    finalPath != TimeoutFallbackClose
      or all {
        l1ProofKind(TimeoutFallbackProof) == TimeoutClose,
        not(proofCanSlash(TimeoutFallbackProof)),
        slashed == 0,
      }

  val proofBeforeDeadlineDischarges =
    status != ObligationDischarged
      or all {
        phase == Closed,
        finalPath == SelfContainedLatestProofClose,
        closedAt < obligation.proofDeadline,
        l1ProofKind(SelfContainedLatestStateProof) == LatestProofClose,
        proofKindAdmissible(SelfContainedLatestStateProof),
        not(proofCanSlash(SelfContainedLatestStateProof)),
        slashed == 0,
      }

  val breachSealBeforeExpiry =
    finalPath != BreachSealClose or closedAt < obligation.expiryHeight

  val breachedObligationHasSealPath =
    status != ObligationBreached
      or phase != Live
      or height >= obligation.expiryHeight
      or canCloseByBreachSeal

  val breachSealProtectsBeneficiary =
    finalPath != BreachSealClose
      or all {
        recovery.get(obligation.beneficiary) >= TimeoutRecovery.get(obligation.beneficiary),
        recovery.get(obligation.beneficiary) >= LatestRecovery.get(obligation.beneficiary),
      }

  val closedPathHasExpectedRecovery =
    phase != Closed
      or any {
        finalPath == SelfContainedLatestProofClose and recovery == LatestRecovery,
        finalPath == TimeoutFallbackClose and recovery == TimeoutRecovery,
        finalPath == BreachSealClose and recovery == BreachSealRecovery,
      }

  val unbackedObligationCannotBreach =
    obligation != UnbackedObligation
      or all {
        not(proofObligationPublic(obligation.kind)),
        not(canMarkBreach),
        not(canCloseByBreachSeal),
      }

  run proofBeforeDeadlineDischargesTest =
    init
      .then(createObligation(MakerProtectedObligation))
      .then(tickLive)
      .then(submitRequiredProof)
      .expect(status == ObligationDischarged
        and finalPath == SelfContainedLatestProofClose
        and recovery == LatestRecovery
        and proofBeforeDeadlineDischarges)

  run breachSealAfterDeadlineTest =
    init
      .then(createObligation(MakerProtectedObligation))
      .then(tickLive)
      .then(tickLive)
      .then(markBreach)
      .then(closeByBreachSeal)
      .expect(status == ObligationBreached
        and finalPath == BreachSealClose
        and slashed == ProofBreachPenalty
        and breachSealBeforeExpiry
        and breachSealProtectsBeneficiary)

  run timeoutFallbackDoesNotSlashTest =
    init
      .then(createObligation(MakerProtectedObligation))
      .then(tickLive)
      .then(tickLive)
      .then(tickLive)
      .then(tickLive)
      .then(closeByTimeout)
      .expect(finalPath == TimeoutFallbackClose
        and recovery == TimeoutRecovery
        and timeoutFallbackIsNotSlashable
        and noSlashWithoutPublicObligation)

  run unbackedObligationCannotBreachTest =
    init
      .then(createUnbackedObligation)
      .then(tickLive)
      .then(tickLive)
      .expect(obligation == UnbackedObligation
        and unbackedObligationCannotBreach
        and noSlashWithoutPublicObligation)

  run unsafeLateDeadlineRejectedTest =
    init
      .expect(not(obligationWellFormed(UnsafeLateObligation))
        and not(canCreateObligation(UnsafeLateObligation))
        and not(obligationDeadlineHasMargin(UnsafeLateObligation)))
}
