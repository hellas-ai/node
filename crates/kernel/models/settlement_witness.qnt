module settlement_witness {
  import frontier.* from "./frontier"
  import proofs.* from "./proofs"

  // Focused model for the L1 settlement witness boundary.
  //
  // This is the contract between the kernel and proof/seal verifiers. It does
  // not model cryptographic internals. It models the public inputs that a close
  // witness must bind: edge id, terms identity, close kind, payout shape,
  // expiry height, frontier commitment, and stake award.

  type Phase =
    | Live
    | Closed

  type EdgeRef =
    | ExpectedEdge
    | WrongEdge

  type TermsRef =
    | LatestTermsRef
    | TimeoutTermsRef
    | ViolationTermsRef
    | WrongTermsRef

  type PayoutRef =
    | LatestPayouts
    | TimeoutPayouts
    | ViolationPayouts
    | WrongPayouts

  type SettlementOutcome =
    | NoSettlement
    | FreshMutualLatestSettlement
    | SelfContainedLatestSettlement
    | TimeoutSettlement
    | ViolationSettlement

  type SettlementWitness = {
    edge: EdgeRef,
    terms: TermsRef,
    payout: PayoutRef,
    expiryHeight: int,
    proof: ProofKind,
    evidence: EvidenceKind,
    frontier: FrontierCommitment,
    stakeAward: int,
    signedByBothNow: bool,
    selfContained: bool,
  }

  var phase: Phase
  var height: int
  var closedAt: int
  var finalOutcome: SettlementOutcome
  var finalWitness: SettlementWitness

  pure val PostedStake = 12
  pure val JobAStakeRequirement = 7
  pure val JobAPenalty = 4
  pure val GenesisHeight = 1
  pure val BeforeExpiryHeight = 3
  pure val ExpiryHeight = 5

  pure val ReleasedFrontier: FrontierCommitment = {
    seq: 2,
    root: EmptyRoot,
    lockedTotal: 0,
    availableStake: PostedStake,
    stakeAward: 0,
  }

  pure val ActiveAFrontier: FrontierCommitment = {
    seq: 1,
    root: JobAActiveRoot,
    lockedTotal: JobAStakeRequirement,
    availableStake: PostedStake - JobAStakeRequirement,
    stakeAward: 0,
  }

  pure val BadAggregateFrontier: FrontierCommitment = {
    seq: 1,
    root: JobAActiveRoot,
    lockedTotal: 0,
    availableStake: PostedStake,
    stakeAward: 0,
  }

  pure val EmptySettlementWitness: SettlementWitness = {
    edge: WrongEdge,
    terms: WrongTermsRef,
    payout: WrongPayouts,
    expiryHeight: 0,
    proof: NoProof,
    evidence: NoEvidence,
    frontier: EmptyFrontier,
    stakeAward: 0,
    signedByBothNow: false,
    selfContained: false,
  }

  pure val FreshMutualLatestWitness: SettlementWitness = {
    edge: ExpectedEdge,
    terms: LatestTermsRef,
    payout: LatestPayouts,
    expiryHeight: ExpiryHeight,
    proof: FreshMutualLatestCloseProof,
    evidence: NoEvidence,
    frontier: ReleasedFrontier,
    stakeAward: 0,
    signedByBothNow: true,
    selfContained: false,
  }

  pure val SelfContainedLatestWitness: SettlementWitness = {
    edge: ExpectedEdge,
    terms: LatestTermsRef,
    payout: LatestPayouts,
    expiryHeight: ExpiryHeight,
    proof: SelfContainedLatestStateProof,
    evidence: NoEvidence,
    frontier: ReleasedFrontier,
    stakeAward: 0,
    signedByBothNow: false,
    selfContained: true,
  }

  pure val ViolationWitness: SettlementWitness = {
    edge: ExpectedEdge,
    terms: ViolationTermsRef,
    payout: ViolationPayouts,
    expiryHeight: ExpiryHeight,
    proof: BadComputeSealProof,
    evidence: BadComputeEvidence,
    frontier: ActiveAFrontier,
    stakeAward: JobAPenalty,
    signedByBothNow: false,
    selfContained: true,
  }

  pure val TimeoutWitness: SettlementWitness = {
    edge: ExpectedEdge,
    terms: TimeoutTermsRef,
    payout: TimeoutPayouts,
    expiryHeight: ExpiryHeight,
    proof: TimeoutFallbackProof,
    evidence: ExpiryEvidence,
    frontier: ReleasedFrontier,
    stakeAward: 0,
    signedByBothNow: false,
    selfContained: false,
  }

  pure val BareSignedReceiptWitness: SettlementWitness = {
    edge: ExpectedEdge,
    terms: LatestTermsRef,
    payout: LatestPayouts,
    expiryHeight: ExpiryHeight,
    proof: BareSignedReceiptProof,
    evidence: NoEvidence,
    frontier: ReleasedFrontier,
    stakeAward: 0,
    signedByBothNow: false,
    selfContained: false,
  }

  pure val WrongTermsLatestWitness: SettlementWitness =
    SelfContainedLatestWitness.with("terms", WrongTermsRef)

  pure val WrongPayoutLatestWitness: SettlementWitness =
    SelfContainedLatestWitness.with("payout", WrongPayouts)

  pure val WrongEdgeLatestWitness: SettlementWitness =
    SelfContainedLatestWitness.with("edge", WrongEdge)

  pure val WrongExpiryLatestWitness: SettlementWitness =
    SelfContainedLatestWitness.with("expiryHeight", ExpiryHeight + 1)

  pure val ActiveRootLatestWitness: SettlementWitness =
    SelfContainedLatestWitness.with("frontier", ActiveAFrontier)

  pure val BadAggregateLatestWitness: SettlementWitness =
    SelfContainedLatestWitness.with("frontier", BadAggregateFrontier)

  pure val NoEvidenceViolationWitness: SettlementWitness =
    ViolationWitness.with("evidence", NoEvidence)

  pure val ReleasedRootViolationWitness: SettlementWitness =
    ViolationWitness.with("frontier", ReleasedFrontier)

  pure val MissingStakeAwardViolationWitness: SettlementWitness =
    ViolationWitness.with("stakeAward", 0)

  pure def sampleFrontierWellFormed(f: FrontierCommitment): bool =
    frontierWellFormed(f, PostedStake, JobAStakeRequirement)

  pure def termsAndPayoutMatch(w: SettlementWitness): bool =
    match w.terms {
      | LatestTermsRef => w.payout == LatestPayouts
      | TimeoutTermsRef => w.payout == TimeoutPayouts
      | ViolationTermsRef => w.payout == ViolationPayouts
      | WrongTermsRef => false
    }

  pure def commonBindingsOk(w: SettlementWitness): bool =
    w.edge == ExpectedEdge
      and w.expiryHeight == ExpiryHeight
      and termsAndPayoutMatch(w)
      and sampleFrontierWellFormed(w.frontier)
      and w.stakeAward >= 0

  pure def validFreshMutualLatest(
    w: SettlementWitness,
    h: int,
  ): bool =
    commonBindingsOk(w)
      and w.proof == FreshMutualLatestCloseProof
      and l1ProofKind(w.proof) == MutualClose
      and proofKindAdmissible(w.proof)
      and not(proofCanSlash(w.proof))
      and w.signedByBothNow
      and w.terms == LatestTermsRef
      and h < w.expiryHeight
      and not(rootContainsJobA(w.frontier.root))
      and w.stakeAward == w.frontier.stakeAward

  pure def validSelfContainedLatest(
    w: SettlementWitness,
    h: int,
  ): bool =
    commonBindingsOk(w)
      and w.proof == SelfContainedLatestStateProof
      and l1ProofKind(w.proof) == LatestProofClose
      and proofKindAdmissible(w.proof)
      and not(proofCanSlash(w.proof))
      and w.selfContained
      and w.terms == LatestTermsRef
      and h < w.expiryHeight
      and not(rootContainsJobA(w.frontier.root))
      and w.stakeAward == w.frontier.stakeAward

  pure def validTimeout(
    w: SettlementWitness,
    h: int,
  ): bool =
    commonBindingsOk(w)
      and w.proof == TimeoutFallbackProof
      and l1ProofKind(w.proof) == TimeoutClose
      and proofKindAdmissible(w.proof)
      and not(proofCanSlash(w.proof))
      and w.terms == TimeoutTermsRef
      and h >= w.expiryHeight
      and not(rootContainsJobA(w.frontier.root))
      and w.stakeAward == w.frontier.stakeAward

  pure def validViolation(
    w: SettlementWitness,
    h: int,
  ): bool =
    commonBindingsOk(w)
      and l1ProofKind(w.proof) == ViolationClose
      and proofKindAdmissible(w.proof)
      and proofCanSlash(w.proof)
      and evidenceCanProveViolation(w.evidence)
      and w.selfContained
      and w.terms == ViolationTermsRef
      and h < w.expiryHeight
      and rootContainsJobA(w.frontier.root)
      and w.frontier.lockedTotal >= JobAPenalty
      and w.stakeAward == w.frontier.stakeAward + JobAPenalty

  pure def validSettlementWitnessAt(
    w: SettlementWitness,
    h: int,
  ): bool =
    any {
      validFreshMutualLatest(w, h),
      validSelfContainedLatest(w, h),
      validTimeout(w, h),
      validViolation(w, h),
    }

  pure def outcomeOf(
    w: SettlementWitness,
    h: int,
  ): SettlementOutcome =
    if (validFreshMutualLatest(w, h)) {
      FreshMutualLatestSettlement
    } else if (validSelfContainedLatest(w, h)) {
      SelfContainedLatestSettlement
    } else if (validTimeout(w, h)) {
      TimeoutSettlement
    } else if (validViolation(w, h)) {
      ViolationSettlement
    } else {
      NoSettlement
    }

  action init = all {
    phase' = Live,
    height' = BeforeExpiryHeight,
    closedAt' = 0,
    finalOutcome' = NoSettlement,
    finalWitness' = EmptySettlementWitness,
  }

  action submitClose(w) = all {
    phase == Live,
    validSettlementWitnessAt(w, height),
    phase' = Closed,
    height' = height,
    closedAt' = height,
    finalOutcome' = outcomeOf(w, height),
    finalWitness' = w,
  }

  action tickToExpiry = all {
    phase == Live,
    height < ExpiryHeight,
    phase' = phase,
    height' = ExpiryHeight,
    closedAt' = closedAt,
    finalOutcome' = finalOutcome,
    finalWitness' = finalWitness,
  }

  action stutterClosed = all {
    phase == Closed,
    phase' = phase,
    height' = height,
    closedAt' = closedAt,
    finalOutcome' = finalOutcome,
    finalWitness' = finalWitness,
  }

  action step = any {
    submitClose(FreshMutualLatestWitness),
    submitClose(SelfContainedLatestWitness),
    submitClose(ViolationWitness),
    submitClose(TimeoutWitness),
    submitClose(BareSignedReceiptWitness),
    submitClose(WrongTermsLatestWitness),
    submitClose(WrongPayoutLatestWitness),
    submitClose(WrongEdgeLatestWitness),
    submitClose(WrongExpiryLatestWitness),
    submitClose(ActiveRootLatestWitness),
    submitClose(BadAggregateLatestWitness),
    submitClose(NoEvidenceViolationWitness),
    submitClose(ReleasedRootViolationWitness),
    submitClose(MissingStakeAwardViolationWitness),
    tickToExpiry,
    stutterClosed,
  }

  val acceptedOnlyWithValidWitness =
    phase != Closed or validSettlementWitnessAt(finalWitness, closedAt)

  val acceptedBindsExpectedEdge =
    phase != Closed or finalWitness.edge == ExpectedEdge

  val acceptedBindsTermsAndPayout =
    phase != Closed or termsAndPayoutMatch(finalWitness)

  val acceptedBindsExpiry =
    phase != Closed or finalWitness.expiryHeight == ExpiryHeight

  val acceptedBindsWellFormedFrontier =
    phase != Closed or sampleFrontierWellFormed(finalWitness.frontier)

  val acceptedProofKindMatchesOutcome =
    phase != Closed
      or any {
        finalOutcome == FreshMutualLatestSettlement
          and l1ProofKind(finalWitness.proof) == MutualClose,
        finalOutcome == SelfContainedLatestSettlement
          and l1ProofKind(finalWitness.proof) == LatestProofClose,
        finalOutcome == TimeoutSettlement
          and l1ProofKind(finalWitness.proof) == TimeoutClose,
        finalOutcome == ViolationSettlement
          and l1ProofKind(finalWitness.proof) == ViolationClose,
      }

  val acceptedStakeAwardMatchesOutcome =
    phase != Closed
      or any {
        finalOutcome == ViolationSettlement
          and finalWitness.stakeAward == finalWitness.frontier.stakeAward + JobAPenalty,
        finalOutcome != ViolationSettlement
          and finalWitness.stakeAward == finalWitness.frontier.stakeAward,
      }

  val bareSignedReceiptRejected =
    not(validSettlementWitnessAt(BareSignedReceiptWitness, BeforeExpiryHeight))
      and not(validSettlementWitnessAt(BareSignedReceiptWitness, ExpiryHeight))
      and l1ProofKind(BareSignedReceiptProof) == NoL1Proof
      and not(proofKindAdmissible(BareSignedReceiptProof))

  val malformedWitnessesRejected =
    all {
      not(validSettlementWitnessAt(WrongTermsLatestWitness, BeforeExpiryHeight)),
      not(validSettlementWitnessAt(WrongPayoutLatestWitness, BeforeExpiryHeight)),
      not(validSettlementWitnessAt(WrongEdgeLatestWitness, BeforeExpiryHeight)),
      not(validSettlementWitnessAt(WrongExpiryLatestWitness, BeforeExpiryHeight)),
      not(validSettlementWitnessAt(BadAggregateLatestWitness, BeforeExpiryHeight)),
    }

  val staleActiveRootRejectedForLatest =
    not(validSettlementWitnessAt(ActiveRootLatestWitness, BeforeExpiryHeight))

  val violationRequiresActiveSlashRoot =
    not(validSettlementWitnessAt(ReleasedRootViolationWitness, BeforeExpiryHeight))

  val violationRequiresEvidence =
    not(validSettlementWitnessAt(NoEvidenceViolationWitness, BeforeExpiryHeight))

  val violationRequiresStakeAward =
    not(validSettlementWitnessAt(MissingStakeAwardViolationWitness, BeforeExpiryHeight))

  val timeoutBeforeExpiryRejected =
    not(validSettlementWitnessAt(TimeoutWitness, BeforeExpiryHeight))

  run freshMutualLatestAcceptedTest =
    init
      .then(submitClose(FreshMutualLatestWitness))
      .expect(phase == Closed
        and finalOutcome == FreshMutualLatestSettlement
        and acceptedOnlyWithValidWitness
        and acceptedProofKindMatchesOutcome)

  run selfContainedLatestAcceptedTest =
    init
      .then(submitClose(SelfContainedLatestWitness))
      .expect(phase == Closed
        and finalOutcome == SelfContainedLatestSettlement
        and acceptedOnlyWithValidWitness
        and acceptedProofKindMatchesOutcome)

  run violationAcceptedTest =
    init
      .then(submitClose(ViolationWitness))
      .expect(phase == Closed
        and finalOutcome == ViolationSettlement
        and finalWitness.stakeAward == JobAPenalty
        and acceptedStakeAwardMatchesOutcome)

  run timeoutAcceptedAtExpiryTest =
    init
      .then(tickToExpiry)
      .then(submitClose(TimeoutWitness))
      .expect(phase == Closed
        and finalOutcome == TimeoutSettlement
        and closedAt == ExpiryHeight
        and acceptedProofKindMatchesOutcome)

  run bareSignedReceiptRejectedTest =
    init
      .expect(bareSignedReceiptRejected)

  run malformedWitnessesRejectedTest =
    init
      .expect(malformedWitnessesRejected
        and staleActiveRootRejectedForLatest
        and timeoutBeforeExpiryRejected)

  run violationWitnessGuardsTest =
    init
      .expect(violationRequiresActiveSlashRoot
        and violationRequiresEvidence
        and violationRequiresStakeAward)
}
