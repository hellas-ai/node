module frontier_commitments {
  import frontier.* from "./frontier"
  import proofs.* from "./proofs"

  // Focused model for signed frontier commitments over active job locks.
  //
  // This abstracts the Merkle-sum map as a small finite root vocabulary. The
  // property under test is not Merkle hashing. It is the verifier boundary:
  // a Close proof is accepted only when it binds the current admissible
  // frontier commitment, the root's aggregate locked total, and the close
  // outcome. There is no on-chain defense round.
  //
  // This model assumes the verifier has a source for "current admissible
  // frontier". See `frontier_progression.qnt` for the separate freshness
  // boundary: a bare historical frontier signature is not enough.

  type Phase =
    | Live
    | Closed

  type ClosePath =
    | NoClose
    | AcceptedReleaseClose
    | ViolationJobSlashClose

  var phase: Phase
  var height: int
  var frontier: FrontierCommitment
  var closedFrontier: FrontierCommitment
  var finalAvailableStake: int
  var finalLockedStake: int
  var finalStakeAward: int
  var finalPath: ClosePath

  pure val PostedStake = 12
  pure val GenesisHeight = 1
  pure val JobAStakeRequirement = 7
  pure val JobAPenalty = 4
  pure val JobAReleaseDeadline = 4

  pure val ActiveAFrontier: FrontierCommitment = {
    seq: 1,
    root: JobAActiveRoot,
    lockedTotal: JobAStakeRequirement,
    availableStake: PostedStake - JobAStakeRequirement,
    stakeAward: 0,
  }

  pure val ReleasedAFrontier: FrontierCommitment = {
    seq: 2,
    root: EmptyRoot,
    lockedTotal: 0,
    availableStake: PostedStake,
    stakeAward: 0,
  }

  pure val BadAggregateFrontier: FrontierCommitment = {
    seq: 1,
    root: JobAActiveRoot,
    lockedTotal: 0,
    availableStake: PostedStake,
    stakeAward: 0,
  }

  pure def sampleFrontierWellFormed(f: FrontierCommitment): bool =
    frontierWellFormed(f, PostedStake, JobAStakeRequirement)

  def frontierIsCurrent(f: FrontierCommitment): bool =
    f == frontier

  def validReleaseCloseProof(f: FrontierCommitment): bool =
    phase == Live
      and frontierIsCurrent(f)
      and sampleFrontierWellFormed(f)
      and not(rootContainsJobA(f.root))

  def validViolationCloseProof(f: FrontierCommitment): bool =
    phase == Live
      and frontierIsCurrent(f)
      and sampleFrontierWellFormed(f)
      and rootContainsJobA(f.root)
      and height < JobAReleaseDeadline
      and evidenceCanProveViolation(BadComputeEvidence)
      and proofCanSlash(BadComputeSealProof)
      and l1ProofKind(BadComputeSealProof) == ViolationClose

  action init = all {
    phase' = Live,
    height' = GenesisHeight,
    frontier' = ActiveAFrontier,
    closedFrontier' = EmptyFrontier,
    finalAvailableStake' = 0,
    finalLockedStake' = 0,
    finalStakeAward' = 0,
    finalPath' = NoClose,
  }

  action signReleaseFrontier = all {
    phase == Live,
    frontier == ActiveAFrontier,
    phase' = phase,
    height' = height,
    frontier' = ReleasedAFrontier,
    closedFrontier' = closedFrontier,
    finalAvailableStake' = finalAvailableStake,
    finalLockedStake' = finalLockedStake,
    finalStakeAward' = finalStakeAward,
    finalPath' = finalPath,
  }

  action closeByRelease(f) = all {
    validReleaseCloseProof(f),
    phase' = Closed,
    height' = height,
    frontier' = frontier,
    closedFrontier' = f,
    finalAvailableStake' = f.availableStake,
    finalLockedStake' = 0,
    finalStakeAward' = f.stakeAward,
    finalPath' = AcceptedReleaseClose,
  }

  action closeByViolation(f) = all {
    validViolationCloseProof(f),
    phase' = Closed,
    height' = height,
    frontier' = frontier,
    closedFrontier' = f,
    finalAvailableStake' = f.availableStake + JobAStakeRequirement - JobAPenalty,
    finalLockedStake' = f.lockedTotal - JobAStakeRequirement,
    finalStakeAward' = f.stakeAward + JobAPenalty,
    finalPath' = ViolationJobSlashClose,
  }

  action tick = all {
    phase == Live,
    height < JobAReleaseDeadline,
    phase' = phase,
    height' = height + 1,
    frontier' = frontier,
    closedFrontier' = closedFrontier,
    finalAvailableStake' = finalAvailableStake,
    finalLockedStake' = finalLockedStake,
    finalStakeAward' = finalStakeAward,
    finalPath' = finalPath,
  }

  action stutterClosed = all {
    phase == Closed,
    phase' = phase,
    height' = height,
    frontier' = frontier,
    closedFrontier' = closedFrontier,
    finalAvailableStake' = finalAvailableStake,
    finalLockedStake' = finalLockedStake,
    finalStakeAward' = finalStakeAward,
    finalPath' = finalPath,
  }

  action step = any {
    signReleaseFrontier,
    closeByRelease(ReleasedAFrontier),
    closeByRelease(BadAggregateFrontier),
    closeByViolation(ActiveAFrontier),
    closeByViolation(BadAggregateFrontier),
    tick,
    stutterClosed,
  }

  val valueAccounted =
    if (phase == Live) {
      frontierCapacityBalances(frontier, PostedStake)
    } else {
      finalAvailableStake + finalLockedStake + finalStakeAward == PostedStake
    }

  val noNegativeBucket =
    height >= GenesisHeight
      and frontierNonNegative(frontier)
      and frontierNonNegative(closedFrontier)
      and finalAvailableStake >= 0
      and finalLockedStake >= 0
      and finalStakeAward >= 0

  val liveFrontierWellFormed =
    phase != Live or sampleFrontierWellFormed(frontier)

  val closedFrontierWasCurrent =
    phase != Closed or closedFrontier == frontier

  val closedFrontierWellFormed =
    phase != Closed or sampleFrontierWellFormed(closedFrontier)

  val closeAcceptedOnlyWithValidProof =
    phase != Closed
      or any {
        finalPath == AcceptedReleaseClose
          and not(rootContainsJobA(closedFrontier.root))
          and finalStakeAward == closedFrontier.stakeAward,
        finalPath == ViolationJobSlashClose
          and rootContainsJobA(closedFrontier.root)
          and finalStakeAward == closedFrontier.stakeAward + JobAPenalty,
      }

  val badAggregateFrontierRejected =
    not(validReleaseCloseProof(BadAggregateFrontier))
      and not(validViolationCloseProof(BadAggregateFrontier))

  val staleActiveRootRejectedAfterRelease =
    frontier != ReleasedAFrontier
      or not(validViolationCloseProof(ActiveAFrontier))

  val violationRequiresActiveJobRoot =
    phase != Closed
      or finalPath != ViolationJobSlashClose
      or rootContainsJobA(closedFrontier.root)

  val releaseCloseDoesNotSlash =
    phase != Closed
      or finalPath != AcceptedReleaseClose
      or finalStakeAward == closedFrontier.stakeAward

  val violationCloseAccountsForPenalty =
    phase != Closed
      or finalPath != ViolationJobSlashClose
      or all {
        finalStakeAward == JobAPenalty,
        finalAvailableStake == PostedStake - JobAPenalty,
        finalLockedStake == 0,
      }

  run currentActiveRootCanSlashTest =
    init
      .then(closeByViolation(ActiveAFrontier))
      .expect(phase == Closed
        and finalPath == ViolationJobSlashClose
        and closedFrontier == ActiveAFrontier
        and violationCloseAccountsForPenalty
        and valueAccounted)

  run signedReleaseFrontierClosesWithoutSlashTest =
    init
      .then(signReleaseFrontier)
      .then(closeByRelease(ReleasedAFrontier))
      .expect(phase == Closed
        and finalPath == AcceptedReleaseClose
        and closedFrontier == ReleasedAFrontier
        and finalStakeAward == 0
        and releaseCloseDoesNotSlash
        and valueAccounted)

  run oldActiveRootCannotSlashAfterReleaseTest =
    init
      .then(signReleaseFrontier)
      .expect(frontier == ReleasedAFrontier
        and not(validViolationCloseProof(ActiveAFrontier))
        and staleActiveRootRejectedAfterRelease)

  run badAggregateRootRejectedTest =
    init
      .expect(not(sampleFrontierWellFormed(BadAggregateFrontier))
        and badAggregateFrontierRejected)
}
