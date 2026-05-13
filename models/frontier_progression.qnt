module frontier_progression {
  import frontier.* from "./frontier"

  // Focused model for signed frontier progression.
  //
  // `frontier_commitments.qnt` checks the verifier boundary once a close proof
  // has a current admissible frontier. This model checks where that "current"
  // fact can come from. A peer can reject stale or semantically invalid
  // successor frontiers off-chain, but a bare old signed frontier is still a
  // valid historical signature. Without an L1 anchor or a fresh mutual close
  // authorization, the kernel cannot infer that a later release exists.

  type Phase =
    | Live
    | Closed

  type JobAStatus =
    | NeverLocked
    | ActiveLock
    | ReleasedLock
    | SlashedLock

  type ClosePath =
    | NoClose
    | AnchoredReleaseClose
    | AnchoredViolationClose
    | MutualFrontierClose

  var phase: Phase
  var peerFrontier: FrontierCommitment
  var peerJobAStatus: JobAStatus
  var l1HasAnchor: bool
  var l1AnchoredFrontier: FrontierCommitment
  var closedFrontier: FrontierCommitment
  var finalPath: ClosePath

  pure val PostedStake = 12
  pure val JobAStakeRequirement = 7
  pure val JobAPenalty = 4

  pure val IdleFrontier: FrontierCommitment = {
    seq: 0,
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

  pure val ReleasedAFrontier: FrontierCommitment = {
    seq: 2,
    root: EmptyRoot,
    lockedTotal: 0,
    availableStake: PostedStake,
    stakeAward: 0,
  }

  pure val SlashedAFrontier: FrontierCommitment = {
    seq: 2,
    root: EmptyRoot,
    lockedTotal: 0,
    availableStake: PostedStake - JobAPenalty,
    stakeAward: JobAPenalty,
  }

  pure val ReintroducedActiveAFrontier: FrontierCommitment = {
    seq: 3,
    root: JobAActiveRoot,
    lockedTotal: JobAStakeRequirement,
    availableStake: PostedStake - JobAStakeRequirement,
    stakeAward: 0,
  }

  pure val BadAggregateFrontier: FrontierCommitment = {
    seq: 2,
    root: JobAActiveRoot,
    lockedTotal: 0,
    availableStake: PostedStake,
    stakeAward: 0,
  }

  pure def sampleFrontierWellFormed(f: FrontierCommitment): bool =
    frontierWellFormed(f, PostedStake, JobAStakeRequirement)

  pure def statusMatchesRoot(status: JobAStatus, f: FrontierCommitment): bool =
    if (status == ActiveLock) {
      rootContainsJobA(f.root)
        and f.lockedTotal == JobAStakeRequirement
    } else {
      not(rootContainsJobA(f.root))
        and f.lockedTotal == 0
    }

  pure def successorConsistent(
    status: JobAStatus,
    current: FrontierCommitment,
    candidate: FrontierCommitment,
  ): bool =
    sampleFrontierWellFormed(candidate)
      and candidate.seq == current.seq + 1
      and any {
        status == NeverLocked
          and current == IdleFrontier
          and candidate == ActiveAFrontier,
        status == ActiveLock
          and current == ActiveAFrontier
          and candidate == ReleasedAFrontier,
        status == ActiveLock
          and current == ActiveAFrontier
          and candidate == SlashedAFrontier,
      }

  pure def statusAfterAccepted(candidate: FrontierCommitment): JobAStatus =
    if (candidate == ActiveAFrontier) {
      ActiveLock
    } else if (candidate == ReleasedAFrontier) {
      ReleasedLock
    } else {
      SlashedLock
    }

  def canAcceptPeerFrontier(candidate: FrontierCommitment): bool =
    phase == Live
      and successorConsistent(peerJobAStatus, peerFrontier, candidate)

  def bareSignedViolationCloseLooksValid(f: FrontierCommitment): bool =
    phase == Live
      and sampleFrontierWellFormed(f)
      and rootContainsJobA(f.root)

  def anchoredReleaseCloseOk(f: FrontierCommitment): bool =
    phase == Live
      and l1HasAnchor
      and f == l1AnchoredFrontier
      and sampleFrontierWellFormed(f)
      and not(rootContainsJobA(f.root))

  def anchoredViolationCloseOk(f: FrontierCommitment): bool =
    phase == Live
      and l1HasAnchor
      and f == l1AnchoredFrontier
      and sampleFrontierWellFormed(f)
      and rootContainsJobA(f.root)

  def mutualFrontierCloseOk(f: FrontierCommitment): bool =
    phase == Live
      and f == peerFrontier
      and sampleFrontierWellFormed(f)

  action init = all {
    phase' = Live,
    peerFrontier' = IdleFrontier,
    peerJobAStatus' = NeverLocked,
    l1HasAnchor' = false,
    l1AnchoredFrontier' = IdleFrontier,
    closedFrontier' = IdleFrontier,
    finalPath' = NoClose,
  }

  action acceptPeerFrontier(candidate) = all {
    canAcceptPeerFrontier(candidate),
    phase' = phase,
    peerFrontier' = candidate,
    peerJobAStatus' = statusAfterAccepted(candidate),
    l1HasAnchor' = l1HasAnchor,
    l1AnchoredFrontier' = l1AnchoredFrontier,
    closedFrontier' = closedFrontier,
    finalPath' = finalPath,
  }

  action anchorPeerFrontier = all {
    phase == Live,
    sampleFrontierWellFormed(peerFrontier),
    phase' = phase,
    peerFrontier' = peerFrontier,
    peerJobAStatus' = peerJobAStatus,
    l1HasAnchor' = true,
    l1AnchoredFrontier' = peerFrontier,
    closedFrontier' = closedFrontier,
    finalPath' = finalPath,
  }

  action closeByAnchoredRelease(f) = all {
    anchoredReleaseCloseOk(f),
    phase' = Closed,
    peerFrontier' = peerFrontier,
    peerJobAStatus' = peerJobAStatus,
    l1HasAnchor' = l1HasAnchor,
    l1AnchoredFrontier' = l1AnchoredFrontier,
    closedFrontier' = f,
    finalPath' = AnchoredReleaseClose,
  }

  action closeByAnchoredViolation(f) = all {
    anchoredViolationCloseOk(f),
    phase' = Closed,
    peerFrontier' = peerFrontier,
    peerJobAStatus' = peerJobAStatus,
    l1HasAnchor' = l1HasAnchor,
    l1AnchoredFrontier' = l1AnchoredFrontier,
    closedFrontier' = f,
    finalPath' = AnchoredViolationClose,
  }

  action closeByMutualFrontier(f) = all {
    mutualFrontierCloseOk(f),
    phase' = Closed,
    peerFrontier' = peerFrontier,
    peerJobAStatus' = peerJobAStatus,
    l1HasAnchor' = l1HasAnchor,
    l1AnchoredFrontier' = l1AnchoredFrontier,
    closedFrontier' = f,
    finalPath' = MutualFrontierClose,
  }

  action stutterClosed = all {
    phase == Closed,
    phase' = phase,
    peerFrontier' = peerFrontier,
    peerJobAStatus' = peerJobAStatus,
    l1HasAnchor' = l1HasAnchor,
    l1AnchoredFrontier' = l1AnchoredFrontier,
    closedFrontier' = closedFrontier,
    finalPath' = finalPath,
  }

  action step = any {
    acceptPeerFrontier(ActiveAFrontier),
    acceptPeerFrontier(ReleasedAFrontier),
    acceptPeerFrontier(SlashedAFrontier),
    acceptPeerFrontier(ReintroducedActiveAFrontier),
    acceptPeerFrontier(BadAggregateFrontier),
    anchorPeerFrontier,
    closeByAnchoredRelease(ReleasedAFrontier),
    closeByAnchoredViolation(ActiveAFrontier),
    closeByMutualFrontier(ActiveAFrontier),
    closeByMutualFrontier(ReleasedAFrontier),
    closeByMutualFrontier(SlashedAFrontier),
    stutterClosed,
  }

  val peerFrontierWellFormed =
    sampleFrontierWellFormed(peerFrontier)

  val peerStatusMatchesRoot =
    statusMatchesRoot(peerJobAStatus, peerFrontier)

  val anchoredFrontierWellFormed =
    not(l1HasAnchor) or sampleFrontierWellFormed(l1AnchoredFrontier)

  val closedFrontierWellFormed =
    phase != Closed or sampleFrontierWellFormed(closedFrontier)

  val closedBySafeFrontierSource =
    phase != Closed
      or any {
        finalPath == AnchoredReleaseClose
          and l1HasAnchor
          and closedFrontier == l1AnchoredFrontier
          and not(rootContainsJobA(closedFrontier.root)),
        finalPath == AnchoredViolationClose
          and l1HasAnchor
          and closedFrontier == l1AnchoredFrontier
          and rootContainsJobA(closedFrontier.root),
        finalPath == MutualFrontierClose
          and closedFrontier == peerFrontier,
      }

  val badAggregateRejectedByPeer =
    not(canAcceptPeerFrontier(BadAggregateFrontier))

  val staleLowerSeqRejectedByPeer =
    peerFrontier != ReleasedAFrontier
      or not(canAcceptPeerFrontier(ActiveAFrontier))

  val releasedJobCannotBeReintroducedByHigherSeq =
    peerJobAStatus != ReleasedLock
      or not(canAcceptPeerFrontier(ReintroducedActiveAFrontier))

  val slashedJobCannotBeReintroducedByHigherSeq =
    peerJobAStatus != SlashedLock
      or not(canAcceptPeerFrontier(ReintroducedActiveAFrontier))

  val safeCloseNeverUsesBareSignedFrontier =
    phase != Closed
      or finalPath == AnchoredReleaseClose
      or finalPath == AnchoredViolationClose
      or finalPath == MutualFrontierClose

  val bareOldActiveReceiptStillLooksLocallyValidAfterRelease =
    peerFrontier == ReleasedAFrontier
      and bareSignedViolationCloseLooksValid(ActiveAFrontier)

  run peerAcceptsLockThenReleaseTest =
    init
      .then(acceptPeerFrontier(ActiveAFrontier))
      .then(acceptPeerFrontier(ReleasedAFrontier))
      .expect(peerJobAStatus == ReleasedLock
        and peerFrontier == ReleasedAFrontier
        and peerStatusMatchesRoot
        and staleLowerSeqRejectedByPeer)

  run peerRejectsBadAggregateTest =
    init
      .expect(badAggregateRejectedByPeer
        and not(canAcceptPeerFrontier(BadAggregateFrontier)))

  run peerRejectsReintroducedJobAfterReleaseTest =
    init
      .then(acceptPeerFrontier(ActiveAFrontier))
      .then(acceptPeerFrontier(ReleasedAFrontier))
      .expect(not(canAcceptPeerFrontier(ReintroducedActiveAFrontier))
        and releasedJobCannotBeReintroducedByHigherSeq)

  run anchoredReleaseCanCloseTest =
    init
      .then(acceptPeerFrontier(ActiveAFrontier))
      .then(acceptPeerFrontier(ReleasedAFrontier))
      .then(anchorPeerFrontier)
      .then(closeByAnchoredRelease(ReleasedAFrontier))
      .expect(phase == Closed
        and finalPath == AnchoredReleaseClose
        and closedBySafeFrontierSource)

  run mutualCloseUsesCurrentPeerFrontierTest =
    init
      .then(acceptPeerFrontier(ActiveAFrontier))
      .then(acceptPeerFrontier(ReleasedAFrontier))
      .then(closeByMutualFrontier(ReleasedAFrontier))
      .expect(phase == Closed
        and finalPath == MutualFrontierClose
        and closedFrontier == ReleasedAFrontier
        and closedBySafeFrontierSource)

  run bareSignedFrontierCounterexampleTest =
    init
      .then(acceptPeerFrontier(ActiveAFrontier))
      .then(acceptPeerFrontier(ReleasedAFrontier))
      .expect(bareOldActiveReceiptStillLooksLocallyValidAfterRelease
        and not(mutualFrontierCloseOk(ActiveAFrontier))
        and not(anchoredViolationCloseOk(ActiveAFrontier)))
}
