module job_stake_locks {
  import proofs.* from "./proofs"

  // Focused model for reusable provider stake with per-job logical locks.
  //
  // A provider posts one stake pot. Each accepted job locks some capacity from
  // that pot until either a signed frontier releases it, the job release
  // deadline expires, or a valid violation proof awards the job penalty to the
  // protected party.

  type JobLockStatus =
    | NoJobLock
    | JobLocked
    | ReleasedByAcceptedFrontier
    | ReleasedByDeadline
    | SlashedByViolationProof

  var height: int
  var availableStake: int
  var jobAStake: int
  var jobBStake: int
  var protectedStakeAward: int
  var jobAStatus: JobLockStatus
  var jobBStatus: JobLockStatus
  var jobAResolvedAt: int
  var jobBResolvedAt: int

  pure val PostedStake = 12
  pure val GenesisHeight = 1
  pure val MaxHeight = 7

  pure val JobAStakeRequirement = 7
  pure val JobBStakeRequirement = 5
  pure val JobAPenalty = 4
  pure val JobBPenalty = 3
  pure val JobAReleaseDeadline = 4
  pure val JobBReleaseDeadline = 5

  pure val jobTermsWellFormed =
    JobAStakeRequirement > 0
      and JobBStakeRequirement > 0
      and JobAPenalty > 0
      and JobBPenalty > 0
      and JobAPenalty <= JobAStakeRequirement
      and JobBPenalty <= JobBStakeRequirement
      and JobAReleaseDeadline > GenesisHeight
      and JobBReleaseDeadline > GenesisHeight

  def lockedStakeTotal: int =
    jobAStake + jobBStake

  def slashedPenaltyTotal: int =
    (if (jobAStatus == SlashedByViolationProof) {
      JobAPenalty
    } else {
      0
    }) + (if (jobBStatus == SlashedByViolationProof) {
      JobBPenalty
    } else {
      0
    })

  def canLockJobA: bool =
    jobAStatus == NoJobLock
      and jobTermsWellFormed
      and height < JobAReleaseDeadline
      and availableStake >= JobAStakeRequirement

  def canLockJobB: bool =
    jobBStatus == NoJobLock
      and jobTermsWellFormed
      and height < JobBReleaseDeadline
      and availableStake >= JobBStakeRequirement

  def canReleaseJobAByAcceptedFrontier: bool =
    jobAStatus == JobLocked

  def canReleaseJobBByAcceptedFrontier: bool =
    jobBStatus == JobLocked

  def canReleaseJobAByDeadline: bool =
    jobAStatus == JobLocked
      and height >= JobAReleaseDeadline

  def canReleaseJobBByDeadline: bool =
    jobBStatus == JobLocked
      and height >= JobBReleaseDeadline

  def canSlashJobA: bool =
    jobAStatus == JobLocked
      and height < JobAReleaseDeadline
      and jobAStake >= JobAPenalty
      and evidenceCanProveViolation(BadComputeEvidence)
      and proofCanSlash(BadComputeSealProof)
      and l1ProofKind(BadComputeSealProof) == ViolationClose

  def canSlashJobB: bool =
    jobBStatus == JobLocked
      and height < JobBReleaseDeadline
      and jobBStake >= JobBPenalty
      and evidenceCanProveViolation(BadComputeEvidence)
      and proofCanSlash(BadComputeSealProof)
      and l1ProofKind(BadComputeSealProof) == ViolationClose

  action init = all {
    height' = GenesisHeight,
    availableStake' = PostedStake,
    jobAStake' = 0,
    jobBStake' = 0,
    protectedStakeAward' = 0,
    jobAStatus' = NoJobLock,
    jobBStatus' = NoJobLock,
    jobAResolvedAt' = 0,
    jobBResolvedAt' = 0,
  }

  action lockJobA = all {
    canLockJobA,
    height' = height,
    availableStake' = availableStake - JobAStakeRequirement,
    jobAStake' = JobAStakeRequirement,
    jobBStake' = jobBStake,
    protectedStakeAward' = protectedStakeAward,
    jobAStatus' = JobLocked,
    jobBStatus' = jobBStatus,
    jobAResolvedAt' = 0,
    jobBResolvedAt' = jobBResolvedAt,
  }

  action lockJobB = all {
    canLockJobB,
    height' = height,
    availableStake' = availableStake - JobBStakeRequirement,
    jobAStake' = jobAStake,
    jobBStake' = JobBStakeRequirement,
    protectedStakeAward' = protectedStakeAward,
    jobAStatus' = jobAStatus,
    jobBStatus' = JobLocked,
    jobAResolvedAt' = jobAResolvedAt,
    jobBResolvedAt' = 0,
  }

  action releaseJobAByAcceptedFrontier = all {
    canReleaseJobAByAcceptedFrontier,
    height' = height,
    availableStake' = availableStake + jobAStake,
    jobAStake' = 0,
    jobBStake' = jobBStake,
    protectedStakeAward' = protectedStakeAward,
    jobAStatus' = ReleasedByAcceptedFrontier,
    jobBStatus' = jobBStatus,
    jobAResolvedAt' = height,
    jobBResolvedAt' = jobBResolvedAt,
  }

  action releaseJobBByAcceptedFrontier = all {
    canReleaseJobBByAcceptedFrontier,
    height' = height,
    availableStake' = availableStake + jobBStake,
    jobAStake' = jobAStake,
    jobBStake' = 0,
    protectedStakeAward' = protectedStakeAward,
    jobAStatus' = jobAStatus,
    jobBStatus' = ReleasedByAcceptedFrontier,
    jobAResolvedAt' = jobAResolvedAt,
    jobBResolvedAt' = height,
  }

  action releaseJobAByDeadline = all {
    canReleaseJobAByDeadline,
    height' = height,
    availableStake' = availableStake + jobAStake,
    jobAStake' = 0,
    jobBStake' = jobBStake,
    protectedStakeAward' = protectedStakeAward,
    jobAStatus' = ReleasedByDeadline,
    jobBStatus' = jobBStatus,
    jobAResolvedAt' = height,
    jobBResolvedAt' = jobBResolvedAt,
  }

  action releaseJobBByDeadline = all {
    canReleaseJobBByDeadline,
    height' = height,
    availableStake' = availableStake + jobBStake,
    jobAStake' = jobAStake,
    jobBStake' = 0,
    protectedStakeAward' = protectedStakeAward,
    jobAStatus' = jobAStatus,
    jobBStatus' = ReleasedByDeadline,
    jobAResolvedAt' = jobAResolvedAt,
    jobBResolvedAt' = height,
  }

  action slashJobA = all {
    canSlashJobA,
    height' = height,
    availableStake' = availableStake + jobAStake - JobAPenalty,
    jobAStake' = 0,
    jobBStake' = jobBStake,
    protectedStakeAward' = protectedStakeAward + JobAPenalty,
    jobAStatus' = SlashedByViolationProof,
    jobBStatus' = jobBStatus,
    jobAResolvedAt' = height,
    jobBResolvedAt' = jobBResolvedAt,
  }

  action slashJobB = all {
    canSlashJobB,
    height' = height,
    availableStake' = availableStake + jobBStake - JobBPenalty,
    jobAStake' = jobAStake,
    jobBStake' = 0,
    protectedStakeAward' = protectedStakeAward + JobBPenalty,
    jobAStatus' = jobAStatus,
    jobBStatus' = SlashedByViolationProof,
    jobAResolvedAt' = jobAResolvedAt,
    jobBResolvedAt' = height,
  }

  action tick = all {
    height < MaxHeight,
    height' = height + 1,
    availableStake' = availableStake,
    jobAStake' = jobAStake,
    jobBStake' = jobBStake,
    protectedStakeAward' = protectedStakeAward,
    jobAStatus' = jobAStatus,
    jobBStatus' = jobBStatus,
    jobAResolvedAt' = jobAResolvedAt,
    jobBResolvedAt' = jobBResolvedAt,
  }

  action step = any {
    lockJobA,
    lockJobB,
    releaseJobAByAcceptedFrontier,
    releaseJobBByAcceptedFrontier,
    releaseJobAByDeadline,
    releaseJobBByDeadline,
    slashJobA,
    slashJobB,
    tick,
  }

  val valueAccounted =
    availableStake + lockedStakeTotal + protectedStakeAward == PostedStake

  val noNegativeBucket =
    height >= GenesisHeight
      and height <= MaxHeight
      and availableStake >= 0
      and jobAStake >= 0
      and jobBStake >= 0
      and protectedStakeAward >= 0
      and jobAResolvedAt >= 0
      and jobBResolvedAt >= 0

  val lockCapacityBounded =
    lockedStakeTotal <= PostedStake

  val availableStakeMatchesUnlockedCapacity =
    availableStake == PostedStake - lockedStakeTotal - protectedStakeAward

  val lockedStakeMatchesStatus =
    if (jobAStatus == JobLocked) {
      jobAStake == JobAStakeRequirement
    } else {
      jobAStake == 0
    } and if (jobBStatus == JobLocked) {
      jobBStake == JobBStakeRequirement
    } else {
      jobBStake == 0
    }

  val activeLockHasResolutionPath =
    (jobAStatus != JobLocked
      or canReleaseJobAByAcceptedFrontier
      or canReleaseJobAByDeadline
      or canSlashJobA)
      and (jobBStatus != JobLocked
        or canReleaseJobBByAcceptedFrontier
        or canReleaseJobBByDeadline
        or canSlashJobB)

  val deadlineDisablesSlash =
    (not(jobAStatus == JobLocked and height >= JobAReleaseDeadline) or not(canSlashJobA))
      and (not(jobBStatus == JobLocked and height >= JobBReleaseDeadline) or not(canSlashJobB))

  val slashBeforeReleaseOnly =
    (jobAStatus != SlashedByViolationProof or jobAResolvedAt < JobAReleaseDeadline)
      and (jobBStatus != SlashedByViolationProof or jobBResolvedAt < JobBReleaseDeadline)

  val resolutionTimesValid =
    if (jobAStatus == NoJobLock or jobAStatus == JobLocked) {
      jobAResolvedAt == 0
    } else if (jobAStatus == ReleasedByDeadline) {
      GenesisHeight <= jobAResolvedAt
        and jobAResolvedAt <= height
        and jobAResolvedAt >= JobAReleaseDeadline
    } else if (jobAStatus == SlashedByViolationProof) {
      GenesisHeight <= jobAResolvedAt
        and jobAResolvedAt <= height
        and jobAResolvedAt < JobAReleaseDeadline
    } else {
      GenesisHeight <= jobAResolvedAt and jobAResolvedAt <= height
    } and if (jobBStatus == NoJobLock or jobBStatus == JobLocked) {
      jobBResolvedAt == 0
    } else if (jobBStatus == ReleasedByDeadline) {
      GenesisHeight <= jobBResolvedAt
        and jobBResolvedAt <= height
        and jobBResolvedAt >= JobBReleaseDeadline
    } else if (jobBStatus == SlashedByViolationProof) {
      GenesisHeight <= jobBResolvedAt
        and jobBResolvedAt <= height
        and jobBResolvedAt < JobBReleaseDeadline
    } else {
      GenesisHeight <= jobBResolvedAt and jobBResolvedAt <= height
    }

  val releasedJobsHaveNoStakeAtRisk =
    (not(
      jobAStatus == ReleasedByAcceptedFrontier
        or jobAStatus == ReleasedByDeadline
    )
      or all {
        jobAStake == 0,
        not(canSlashJobA),
      })
      and (not(
        jobBStatus == ReleasedByAcceptedFrontier
          or jobBStatus == ReleasedByDeadline
      )
        or all {
          jobBStake == 0,
          not(canSlashJobB),
        })

  val stakeAwardsBackedBySlashedJobs =
    protectedStakeAward == slashedPenaltyTotal

  val stakeAwardOnlyThroughViolationProof =
    protectedStakeAward == 0
      or all {
        evidenceCanProveViolation(BadComputeEvidence),
        proofCanSlash(BadComputeSealProof),
        l1ProofKind(BadComputeSealProof) == ViolationClose,
      }

  val stakeAwardBackedOnlyByLockedStake =
    protectedStakeAward == PostedStake - availableStake - lockedStakeTotal

  run concurrentLocksUseProviderCapacityTest =
    init
      .then(lockJobA)
      .then(lockJobB)
      .expect(lockedStakeTotal == PostedStake
        and availableStake == 0
        and valueAccounted
        and lockedStakeMatchesStatus)

  run acceptedFrontierReleasesCapacityTest =
    init
      .then(lockJobA)
      .then(releaseJobAByAcceptedFrontier)
      .then(lockJobB)
      .expect(jobAStatus == ReleasedByAcceptedFrontier
        and jobBStatus == JobLocked
        and jobAResolvedAt == GenesisHeight
        and jobAStake == 0
        and jobBStake == JobBStakeRequirement
        and availableStake == PostedStake - JobBStakeRequirement
        and releasedJobsHaveNoStakeAtRisk
        and valueAccounted)

  run deadlineReleasesCapacityTest =
    init
      .then(lockJobA)
      .then(tick)
      .then(tick)
      .then(tick)
      .then(releaseJobAByDeadline)
      .expect(jobAStatus == ReleasedByDeadline
        and height == JobAReleaseDeadline
        and jobAResolvedAt == JobAReleaseDeadline
        and availableStake == PostedStake
        and lockedStakeTotal == 0
        and releasedJobsHaveNoStakeAtRisk
        and valueAccounted)

  run violationSlashesJobStakeTest =
    init
      .then(lockJobA)
      .then(slashJobA)
      .expect(jobAStatus == SlashedByViolationProof
        and protectedStakeAward == JobAPenalty
        and jobAResolvedAt == GenesisHeight
        and availableStake == PostedStake - JobAPenalty
        and lockedStakeTotal == 0
        and stakeAwardsBackedBySlashedJobs
        and stakeAwardBackedOnlyByLockedStake
        and valueAccounted)

  run releasedJobCannotBeSlashedTest =
    init
      .then(lockJobA)
      .then(releaseJobAByAcceptedFrontier)
      .expect(not(canSlashJobA)
        and releasedJobsHaveNoStakeAtRisk
        and protectedStakeAward == 0
        and valueAccounted)
}
