module frontier {
  // Shared vocabulary for signed frontier commitments over active job locks.
  //
  // This does not model Merkle hashing. It models the public values the
  // verifier relation must bind: authenticated root, aggregate locked stake,
  // available stake, stake awards, and sequence.

  type JobLockRoot =
    | EmptyRoot
    | JobAActiveRoot

  type FrontierCommitment = {
    seq: int,
    root: JobLockRoot,
    lockedTotal: int,
    availableStake: int,
    stakeAward: int,
  }

  pure val EmptyFrontier: FrontierCommitment = {
    seq: 0,
    root: EmptyRoot,
    lockedTotal: 0,
    availableStake: 0,
    stakeAward: 0,
  }

  pure def rootLockedTotal(root: JobLockRoot, jobAStakeRequirement: int): int =
    match root {
      | EmptyRoot => 0
      | JobAActiveRoot => jobAStakeRequirement
    }

  pure def rootContainsJobA(root: JobLockRoot): bool =
    root == JobAActiveRoot

  pure def frontierRootSumMatches(
    f: FrontierCommitment,
    jobAStakeRequirement: int,
  ): bool =
    f.lockedTotal == rootLockedTotal(f.root, jobAStakeRequirement)

  pure def frontierCapacityBalances(
    f: FrontierCommitment,
    postedStake: int,
  ): bool =
    f.availableStake + f.lockedTotal + f.stakeAward == postedStake

  pure def frontierNonNegative(f: FrontierCommitment): bool =
    f.seq >= 0
      and f.lockedTotal >= 0
      and f.availableStake >= 0
      and f.stakeAward >= 0

  pure def frontierWellFormed(
    f: FrontierCommitment,
    postedStake: int,
    jobAStakeRequirement: int,
  ): bool =
    frontierNonNegative(f)
      and frontierRootSumMatches(f, jobAStakeRequirement)
      and frontierCapacityBalances(f, postedStake)
}
