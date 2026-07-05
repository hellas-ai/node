{
  pkgs,
  lib,
  rustToolchain,
  cargoToolPackages,
  commonToolPackages,
}:
let
  modelTestModules = [
    "l1.qnt"
    "l1_fees.qnt"
    "lifetime.qnt"
    "proof_lifetime.qnt"
    "settlement_witness.qnt"
    "proof_obligations.qnt"
    "staked_obligations.qnt"
    "job_stake_locks.qnt"
    "frontier_commitments.qnt"
    "frontier_progression.qnt"
    "incentives.qnt"
  ];

  runSpecs = [
    {
      model = "l1.qnt";
      maxSamples = 500;
      maxSteps = 8;
      invariants = [
        "valueConserved"
        "atMostOneLiveEdge"
        "noNegativeValue"
        "liveEdgesAreKnown"
        "liveCoinsAreKnown"
        "wiringIsExpected"
        "liveCoinsHaveCanonicalValue"
        "payoutsHonorBindings"
        "payoutOutputsPaired"
        "deadSlotsAreZero"
        "liveEdgesHaveCanonicalValue"
        "fundingInputsConsumed"
        "heightAtLeastGenesis"
        "fundingAuthorized"
      ];
    }
    {
      model = "l1_fees.qnt";
      maxSamples = 500;
      maxSteps = 8;
      invariants = [
        "valueAccounted"
        "partyValueAccounted"
        "constantsBalanced"
        "noNegativeBucket"
        "reserveAtLeastCommittedFee"
        "paidIsLifecycleAmount"
        "currentCloseFeeKnown"
        "heightAtLeastGenesis"
        "atMostOneLiveEdge"
        "liveCoinsAreKnown"
        "liveEdgesAreKnown"
        "deadSlotsAreZero"
        "liveEdgesCarryPrincipalAndReserve"
        "reserveLivesWithEdge"
        "closeFeeLivesWithEdge"
        "termsCoherentForClose"
        "escapeHatchBoundsNonNegative"
        "escapeHatchTotalMatchesRecoverableValue"
        "fundingShapeDecisionsCoherent"
        "fundingAuthorized"
        "expiredLiveHasTimeoutPath"
        "nonTimeoutProofsExpire"
        "stakeDomainConserved"
        "stakeAwardBackedOnlyByStakeDebits"
        "stakeAwardNeverExceedsPostedStake"
        "stakeAwardOnlyThroughViolation"
        "timeoutDoesNotAwardStake"
        "selfEdgeCannotSlashWithoutOwnStake"
      ];
    }
    {
      model = "lifetime.qnt";
      maxSamples = 500;
      maxSteps = 8;
      invariants = [
        "valueAccounted"
        "noNegativeBucket"
        "closeReserveCoversCommittedFee"
        "closeAlwaysAvailableWhenLive"
        "feeRaiseCannotStrandClose"
        "liveCloseReserveIsNotRent"
        "expiredLiveHasCleanup"
        "termsCoherentForLiveState"
        "escapeHatchBoundsNonNegative"
        "escapeHatchTotalMatchesRecoverableValue"
        "collectorRewardsOnlySlotValue"
        "policyBucketsConsistent"
        "currentCloseFeeKnown"
        "heightAtLeastGenesis"
      ];
    }
    {
      model = "proof_lifetime.qnt";
      maxSamples = 500;
      maxSteps = 8;
      invariants = [
        "valueAccounted"
        "noNegativeBucket"
        "lifetimeFeePrepaid"
        "noMarginalCloseFee"
        "liveWithinPaidLifetime"
        "liveHasLatestProofPath"
        "closeReserveCoversCommittedFee"
        "feeRaiseCannotStrandProofClose"
        "latestTermsCoherent"
        "timeoutTermsCoherent"
        "staleTermsCoherent"
        "staleReceiptNotAdmissible"
        "bareSignedReceiptNotAdmissible"
        "closedByAdmissibleProofOnly"
        "latestProofPreservesLatestBound"
        "timeoutCloseUsesTimeoutTerms"
        "closeProofTimingValid"
        "closedAtConsistent"
        "expiryClosesByTimeout"
        "currentCloseFeeKnown"
        "heightAtLeastGenesis"
      ];
    }
    {
      model = "settlement_witness.qnt";
      maxSamples = 500;
      maxSteps = 6;
      invariants = [
        "acceptedOnlyWithValidWitness"
        "acceptedBindsExpectedEdge"
        "acceptedBindsTermsAndPayout"
        "acceptedBindsExpiry"
        "acceptedBindsWellFormedFrontier"
        "acceptedProofKindMatchesOutcome"
        "acceptedStakeAwardMatchesOutcome"
        "bareSignedReceiptRejected"
        "malformedWitnessesRejected"
        "staleActiveRootRejectedForLatest"
        "violationRequiresActiveSlashRoot"
        "violationRequiresEvidence"
        "violationRequiresStakeAward"
        "timeoutBeforeExpiryRejected"
      ];
    }
    {
      model = "proof_obligations.qnt";
      maxSamples = 500;
      maxSteps = 8;
      invariants = [
        "noNegativeValue"
        "publicObligationHasSafeDeadline"
        "noSlashWithoutPublicObligation"
        "slashOnlyThroughViolationSeal"
        "slashOnlyAfterDeadline"
        "timeoutFallbackIsNotSlashable"
        "proofBeforeDeadlineDischarges"
        "breachSealBeforeExpiry"
        "breachedObligationHasSealPath"
        "breachSealProtectsBeneficiary"
        "closedPathHasExpectedRecovery"
        "unbackedObligationCannotBreach"
      ];
    }
    {
      model = "staked_obligations.qnt";
      maxSamples = 500;
      maxSteps = 8;
      invariants = [
        "valueAccounted"
        "noNegativeBucket"
        "termsCoherentForClose"
        "stakeDomainConserved"
        "stakeAwardBackedOnlyByStakeDebits"
        "stakeAwardNeverExceedsPostedStake"
        "stakeAwardOnlyThroughViolation"
        "timeoutDoesNotAwardStake"
        "selfContainedLatestProofDoesNotAwardStake"
        "violationRequiresWellFormedObligation"
        "violationAwardsStakeToViolatedParty"
        "violationRecoveryProtectsBeneficiary"
        "closedPathHasExpectedPrincipal"
        "closePaysCommittedFee"
        "unbackedOrLateObligationCannotAwardStake"
      ];
    }
    {
      model = "job_stake_locks.qnt";
      maxSamples = 500;
      maxSteps = 8;
      invariants = [
        "valueAccounted"
        "noNegativeBucket"
        "lockCapacityBounded"
        "availableStakeMatchesUnlockedCapacity"
        "lockedStakeMatchesStatus"
        "jobTermsWellFormed"
        "activeLockHasResolutionPath"
        "deadlineDisablesSlash"
        "slashBeforeReleaseOnly"
        "resolutionTimesValid"
        "releasedJobsHaveNoStakeAtRisk"
        "stakeAwardsBackedBySlashedJobs"
        "stakeAwardOnlyThroughViolationProof"
        "stakeAwardBackedOnlyByLockedStake"
      ];
    }
    {
      model = "frontier_commitments.qnt";
      maxSamples = 500;
      maxSteps = 6;
      invariants = [
        "valueAccounted"
        "noNegativeBucket"
        "liveFrontierWellFormed"
        "closedFrontierWasCurrent"
        "closedFrontierWellFormed"
        "closeAcceptedOnlyWithValidProof"
        "badAggregateFrontierRejected"
        "staleActiveRootRejectedAfterRelease"
        "violationRequiresActiveJobRoot"
        "releaseCloseDoesNotSlash"
        "violationCloseAccountsForPenalty"
      ];
    }
    {
      model = "frontier_progression.qnt";
      maxSamples = 500;
      maxSteps = 6;
      invariants = [
        "peerFrontierWellFormed"
        "peerStatusMatchesRoot"
        "anchoredFrontierWellFormed"
        "closedFrontierWellFormed"
        "closedBySafeFrontierSource"
        "badAggregateRejectedByPeer"
        "staleLowerSeqRejectedByPeer"
        "releasedJobCannotBeReintroducedByHigherSeq"
        "slashedJobCannotBeReintroducedByHigherSeq"
        "safeCloseNeverUsesBareSignedFrontier"
      ];
    }
    {
      model = "incentives.qnt";
      maxSamples = 500;
      maxSteps = 4;
      invariants = [
        "termsCoherentForPayoffs"
        "configuredPenaltiesBacked"
        "configuredProofObligationBacksPenalty"
        "configuredProofsMapToL1Boundary"
        "penaltyRequirementsDerived"
        "proofCostBoundDerived"
        "requiredStakeDerived"
        "penaltiesFundedByStake"
        "proofCostCoveredWhenProofImproves"
        "timeoutFallbackNotSlashable"
        "proofObligationBreachDeviationUnprofitable"
        "proofObligationBreachUnprofitable"
        "staleReceiptUnprofitable"
        "badComputeUnprofitable"
        "allModeledDeviationsUnprofitable"
        "chosenDeviationUnprofitable"
        "currentMarginsKnown"
      ];
    }
  ];

  verifySpecs = [
    {
      model = "l1.qnt";
      maxSteps = 5;
      invariants = [
        "valueConserved"
        "noNegativeValue"
        "atMostOneLiveEdge"
        "liveCoinsAreKnown"
        "liveEdgesAreKnown"
        "wiringIsExpected"
        "liveCoinsHaveCanonicalValue"
        "payoutsHonorBindings"
        "payoutOutputsPaired"
        "deadSlotsAreZero"
        "liveEdgesHaveCanonicalValue"
        "fundingInputsConsumed"
        "heightAtLeastGenesis"
        "fundingAuthorized"
      ];
    }
    {
      model = "l1_fees.qnt";
      maxSteps = 4;
      invariants = [
        "valueAccounted"
        "partyValueAccounted"
        "constantsBalanced"
        "noNegativeBucket"
        "reserveAtLeastCommittedFee"
        "paidIsLifecycleAmount"
        "currentCloseFeeKnown"
        "heightAtLeastGenesis"
        "atMostOneLiveEdge"
        "liveCoinsAreKnown"
        "liveEdgesAreKnown"
        "deadSlotsAreZero"
        "liveEdgesCarryPrincipalAndReserve"
        "reserveLivesWithEdge"
        "closeFeeLivesWithEdge"
        "termsCoherentForClose"
        "escapeHatchBoundsNonNegative"
        "escapeHatchTotalMatchesRecoverableValue"
        "fundingShapeDecisionsCoherent"
        "fundingAuthorized"
        "expiredLiveHasTimeoutPath"
        "nonTimeoutProofsExpire"
        "stakeDomainConserved"
        "stakeAwardBackedOnlyByStakeDebits"
        "stakeAwardNeverExceedsPostedStake"
        "stakeAwardOnlyThroughViolation"
        "timeoutDoesNotAwardStake"
        "selfEdgeCannotSlashWithoutOwnStake"
      ];
    }
    {
      model = "lifetime.qnt";
      invariants = [
        "valueAccounted"
        "noNegativeBucket"
        "closeReserveCoversCommittedFee"
        "closeAlwaysAvailableWhenLive"
        "feeRaiseCannotStrandClose"
        "liveCloseReserveIsNotRent"
        "expiredLiveHasCleanup"
        "termsCoherentForLiveState"
        "escapeHatchBoundsNonNegative"
        "escapeHatchTotalMatchesRecoverableValue"
        "collectorRewardsOnlySlotValue"
        "policyBucketsConsistent"
        "currentCloseFeeKnown"
        "heightAtLeastGenesis"
      ];
    }
    {
      model = "proof_lifetime.qnt";
      invariants = [
        "valueAccounted"
        "noNegativeBucket"
        "lifetimeFeePrepaid"
        "noMarginalCloseFee"
        "liveWithinPaidLifetime"
        "liveHasLatestProofPath"
        "closeReserveCoversCommittedFee"
        "feeRaiseCannotStrandProofClose"
        "latestTermsCoherent"
        "timeoutTermsCoherent"
        "staleTermsCoherent"
        "staleReceiptNotAdmissible"
        "bareSignedReceiptNotAdmissible"
        "closedByAdmissibleProofOnly"
        "latestProofPreservesLatestBound"
        "timeoutCloseUsesTimeoutTerms"
        "closeProofTimingValid"
        "closedAtConsistent"
        "expiryClosesByTimeout"
        "currentCloseFeeKnown"
        "heightAtLeastGenesis"
      ];
    }
    {
      model = "settlement_witness.qnt";
      invariants = [
        "acceptedOnlyWithValidWitness"
        "acceptedBindsExpectedEdge"
        "acceptedBindsTermsAndPayout"
        "acceptedBindsExpiry"
        "acceptedBindsWellFormedFrontier"
        "acceptedProofKindMatchesOutcome"
        "acceptedStakeAwardMatchesOutcome"
        "bareSignedReceiptRejected"
        "malformedWitnessesRejected"
        "staleActiveRootRejectedForLatest"
        "violationRequiresActiveSlashRoot"
        "violationRequiresEvidence"
        "violationRequiresStakeAward"
        "timeoutBeforeExpiryRejected"
      ];
    }
    {
      model = "proof_obligations.qnt";
      invariants = [
        "noNegativeValue"
        "publicObligationHasSafeDeadline"
        "noSlashWithoutPublicObligation"
        "slashOnlyThroughViolationSeal"
        "slashOnlyAfterDeadline"
        "timeoutFallbackIsNotSlashable"
        "proofBeforeDeadlineDischarges"
        "breachSealBeforeExpiry"
        "breachedObligationHasSealPath"
        "breachSealProtectsBeneficiary"
        "closedPathHasExpectedRecovery"
        "unbackedObligationCannotBreach"
      ];
    }
    {
      model = "staked_obligations.qnt";
      invariants = [
        "valueAccounted"
        "noNegativeBucket"
        "termsCoherentForClose"
        "stakeDomainConserved"
        "stakeAwardBackedOnlyByStakeDebits"
        "stakeAwardNeverExceedsPostedStake"
        "stakeAwardOnlyThroughViolation"
        "timeoutDoesNotAwardStake"
        "selfContainedLatestProofDoesNotAwardStake"
        "violationRequiresWellFormedObligation"
        "violationAwardsStakeToViolatedParty"
        "violationRecoveryProtectsBeneficiary"
        "closedPathHasExpectedPrincipal"
        "closePaysCommittedFee"
        "unbackedOrLateObligationCannotAwardStake"
      ];
    }
    {
      model = "job_stake_locks.qnt";
      invariants = [
        "valueAccounted"
        "noNegativeBucket"
        "lockCapacityBounded"
        "availableStakeMatchesUnlockedCapacity"
        "lockedStakeMatchesStatus"
        "jobTermsWellFormed"
        "activeLockHasResolutionPath"
        "deadlineDisablesSlash"
        "slashBeforeReleaseOnly"
        "resolutionTimesValid"
        "releasedJobsHaveNoStakeAtRisk"
        "stakeAwardsBackedBySlashedJobs"
        "stakeAwardOnlyThroughViolationProof"
        "stakeAwardBackedOnlyByLockedStake"
      ];
    }
    {
      model = "frontier_commitments.qnt";
      invariants = [
        "valueAccounted"
        "noNegativeBucket"
        "liveFrontierWellFormed"
        "closedFrontierWasCurrent"
        "closedFrontierWellFormed"
        "closeAcceptedOnlyWithValidProof"
        "badAggregateFrontierRejected"
        "staleActiveRootRejectedAfterRelease"
        "violationRequiresActiveJobRoot"
        "releaseCloseDoesNotSlash"
        "violationCloseAccountsForPenalty"
      ];
    }
    {
      model = "frontier_progression.qnt";
      invariants = [
        "peerFrontierWellFormed"
        "peerStatusMatchesRoot"
        "anchoredFrontierWellFormed"
        "closedFrontierWellFormed"
        "closedBySafeFrontierSource"
        "badAggregateRejectedByPeer"
        "staleLowerSeqRejectedByPeer"
        "releasedJobCannotBeReintroducedByHigherSeq"
        "slashedJobCannotBeReintroducedByHigherSeq"
        "safeCloseNeverUsesBareSignedFrontier"
      ];
    }
    {
      model = "incentives.qnt";
      invariants = [
        "termsCoherentForPayoffs"
        "configuredPenaltiesBacked"
        "configuredProofObligationBacksPenalty"
        "configuredProofsMapToL1Boundary"
        "penaltyRequirementsDerived"
        "proofCostBoundDerived"
        "requiredStakeDerived"
        "penaltiesFundedByStake"
        "proofCostCoveredWhenProofImproves"
        "timeoutFallbackNotSlashable"
        "currentMarginsKnown"
      ];
    }
    {
      model = "incentives.qnt";
      invariants = [
        "proofObligationBreachDeviationUnprofitable"
        "proofObligationBreachUnprofitable"
        "staleReceiptUnprofitable"
        "badComputeUnprofitable"
        "allModeledDeviationsUnprofitable"
        "chosenDeviationUnprofitable"
      ];
    }
  ];

  modelPath = model: "models/${model}";
  invariantFlags = invariants: lib.concatMapStringsSep " " (name: "--invariants=${name}") invariants;
  invariantArgs = invariants: lib.concatStringsSep " " invariants;

  testCommand = lib.concatMapStringsSep "\n" (model: ''
    quint typecheck ${modelPath model}
    quint test ${modelPath model} --verbosity=2
  '') modelTestModules;

  simulationCommand = lib.concatMapStringsSep "\n" (spec: ''
    quint run ${modelPath spec.model} --max-samples=${toString spec.maxSamples} --max-steps=${toString spec.maxSteps} ${invariantFlags spec.invariants} --verbosity=1
  '') runSpecs;

  verificationCommand = lib.concatMapStringsSep "\n" (spec: ''
    quint verify ${modelPath spec.model} ${
      lib.optionalString (spec ? maxSteps) "--max-steps=${toString spec.maxSteps}"
    } --invariants ${invariantArgs spec.invariants} --verbosity=1
  '') verifySpecs;

  fixtureCommand = ''
    rm -f models/traces/*.itf.json
    mkdir -p models/traces
    quint test models/l1.qnt --out-itf 'models/traces/l1_{test}.itf.json' --verbosity=0
    quint test models/l1_fees.qnt --out-itf 'models/traces/l1_fees_{test}.itf.json' --verbosity=0
  '';

  modelRuntimePackages = with pkgs; [
    quint
    temurin-bin
    stdenv.cc.cc.lib
  ];

  devShellPackages = [
    rustToolchain
    pkgs.rust-analyzer
    pkgs.llvmPackages.lld
    pkgs.pkg-config
    pkgs.git
  ]
  ++ modelRuntimePackages
  ++ cargoToolPackages
  ++ commonToolPackages;

  mkModelApp =
    {
      name,
      command,
      needsJvm ? false,
    }:
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [
        pkgs.coreutils
        pkgs.git
        pkgs.quint
      ]
      ++ lib.optionals needsJvm [ pkgs.temurin-bin ];
      text = ''
        repo_root="$(git rev-parse --show-toplevel)"
        cd "$repo_root/crates/kernel"
        ${lib.optionalString needsJvm ''
          export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib''${LD_LIBRARY_PATH:+:''${LD_LIBRARY_PATH}}"
        ''}
        ${command}
      '';
    };

  modelTest = mkModelApp {
    name = "hellas-kernel-model-test";
    command = testCommand;
  };

  modelRun = mkModelApp {
    name = "hellas-kernel-model-run";
    command = simulationCommand;
  };

  modelVerify = mkModelApp {
    name = "hellas-kernel-model-verify";
    command = verificationCommand;
    needsJvm = true;
  };

  modelFixtures = mkModelApp {
    name = "hellas-kernel-model-fixtures";
    command = fixtureCommand;
  };
in
{
  devShell = pkgs.mkShell {
    packages = devShellPackages;
    RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
    LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
  };

  checks = {
    kernel-models = modelTest;
    kernel-model-run = modelRun;
    kernel-model-verify = modelVerify;
  };

  apps = {
    "check-kernel-models" = {
      type = "app";
      program = lib.getExe modelTest;
      meta.description = "Run hellas-kernel Quint model tests";
    };
    "check-kernel-model-run" = {
      type = "app";
      program = lib.getExe modelRun;
      meta.description = "Run hellas-kernel Quint model simulations";
    };
    "check-kernel-model-verify" = {
      type = "app";
      program = lib.getExe modelVerify;
      meta.description = "Run hellas-kernel Quint model verification";
    };
    "update-kernel-model-fixtures" = {
      type = "app";
      program = lib.getExe modelFixtures;
      meta.description = "Regenerate hellas-kernel Quint ITF fixtures";
    };
  };
}
