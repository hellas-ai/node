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
    "l1_stake.qnt"
    "lifetime.qnt"
    "proof_lifetime.qnt"
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
      ];
    }
    {
      model = "l1_stake.qnt";
      maxSamples = 1000;
      maxSteps = 8;
      invariants = [
        "valueConserved"
        "noNegativeValue"
        "liveCoinsAreKnown"
        "deadSlotsAreZero"
        "liveBondIsWellFormed"
        "liveBondHoldsCommittedStake"
        "slashRoutingPinned"
        "timeoutReturnsStakeOnly"
        "timeoutOnlyAfterCommittedHeight"
        "heightAtLeastGenesis"
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
      ];
    }
    {
      model = "l1_stake.qnt";
      maxSteps = 5;
      invariants = [
        "valueConserved"
        "noNegativeValue"
        "deadSlotsAreZero"
        "liveBondIsWellFormed"
        "liveBondHoldsCommittedStake"
        "slashRoutingPinned"
        "timeoutReturnsStakeOnly"
        "timeoutOnlyAfterCommittedHeight"
      ];
    }
    {
      model = "lifetime.qnt";
      invariants = [
        "valueAccounted"
        "noNegativeBucket"
        "closeReserveCoversCommittedFee"
        "closeAlwaysAvailableWhenLive"
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
    quint test models/l1_stake.qnt --out-itf 'models/traces/l1_stake_{test}.itf.json' --verbosity=0
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
      crate ? "kernel",
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
        cd "$repo_root/crates/${crate}"
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

  chainModelCommand = ''
    quint typecheck models/staked_channel.qnt
    quint test models/staked_channel.qnt --verbosity=2
    quint run models/staked_channel.qnt --max-samples=1000 --max-steps=10 \
      --invariants=atMostOneActiveJob --invariants=frontierWithinCapacity \
      --invariants=admittedJobsAreCovered --invariants=activeJobIsFunded \
      --invariants=heightMovesForward --verbosity=1
  '';

  chainModelTest = mkModelApp {
    name = "hellas-chain-model-test";
    command = chainModelCommand;
    crate = "chain";
  };

  chainModelFixtures = mkModelApp {
    name = "hellas-chain-model-fixtures";
    command = ''
      rm -f models/traces/*.itf.json
      mkdir -p models/traces
      quint test models/staked_channel.qnt --out-itf 'models/traces/staked_channel_{test}.itf.json' --verbosity=0
    '';
    crate = "chain";
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
    chain-models = chainModelTest;
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
    "update-chain-model-fixtures" = {
      type = "app";
      program = lib.getExe chainModelFixtures;
      meta.description = "Regenerate hellas-chain Quint ITF fixtures";
    };
  };
}
