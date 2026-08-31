{
  self,
  pkgs,
  lib,
  package,
}:
let
  # Exercise the exported module with unmodified nixpkgs. Importing the
  # module must not require consumers to install the Hellas overlay first.
  plainPkgs = import pkgs.path {
    system = pkgs.stdenv.hostPlatform.system;
  };
  darwinPkgs = import pkgs.path {
    system = "aarch64-darwin";
  };
  hellasModule = import ../modules/hellas.nix { inherit self; };
  runtimeEnvironmentWrapper = hellasModule.mkRuntimeEnvironmentWrapper pkgs;
  runtimeEnvironmentStoreFile = pkgs.writeText "hellas-runtime-environment-store-fixture" ''
    STORE_FIXTURE=must-not-load
  '';
  repeatedSlashStoreDir = lib.concatStringsSep "//" (lib.splitString "/" builtins.storeDir);
  repeatedSlashStorePath = "${repeatedSlashStoreDir}/provider.env";
  dotStorePath = "/.${builtins.storeDir}/./provider.env";
  dotDotStorePath = "/run/hellas/../..${builtins.storeDir}/provider.env";
  contextualRuntimePath = builtins.appendContext "/run/hellas/contextual.env" (
    builtins.getContext "${package}"
  );
  evalGateway =
    gateway:
    import (pkgs.path + "/nixos/lib/eval-config.nix") {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        self.nixosModules.default
        {
          nixpkgs.pkgs = plainPkgs;
          system.stateVersion = "26.05";
          services.hellas = {
            inherit package;
            gateway = {
              enable = true;
              causalLmEnvironment = "/srv/hellas/test.environment";
              tokenizer = "/srv/hellas/tokenizer.json";
            }
            // gateway;
          };
        }
      ];
    };
  providerAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "services.hellas.gateway.provider is required" assertion.message
    ) (throw "missing gateway provider assertion") evaluation.config.assertions;
  runtimeStoreAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "must be runtime data outside the Nix store" assertion.message
    ) (throw "missing runtime-data store assertion") evaluation.config.assertions;
  environmentStoreAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "services.hellas.environment string values must not" assertion.message
    ) (throw "missing environment store assertion") evaluation.config.assertions;
  serveExtraArgsAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "services.hellas.extraArgs may not override" assertion.message
    ) (throw "missing serve extraArgs assertion") evaluation.config.assertions;
  providerAssuranceAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "cannot serve apple-app-attest assurance" assertion.message
    ) (throw "missing provider assurance assertion") evaluation.config.assertions;
  gatewayExtraArgsAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "services.hellas.gateway.extraArgs may not override" assertion.message
    ) (throw "missing gateway extraArgs assertion") evaluation.config.assertions;
  appleTrustPairAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "appleAppAttestAppId and appleAppAttestCdhashes" assertion.message
    ) (throw "missing Apple trust pair assertion") evaluation.config.assertions;
  appleTrustRequiredAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "apple-app-attest assurance requires" assertion.message
    ) (throw "missing required Apple trust assertion") evaluation.config.assertions;
  memoryHeadroomAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "memoryMaxBytes must exceed gpuSessionAssetBytes" assertion.message
    ) (throw "missing provider memory-headroom assertion") evaluation.config.assertions;
  readinessContentAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "readinessEnvironments requires" assertion.message
    ) (throw "missing readiness-content assertion") evaluation.config.assertions;
  writableRootAssertion =
    evaluation:
    lib.findFirst (
      assertion:
      !assertion.assertion
      && lib.hasInfix "must not expose the filesystem root as writable" assertion.message
    ) (throw "missing writable-root assertion") evaluation.config.assertions;
  writableContentDisjointAssertion =
    evaluation:
    lib.findFirst (
      assertion: !assertion.assertion && lib.hasInfix "dedicated writable location" assertion.message
    ) (throw "missing writable-content-disjoint assertion") evaluation.config.assertions;
  evalProvider =
    provider:
    import (pkgs.path + "/nixos/lib/eval-config.nix") {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        self.nixosModules.default
        {
          nixpkgs.pkgs = plainPkgs;
          system.stateVersion = "26.05";
          services.hellas = {
            enable = true;
            inherit package;
          }
          // provider;
        }
      ];
    };
  executePolicyEvaluation =
    executePolicy:
    builtins.tryEval (
      builtins.deepSeq
        (evalProvider { inherit executePolicy; }).config.systemd.services.hellas.serviceConfig
        true
    );
  evalHomeManagerWith =
    homeManagerPkgs: configuration:
    lib.evalModules {
      specialArgs = {
        inherit self;
        pkgs = homeManagerPkgs;
      };
      modules = [
        ({ lib, ... }: {
          options = {
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.anything;
              default = [ ];
            };
            home = {
              packages = lib.mkOption {
                type = lib.types.listOf lib.types.anything;
                default = [ ];
              };
              sessionVariables = lib.mkOption {
                type = lib.types.attrsOf lib.types.anything;
                default = { };
              };
              homeDirectory = lib.mkOption {
                type = lib.types.str;
                default = "/home/hellas";
              };
            };
            # This intentionally small schema stub checks the module's launchd
            # value shape and option merging. It is not Home Manager's launchd
            # implementation and does not constitute a native Darwin test.
            launchd.agents = lib.mkOption {
              type = lib.types.attrsOf (
                lib.types.submodule {
                  options = {
                    enable = lib.mkOption {
                      type = lib.types.bool;
                      default = false;
                    };
                    config = lib.mkOption {
                      type = lib.types.attrsOf lib.types.anything;
                      default = { };
                    };
                  };
                }
              );
              default = { };
            };
          };
        })
        self.homeManagerModules.default
        configuration
      ];
    };
  evalHomeManager = evalHomeManagerWith plainPkgs;
  evalDarwinHomeManager = evalHomeManagerWith darwinPkgs;
  homeManagerPlatformAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "programs.hellas.serve is only supported on darwin" assertion.message
    ) (throw "missing Home Manager platform assertion") evaluation.config.assertions;
  homeManagerCatenaAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "Local Catena execution is not supported" assertion.message
    ) (throw "missing Home Manager Catena assertion") evaluation.config.assertions;
  homeManagerRuntimeStoreAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "programs.hellas.serve content" assertion.message
    ) (throw "missing Home Manager runtime-data store assertion") evaluation.config.assertions;
  homeManagerEnvironmentStoreAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "programs.hellas.environment string values" assertion.message
    ) (throw "missing Home Manager environment store assertion") evaluation.config.assertions;
  homeManagerExtraArgsAssertion =
    evaluation:
    lib.findFirst (
      assertion: lib.hasInfix "programs.hellas.serve.extraArgs may not override" assertion.message
    ) (throw "missing Home Manager serve extraArgs assertion") evaluation.config.assertions;
  evalDarwinServe =
    serve:
    evalDarwinHomeManager {
      home.homeDirectory = "/Users/hellas";
      programs.hellas = {
        inherit package;
        serve = {
          enable = true;
        }
        // serve;
      };
    };
  discoveryGateway = evalGateway { };
  proxyOnlyGateway = evalGateway { responsesBackend = "proxy"; };
  storePathGateway = evalGateway {
    responsesBackend = "proxy";
    environmentFile = "${builtins.storeDir}/secret.env";
  };
  storePathIdentityGateway = evalGateway {
    responsesBackend = "proxy";
    identityPath = "${builtins.storeDir}/identity";
  };
  storePathTokenizerGateway = evalGateway {
    responsesBackend = "proxy";
    tokenizer = "${builtins.storeDir}/tokenizer.json";
  };
  storePathIdentityProvider = evalProvider {
    identityPath = "${builtins.storeDir}/identity";
  };
  storePathContentProvider = evalProvider {
    content = [ "${builtins.storeDir}/model.hex" ];
  };
  defaultIdentityProvider = evalProvider { };
  invalidEmptyPolicyList = executePolicyEvaluation [ ];
  invalidBogusPolicy = executePolicyEvaluation "sometimes";
  invalidPaddedNonePolicy = executePolicyEvaluation " none ";
  invalidEmptyOnlyPolicy = executePolicyEvaluation "only()";
  invalidEmptyGlobPolicy = executePolicyEvaluation "only(ab,,cd)";
  invalidCharacterGlobPolicy = executePolicyEvaluation "only(abcG*)";
  invalidLongGlobPolicy = executePolicyEvaluation "only(${
    builtins.concatStringsSep "" (builtins.genList (_: "a") 65)
  })";
  invalidEmptyListGlobPolicy = executePolicyEvaluation [ "" ];
  validAnyPolicyProvider = evalProvider { executePolicy = "any"; };
  validNonePolicyProvider = evalProvider { executePolicy = "none"; };
  validOnlyPolicyProvider = evalProvider { executePolicy = "only(0123*,abcdef)"; };
  validListPolicyProvider = evalProvider {
    executePolicy = [
      "0123*"
      "abcdef"
    ];
  };
  storePathArtifactStore = evalProvider {
    artifactStorePath = "${builtins.storeDir}/artifacts";
  };
  contextualArtifactStore = evalProvider {
    artifactStorePath = contextualRuntimePath;
  };
  relativeArtifactStore =
    let
      evaluation = evalProvider { artifactStorePath = "relative/artifacts"; };
    in
    builtins.tryEval evaluation.config.services.hellas.artifactStorePath;
  storePathWorkConfig = evalProvider {
    workConfigFile = "${builtins.storeDir}/work.json";
  };
  storePathFetchConfig = evalProvider {
    fetchConfigFile = "${builtins.storeDir}/fetch.json";
  };
  storePathProviderEnvironmentFile = evalProvider {
    environmentFile = "${builtins.storeDir}/provider.env";
  };
  verifyLocalProxyGateway = evalGateway {
    responsesBackend = "proxy";
    verifyLocal = true;
    contentRoots = [ "/srv/hellas/content" ];
    contentIndex = "/srv/hellas-gateway-index/content-index.bin";
  };
  rootArtifactStoreProvider = evalProvider {
    artifactStorePath = "/";
  };
  overlappingArtifactStoreProvider = evalProvider {
    contentRoots = [ "/srv/hellas/content" ];
    artifactStorePath = "/srv/hellas/content/artifacts";
  };
  rootContentIndexGateway = evalGateway {
    responsesBackend = "proxy";
    verifyLocal = true;
    contentRoots = [ "/srv/hellas/content" ];
    contentIndex = "/content-index.bin";
  };
  overlappingContentIndexGateway = evalGateway {
    responsesBackend = "proxy";
    verifyLocal = true;
    contentRoots = [ "/srv/hellas/content" ];
    contentIndex = "/srv/hellas/content/index/content-index.bin";
  };
  unsafeServeExtraArgs = evalProvider {
    extraArgs = [ "--content=${builtins.storeDir}/model.hex" ];
  };
  unsafeServeAssuranceArgs = evalProvider {
    extraArgs = [ "--assurance=producer-signed" ];
  };
  unsafeServeArtifactStoreArgs = evalProvider {
    extraArgs = [ "--artifact-store-path=/srv/hellas/other-artifacts" ];
  };
  unsafeGatewayExtraArgs = evalGateway {
    responsesBackend = "proxy";
    extraArgs = [ "--tokenizer=${builtins.storeDir}/tokenizer.json" ];
  };
  harmlessExtraArgs = evalProvider {
    extraArgs = [ "--software-root" ];
  };
  unsupportedProviderApple = evalProvider {
    assurance = "apple-app-attest";
    executePolicy = "none";
  };
  incompleteAppleTrust = evalGateway {
    responsesBackend = "proxy";
    appleAppAttestAppId = "TEAMID.example.hellas";
  };
  missingRequiredAppleTrust = evalGateway {
    responsesBackend = "proxy";
    assurance = "apple-app-attest";
  };
  oversizedGpuCapacity =
    builtins.tryEval
      (evalProvider {
        gpuMaxGenerationCapacity = 524289;
      }).config.systemd.services.hellas.serviceConfig.ExecStart;
  maxGpuSessionAssetBytes = evalProvider {
    gpuSessionAssetBytes = 4398046511104;
  };
  insufficientMemoryHeadroom = evalProvider {
    gpuSessionAssetBytes = 1073741824;
    memoryMaxBytes = 1073741824;
  };
  insufficientDefaultMemoryHeadroom = evalProvider {
    # Equal to the CLI's effective 128 GiB session-asset default: there is no
    # room left for the runtime, compiler, or generation state.
    memoryMaxBytes = 137438953472;
  };
  readinessWithoutContent = evalProvider {
    readinessEnvironments = [ "/srv/hellas/smollm2.environment" ];
  };
  readinessOnlyProvider = evalProvider {
    contentRoots = [ "/srv/hellas/content" ];
    readinessEnvironments = [ "/srv/hellas/content/smollm2.environment" ];
  };
  managedContentProvider = evalProvider {
    contentRoots = [ "/var/lib/hellas/content" ];
  };
  managedContentGateway = evalGateway {
    responsesBackend = "proxy";
    verifyLocal = true;
    contentRoots = [ "/var/lib/hellas-gateway/content" ];
  };
  storePathReadinessProvider = evalProvider {
    contentRoots = [ "/srv/hellas/content" ];
    readinessEnvironments = [ "${builtins.storeDir}/smollm2.environment" ];
  };
  oversizedGpuSessionAssetBytes =
    builtins.tryEval
      (evalProvider {
        gpuSessionAssetBytes = 4398046511105;
      }).config.systemd.services.hellas.serviceConfig.ExecStart;
  oversizedDefaultMaxTokens =
    builtins.tryEval
      (evalGateway {
        responsesBackend = "proxy";
        defaultMaxTokens = 4294967296;
      }).config.systemd.services.hellas-gateway.serviceConfig.ExecStart;
  oversizedStopToken =
    builtins.tryEval
      (evalGateway {
        responsesBackend = "proxy";
        stopTokenIds = [ 4294967296 ];
      }).config.systemd.services.hellas-gateway.serviceConfig.ExecStart;
  environmentPathEvaluation =
    builtins.tryEval
      (evalProvider {
        environment.MODEL_FILE = ../../README.md;
      }).config.systemd.services.hellas.environment.MODEL_FILE;
  interpolatedEnvironmentPath = evalProvider {
    environment.MODEL_FILE = "${../../README.md}";
  };
  embeddedStoreEnvironmentString = evalProvider {
    environment.MODEL_URI = "file://${builtins.storeDir}/model.hex";
  };
  contextualEnvironmentString = evalProvider {
    environment.RUNTIME_DATA = contextualRuntimePath;
  };
  dotFileUriEnvironmentString = evalProvider {
    environment.RUNTIME_DATA = "file:///nix/./store/runtime-data";
  };
  repeatedSlashFileUriEnvironmentString = evalProvider {
    environment.RUNTIME_DATA = "file:////nix//store/runtime-data";
  };
  percentFileUriEnvironmentString = evalProvider {
    environment.RUNTIME_DATA = "file:///nix/%73tore/runtime-data";
  };
  paddedFileUriEnvironmentString = evalProvider {
    environment.RUNTIME_DATA = "  file:///nix/%73tore/runtime-data";
  };
  controlFileUriEnvironmentString = evalProvider {
    environment.RUNTIME_DATA = "fi\tle:///nix/%73tore/runtime-data";
  };
  ordinaryHttpsEnvironmentString = evalProvider {
    environment.API_ENDPOINT = "https://api.example.test/v1/responses";
  };
  scalarEnvironment = evalProvider {
    environment = {
      TEST_BOOLEAN = true;
      TEST_INTEGER = 7;
    };
  };
  homeManagerLinuxServe = evalHomeManager {
    programs.hellas = {
      inherit package;
      serve.enable = true;
    };
  };
  homeManagerDarwinServe = evalDarwinServe {
    identityPath = "/Users/hellas/Library/Application Support/Hellas/identity";
    artifactStorePath = "/Users/hellas/Library/Application Support/Hellas/artifacts";
    environmentFile = "/Users/hellas/.config/hellas/provider.env";
    fetchConfigFile = "/Users/hellas/.config/hellas/fetch.json";
    assurance = "apple-app-attest";
  };
  homeManagerDarwinService = homeManagerDarwinServe.config.launchd.agents.hellas;
  homeManagerDarwinProgramArguments = homeManagerDarwinService.config.ProgramArguments;
  homeManagerDarwinDirect = evalDarwinServe { };
  homeManagerDarwinStoreIdentity = evalDarwinServe {
    identityPath = "${builtins.storeDir}/identity";
  };
  homeManagerDarwinStoreContent = evalDarwinServe {
    content = [ "${builtins.storeDir}/model.hex" ];
  };
  homeManagerDarwinStoreArtifactStore = evalDarwinServe {
    artifactStorePath = "${builtins.storeDir}/artifacts";
  };
  homeManagerDarwinContextualArtifactStore = evalDarwinServe {
    artifactStorePath = contextualRuntimePath;
  };
  homeManagerDarwinRelativeArtifactStore = builtins.tryEval (
    builtins.deepSeq
      (evalDarwinServe { artifactStorePath = "relative/artifacts"; }).config.launchd.agents.hellas
      true
  );
  homeManagerDarwinStoreWorkConfig = evalDarwinServe {
    workConfigFile = "${builtins.storeDir}/work.json";
  };
  homeManagerDarwinStoreFetchConfig = evalDarwinServe {
    fetchConfigFile = "${builtins.storeDir}/fetch.json";
  };
  homeManagerDarwinStoreEnvironmentFile = evalDarwinServe {
    environmentFile = "${builtins.storeDir}/provider.env";
  };
  homeManagerDarwinRepeatedSlashStoreEnvironmentFile = evalDarwinServe {
    environmentFile = repeatedSlashStorePath;
  };
  homeManagerDarwinDotStoreEnvironmentFile = evalDarwinServe {
    environmentFile = dotStorePath;
  };
  homeManagerDarwinDotDotStoreEnvironmentFile = evalDarwinServe {
    environmentFile = dotDotStorePath;
  };
  homeManagerDarwinContextualEnvironmentFile = evalDarwinServe {
    environmentFile = contextualRuntimePath;
  };
  homeManagerDarwinStoreEnvironment = evalDarwinHomeManager {
    programs.hellas = {
      enable = true;
      inherit package;
      environment.RUNTIME_DATA = "${builtins.storeDir}/runtime-data";
    };
  };
  homeManagerDarwinPaddedFileUriEnvironment = evalDarwinHomeManager {
    programs.hellas = {
      enable = true;
      inherit package;
      environment.RUNTIME_DATA = "  file:///nix/%73tore/runtime-data";
    };
  };
  homeManagerDarwinControlFileUriEnvironment = evalDarwinHomeManager {
    programs.hellas = {
      enable = true;
      inherit package;
      environment.RUNTIME_DATA = "fi\tle:///nix/%73tore/runtime-data";
    };
  };
  homeManagerDarwinUnsafeAssuranceArgs = evalDarwinServe {
    extraArgs = [ "--assurance=producer-signed" ];
  };
  homeManagerDarwinLocalCatena = evalDarwinServe {
    executePolicy = "any";
    contentRoots = [ "/srv/hellas/content" ];
  };
  homeManagerRelativeEnvironmentFile = builtins.tryEval (
    builtins.deepSeq
      (evalDarwinServe { environmentFile = "relative.env"; }).config.launchd.agents.hellas
      true
  );
  homeManagerNixPathEnvironmentFile = builtins.tryEval (
    builtins.deepSeq
      (evalDarwinServe { environmentFile = ../../README.md; }).config.launchd.agents.hellas
      true
  );
  evaluated = import (pkgs.path + "/nixos/lib/eval-config.nix") {
    system = pkgs.stdenv.hostPlatform.system;
    modules = [
      self.nixosModules.default
      {
        nixpkgs.pkgs = plainPkgs;
        system.stateVersion = "26.05";
        services.hellas = {
          enable = true;
          inherit package;
          # An operator explicitly enables arbitrary locally satisfiable
          # Evaluate work, including restart from an already-populated index.
          executePolicy = "any";
          identityPath = "/var/lib/hellas/.hellas/identity-v3";
          contentRoots = [ "/srv/hellas/content" ];
          contentIndex = "/srv/hellas-index/content-index.bin";
          readinessEnvironments = [ "/srv/hellas/content/smollm2.environment" ];
          artifactStorePath = "/srv/hellas/artifacts";
          gpuSessionAssetBytes = 1073741824;
          memoryMaxBytes = 2147483648;
          workConfigFile = "/run/hellas/work.json";
          queueSize = 0;
          fetchConfigFile = "/run/hellas/fetch.json";
          fetchRetainedTranscriptCapacity = 0;
          evaluateRetainedExecutionCapacity = 0;
          fetchReplayMaxInFlight = 3;
          environmentFile = "/run/hellas/provider.env";
          gateway = {
            enable = true;
            causalLmEnvironment = "/srv/hellas/smollm2.environment";
            tokenizer = "/srv/hellas/tokenizer.json";
            provider = builtins.concatStringsSep "" (builtins.genList (_: "00") 32);
            queueSize = 0;
            defaultMaxTokens = 4294967295;
            stopTokenIds = [ 4294967295 ];
            assurance = "apple-app-attest";
            appleAppAttestAppId = "TEAMID.example.hellas";
            appleAppAttestCdhashes = [ (builtins.concatStringsSep "" (builtins.genList (_: "ab") 32)) ];
            responsesBackend = "fetch";
            responsesFetchExecutionEnvironment = "openai-responses";
            retries = 7;
            environmentFile = "/run/hellas/gateway.env";
          };
        };
      }
    ];
  };
  service = evaluated.config.systemd.services.hellas;
  defaultProviderService = defaultIdentityProvider.config.systemd.services.hellas;
  readinessOnlyService = readinessOnlyProvider.config.systemd.services.hellas;
  managedContentProviderService = managedContentProvider.config.systemd.services.hellas;
  managedContentGatewayService = managedContentGateway.config.systemd.services.hellas-gateway;
  gatewayService = evaluated.config.systemd.services.hellas-gateway;
  verifyLocalGatewayService = verifyLocalProxyGateway.config.systemd.services.hellas-gateway;
in
{
  provider-content-index-eval =
    assert service.environment ? ROCM_PATH;
    assert service.environment ? HIP_PATH;
    assert service.environment.TMPDIR == "/var/cache/hellas";
    assert service.path != [ ];
    assert service.serviceConfig.CacheDirectory == "hellas";
    # The logical resident-asset cap must never lower the driver's memlock
    # permission. The cgroup ceiling is the whole-unit containment boundary.
    assert service.serviceConfig.LimitMEMLOCK == "infinity";
    assert service.serviceConfig.MemoryMax == "2147483648";
    assert service.serviceConfig.MemorySwapMax == 0;
    assert service.serviceConfig.OOMPolicy == "kill";
    assert builtins.length service.serviceConfig.ExecStartPre == 1;
    assert lib.hasInfix "environment verify" (builtins.head service.serviceConfig.ExecStartPre);
    assert lib.hasInfix "--environment /srv/hellas/content/smollm2.environment" (
      builtins.head service.serviceConfig.ExecStartPre
    );
    assert lib.hasInfix "--content-root /srv/hellas/content" (
      builtins.head service.serviceConfig.ExecStartPre
    );
    assert lib.hasInfix "--content-index /srv/hellas-index/content-index.bin" (
      builtins.head service.serviceConfig.ExecStartPre
    );
    assert !(lib.hasInfix "--recheck" (builtins.head service.serviceConfig.ExecStartPre));
    assert
      service.serviceConfig.SupplementaryGroups == [
        "render"
        "video"
      ];
    assert lib.elem "/dev/kfd rw" service.serviceConfig.DeviceAllow;
    assert lib.elem "char-drm rw" service.serviceConfig.DeviceAllow;
    assert lib.hasInfix "--execute-policy any" service.serviceConfig.ExecStart;
    assert lib.hasInfix "--execute-policy none" defaultProviderService.serviceConfig.ExecStart;
    assert !(defaultProviderService.environment ? ROCM_PATH);
    assert !(defaultProviderService.environment ? HIP_PATH);
    assert !(lib.elem pkgs.rocmPackages.clang defaultProviderService.path);
    assert !(lib.elem pkgs.rocmPackages.hipcc defaultProviderService.path);
    assert !(defaultProviderService.serviceConfig ? SupplementaryGroups);
    assert !(defaultProviderService.serviceConfig ? DeviceAllow);
    assert builtins.length readinessOnlyService.serviceConfig.ExecStartPre == 1;
    assert !(readinessOnlyService.environment ? ROCM_PATH);
    assert !(readinessOnlyService.environment ? HIP_PATH);
    assert !(lib.elem pkgs.rocmPackages.clang readinessOnlyService.path);
    assert !(lib.elem pkgs.rocmPackages.hipcc readinessOnlyService.path);
    assert !(readinessOnlyService.serviceConfig ? SupplementaryGroups);
    assert !(readinessOnlyService.serviceConfig ? DeviceAllow);
    assert !(readinessOnlyService.serviceConfig ? LimitMEMLOCK);
    assert lib.hasInfix "--identity /var/lib/hellas/.hellas/identity-v3"
      service.serviceConfig.ExecStart;
    assert lib.hasInfix "--identity /var/lib/hellas/.hellas/identity"
      defaultIdentityProvider.config.systemd.services.hellas.serviceConfig.ExecStart;
    assert lib.hasInfix "--queue-size 0" service.serviceConfig.ExecStart;
    assert lib.hasInfix "--content-index /srv/hellas-index/content-index.bin"
      service.serviceConfig.ExecStart;
    assert lib.hasInfix "--artifact-store-path /srv/hellas/artifacts" service.serviceConfig.ExecStart;
    assert !(lib.hasInfix "--artifact-store-path" defaultProviderService.serviceConfig.ExecStart);
    assert lib.hasInfix "--assurance producer-signed" service.serviceConfig.ExecStart;
    assert lib.all (path: lib.elem path service.unitConfig.RequiresMountsFor) [
      "/var/lib/hellas/.hellas/identity-v3"
      "/srv/hellas/content"
      "/srv/hellas/content/smollm2.environment"
      "/srv/hellas-index/content-index.bin"
      "/srv/hellas/artifacts"
      "/run/hellas/work.json"
      "/run/hellas/fetch.json"
      "/run/hellas/provider.env"
    ];
    assert
      service.serviceConfig.ReadWritePaths == [
        "/srv/hellas/artifacts"
        "/srv/hellas-index"
      ];
    assert service.serviceConfig.ReadOnlyPaths == [ "/srv/hellas/content" ];
    assert !(lib.elem "/srv/hellas/content" service.serviceConfig.ReadWritePaths);
    assert
      verifyLocalGatewayService.serviceConfig.ReadWritePaths == [
        "/srv/hellas-gateway-index"
      ];
    assert verifyLocalGatewayService.serviceConfig.ReadOnlyPaths == [ "/srv/hellas/content" ];
    assert !(lib.elem "/srv/hellas/content" verifyLocalGatewayService.serviceConfig.ReadWritePaths);
    assert
      managedContentProviderService.serviceConfig.ReadOnlyPaths == [
        "/var/lib/hellas/content"
      ];
    assert !(managedContentProviderService.serviceConfig ? ReadWritePaths);
    assert
      managedContentGatewayService.serviceConfig.ReadOnlyPaths == [
        "/var/lib/hellas-gateway/content"
      ];
    assert !(managedContentGatewayService.serviceConfig ? ReadWritePaths);
    assert service.serviceConfig.EnvironmentFile == "/run/hellas/provider.env";
    assert lib.hasInfix "--work-config /run/hellas/work.json" service.serviceConfig.ExecStart;
    assert lib.hasInfix "--fetch-config /run/hellas/fetch.json" service.serviceConfig.ExecStart;
    assert lib.hasInfix "--fetch-retained-transcript-capacity 0" service.serviceConfig.ExecStart;
    assert lib.hasInfix "--evaluate-retained-execution-capacity 0" service.serviceConfig.ExecStart;
    assert lib.hasInfix "--fetch-replay-max-in-flight 3" service.serviceConfig.ExecStart;
    assert
      (builtins.length (lib.splitString "--retries" gatewayService.serviceConfig.ExecStart) - 1) == 1;
    assert lib.hasInfix "--responses-fetch-execution-environment openai-responses"
      gatewayService.serviceConfig.ExecStart;
    assert lib.hasInfix "--queue-size 0" gatewayService.serviceConfig.ExecStart;
    assert lib.hasInfix "--default-max-tokens 4294967295" gatewayService.serviceConfig.ExecStart;
    assert lib.hasInfix "--stop-token 4294967295" gatewayService.serviceConfig.ExecStart;
    assert lib.hasInfix "--assurance apple-app-attest" gatewayService.serviceConfig.ExecStart;
    assert lib.hasInfix "--apple-app-attest-app-id TEAMID.example.hellas"
      gatewayService.serviceConfig.ExecStart;
    assert lib.hasInfix
      "--apple-app-attest-cdhashes abababababababababababababababababababababababababababababababab"
      gatewayService.serviceConfig.ExecStart;
    assert lib.elem "/run/hellas/gateway.env" gatewayService.unitConfig.RequiresMountsFor;
    assert gatewayService.serviceConfig.EnvironmentFile == "/run/hellas/gateway.env";
    assert !(runtimeStoreAssertion storePathGateway).assertion;
    assert !(runtimeStoreAssertion storePathIdentityGateway).assertion;
    assert !(runtimeStoreAssertion storePathTokenizerGateway).assertion;
    assert !(runtimeStoreAssertion storePathIdentityProvider).assertion;
    assert !(runtimeStoreAssertion storePathContentProvider).assertion;
    assert !(runtimeStoreAssertion storePathArtifactStore).assertion;
    assert !(runtimeStoreAssertion contextualArtifactStore).assertion;
    assert !relativeArtifactStore.success;
    assert !(runtimeStoreAssertion storePathWorkConfig).assertion;
    assert !(runtimeStoreAssertion storePathFetchConfig).assertion;
    assert !(runtimeStoreAssertion storePathProviderEnvironmentFile).assertion;
    assert !(serveExtraArgsAssertion unsafeServeExtraArgs).assertion;
    assert !(serveExtraArgsAssertion unsafeServeAssuranceArgs).assertion;
    assert !(serveExtraArgsAssertion unsafeServeArtifactStoreArgs).assertion;
    assert !(gatewayExtraArgsAssertion unsafeGatewayExtraArgs).assertion;
    assert (serveExtraArgsAssertion harmlessExtraArgs).assertion;
    assert !(providerAssuranceAssertion unsupportedProviderApple).assertion;
    assert !(appleTrustPairAssertion incompleteAppleTrust).assertion;
    assert !(appleTrustRequiredAssertion missingRequiredAppleTrust).assertion;
    assert !oversizedGpuCapacity.success;
    assert !(memoryHeadroomAssertion insufficientMemoryHeadroom).assertion;
    assert !(memoryHeadroomAssertion insufficientDefaultMemoryHeadroom).assertion;
    assert !(readinessContentAssertion readinessWithoutContent).assertion;
    assert !(writableRootAssertion rootArtifactStoreProvider).assertion;
    assert !(writableRootAssertion rootContentIndexGateway).assertion;
    assert !(writableContentDisjointAssertion overlappingArtifactStoreProvider).assertion;
    assert !(writableContentDisjointAssertion overlappingContentIndexGateway).assertion;
    assert !invalidEmptyPolicyList.success;
    assert !invalidBogusPolicy.success;
    assert !invalidPaddedNonePolicy.success;
    assert !invalidEmptyOnlyPolicy.success;
    assert !invalidEmptyGlobPolicy.success;
    assert !invalidCharacterGlobPolicy.success;
    assert !invalidLongGlobPolicy.success;
    assert !invalidEmptyListGlobPolicy.success;
    assert validAnyPolicyProvider.config.systemd.services.hellas.serviceConfig ? LimitMEMLOCK;
    assert !(validNonePolicyProvider.config.systemd.services.hellas.serviceConfig ? LimitMEMLOCK);
    assert validOnlyPolicyProvider.config.systemd.services.hellas.serviceConfig ? LimitMEMLOCK;
    assert validListPolicyProvider.config.systemd.services.hellas.serviceConfig ? LimitMEMLOCK;
    assert lib.hasInfix "only(0123*,abcdef)"
      validOnlyPolicyProvider.config.systemd.services.hellas.serviceConfig.ExecStart;
    assert lib.hasInfix "only(0123*,abcdef)"
      validListPolicyProvider.config.systemd.services.hellas.serviceConfig.ExecStart;
    assert !(runtimeStoreAssertion storePathReadinessProvider).assertion;
    assert lib.hasInfix "--gpu-session-asset-bytes 4398046511104"
      maxGpuSessionAssetBytes.config.systemd.services.hellas.serviceConfig.ExecStart;
    assert !oversizedGpuSessionAssetBytes.success;
    assert !oversizedDefaultMaxTokens.success;
    assert !oversizedStopToken.success;
    assert !environmentPathEvaluation.success;
    assert !(environmentStoreAssertion interpolatedEnvironmentPath).assertion;
    assert !(environmentStoreAssertion embeddedStoreEnvironmentString).assertion;
    assert builtins.hasContext contextualRuntimePath;
    assert !(environmentStoreAssertion contextualEnvironmentString).assertion;
    assert !(environmentStoreAssertion dotFileUriEnvironmentString).assertion;
    assert !(environmentStoreAssertion repeatedSlashFileUriEnvironmentString).assertion;
    assert !(environmentStoreAssertion percentFileUriEnvironmentString).assertion;
    assert !(environmentStoreAssertion paddedFileUriEnvironmentString).assertion;
    assert !(environmentStoreAssertion controlFileUriEnvironmentString).assertion;
    assert (environmentStoreAssertion ordinaryHttpsEnvironmentString).assertion;
    assert !(hellasModule.runtimeStringIsOutsideStore lib "file://${builtins.storeDir}/model.hex");
    assert !(hellasModule.runtimeStringIsOutsideStore lib "file:///nix/./store/model.hex");
    assert !(hellasModule.runtimeStringIsOutsideStore lib "file:////nix//store/model.hex");
    assert !(hellasModule.runtimeStringIsOutsideStore lib "file:///nix/%73tore/model.hex");
    assert !(hellasModule.runtimeStringIsOutsideStore lib "  file:///nix/%73tore/model.hex");
    assert !(hellasModule.runtimeStringIsOutsideStore lib "fi\tle:///nix/%73tore/model.hex");
    assert !(hellasModule.runtimeStringIsOutsideStore lib "fil\ne:///nix/%73tore/model.hex");
    assert !(hellasModule.runtimeStringIsOutsideStore lib "file\r:///nix/%73tore/model.hex");
    assert hellasModule.runtimeStringIsOutsideStore lib "https://api.example.test/v1/responses";
    assert hellasModule.runtimePathIsOutsideStore lib "/run/hellas/provider.env";
    assert !(hellasModule.runtimePathIsOutsideStore lib "relative.env");
    assert !(hellasModule.runtimePathIsOutsideStore lib repeatedSlashStorePath);
    assert !(hellasModule.runtimePathIsOutsideStore lib dotStorePath);
    assert !(hellasModule.runtimePathIsOutsideStore lib dotDotStorePath);
    assert !(hellasModule.runtimePathIsOutsideStore lib contextualRuntimePath);
    assert
      scalarEnvironment.config.systemd.services.hellas.environment.TEST_BOOLEAN == builtins.toString true;
    assert scalarEnvironment.config.systemd.services.hellas.environment.TEST_INTEGER == "7";
    assert !(homeManagerPlatformAssertion homeManagerLinuxServe).assertion;
    assert
      homeManagerLinuxServe.config.programs.hellas.serve.identityPath == "/home/hellas/.hellas/identity";
    assert homeManagerDarwinService.enable;
    assert lib.hasSuffix "-hellas-runtime-environment" (
      builtins.head homeManagerDarwinProgramArguments
    );
    assert
      builtins.tail homeManagerDarwinProgramArguments == [
        "/Users/hellas/.config/hellas/provider.env"
        "${package}/bin/hellas-cli"
        "serve"
        "--identity"
        "/Users/hellas/Library/Application Support/Hellas/identity"
        "--port"
        "31145"
        "--execute-policy"
        "none"
        "--artifact-store-path"
        "/Users/hellas/Library/Application Support/Hellas/artifacts"
        "--assurance"
        "apple-app-attest"
        "--fetch-config"
        "/Users/hellas/.config/hellas/fetch.json"
      ];
    assert !(homeManagerDarwinService.config ? EnvironmentFile);
    assert homeManagerDarwinService.config.EnvironmentVariables == { HOME = "/Users/hellas"; };
    assert
      homeManagerDarwinDirect.config.launchd.agents.hellas.config.ProgramArguments == [
        "${package}/bin/hellas-cli"
        "serve"
        "--identity"
        "/Users/hellas/.hellas/identity"
        "--port"
        "31145"
        "--execute-policy"
        "none"
        "--assurance"
        "producer-signed"
      ];
    assert (homeManagerCatenaAssertion homeManagerDarwinServe).assertion;
    assert (homeManagerRuntimeStoreAssertion homeManagerDarwinServe).assertion;
    assert !(homeManagerRuntimeStoreAssertion homeManagerDarwinStoreIdentity).assertion;
    assert !(homeManagerRuntimeStoreAssertion homeManagerDarwinStoreContent).assertion;
    assert !(homeManagerRuntimeStoreAssertion homeManagerDarwinStoreArtifactStore).assertion;
    assert !(homeManagerRuntimeStoreAssertion homeManagerDarwinContextualArtifactStore).assertion;
    assert !homeManagerDarwinRelativeArtifactStore.success;
    assert !(homeManagerRuntimeStoreAssertion homeManagerDarwinStoreWorkConfig).assertion;
    assert !(homeManagerRuntimeStoreAssertion homeManagerDarwinStoreFetchConfig).assertion;
    assert !(homeManagerRuntimeStoreAssertion homeManagerDarwinStoreEnvironmentFile).assertion;
    assert
      !(homeManagerRuntimeStoreAssertion homeManagerDarwinRepeatedSlashStoreEnvironmentFile).assertion;
    assert !(homeManagerRuntimeStoreAssertion homeManagerDarwinDotStoreEnvironmentFile).assertion;
    assert !(homeManagerRuntimeStoreAssertion homeManagerDarwinDotDotStoreEnvironmentFile).assertion;
    assert !(homeManagerRuntimeStoreAssertion homeManagerDarwinContextualEnvironmentFile).assertion;
    assert !(homeManagerEnvironmentStoreAssertion homeManagerDarwinStoreEnvironment).assertion;
    assert !(homeManagerEnvironmentStoreAssertion homeManagerDarwinPaddedFileUriEnvironment).assertion;
    assert !(homeManagerEnvironmentStoreAssertion homeManagerDarwinControlFileUriEnvironment).assertion;
    assert !(homeManagerExtraArgsAssertion homeManagerDarwinUnsafeAssuranceArgs).assertion;
    assert !(homeManagerCatenaAssertion homeManagerDarwinLocalCatena).assertion;
    assert !homeManagerRelativeEnvironmentFile.success;
    assert !homeManagerNixPathEnvironmentFile.success;
    assert !(providerAssertion discoveryGateway).assertion;
    assert (providerAssertion proxyOnlyGateway).assertion;
    assert !(providerAssertion verifyLocalProxyGateway).assertion;
    pkgs.runCommand "hellas-provider-content-index-module-eval" { } ''
      umask 077
      environment_file="$PWD/provider.env"
      printf '%s\n' \
        '# literal runtime environment' \
        'TOKEN=runtime-secret-not-in-wrapper' \
        'COMPLEX=value with spaces=#literal=tail' \
        'LITERAL=$(touch should-not-exist)' \
        'EMPTY=' > "$environment_file"

      actual="$(${runtimeEnvironmentWrapper} "$environment_file" \
        ${pkgs.bash}/bin/bash -c 'printf "%s|%s|%s|%s" "$TOKEN" "$COMPLEX" "$LITERAL" "$EMPTY"')"
      test "$actual" = 'runtime-secret-not-in-wrapper|value with spaces=#literal=tail|$(touch should-not-exist)|'
      test ! -e "$PWD/should-not-exist"
      ! ${pkgs.gnugrep}/bin/grep -F 'runtime-secret-not-in-wrapper' ${runtimeEnvironmentWrapper}
      ! ${pkgs.gnugrep}/bin/grep -F '/Users/hellas/.config/hellas/provider.env' ${runtimeEnvironmentWrapper}

      printf '%s\n' 'INSECURE=value' > "$PWD/insecure-mode.env"
      chmod 0644 "$PWD/insecure-mode.env"
      if ${runtimeEnvironmentWrapper} "$PWD/insecure-mode.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      printf '%s\n' 'SYMLINK=value' > "$PWD/symlink-target.env"
      ln -s "$PWD/symlink-target.env" "$PWD/symlink.env"
      if ${runtimeEnvironmentWrapper} "$PWD/symlink.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      ${pkgs.coreutils}/bin/mkfifo "$PWD/fifo.env"
      chmod 0600 "$PWD/fifo.env"
      fifo_status=0
      ${pkgs.coreutils}/bin/timeout 2 \
        ${runtimeEnvironmentWrapper} "$PWD/fifo.env" ${pkgs.coreutils}/bin/true \
        2>/dev/null || fifo_status=$?
      test "$fifo_status" -ne 0
      test "$fifo_status" -ne 124

      ln -s ${builtins.dirOf runtimeEnvironmentStoreFile} "$PWD/store-parent"
      if ${runtimeEnvironmentWrapper} \
        "$PWD/store-parent/${builtins.baseNameOf runtimeEnvironmentStoreFile}" \
        ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      printf '%s\n' 'MALFORMED' > "$PWD/malformed.env"
      if ${runtimeEnvironmentWrapper} "$PWD/malformed.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      printf '%s\n' 'DUPLICATE=one' 'DUPLICATE=two' > "$PWD/duplicate.env"
      if ${runtimeEnvironmentWrapper} "$PWD/duplicate.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      printf 'CR=value\r\n' > "$PWD/carriage-return.env"
      if ${runtimeEnvironmentWrapper} "$PWD/carriage-return.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      printf 'NUL=value\000suffix\n' > "$PWD/nul.env"
      if ${runtimeEnvironmentWrapper} "$PWD/nul.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      if ${runtimeEnvironmentWrapper} "$PWD/missing.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      touch "$out"
    '';
}
