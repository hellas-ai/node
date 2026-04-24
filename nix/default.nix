{
  self,
  system,
  nixpkgs,
  rust-overlay,
  catgrad,
}: let
  nativePkg = import ./package.nix {
    inherit self system nixpkgs rust-overlay;
  };
  inherit
    (nativePkg)
    pkgs
    lib
    rustToolchain
    devShellPackages
    envShellHook
    ;

  ci = import ./ci.nix {
    inherit pkgs lib rustToolchain;
  };

  testsLib = import ./tests/lib.nix {
    inherit pkgs lib;
  };

  packagesFor = crossSystem: let
    pkgSpec = import ./package.nix {
      inherit self system nixpkgs rust-overlay crossSystem;
    };
    hostPlatform = pkgSpec.pkgs.stdenv.hostPlatform;
  in
    {
      cli = pkgSpec.mkHellasPackage {
        buildInputs = [];
        doCheck = false;
      };
      cli-cpu = pkgSpec.mkHellasPackage {
        buildNoDefaultFeatures = true;
        buildFeatures = ["candle-cpu"];
        doCheck = false;
      };
    }
    // lib.optionalAttrs hostPlatform.isDarwin {
      cli-metal = pkgSpec.mkHellasPackage {
        buildNoDefaultFeatures = true;
        buildFeatures = ["candle-metal"];
        doCheck = false;
      };
    };

  crossTargets = {
    "aarch64-linux" = nixpkgs.lib.systems.examples.aarch64-multiplatform;
    "riscv64-linux" = nixpkgs.lib.systems.examples.riscv64;
    "x86_64-linux-musl" = nixpkgs.lib.systems.examples.musl64 // {isStatic = true;};
    "aarch64-linux-musl" = nixpkgs.lib.systems.examples.aarch64-multiplatform-musl // {isStatic = true;};
    "x86_64-windows" = nixpkgs.lib.systems.examples.mingwW64;
  };

  nativePackages = packagesFor null;
  crossOutputs = lib.mapAttrs (_: spec: packagesFor spec) crossTargets;

  linuxOutputs =
    if pkgs.stdenv.hostPlatform.isLinux
    then let
      docker = import ./docker.nix {
        inherit pkgs lib rustToolchain catgrad system;
        mkHellasPackage = nativePkg.mkHellasPackage;
        cliCpu = nativePackages.cli-cpu;
      };

      nixosTests = import ./tests {
        inherit self pkgs lib;
        package = nativePackages.cli-cpu;
      };
    in {
      packages =
        {cli-cuda = docker.defaultCudaCli;}
        // lib.mapAttrs'
        (name: value: lib.nameValuePair "docker-${name}" value)
        docker.dockerImages
        // lib.mapAttrs'
        (name: value: lib.nameValuePair "cli-cuda-${name}" value)
        docker.cudaCliPackages;

      apps = {
        "docker-push-all" = {
          type = "app";
          program = "${docker.pushAll}/bin/docker-push-all";
        };
      };

      devShells = {
        cuda = pkgs.mkShell {
          packages = devShellPackages;
          shellHook = envShellHook;
          nativeBuildInputs = docker.defaultCudaEnv.nativeBuildInputs;
          buildInputs = docker.defaultCudaEnv.buildInputs;
          inherit
            (docker.defaultCudaEnv)
            CUDA_COMPUTE_CAP
            CUDA_TOOLKIT_ROOT_DIR
            ;
          LD_LIBRARY_PATH = "${docker.defaultCudaEnv.runtimeLibraryPath}:${docker.defaultCudaEnv.driverLink}/lib";
        };
      };

      checks = nixosTests;
      inherit nixosTests;
    }
    else {
      packages = {};
      apps = {};
      devShells = {};
      checks = {};
      nixosTests = {};
    };
in {
  packages =
    nativePackages
    // {
      default = nativePackages.cli;
      cross = crossOutputs;
      "hf-cache-smollm2-135m-instruct" = testsLib.smolLm2InstructCache;
    }
    // linuxOutputs.packages;

  apps =
    {
      check = {
        type = "app";
        program = "${ci.checkPackages.all}/bin/hellas-check-all";
        meta.description = "Run all CI checks (sort, fmt, clippy, outdated)";
      };
      fix = {
        type = "app";
        program = "${ci.fixPackages.all}/bin/hellas-fix-all";
        meta.description = "Apply all CI auto-fixes where supported";
      };
    }
    // linuxOutputs.apps;

  devShells =
    {
      default = pkgs.mkShell {
        packages = devShellPackages;
        shellHook = envShellHook;
      };
    }
    // linuxOutputs.devShells;

  checks = linuxOutputs.checks;
  inherit (linuxOutputs) nixosTests;
}
