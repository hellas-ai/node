{
  self,
  system,
  nixpkgs,
  rust-overlay,
  catgrad,
}: let
  package = import ./package.nix {
    inherit system nixpkgs rust-overlay;
  };
  inherit
    (package)
    pkgs
    lib
    rustToolchain
    rustPlatform
    commonArgs
    cli
    server
    devShellPackages
    envShellHook
    ;

  testsLib = import ./tests/lib.nix {
    inherit pkgs lib;
  };

  linuxOutputs =
    if pkgs.stdenv.hostPlatform.isLinux
    then let
      docker = import ./docker.nix {
        inherit
          pkgs
          lib
          rustPlatform
          commonArgs
          rustToolchain
          catgrad
          system
          server
          ;
      };

      nixosTests = import ./tests {
        inherit self pkgs lib server;
      };
    in {
      packages =
        lib.mapAttrs'
        (name: value: lib.nameValuePair "docker-${name}" value)
        docker.dockerImages
        // lib.mapAttrs'
        (name: value: lib.nameValuePair "server-${name}" value)
        docker.cudaServerPackages
        // {
          server-cuda = docker.defaultCudaServer;
        };

      apps = {
        "docker-push-all" = {
          type = "app";
          program = "${docker.pushAll}/bin/docker-push-all";
        };
      };

      devShells = rec {
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

        "server-cuda" = cuda;
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
    {
      default = cli;
      inherit cli server;
      "hf-cache-smollm2-135m-instruct" = testsLib.smolLm2InstructCache;
    }
    // linuxOutputs.packages;

  apps = linuxOutputs.apps;

  devShells =
    {
      default = pkgs.mkShell {
        packages = devShellPackages;
        shellHook = envShellHook;
      };

      server = pkgs.mkShell {
        packages = devShellPackages;
        shellHook = envShellHook;
      };
    }
    // linuxOutputs.devShells;

  checks = linuxOutputs.checks;
  inherit (linuxOutputs) nixosTests;
}
