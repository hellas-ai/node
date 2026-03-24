{
  self,
  system,
  nixpkgs,
  rust-overlay,
  catgrad,
}: let
  repoRoot = ../.;
  overlays = [(import rust-overlay)];
  pkgs = import nixpkgs {
    inherit system overlays;
    config.allowUnfree = true;
  };

  rust-toolchain = pkgs.buildPackages.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
  rustPlatform = pkgs.makeRustPlatform {
    rustc = rust-toolchain;
    cargo = rust-toolchain;
  };

  buildSrc = pkgs.lib.cleanSourceWith {
    src = repoRoot;
    filter = path: type: let
      name = builtins.baseNameOf (toString path);
    in
      pkgs.lib.cleanSourceFilter path type
      && !(builtins.elem name [
        ".claude"
        ".direnv"
        ".envrc"
        "result"
        "target"
      ])
      && !pkgs.lib.hasPrefix "result-" name;
  };

  workspaceBuildInputs = with pkgs; [openssl];
  workspaceNativeBuildInputs = with pkgs; [pkg-config protobuf llvmPackages.lld];
  devShellPackages = with pkgs; [
    rust-toolchain
    openssl
    pkg-config
    protobuf
    llvmPackages.lld
    pre-commit
    protobuf-language-server
    cargo-watch
    gh
    cargo-audit
    cargo-outdated
    skopeo
  ];

  commonArgs = {
    pname = "hellas";
    version = "0.1.0";
    src = buildSrc;
    cargoLock = {
      lockFile = ../Cargo.lock;
      outputHashes = {
        "catgrad-0.2.1" = "sha256-rGc/uMao5PGwk33wkL62UvhcbH9rs4tbGcJVw9GPrlA=";
      };
    };
    auditable = false;
    buildInputs = workspaceBuildInputs;
    nativeBuildInputs = workspaceNativeBuildInputs;
    checkInputs = with pkgs; [cargo-outdated];
    separateDebugInfo = true;
    meta.mainProgram = "hellas-cli";
  };

  cli = rustPlatform.buildRustPackage commonArgs;
  server = rustPlatform.buildRustPackage (
    commonArgs
    // {
      buildFeatures = ["serve"];
    }
  );

  docker = import ./docker.nix {
    inherit
      pkgs
      rustPlatform
      commonArgs
      rust-toolchain
      catgrad
      system
      server
      ;
    lib = pkgs.lib;
  };

  e2eTest = pkgs.writeShellApplication {
    name = "e2e-test";
    runtimeInputs = [server pkgs.coreutils pkgs.gnugrep pkgs.gawk];
    text = builtins.readFile ../tests/e2e.sh;
  };
in rec {
  packages =
    {
      default = cli;
      inherit cli server;
      "e2e-test" = e2eTest;
    }
    // pkgs.lib.mapAttrs' (name: value: pkgs.lib.nameValuePair "docker-${name}" value) docker.dockerImages;

  apps = {
    "e2e" = {
      type = "app";
      program = "${e2eTest}/bin/e2e-test";
    };
    "docker-push-all" = {
      type = "app";
      program = "${docker.pushAll}/bin/docker-push-all";
    };
  };

  envShellHook = ''
    if [ -f .env ]; then
      set -a
      source .env
      set +a
    fi
  '';

  devShells = rec {
    default = pkgs.mkShell {
      packages = devShellPackages;
      shellHook = envShellHook;
    };

    # Explicit shell aliases so users can `nix develop .#server` / `.#server-cuda`
    # and still get a full development environment (not a package build env).
    server = default;

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

  checks = import ./tests {
    inherit pkgs packages;
  };
}
