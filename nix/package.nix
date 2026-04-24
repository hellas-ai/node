{
  self,
  system,
  nixpkgs,
  rust-overlay,
  # When set, builds everything for this target triple via `pkgsCross`.
  # Leave null for native builds.
  crossSystem ? null,
}: let
  repoRoot = ../.;
  overlays = [(import rust-overlay)];
  pkgs = import nixpkgs ({
      inherit system overlays;
      config.allowUnfree = true;
    }
    // nixpkgs.lib.optionalAttrs (crossSystem != null) {inherit crossSystem;});
  lib = pkgs.lib;

  isCross = crossSystem != null;
  targetTriple = pkgs.stdenv.hostPlatform.rust.rustcTarget;

  rustToolchain =
    (pkgs.buildPackages.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml).override
    {
      targets = lib.optional isCross targetTriple;
    };

  # clangStdenv avoids the GCC 15 ICE in zstd-sys (gimple_lower_bitint crash).
  # Under pkgsCross this is the *target* stdenv.
  stdenv = pkgs.clangStdenv;

  rustPlatform = pkgs.makeRustPlatform {
    rustc = rustToolchain;
    cargo = rustToolchain;
    inherit stdenv;
  };

  buildSrc = lib.cleanSourceWith {
    src = repoRoot;
    filter = path: type: let
      name = builtins.baseNameOf (toString path);
    in
      lib.cleanSourceFilter path type
      && !(builtins.elem name [
        ".claude"
        ".direnv"
        ".envrc"
        "result"
        "target"
      ])
      && !lib.hasPrefix "result-" name;
  };

  workspaceBuildInputs = with pkgs; [openssl];
  workspaceNativeBuildInputs = with pkgs.buildPackages; [pkg-config protobuf llvmPackages.lld];

  devShellPackages = with pkgs; [
    rustToolchain
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
    cargo-sort
    skopeo
  ];

  rev = self.rev or self.dirtyRev or "unknown";

  rustEnvTarget = pkgs.stdenv.hostPlatform.rust.cargoEnvVarTarget;

  crossEnv = lib.optionalAttrs isCross {
    CARGO_BUILD_TARGET = targetTriple;
    "CARGO_TARGET_${rustEnvTarget}_LINKER" = "${stdenv.cc}/bin/${stdenv.cc.targetPrefix}cc";
  };

  commonArgs =
    {
      pname = "hellas";
      version = "0.1.0";
      src = buildSrc;
      cargoLock = {
        lockFile = ../Cargo.lock;
        outputHashes = {
          "catgrad-0.2.1" = "sha256-WAuFgZGG4fIDkz2gZAN/oPiVg5DwHGiiPPykHMA/2yc=";
        };
      };
      inherit stdenv;
      auditable = false;
      RUST_MIN_STACK = "16777216";
      GIT_REV = builtins.substring 0 12 rev;
      buildInputs = workspaceBuildInputs;
      nativeBuildInputs = workspaceNativeBuildInputs;
      checkInputs = with pkgs; [cargo-outdated];
      separateDebugInfo = true;
      # stdenv's default stripDebugList only does --strip-debug on bin/;
      # stripAllList promotes it to --strip-all so .symtab goes too.
      stripAllList = ["bin"];
      meta.mainProgram = "hellas-cli";
    }
    // crossEnv;

  mkHellasPackage = overrides: rustPlatform.buildRustPackage (commonArgs // overrides);

  envShellHook = ''
    if [ -f .env ]; then
      set -a
      source .env
      set +a
    fi
  '';
in {
  inherit
    pkgs
    lib
    rustToolchain
    rustPlatform
    buildSrc
    commonArgs
    mkHellasPackage
    devShellPackages
    envShellHook
    ;
}
