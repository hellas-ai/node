{
  self,
  system,
  nixpkgs,
  rust-overlay,
}: let
  repoRoot = ../.;
  overlays = [(import rust-overlay)];
  pkgs = import nixpkgs {
    inherit system overlays;
    config.allowUnfree = true;
  };
  lib = pkgs.lib;

  rustToolchain = pkgs.buildPackages.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
  rustPlatform = pkgs.makeRustPlatform {
    rustc = rustToolchain;
    cargo = rustToolchain;
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
  workspaceNativeBuildInputs = with pkgs; [pkg-config protobuf llvmPackages.lld];

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

  commonArgs = {
    pname = "hellas";
    version = "0.1.0";
    src = buildSrc;
    cargoLock = {
      lockFile = ../Cargo.lock;
      outputHashes = {
        "catgrad-0.2.1" = "sha256-j2CDXsHloJctpnbsPNT3pXlQpWR2e5GdIgnLNB4FSis=";
      };
    };
    auditable = false;
    GIT_REV = builtins.substring 0 12 rev;
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
    cli
    server
    devShellPackages
    envShellHook
    ;
}
