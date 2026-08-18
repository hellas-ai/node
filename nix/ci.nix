{
  pkgs,
  lib,
  rustToolchain,
  workspaceNativeBuildInputs,
  extraChecks ? { },
}:
let
  mk =
    name: cmd: inputs:
    pkgs.writeShellApplication {
      inherit name;
      text = ''
        export PATH="${lib.makeBinPath inputs}"
        ${cmd}
      '';
    };

  cargoEnv =
    toolchain:
    [
      toolchain
      pkgs.stdenv.cc
    ]
    ++ workspaceNativeBuildInputs;

  # CI-gating checks. These surface as `apps.<sys>.check-<name>` for local and
  # external matrix runners.
  baseChecks = {
    fmt = mk "check-fmt" "cargo fmt --all -- --check" [ rustToolchain ];
    clippy = mk "check-clippy" "cargo clippy --workspace --all-targets -- -D warnings" (
      cargoEnv rustToolchain
    );
    # Default features alone leave most of the CLI unlinted: `evaluate`,
    # `node` and `gateway` are all off by default, which is most of what
    # the binary actually does. Not `--all-features` — that pulls
    # candle-cuda and objc2, which cannot build here. So: the buildable
    # feature sets, named.
    clippy-features = mk "check-clippy-features" (builtins.concatStringsSep " && " (
      map
        (f: "cargo clippy -p hellas-cli --no-default-features --features ${f} --all-targets -- -D warnings")
        [
          "chain"
          "indexer"
          "validator"
          "evaluate"
          "node"
          "gateway"
          "otel"
        ]
    )) (cargoEnv rustToolchain);
    # The kernel's whole suite, including `tests/itf.rs` — the Quint↔Rust
    # replay that the entire abstract-correspondence story rests on — and
    # the exact-error pins in `tests/channel/`. `--all-features` is load
    # bearing: `secp256k1`, `webauthn`, and `test-support` gate whole test
    # files, and a bare `cargo test -p hellas-kernel` compiles them away
    # to empty binaries.
    kernel = mk "check-kernel" "cargo test -p hellas-kernel --all-features" (cargoEnv rustToolchain);
    executor = mk "check-executor" "cargo test -p hellas-executor" (cargoEnv rustToolchain);
    validator =
      mk "check-validator" "cargo test -p hellas-chain --no-default-features --features validator"
        (cargoEnv rustToolchain);
    sort = mk "check-sort" "cargo-sort --workspace --check --no-format" [ pkgs.cargo-sort ];
    taplo =
      mk "check-taplo" "taplo fmt --option 'indent_string=    ' --check '*.toml' 'crates/**/Cargo.toml'"
        [
          pkgs.taplo
        ];
    buf = mk "check-buf" "buf lint" [ pkgs.buf ];
    deny = mk "check-deny" "cargo deny check" (
      (cargoEnv rustToolchain)
      ++ [
        pkgs.cargo-deny
        pkgs.git
      ]
    );
    deadnix = mk "check-deadnix" ''
      shopt -s globstar
      deadnix --fail flake.nix nix/**/*.nix
    '' [ pkgs.deadnix ];
    statix = mk "check-statix" "statix check ." [ pkgs.statix ];
    nixfmt = mk "check-nixfmt" ''
      shopt -s globstar
      nixfmt --check flake.nix nix/**/*.nix
    '' [ pkgs.nixfmt ];
    flake-check = mk "check-flake-check" "nix flake check --accept-flake-config --no-build" [
      pkgs.nix
    ];
    wasm-rpc = mk "check-wasm-rpc" "cargo check -p hellas-rpc --target wasm32-unknown-unknown" (
      cargoEnv (rustToolchain.override { targets = [ "wasm32-unknown-unknown" ]; })
    );
    wasm-chain = mk "check-wasm-chain" ''
      export CC_wasm32_unknown_unknown=${lib.getExe' pkgs.llvmPackages.clang-unwrapped "clang"}
      export AR_wasm32_unknown_unknown=${lib.getExe' pkgs.llvmPackages.llvm "llvm-ar"}
      cargo check -p hellas-chain --no-default-features --features wasm-client --target wasm32-unknown-unknown
    '' (cargoEnv (rustToolchain.override { targets = [ "wasm32-unknown-unknown" ]; }));
    wasm-xet = mk "check-wasm-xet" "cargo check -p hellas-xet --target wasm32-unknown-unknown" (
      cargoEnv (rustToolchain.override { targets = [ "wasm32-unknown-unknown" ]; })
    );
    # `hellas-xet` sits inside the `#![no_std]` kernel's dependency
    # closure, which must be allocation-free. With default features off
    # the crate takes the `alloc` name for an empty module of its own, so
    # this build is what fails — loudly, at compile time — the moment
    # someone reaches for a `Vec` there again. It cannot ride along with
    # `check-clippy`: a workspace build unifies `chunking` back on.
    xet-no-alloc = mk "check-xet-no-alloc" "cargo build -p hellas-xet --no-default-features" (
      cargoEnv rustToolchain
    );
  };

  checks = baseChecks // extraChecks;

  # Auto-fix variants. Not all checks have one (e.g. test, wasm-rpc).
  fixes = {
    fmt = mk "fix-fmt" "cargo fmt --all" [ rustToolchain ];
    clippy =
      mk "fix-clippy" "cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged"
        (cargoEnv rustToolchain);
    sort = mk "fix-sort" "cargo-sort --workspace --no-format" [ pkgs.cargo-sort ];
  };

  # `nix run .#check` runs every gating check.
  # `nix run .#fix`   runs the auto-fix variants.
  mkAggregate =
    name: pkgList:
    pkgs.writeShellApplication {
      inherit name;
      text = lib.concatMapStringsSep "\n" lib.getExe pkgList;
    };

  # Extended builds. Each value is an attribute path under `packages.<system>`
  # consumed by matrix runners as
  # `nix build .#packages.<system>.<attr>`.
  ciBuilds = {
    cli = "cli";
    cli-candle = "cli-candle";
    cli-validator = "cli-validator";
    static-x86_64 = "cross-x86_64-linux-musl-cli";
    static-aarch64 = "cross-aarch64-linux-musl-cli";
    static-windows = "cross-x86_64-windows-cli";
    docker-cuda = "docker-cuda";
    hellas-rpc-wasm = "hellas-rpc-wasm";
  };
in
{
  inherit checks fixes;
  builds = ciBuilds;
  checkAll = mkAggregate "check-all" (lib.attrValues checks);
  fixAll = mkAggregate "fix-all" (lib.attrValues fixes);
}
